use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use hickory_resolver::{net::runtime::TokioRuntimeProvider, TokioResolver};
use regex::Regex;
use reqwest::{
    dns::{Name, Resolve, Resolving},
    header, Client, ClientBuilder,
};
use url::Host;

use crate::{util::is_global, CONFIG};

pub fn make_http_request(method: reqwest::Method, url: &str) -> Result<reqwest::RequestBuilder, crate::Error> {
    let Ok(url) = url::Url::parse(url) else {
        err!("Invalid URL");
    };
    let Some(host) = url.host() else {
        err!("Invalid host");
    };

    should_block_host(&host)?;

    static INSTANCE: LazyLock<Client> =
        LazyLock::new(|| get_reqwest_client_builder().build().expect("Failed to build client"));

    Ok(INSTANCE.request(method, url))
}

pub fn get_reqwest_client_builder() -> ClientBuilder {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("Vaultwarden"));

    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("Too many redirects");
        }

        let Some(host) = attempt.url().host() else {
            return attempt.error("Invalid host");
        };

        if let Err(e) = should_block_host(&host) {
            return attempt.error(e);
        }

        attempt.follow()
    });

    Client::builder()
        .default_headers(headers)
        .redirect(redirect_policy)
        .dns_resolver(CustomDnsResolver::instance())
        .timeout(Duration::from_secs(10))
}

fn should_block_ip(ip: IpAddr) -> bool {
    if !CONFIG.http_request_block_non_global_ips() {
        return false;
    }

    !is_global(ip)
}

fn should_block_address_regex(domain_or_ip: &str) -> bool {
    let Some(block_regex) = CONFIG.http_request_block_regex() else {
        return false;
    };

    static COMPILED_REGEX: Mutex<Option<(String, Regex)>> = Mutex::new(None);
    let mut guard = COMPILED_REGEX.lock().unwrap();

    // If the stored regex is up to date, use it
    if let Some((value, regex)) = &*guard {
        if value == &block_regex {
            return regex.is_match(domain_or_ip);
        }
    }

    // If we don't have a regex stored, or it's not up to date, recreate it
    let regex = Regex::new(&block_regex).unwrap();
    let is_match = regex.is_match(domain_or_ip);
    *guard = Some((block_regex, regex));

    is_match
}

pub fn get_valid_host(host: &str) -> Result<Host, CustomHttpClientError> {
    let Ok(host) = Host::parse(host) else {
        return Err(CustomHttpClientError::Invalid {
            domain: host.to_string(),
        });
    };

    // Some extra checks to validate hosts
    match host {
        Host::Domain(ref domain) => {
            // Host::parse() does not verify length or all possible invalid characters
            // We do some extra checks here to prevent issues
            if domain.len() > 253 {
                debug!("Domain validation error: '{domain}' exceeds 253 characters");
                return Err(CustomHttpClientError::Invalid {
                    domain: host.to_string(),
                });
            }
            if !domain.split('.').all(|label| {
                !label.is_empty()
                    // Labels can't be longer than 63 chars
                    && label.len() <= 63
                    // Labels are not allowed to start or end with a hyphen `-`
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    // Only ASCII Alphanumeric characters are allowed
                    // We already received a punycoded domain back, so no unicode should exists here
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            }) {
                debug!(
                    "Domain validation error: '{domain}' labels contain invalid characters or exceed the maximum length"
                );
                return Err(CustomHttpClientError::Invalid {
                    domain: host.to_string(),
                });
            }
        }
        Host::Ipv4(_) | Host::Ipv6(_) => {}
    }

    Ok(host)
}

pub fn should_block_host<S: AsRef<str>>(host: &Host<S>) -> Result<(), CustomHttpClientError> {
    let (ip, host_str): (Option<IpAddr>, String) = match host {
        Host::Ipv4(ip) => (Some(IpAddr::V4(*ip)), ip.to_string()),
        Host::Ipv6(ip) => (Some(IpAddr::V6(*ip)), ip.to_string()),
        Host::Domain(d) => (None, d.as_ref().to_string()),
    };

    if let Some(ip) = ip {
        if should_block_ip(ip) {
            return Err(CustomHttpClientError::NonGlobalIp {
                domain: None,
                ip,
            });
        }
    }

    if should_block_address_regex(&host_str) {
        return Err(CustomHttpClientError::Blocked {
            domain: host_str,
        });
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub enum CustomHttpClientError {
    Blocked {
        domain: String,
    },
    NonGlobalIp {
        domain: Option<String>,
        ip: IpAddr,
    },
    Invalid {
        domain: String,
    },
}

impl CustomHttpClientError {
    pub fn downcast_ref(e: &dyn std::error::Error) -> Option<&Self> {
        let mut source = e.source();

        while let Some(err) = source {
            source = err.source();
            if let Some(err) = err.downcast_ref::<CustomHttpClientError>() {
                return Some(err);
            }
        }
        None
    }
}

impl fmt::Display for CustomHttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked {
                domain,
            } => write!(f, "Blocked domain: '{domain}' matched HTTP_REQUEST_BLOCK_REGEX"),
            Self::NonGlobalIp {
                domain: Some(domain),
                ip,
            } => write!(f, "IP {ip} for domain '{domain}' is not a global IP!"),
            Self::NonGlobalIp {
                domain: None,
                ip,
            } => write!(f, "IP '{ip}' is not a global IP!"),
            Self::Invalid {
                domain,
            } => write!(f, "Invalid host: '{domain}' contains invalid characters or exceeds the maximum length"),
        }
    }
}

impl std::error::Error for CustomHttpClientError {}

#[derive(Debug, Clone)]
enum CustomDnsResolver {
    Default(),
    Hickory(Arc<TokioResolver>),
}
type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl CustomDnsResolver {
    fn instance() -> Arc<Self> {
        static INSTANCE: LazyLock<Arc<CustomDnsResolver>> = LazyLock::new(CustomDnsResolver::new);
        Arc::clone(&*INSTANCE)
    }

    fn new() -> Arc<Self> {
        TokioResolver::builder(TokioRuntimeProvider::default())
            .and_then(|mut builder| {
                // Hickory's default since v0.26 is `Ipv6AndIpv4`, which sorts IPv6 first
                // This might cause issues on IPv4 only systems or containers
                // Unless someone enabled DNS_PREFER_IPV6, use Ipv4AndIpv6, which returns IPv4 first which was our previous default
                if !CONFIG.dns_prefer_ipv6() {
                    builder.options_mut().ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
                }
                builder.build()
            })
            .inspect_err(|e| warn!("Error creating Hickory resolver, falling back to default: {e:?}"))
            .map(|resolver| Arc::new(Self::Hickory(Arc::new(resolver))))
            .unwrap_or_else(|_| Arc::new(Self::Default()))
    }

    // Note that we get an iterator of addresses, but we only grab the first one for convenience
    async fn resolve_domain(&self, name: &str) -> Result<Vec<SocketAddr>, BoxError> {
        pre_resolve(name)?;

        let results: Vec<SocketAddr> = match self {
            Self::Default() => tokio::net::lookup_host((name, 0)).await?.collect(),
            Self::Hickory(r) => r.lookup_ip(name).await?.iter().map(|i| SocketAddr::new(i, 0)).collect(),
        };

        for addr in &results {
            post_resolve(name, addr.ip())?;
        }

        Ok(results)
    }
}

fn pre_resolve(name: &str) -> Result<(), CustomHttpClientError> {
    let Ok(host) = get_valid_host(name) else {
        return Err(CustomHttpClientError::Invalid {
            domain: name.to_string(),
        });
    };

    if should_block_host(&host).is_err() {
        return Err(CustomHttpClientError::Blocked {
            domain: name.to_string(),
        });
    }

    Ok(())
}

fn post_resolve(name: &str, ip: IpAddr) -> Result<(), CustomHttpClientError> {
    if should_block_ip(ip) {
        Err(CustomHttpClientError::NonGlobalIp {
            domain: Some(name.to_string()),
            ip,
        })
    } else {
        Ok(())
    }
}

impl Resolve for CustomDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        Box::pin(async move {
            let name = name.as_str();
            let results = this.resolve_domain(name).await?;
            if results.is_empty() {
                warn!("Unable to resolve {name} to any valid IP address");
            }
            Ok::<reqwest::dns::Addrs, _>(Box::new(results.into_iter()))
        })
    }
}

#[cfg(s3)]
pub(crate) mod aws {
    use aws_smithy_runtime_api::client::{
        http::{HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector},
        orchestrator::HttpResponse,
        result::ConnectorError,
        runtime_components::RuntimeComponents,
    };
    use reqwest::Client;

    // Adapter that wraps reqwest to be compatible with the AWS SDK
    #[derive(Debug)]
    pub(crate) struct AwsReqwestConnector {
        pub(crate) client: Client,
    }

    impl HttpConnector for AwsReqwestConnector {
        fn call(&self, request: aws_smithy_runtime_api::client::orchestrator::HttpRequest) -> HttpConnectorFuture {
            // Convert the AWS-style request to a reqwest request
            let client = self.client.clone();
            let future = async move {
                let method = reqwest::Method::from_bytes(request.method().as_bytes())
                    .map_err(|e| ConnectorError::user(Box::new(e)))?;
                let mut req_builder = client.request(method, request.uri().to_string());

                for (name, value) in request.headers() {
                    req_builder = req_builder.header(name, value);
                }

                if let Some(body_bytes) = request.body().bytes() {
                    req_builder = req_builder.body(body_bytes.to_vec());
                }

                let response = req_builder.send().await.map_err(|e| ConnectorError::io(Box::new(e)))?;

                let status = response.status().into();
                let bytes = response.bytes().await.map_err(|e| ConnectorError::io(Box::new(e)))?;

                Ok(HttpResponse::new(status, bytes.into()))
            };

            HttpConnectorFuture::new(Box::pin(future))
        }
    }

    impl HttpClient for AwsReqwestConnector {
        fn http_connector(
            &self,
            _settings: &HttpConnectorSettings,
            _components: &RuntimeComponents,
        ) -> SharedHttpConnector {
            SharedHttpConnector::new(AwsReqwestConnector {
                client: self.client.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::is_global_hardcoded;
    use std::net::Ipv4Addr;
    use url::Host;

    // ===
    // IPv4 numeric-format normalization
    fn parse_to_ip(s: &str) -> Option<IpAddr> {
        match Host::parse(s).ok()? {
            Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
            Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
            Host::Domain(_) => None,
        }
    }

    #[test]
    fn dotted_decimal_loopback_normalizes() {
        let ip = parse_to_ip("127.0.0.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn single_decimal_loopback_normalizes() {
        // 127.0.0.1 == 2130706433
        let ip = parse_to_ip("2130706433").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn hex_loopback_normalizes() {
        let ip = parse_to_ip("0x7f000001").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn dotted_hex_loopback_normalizes() {
        let ip = parse_to_ip("0x7f.0.0.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn octal_loopback_normalizes() {
        // 017700000001 == 127.0.0.1
        let ip = parse_to_ip("017700000001").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn dotted_octal_loopback_normalizes() {
        let ip = parse_to_ip("0177.0.0.01").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn aws_metadata_decimal_blocked() {
        // 169.254.169.254 == 2852039166 (link-local, AWS IMDS)
        let ip = parse_to_ip("2852039166").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn rfc1918_hex_blocked() {
        // 10.0.0.1
        let ip = parse_to_ip("0x0a000001").unwrap();
        assert!(!is_global_hardcoded(ip));
    }

    #[test]
    fn public_ip_decimal_allowed() {
        // 8.8.8.8 == 134744072
        let ip = parse_to_ip("134744072").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_global_hardcoded(ip));
    }

    // ===
    // get_valid_host integration: numeric forms become Host::Ipv4
    #[test]
    fn get_valid_host_normalizes_decimal_int() {
        let h = get_valid_host("2130706433").expect("valid");
        assert!(matches!(h, Host::Ipv4(ip) if ip == Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn get_valid_host_normalizes_hex() {
        let h = get_valid_host("0x7f000001").expect("valid");
        assert!(matches!(h, Host::Ipv4(ip) if ip == Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn get_valid_host_normalizes_octal() {
        let h = get_valid_host("017700000001").expect("valid");
        assert!(matches!(h, Host::Ipv4(ip) if ip == Ipv4Addr::new(127, 0, 0, 1)));
    }

    // ===
    // IPv6 formats
    #[test]
    fn ipv6_loopback_blocked() {
        let h = get_valid_host("[::1]").expect("valid");
        let Host::Ipv6(ip) = h else {
            panic!("expected v6")
        };
        assert!(!is_global_hardcoded(IpAddr::V6(ip)));
    }

    #[test]
    fn ipv4_mapped_in_ipv6_loopback_blocked() {
        // ::ffff:127.0.0.1 — v4-mapped form; is_global_hardcoded blocks via ::ffff:0:0/96
        let h = get_valid_host("[::ffff:127.0.0.1]").expect("valid");
        let Host::Ipv6(ip) = h else {
            panic!("expected v6")
        };
        assert!(!is_global_hardcoded(IpAddr::V6(ip)));
    }

    #[test]
    fn ipv6_unique_local_blocked() {
        let h = get_valid_host("[fc00::1]").expect("valid");
        let Host::Ipv6(ip) = h else {
            panic!("expected v6")
        };
        assert!(!is_global_hardcoded(IpAddr::V6(ip)));
    }

    // ===
    // Punycode / IDN
    #[test]
    fn punycode_passthrough() {
        let h = get_valid_host("xn--deadbeafcaf-lbb.test").expect("valid");
        match h {
            Host::Domain(d) => assert_eq!(d, "xn--deadbeafcaf-lbb.test"),
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn idn_unicode_gets_punycoded() {
        let h = get_valid_host("deadbeafcafé.test").expect("valid");
        match h {
            Host::Domain(d) => assert_eq!(d, "xn--deadbeafcaf-lbb.test"),
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn idn_unicode_gets_punycoded_tld() {
        let h = get_valid_host("deadbeaf.café").expect("valid");
        match h {
            Host::Domain(d) => assert_eq!(d, "deadbeaf.xn--caf-dma"),
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn idn_emoji_gets_punycoded() {
        let h = get_valid_host("xn--t88h.test").expect("valid"); // 🛡️.test
        match h {
            Host::Domain(d) => assert_eq!(d, "xn--t88h.test"),
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn idn_unicode_to_punycode_roundtrip() {
        let from_unicode = get_valid_host("🛡️.test").expect("valid");
        let from_puny = get_valid_host("xn--t88h.test").expect("valid");
        match (from_unicode, from_puny) {
            (Host::Domain(a), Host::Domain(b)) => assert_eq!(a, b),
            _ => panic!("expected domains"),
        }
    }

    #[test]
    fn invalid_punycode_rejected() {
        // bare invalid punycode
        assert!(get_valid_host("xn--").is_err());
    }

    #[test]
    fn underscore_in_label_rejected() {
        assert!(get_valid_host("dead_beaf.cafe").is_err());
    }

    #[test]
    fn label_too_long_rejected() {
        let label = "a".repeat(64);
        assert!(get_valid_host(&format!("{label}.test")).is_err());
    }

    #[test]
    fn domain_too_long_rejected() {
        let big = "a.".repeat(130) + "test"; // > 253
        assert!(get_valid_host(&big).is_err());
    }
}
