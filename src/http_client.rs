use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use hickory_resolver::{name_server::TokioConnectionProvider, TokioResolver};
use once_cell::sync::Lazy;
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

    should_block_host(host)?;

    static INSTANCE: Lazy<Client> = Lazy::new(|| get_reqwest_client_builder().build().expect("Failed to build client"));

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

        if let Err(e) = should_block_host(host) {
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

pub fn should_block_address(domain_or_ip: &str) -> bool {
    if let Ok(ip) = IpAddr::from_str(domain_or_ip) {
        if should_block_ip(ip) {
            return true;
        }
    }

    should_block_address_regex(domain_or_ip)
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

fn should_block_host(host: Host<&str>) -> Result<(), CustomHttpClientError> {
    let (ip, host_str): (Option<IpAddr>, String) = match host {
        Host::Ipv4(ip) => (Some(ip.into()), ip.to_string()),
        Host::Ipv6(ip) => (Some(ip.into()), ip.to_string()),
        Host::Domain(d) => (None, d.to_string()),
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
            } => write!(f, "Blocked domain: {domain} matched HTTP_REQUEST_BLOCK_REGEX"),
            Self::NonGlobalIp {
                domain: Some(domain),
                ip,
            } => write!(f, "IP {ip} for domain '{domain}' is not a global IP!"),
            Self::NonGlobalIp {
                domain: None,
                ip,
            } => write!(f, "IP {ip} is not a global IP!"),
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
        static INSTANCE: Lazy<Arc<CustomDnsResolver>> = Lazy::new(CustomDnsResolver::new);
        Arc::clone(&*INSTANCE)
    }

    fn new() -> Arc<Self> {
        match TokioResolver::builder(TokioConnectionProvider::default()) {
            Ok(builder) => {
                let resolver = builder.build();
                Arc::new(Self::Hickory(Arc::new(resolver)))
            }
            Err(e) => {
                warn!("Error creating Hickory resolver, falling back to default: {e:?}");
                Arc::new(Self::Default())
            }
        }
    }

    // Note that we get an iterator of addresses, but we only grab the first one for convenience
    async fn resolve_domain(&self, name: &str) -> Result<Option<SocketAddr>, BoxError> {
        pre_resolve(name)?;

        let result = match self {
            Self::Default() => tokio::net::lookup_host(name).await?.next(),
            Self::Hickory(r) => r.lookup_ip(name).await?.iter().next().map(|a| SocketAddr::new(a, 0)),
        };

        if let Some(addr) = &result {
            post_resolve(name, addr.ip())?;
        }

        Ok(result)
    }
}

fn pre_resolve(name: &str) -> Result<(), CustomHttpClientError> {
    if should_block_address(name) {
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
            let result = this.resolve_domain(name).await?;
            Ok::<reqwest::dns::Addrs, _>(Box::new(result.into_iter()))
        })
    }
}
