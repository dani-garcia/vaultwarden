use std::sync::LazyLock;

pub(crate) fn join_path(base: &str, child: &str) -> String {
    #[cfg(s3)]
    if s3::is_uri(base) {
        return s3::join_path(base, child);
    }

    let base = base.trim_end_matches('/');
    let child = child.trim_start_matches('/');
    if base.is_empty() {
        child.to_string()
    } else if child.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{child}")
    }
}

pub(crate) fn with_extension(path: &str, extension: &str) -> String {
    let extension = extension.trim_start_matches('.');

    #[cfg(s3)]
    if s3::is_uri(path) {
        return s3::with_extension(path, extension);
    }

    format!("{path}.{extension}")
}

pub(crate) fn parent(path: &str) -> Option<String> {
    #[cfg(s3)]
    if s3::is_uri(path) {
        return s3::parent(path);
    }

    std::path::Path::new(path).parent()?.to_str().map(ToString::to_string)
}

pub(crate) fn file_name(path: &str) -> Option<String> {
    #[cfg(s3)]
    if s3::is_uri(path) {
        return s3::file_name(path);
    }

    std::path::Path::new(path).file_name()?.to_str().map(ToString::to_string)
}

pub(crate) fn is_fs_operator(operator: &opendal::Operator) -> bool {
    operator.info().scheme() == opendal::services::FS_SCHEME
}

pub(crate) fn operator_for_path(path: &str) -> Result<opendal::Operator, crate::Error> {
    // Cache of previously built operators by path
    static OPERATORS_BY_PATH: LazyLock<dashmap::DashMap<String, opendal::Operator>> =
        LazyLock::new(dashmap::DashMap::new);

    if let Some(operator) = OPERATORS_BY_PATH.get(path) {
        return Ok(operator.clone());
    }

    let operator = if path.starts_with("s3://") {
        #[cfg(not(s3))]
        return Err(opendal::Error::new(opendal::ErrorKind::ConfigInvalid, "S3 support is not enabled").into());

        #[cfg(s3)]
        s3::operator_for_path(path)?
    } else {
        let builder = opendal::services::Fs::default().root(path);
        opendal::Operator::new(builder)?.finish()
    };

    OPERATORS_BY_PATH.insert(path.to_string(), operator.clone());

    Ok(operator)
}

#[cfg(s3)]
mod s3 {
    use reqwest::Url;

    use crate::error::Error;

    pub(super) fn is_uri(path: &str) -> bool {
        path.starts_with("s3://")
    }

    pub(super) fn join_path(base: &str, child: &str) -> String {
        if let Ok(mut url) = Url::parse(base) {
            let mut segments = path_segments(&url);
            segments.extend(child.split('/').filter(|segment| !segment.is_empty()).map(ToString::to_string));
            set_path_segments(&mut url, &segments);
            return url.to_string();
        }

        let base = base.trim_end_matches('/');
        let child = child.trim_start_matches('/');
        if base.is_empty() {
            child.to_string()
        } else if child.is_empty() {
            base.to_string()
        } else {
            format!("{base}/{child}")
        }
    }

    pub(super) fn with_extension(path: &str, extension: &str) -> String {
        if let Ok(mut url) = Url::parse(path) {
            let mut segments = path_segments(&url);
            if let Some(file_name) = segments.last_mut() {
                file_name.push('.');
                file_name.push_str(extension);
                set_path_segments(&mut url, &segments);
                return url.to_string();
            }
        }

        format!("{path}.{extension}")
    }

    pub(super) fn parent(path: &str) -> Option<String> {
        if let Ok(mut url) = Url::parse(path) {
            let mut segments = path_segments(&url);
            segments.pop()?;
            set_path_segments(&mut url, &segments);
            return Some(url.to_string());
        }

        std::path::Path::new(path).parent()?.to_str().map(ToString::to_string)
    }

    pub(super) fn file_name(path: &str) -> Option<String> {
        if let Ok(url) = Url::parse(path) {
            return path_segments(&url).pop();
        }

        std::path::Path::new(path).file_name()?.to_str().map(ToString::to_string)
    }

    fn path_segments(url: &Url) -> Vec<String> {
        url.path_segments()
            .map(|segments| segments.filter(|segment| !segment.is_empty()).map(ToString::to_string).collect())
            .unwrap_or_default()
    }

    fn set_path_segments(url: &mut Url, segments: &[String]) {
        if segments.is_empty() {
            url.set_path("");
        } else {
            url.set_path(&format!("/{}", segments.join("/")));
        }
    }

    pub(super) fn operator_for_path(path: &str) -> Result<opendal::Operator, Error> {
        use crate::http_client::aws::AwsReqwestConnector;
        use aws_config::{default_provider::credentials::DefaultCredentialsChain, provider_config::ProviderConfig};
        use opendal::Configurator;
        use reqsign_aws_v4::Credential;
        use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain};

        // This is a custom AWS credential loader that uses the official AWS Rust
        // SDK config crate to load credentials. This ensures maximum compatibility
        // with AWS credential configurations. For example, OpenDAL doesn't support
        // AWS SSO temporary credentials yet.
        #[derive(Debug)]
        struct OpenDALS3CredentialProvider;

        impl ProvideCredential for OpenDALS3CredentialProvider {
            type Credential = Credential;

            async fn provide_credential(&self, _ctx: &Context) -> reqsign_core::Result<Option<Self::Credential>> {
                use aws_credential_types::provider::ProvideCredentials as _;
                use reqsign_core::time::Timestamp;
                use tokio::sync::OnceCell;

                static DEFAULT_CREDENTIAL_CHAIN: OnceCell<DefaultCredentialsChain> = OnceCell::const_new();

                let chain = DEFAULT_CREDENTIAL_CHAIN
                    .get_or_init(|| {
                        let reqwest_client = reqwest::Client::builder().build().unwrap();
                        let connector = AwsReqwestConnector {
                            client: reqwest_client,
                        };

                        let conf = ProviderConfig::default().with_http_client(connector);

                        DefaultCredentialsChain::builder().configure(conf).build()
                    })
                    .await;

                let creds = chain.provide_credentials().await.map_err(|e| {
                    reqsign_core::Error::unexpected("failed to load AWS credentials via AWS SDK").with_source(e)
                })?;

                let expires_in = if let Some(expiration) = creds.expiry() {
                    let duration = expiration.duration_since(std::time::UNIX_EPOCH).map_err(|e| {
                        reqsign_core::Error::unexpected("AWS credential expiration is before the Unix epoch")
                            .with_source(e)
                    })?;
                    let seconds = i64::try_from(duration.as_secs()).map_err(|e| {
                        reqsign_core::Error::unexpected("AWS credential expiration is too large").with_source(e)
                    })?;
                    Some(Timestamp::from_second(seconds)?)
                } else {
                    None
                };

                Ok(Some(Credential {
                    access_key_id: creds.access_key_id().to_string(),
                    secret_access_key: creds.secret_access_key().to_string(),
                    session_token: creds.session_token().map(|s| s.to_string()),
                    expires_in,
                }))
            }
        }

        let uri = opendal::OperatorUri::new(path, std::iter::empty::<(String, String)>())?;
        let mut config = opendal::services::S3Config::from_uri(&uri)?;

        if !uri_has_option(&uri, &["default_storage_class"]) {
            config.default_storage_class = Some("INTELLIGENT_TIERING".to_string());
        }

        if !uri_has_option(
            &uri,
            &["enable_virtual_host_style", "aws_virtual_hosted_style_request", "virtual_hosted_style_request"],
        ) {
            config.enable_virtual_host_style = true;
        }

        let use_aws_sdk_credentials = !uri_has_credential_options(&uri, &config);
        let mut builder = config.into_builder();

        if use_aws_sdk_credentials {
            builder =
                builder.credential_provider_chain(ProvideCredentialChain::new().push(OpenDALS3CredentialProvider));
        }

        Ok(opendal::Operator::new(builder)?.finish())
    }

    fn uri_has_option(uri: &opendal::OperatorUri, names: &[&str]) -> bool {
        names.iter().any(|name| uri.options().contains_key(*name))
    }

    fn uri_has_credential_options(uri: &opendal::OperatorUri, config: &opendal::services::S3Config) -> bool {
        config.access_key_id.is_some()
            || config.secret_access_key.is_some()
            || config.session_token.is_some()
            || config.role_arn.is_some()
            || config.external_id.is_some()
            || config.role_session_name.is_some()
            || uri_has_option(uri, &["allow_anonymous", "disable_config_load", "disable_ec2_metadata"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_local_paths() {
        assert_eq!(join_path("data", "attachments"), "data/attachments");
        assert_eq!(with_extension("data/rsa_key", "pem"), "data/rsa_key.pem");
        assert_eq!(parent("data/rsa_key.pem").as_deref(), Some("data"));
        assert_eq!(file_name("data/rsa_key.pem").as_deref(), Some("rsa_key.pem"));
    }
}

#[cfg(all(test, s3))]
mod s3_tests {
    use super::*;

    #[test]
    fn joins_s3_path_before_query_string() {
        assert_eq!(
            join_path("s3://bucket/base?region=us-west-2", "attachments"),
            "s3://bucket/base/attachments?region=us-west-2"
        );
    }

    #[test]
    fn appends_extension_before_s3_query_string() {
        assert_eq!(
            with_extension("s3://bucket/base/rsa_key?region=us-west-2", "pem"),
            "s3://bucket/base/rsa_key.pem?region=us-west-2"
        );
    }

    #[test]
    fn splits_s3_parent_and_file_name_without_query_string() {
        let path = "s3://bucket/base/config.json?region=us-west-2";

        assert_eq!(parent(path).as_deref(), Some("s3://bucket/base?region=us-west-2"));
        assert_eq!(file_name(path).as_deref(), Some("config.json"));
    }
}
