use std::{borrow::Cow, collections::HashSet, future::Future, pin::Pin, sync::LazyLock, time::Duration};

use openidconnect::{
    AccessToken, AsyncHttpClient, AuthDisplay, AuthPrompt, AuthType, AuthenticationFlow, AuthorizationCode,
    AuthorizationRequest, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, HttpClientError, HttpRequest, HttpResponse, IdTokenClaims, IdTokenFields, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, RequestTokenError, ResponseType, Scope,
    StandardErrorResponse, StandardTokenResponse, UserInfoError,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreClientAuthMethod, CoreErrorResponseType, CoreGenderClaim,
        CoreIdTokenVerifier, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreTokenIntrospectionResponse, CoreTokenResponse, CoreTokenType, CoreUserInfoClaims,
    },
    http, url,
};
use regex::Regex;
use url::Url;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    db::models::SsoAuth,
    error::Error,
    http_client::get_reqwest_client_builder,
    sso::{OIDCCode, OIDCCodeChallenge, OIDCCodeVerifier, OIDCState},
};

static CLIENT_CACHE_KEY: LazyLock<String> = LazyLock::new(|| "sso-client".to_owned());
static CLIENT_CACHE: LazyLock<moka::sync::Cache<String, Client>> = LazyLock::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(1)
        .time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration()))
        .build()
});
static REFRESH_CACHE: LazyLock<moka::future::Cache<String, RefreshResult>> =
    LazyLock::new(|| moka::future::Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(30)).build());

/// OpenID Connect Core client.
pub type CustomClient = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

pub type RefreshTokenResponse = (Option<String>, String, Option<Duration>);
// The error carries the HTTP status to answer with, see `refresh_error_status`.
type RefreshResult = Result<RefreshTokenResponse, (u16, String)>;

#[derive(Clone)]
pub struct Client {
    pub http_client: OidcHttpClient,
    pub core_client: CustomClient,
}

#[derive(Clone)]
pub struct OidcHttpClient {
    client: reqwest::Client,
}

impl OidcHttpClient {
    fn new() -> Result<Self, reqwest::Error> {
        get_reqwest_client_builder(false).redirect(reqwest::redirect::Policy::none()).build().map(|client| Self {
            client,
        })
    }
}

impl<'c> AsyncHttpClient<'c> for OidcHttpClient {
    type Error = HttpClientError<reqwest::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.client.execute(request.try_into().map_err(Box::new)?).await.map_err(|e| {
                debug!("Request failed {e:?}");
                Box::new(e)
            })?;

            let mut builder = http::Response::builder().status(response.status()).version(response.version());

            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }

            let body = response.bytes().await.map_err(Box::new)?;
            if CONFIG.sso_debug_tokens() {
                debug!("Response body {}", String::from_utf8_lossy(&body));
            }
            builder.body(body.to_vec()).map_err(HttpClientError::Http)
        })
    }
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match OidcHttpClient::new() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
            Err(err) => err_code!(format!("Failed to discover OpenID provider: {err}"), 503),
            Ok(metadata) => metadata,
        };

        let auth_methods: Option<HashSet<CoreClientAuthMethod>> = provider_metadata
            .token_endpoint_auth_methods_supported()
            .map(|v| v.iter().map(ToOwned::to_owned).collect());

        let mut base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        if let Some(am) = auth_methods {
            if am.contains(&CoreClientAuthMethod::ClientSecretBasic) {
                base_client = base_client.set_auth_type(AuthType::BasicAuth); // Default
            } else if am.contains(&CoreClientAuthMethod::ClientSecretPost) {
                base_client = base_client.set_auth_type(AuthType::RequestBody);
            } else {
                err!(format!("No supported auth_methods (only basic or request body), advertised: {am:?}"));
            }
        }

        let token_uri = if let Some(uri) = base_client.token_uri() {
            uri.clone()
        } else {
            err!("Failed to discover token_url, cannot proceed")
        };

        let user_info_url = if let Some(url) = base_client.user_info_url() {
            url.clone()
        } else {
            err!("Failed to discover user_info url, cannot proceed")
        };

        let core_client = base_client
            .set_redirect_uri(CONFIG.sso_redirect_url()?)
            .set_token_uri(token_uri)
            .set_user_info_url(user_info_url);

        Ok(Client {
            http_client,
            core_client,
        })
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    pub async fn cached() -> ApiResult<Self> {
        if CONFIG.sso_client_cache_expiration() > 0 {
            match CLIENT_CACHE.get(&*CLIENT_CACHE_KEY) {
                Some(client) => Ok(client),
                None => Self::get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::get_client().await
        }
    }

    pub fn invalidate() {
        if CONFIG.sso_client_cache_expiration() > 0 {
            CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
        }
    }

    // The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
    pub async fn authorize_url(
        state: OIDCState,
        client_challenge: OIDCCodeChallenge,
        redirect_uri: String,
        binding_hash: Option<String>,
    ) -> ApiResult<(Url, SsoAuth)> {
        let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);
        let base64_state = data_encoding::BASE64.encode(state.to_string().as_bytes());

        let client = Self::cached().await?;
        let mut auth_req = client
            .core_client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                || CsrfToken::new(base64_state),
                Nonce::new_random,
            )
            .add_scopes(scopes)
            .add_extra_params(CONFIG.sso_authorize_extra_params_vec());

        if CONFIG.sso_pkce() {
            auth_req = auth_req
                .add_extra_param::<&str, String>("code_challenge", client_challenge.clone().into())
                .add_extra_param("code_challenge_method", "S256");
        }

        let (auth_url, _, nonce) = auth_req.url();
        Ok((auth_url, SsoAuth::new(state, client_challenge, nonce.secret().clone(), redirect_uri, binding_hash)))
    }

    // Check the client's PKCE verifier against the challenge it sent when starting the flow
    pub fn check_client_verifier(client_verifier: &OIDCCodeVerifier, sso_auth: &SsoAuth) -> EmptyResult {
        let verifier = PkceCodeVerifier::new(client_verifier.to_string());
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        if challenge.as_str() != &*sso_auth.client_challenge {
            err!("PKCE client challenge failed")
        }
        Ok(())
    }

    pub async fn exchange_code(
        &self,
        code: OIDCCode,
        client_verifier: OIDCCodeVerifier,
        sso_auth: &SsoAuth,
    ) -> ApiResult<(
        StandardTokenResponse<
            IdTokenFields<
                EmptyAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            >,
            CoreTokenType,
        >,
        IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
    )> {
        let oidc_code = AuthorizationCode::new(code.to_string());

        let mut exchange = self.core_client.exchange_code(oidc_code);

        if CONFIG.sso_pkce() {
            exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(client_verifier.into()));
        } else {
            Self::check_client_verifier(&client_verifier, sso_auth)?;
        }

        match exchange.request_async(&self.http_client).await {
            Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
            Ok(token_response) => {
                let oidc_nonce = Nonce::new(sso_auth.nonce.clone());

                let Some(id_token) = token_response.extra_fields().id_token() else {
                    err!("Token response did not contain an id_token")
                };

                if CONFIG.sso_debug_tokens() {
                    debug!("Id token: {}", id_token.to_string());
                    debug!("Access token: {}", token_response.access_token().secret());
                    debug!("Refresh token: {:?}", token_response.refresh_token().map(RefreshToken::secret));
                    debug!("Expiration time: {:?}", token_response.expires_in());
                }

                let id_claims = match id_token.claims(&self.vw_id_token_verifier(), &oidc_nonce) {
                    Ok(claims) => claims.clone(),
                    Err(err) => {
                        Self::invalidate();
                        err!(format!("Could not read id_token claims, {err}"));
                    }
                };

                Ok((token_response, id_claims))
            }
        }
    }

    pub async fn user_info(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
        match self.core_client.user_info(access_token, None).request_async(&self.http_client).await {
            Err(err) => {
                let code = user_info_error_status(&err);
                err_code!(format!("Request to user_info endpoint failed: {err}"), code)
            }
            Ok(user_info) => Ok(user_info),
        }
    }

    pub async fn check_validity(access_token: String) -> EmptyResult {
        let client = Client::cached().await?;
        match client.user_info(AccessToken::new(access_token)).await {
            Err(err) => {
                Err(Error::new_msg(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
                    .with_code(err.get_code()))
            }
            Ok(_) => Ok(()),
        }
    }

    pub fn vw_id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
        let mut verifier = self.core_client.id_token_verifier();
        if let Some(regex_str) = CONFIG.sso_audience_trusted() {
            match Regex::new(&regex_str) {
                Ok(regex) => {
                    verifier = verifier.set_other_audience_verifier_fn(move |aud| regex.is_match(aud));
                }
                Err(err) => {
                    error!("Failed to parse SSO_AUDIENCE_TRUSTED={regex_str} regex: {err}");
                }
            }
        }
        verifier
    }

    pub async fn exchange_refresh_token(refresh_token: String) -> ApiResult<RefreshTokenResponse> {
        let client = Client::cached().await?;

        REFRESH_CACHE
            .get_with(refresh_token.clone(), async move { client.exchange_refresh_token_impl(refresh_token).await })
            .await
            .map_err(|(code, msg)| Error::new_msg(msg).with_code(code))
    }

    async fn exchange_refresh_token_impl(&self, refresh_token: String) -> RefreshResult {
        let rt = RefreshToken::new(refresh_token);

        match self.core_client.exchange_refresh_token(&rt).request_async(&self.http_client).await {
            Err(err) => {
                error!("Request to exchange_refresh_token endpoint failed: {err}");
                let code = refresh_error_status(&err);
                Err((code, format!("Request to exchange_refresh_token endpoint failed: {err}")))
            }
            Ok(token_response) => Ok((
                token_response.refresh_token().map(|token| token.secret().clone()),
                token_response.access_token().secret().clone(),
                token_response.expires_in(),
            )),
        }
    }
}

trait AuthorizationRequestExt<'a> {
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(self, params: Vec<(N, V)>) -> Self;
}

impl<'a, AD: AuthDisplay, P: AuthPrompt, RT: ResponseType> AuthorizationRequestExt<'a>
    for AuthorizationRequest<'a, AD, P, RT>
{
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(mut self, params: Vec<(N, V)>) -> Self {
        for (key, value) in params {
            self = self.add_extra_param(key, value);
        }
        self
    }
}

fn refresh_error_status<RE>(err: &RequestTokenError<RE, StandardErrorResponse<CoreErrorResponseType>>) -> u16
where
    RE: std::error::Error + 'static,
{
    match err {
        RequestTokenError::ServerResponse(resp) => match resp.error() {
            CoreErrorResponseType::Extension(code) if code == "temporarily_unavailable" || code == "server_error" => {
                503
            }
            _ => 400,
        },
        RequestTokenError::Request(_) | RequestTokenError::Parse(..) | RequestTokenError::Other(_) => 503,
    }
}

fn user_info_error_status<RE>(err: &UserInfoError<RE>) -> u16
where
    RE: std::error::Error + 'static,
{
    match err {
        UserInfoError::Request(_) => 503,
        UserInfoError::Response(status, ..) if status.is_server_error() => 503,
        _ => 400,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TokenErr = RequestTokenError<HttpClientError<reqwest::Error>, StandardErrorResponse<CoreErrorResponseType>>;

    #[test]
    fn test_refresh_error_status_invalid_grant() {
        let err = TokenErr::ServerResponse(StandardErrorResponse::new(CoreErrorResponseType::InvalidGrant, None, None));
        assert_eq!(refresh_error_status(&err), 400);
    }

    #[test]
    fn test_refresh_error_status_temporarily_unavailable() {
        let err = TokenErr::ServerResponse(StandardErrorResponse::new(
            CoreErrorResponseType::Extension("temporarily_unavailable".to_owned()),
            None,
            None,
        ));
        assert_eq!(refresh_error_status(&err), 503);
    }

    #[test]
    fn test_refresh_error_status_other() {
        let err = TokenErr::Other("unexpected response from the token endpoint".to_owned());
        assert_eq!(refresh_error_status(&err), 503);
    }

    #[test]
    fn test_refresh_error_status_request() {
        let err = TokenErr::Request(HttpClientError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        )));
        assert_eq!(refresh_error_status(&err), 503);
    }

    type UserInfoErr = UserInfoError<HttpClientError<reqwest::Error>>;

    #[test]
    fn test_user_info_error_status_unauthorized() {
        let err = UserInfoErr::Response(http::StatusCode::UNAUTHORIZED, Vec::new(), "invalid_token".to_owned());
        assert_eq!(user_info_error_status(&err), 400);
    }

    #[test]
    fn test_user_info_error_status_unavailable() {
        let err = UserInfoErr::Response(http::StatusCode::SERVICE_UNAVAILABLE, Vec::new(), "down".to_owned());
        assert_eq!(user_info_error_status(&err), 503);
    }
}
