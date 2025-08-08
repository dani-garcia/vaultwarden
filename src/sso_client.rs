use regex::Regex;
use std::borrow::Cow;
use std::time::Duration;
use url::Url;

use mini_moka::sync::Cache;
use once_cell::sync::Lazy;
use openidconnect::core::*;
use openidconnect::reqwest;
use openidconnect::*;

use crate::{
    api::{ApiResult, EmptyResult},
    db::models::SsoNonce,
    sso::{OIDCCode, OIDCState},
    CONFIG,
};

static CLIENT_CACHE_KEY: Lazy<String> = Lazy::new(|| "sso-client".to_string());
static CLIENT_CACHE: Lazy<Cache<String, Client>> = Lazy::new(|| {
    Cache::builder().max_capacity(1).time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration())).build()
});

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

#[derive(Clone)]
pub struct Client {
    pub http_client: reqwest::Client,
    pub core_client: CustomClient,
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn _get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
            Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
            Ok(metadata) => metadata,
        };

        let base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        let token_uri = match base_client.token_uri() {
            Some(uri) => uri.clone(),
            None => err!("Failed to discover token_url, cannot proceed"),
        };

        let user_info_url = match base_client.user_info_url() {
            Some(url) => url.clone(),
            None => err!("Failed to discover user_info url, cannot proceed"),
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
                None => Self::_get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::_get_client().await
        }
    }

    pub fn invalidate() {
        if CONFIG.sso_client_cache_expiration() > 0 {
            CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
        }
    }

    // The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
    pub async fn authorize_url(state: OIDCState, redirect_uri: String) -> ApiResult<(Url, SsoNonce)> {
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

        let verifier = if CONFIG.sso_pkce() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            auth_req = auth_req.set_pkce_challenge(pkce_challenge);
            Some(pkce_verifier.into_secret())
        } else {
            None
        };

        let (auth_url, _, nonce) = auth_req.url();
        Ok((auth_url, SsoNonce::new(state, nonce.secret().clone(), verifier, redirect_uri)))
    }

    pub async fn exchange_code(
        &self,
        code: OIDCCode,
        nonce: SsoNonce,
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
            match nonce.verifier {
                None => err!(format!("Missing verifier in the DB nonce table")),
                Some(secret) => exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(secret.clone())),
            }
        }

        match exchange.request_async(&self.http_client).await {
            Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
            Ok(token_response) => {
                let oidc_nonce = Nonce::new(nonce.nonce);

                let id_token = match token_response.extra_fields().id_token() {
                    None => err!("Token response did not contain an id_token"),
                    Some(token) => token,
                };

                if CONFIG.sso_debug_tokens() {
                    debug!("Id token: {}", id_token.to_string());
                    debug!("Access token: {}", token_response.access_token().secret());
                    debug!("Refresh token: {:?}", token_response.refresh_token().map(|t| t.secret()));
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
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }

    pub async fn check_validity(access_token: String) -> EmptyResult {
        let client = Client::cached().await?;
        match client.user_info(AccessToken::new(access_token)).await {
            Err(err) => {
                err_silent!(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
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

    pub async fn exchange_refresh_token(
        refresh_token: String,
    ) -> ApiResult<(Option<String>, String, Option<Duration>)> {
        let rt = RefreshToken::new(refresh_token);

        let client = Client::cached().await?;
        let token_response =
            match client.core_client.exchange_refresh_token(&rt).request_async(&client.http_client).await {
                Err(err) => err!(format!("Request to exchange_refresh_token endpoint failed: {:?}", err)),
                Ok(token_response) => token_response,
            };

        Ok((
            token_response.refresh_token().map(|token| token.secret().clone()),
            token_response.access_token().secret().clone(),
            token_response.expires_in(),
        ))
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
