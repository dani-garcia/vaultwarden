use chrono::Utc;
use data_encoding::HEXLOWER;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use reqwest::{header, StatusCode};
use ring::digest::{digest, Digest, SHA512_256};
use serde::Serialize;
use std::collections::HashMap;

use url::Url;
use crate::{
    api::{core::two_factor::duo::get_duo_keys_email, EmptyResult},
    crypto,
    db::{models::{
            EventType,
            TwoFactorDuoContext,
        },
         DbConn,
         DbPool,
    },
    error::Error,
    util::get_reqwest_client,
    CONFIG,
};

// State length must be at least 16 characters and at most 1024 characters.
const STATE_LENGTH: usize = 64;

// Pool of characters for state and nonce generation
// 0-9 -> 0x30-0x39
// A-Z -> 0x41-0x5A
// a-z -> 0x61-0x7A
const STATE_CHAR_POOL: [u8; 62] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A,
];
// Generate a state/nonce string.
pub fn generate_state() -> String {
    return crypto::get_random_string(&STATE_CHAR_POOL, STATE_LENGTH);
}

// Client URL constants. Defined as macros, so they can be passed into format!()
#[allow(non_snake_case)]
macro_rules! HEALTH_ENDPOINT {
    () => {
        "https://{}/oauth/v1/health_check"
    };
}
#[allow(non_snake_case)]
macro_rules! AUTHZ_ENDPOINT {
    () => {
        "https://{}/oauth/v1/authorize"
    };
}
#[allow(non_snake_case)]
macro_rules! API_HOST_FMT {
    () => {
        "https://{}"
    };
}
#[allow(non_snake_case)]
macro_rules! TOKEN_ENDPOINT {
    () => {
        "https://{}/oauth/v1/token"
    };
}

// Default JWT validity time
const JWT_VALIDITY_SECS: i64 = 300;

// Stored Duo context validity duration
const CTX_VALIDITY_SECS: i64 = 300;

// Expected algorithm used by Duo to sign JWTs.
const DUO_RESP_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

// Signature algorithm we're using to sign JWTs for Duo. Must be either HS512 or HS256.
const JWT_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

// client_assertion payload for health checks and obtaining MFA results.
#[derive(Debug, Serialize, Deserialize)]
struct ClientAssertion {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub jti: String,
    pub iat: i64,
}

// request payload sent with clients to Duo for MFA
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationRequest {
    pub response_type: String,
    pub scope: String,
    pub exp: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub duo_uname: String,
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

// Duo service health check responses
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum HealthCheckResponse {
    HealthOK {
        stat: String,
    },
    HealthFail {
        message: String,
        message_detail: String,
    },
}

// Iuter structure of response when exchanging authz code for MFA results
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenResponse {
    id_token: String, // IdTokenClaims
    access_token: String,
    expires_in: i64,
    token_type: String,
}

// Inner structure of IdTokenResponse.id_token
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    preferred_username: String,
    nonce: String,
}

// Duo OIDC Authorization Client
// See https://duo.com/docs/oauthapi
struct DuoClient {
    client_id: String,     // Duo Client ID (DuoData.ik)
    client_secret: String, // Duo Client Secret (DuoData.sk)
    api_host: String,      // Duo API hostname (DuoData.host)
    redirect_uri: String,  // URL in this application clients should call for MFA verification
    jwt_exp_seconds: i64,  // Number of seconds that JWTs we create should be valid for
}

impl DuoClient {

    // Construct a new DuoClient
    fn new(client_id: String, client_secret: String, api_host: String, redirect_uri: String) -> DuoClient {
        return DuoClient {
            client_id,
            client_secret,
            api_host,
            redirect_uri,
            jwt_exp_seconds: JWT_VALIDITY_SECS,
        };
    }

    // Generate a client assertion for health checks and authorization code exchange.
    fn new_client_assertion(&self, url: &String) -> ClientAssertion {
        let now = Utc::now().timestamp();
        let jwt_id = generate_state();

        ClientAssertion {
            iss: self.client_id.clone(),
            sub: self.client_id.clone(),
            aud: url.clone(),
            exp: now + self.jwt_exp_seconds,
            jti: jwt_id,
            iat: now,
        }
    }

    // Given a serde-serializable struct, attempt to encode it as a JWT
    fn encode_duo_jwt<T: Serialize>(&self, jwt_payload: T) -> Result<String, Error> {
        match jsonwebtoken::encode(
            &Header::new(JWT_SIGNATURE_ALG),
            &jwt_payload,
            &EncodingKey::from_secret(&self.client_secret.as_bytes()),
        ) {
            Ok(token) => Ok(token),
            Err(e) => err!(format!("{}", e)),
        }
    }

    // "required" health check to verify the integration is configured and Duo's services
    // are up.
    // https://duo.com/docs/oauthapi#health-check
    async fn health_check(&self) -> Result<(), Error> {
        let health_check_url: String = format!(HEALTH_ENDPOINT!(), self.api_host);

        let jwt_payload = self.new_client_assertion(&health_check_url);

        let token = match self.encode_duo_jwt(jwt_payload) {
            Ok(token) => token,
            Err(e) => err!(format!("{}", e)),
        };

        let mut post_body = HashMap::new();
        post_body.insert("client_assertion", token);
        post_body.insert("client_id", self.client_id.clone());

        let res = match get_reqwest_client()
            .post(health_check_url)
            .header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)")
            .form(&post_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => err!(format!("Error requesting Duo health check: {}", e)),
        };

        let response: HealthCheckResponse = match res.json::<HealthCheckResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Duo health check response decode error: {}", e)),
        };

        let health_stat: String = match response {
            HealthCheckResponse::HealthOK {
                stat,
            } => stat,
            HealthCheckResponse::HealthFail {
                message,
                message_detail,
            } => err!(format!("Duo health check FAIL response msg: {}, detail: {}", message, message_detail)),
        };

        if health_stat != "OK" {
            err!("Duo health check returned OK-like body but did not contain an OK stat.");
        }

        Ok(())
    }

    // Constructs the URL for the authorization request endpoint on Duo's service.
    // Clients are sent here to continue authentication.
    // https://duo.com/docs/oauthapi#authorization-request
    fn make_authz_req_url(&self, duo_username: &str, state: String, nonce: String) -> Result<String, Error> {
        let now = Utc::now().timestamp();

        let jwt_payload = AuthorizationRequest {
            response_type: String::from("code"),
            scope: String::from("openid"),
            exp: now + self.jwt_exp_seconds,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state,
            duo_uname: String::from(duo_username),
            iss: self.client_id.clone(),
            aud: format!(API_HOST_FMT!(), self.api_host),
            nonce,
        };

        let token = match self.encode_duo_jwt(jwt_payload) {
            Ok(token) => token,
            Err(e) => err!(format!("{}", e)),
        };

        let authz_endpoint = format!(AUTHZ_ENDPOINT!(), self.api_host);
        let mut auth_url = match Url::parse(authz_endpoint.as_str()) {
            Ok(url) => url,
            Err(e) => err!(format!("{}", e)),
        };

        {
            let mut query_params = auth_url.query_pairs_mut();
            query_params.append_pair("response_type", "code");
            query_params.append_pair("client_id", self.client_id.as_str());
            query_params.append_pair("request", token.as_str());
        }

        let final_auth_url = auth_url.to_string();
        return Ok(final_auth_url);
    }

    // Exchange the authorization code obtained from an access token provided by the user
    // for the result of the MFA and validate.
    // See: https://duo.com/docs/oauthapi#access-token (under Response Format)
    async fn exchange_authz_code_for_result(
        &self,
        duo_code: &str,
        duo_username: &str,
        nonce: &str,
    ) -> Result<(), Error> {
        if duo_code.is_empty() {
            err!("Invalid Duo Code")
        }

        let token_url = format!(TOKEN_ENDPOINT!(), self.api_host);

        let jwt_payload = self.new_client_assertion(&token_url);

        let token = match self.encode_duo_jwt(jwt_payload) {
            Ok(token) => token,
            Err(e) => err!(format!("{}", e)),
        };

        let mut post_body = HashMap::new();
        post_body.insert("grant_type", String::from("authorization_code"));
        post_body.insert("code", String::from(duo_code));
        post_body.insert("redirect_uri", self.redirect_uri.clone());
        post_body
            .insert("client_assertion_type", String::from("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        post_body.insert("client_assertion", token);

        let res = match get_reqwest_client()
            .post(&token_url)
            .header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)")
            .form(&post_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => err!(format!("Error exchanging Duo code: {}", e)),
        };

        let status_code = res.status();
        if status_code != StatusCode::OK {
            err!(format!("Failure response from Duo: {}", status_code))
        }

        let response: IdTokenResponse = match res.json::<IdTokenResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Error decoding ID token response: {}", e)),
        };

        let mut validation = Validation::new(DUO_RESP_SIGNATURE_ALG);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[token_url.as_str()]);

        let token_data = match jsonwebtoken::decode::<IdTokenClaims>(
            &response.id_token,
            &DecodingKey::from_secret(self.client_secret.as_bytes()),
            &validation,
        ) {
            Ok(c) => c,
            Err(e) => err!(format!("Failed to decode Duo token {}", e)),
        };

        let matching_nonces = crypto::ct_eq(&nonce, &token_data.claims.nonce);
        let matching_usernames = crypto::ct_eq(&duo_username, &token_data.claims.preferred_username);

        if !(matching_nonces && matching_usernames) {
            err!(format!(
                "Error validating Duo user, expected {}, got {}",
                duo_username, token_data.claims.preferred_username
            ))
        };

        Ok(())
    }
}

struct DuoAuthContext {
    pub state: String,
    pub user_email: String,
    pub nonce: String,
    pub exp: i64,
}

// Given a state string, retrieve the associated Duo auth context and
// delete the retrieved state from the database.
async fn extract_context(state: &str, conn: &mut DbConn) -> Option<DuoAuthContext> {
    let ctx: TwoFactorDuoContext = match TwoFactorDuoContext::find_by_state(state, conn).await {
        Some(c) => c,
        None => return None
    };

    if ctx.exp < Utc::now().timestamp() {
        ctx.delete(conn).await.ok();
        return None
    }

    // Copy the context data, so that we can delete the context from
    // the database before returning.
    let ret_ctx = DuoAuthContext {
        state: ctx.state.clone(),
        user_email: ctx.user_email.clone(),
        nonce: ctx.nonce.clone(),
        exp: ctx.exp,
    };

    ctx.delete(conn).await.ok();
    return Some(ret_ctx)
}

// Task to clean up expired Duo authentication contexts that may have accumulated in the database.
pub async fn purge_duo_contexts(pool: DbPool) {
    debug!("Purging Duo authentication contexts");
    if let Ok(mut conn) = pool.get().await {
        TwoFactorDuoContext::purge_expired_duo_contexts(&mut conn).await;
    } else {
        error!("Failed to get DB connection while purging expired Duo authentications")
    }
}

// The location Duo redirects to is a bridge built in to the clients.
// See: /clients/apps/web/src/connectors/duo-redirect.ts
const DUO_REDIRECT_LOCATION: &str = "duo-redirect-connector.html";

// Construct the url that Duo should redirect users to.
fn make_callback_url(client_name: &str) -> Result<String, Error> {
    // Get the location of this application as defined in the config.
    let base = match Url::parse(CONFIG.domain().as_str()) {
        Ok(url) => url,
        Err(e) => err!(format!("{}", e)),
    };

    // Add the client redirect bridge location
    let mut callback = match base.join(DUO_REDIRECT_LOCATION) {
        Ok(url) => url,
        Err(e) => err!(format!("{}", e)),
    };

    // Add the 'client' string. This is sent by clients in the 'Bitwarden-Client-Name'
    // HTTP header of the request to /identity/connect/token
    {
        let mut query_params = callback.query_pairs_mut();
        query_params.append_pair("client", client_name);
    }
    return Ok(callback.to_string());
}

// Pre-redirect first stage of the Duo WebSDKv4 authentication flow.
// Returns the "AuthUrl" that should be returned to clients for MFA.
pub async fn get_duo_auth_url(email: &str,
                              client_id: &String,
                              device_identifier: &String,
                              conn: &mut DbConn) -> Result<String, Error> {
    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    let callback_url = match make_callback_url(client_id.as_str()) {
        Ok(url) => url,
        Err(e) => err!(format!("{}", e)),
    };

    let client = DuoClient::new(ik, sk, host, callback_url);

    match client.health_check().await {
        Ok(()) => {}
        Err(e) => err!(format!("{}", e)),
    };

    // Generate random OAuth2 state and OIDC Nonce
    let state: String = generate_state();
    let nonce: String = generate_state();

    // Bind the nonce to the device that's currently authing by hashing the nonce and device id
    // and sending that as the OIDC nonce.
    let d: Digest = digest(&SHA512_256, format!("{nonce}{device_identifier}").as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    match TwoFactorDuoContext::save(state.as_str(), email, nonce.as_str(), CTX_VALIDITY_SECS, conn).await {
        Ok(()) => client.make_authz_req_url(email, state, hash),
        Err(e) => err!(format!("Error storing Duo authentication context: {}", e))
    }
}

// Post-redirect second stage of the Duo WebSDKv4 authentication flow.
// Exchanges an authorization code for the MFA result with Duo's API and validates the result.
pub async fn validate_duo_login(
    email: &str,
    two_factor_token: &str,
    client_id: &String,
    device_identifier: &String,
    conn: &mut DbConn,
) -> EmptyResult {
    let email = &email.to_lowercase();

    let split: Vec<&str> = two_factor_token.split('|').collect();
    if split.len() != 2 {
        err!(
            "Invalid response length",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        );
    }

    let code = split[0];
    let state = split[1];

    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    // Get the context by the state reported by the client. If we don't have one,
    // it means the context is either missing or expired.
    let ctx = match extract_context(state, conn).await {
        Some(c) => c,
        None => {
            err!(
                "Error validating duo authentication",
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            )
        }
    };

    // Context validation steps
    let matching_usernames = crypto::ct_eq(&email, &ctx.user_email);

    // Probably redundant, but we're double-checking them anyway.
    let matching_states = crypto::ct_eq(&state, &ctx.state);
    let unexpired_context = ctx.exp > Utc::now().timestamp();

    if !(matching_usernames && matching_states && unexpired_context) {
        err!(
            "Error validating duo authentication",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    let callback_url = match make_callback_url(client_id.as_str()) {
        Ok(url) => url,
        Err(e) => err!(format!("{}", e)),
    };

    let client = DuoClient::new(ik, sk, host, callback_url);

    match client.health_check().await {
        Ok(()) => {}
        Err(e) => err!(format!("{}", e)),
    };

    let d: Digest = digest(&SHA512_256, format!("{}{}", ctx.nonce, device_identifier).as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    match client.exchange_authz_code_for_result(code, email, hash.as_str()).await {
        Ok(_) => Ok(()),
        Err(_) => {
            err!(
                "Error validating duo authentication",
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            )
        }
    }
}
