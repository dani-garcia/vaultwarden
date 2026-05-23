pub mod accounts;
pub mod two_factor;

mod ciphers;
mod emergency_access;
mod events;
mod folders;
mod organizations;
mod public;
mod sends;

pub use accounts::purge_auth_requests;
pub use ciphers::{CipherData, CipherSyncData, CipherSyncType, purge_trashed_ciphers};
pub use emergency_access::{emergency_notification_reminder_job, emergency_request_timeout_job};
pub use events::{event_cleanup_job, log_event, log_user_event};
pub use sends::purge_sends;

use reqwest::Method;
use rocket::{Catcher, Route, http::Status, serde::json::Json, serde::json::Value};
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};
use webauthn_rs_proto::UserVerificationPolicy;

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::two_factor::webauthn::{PublicKeyCredentialCopy, RegisterPublicKeyCredentialCopy, WEBAUTHN},
    },
    auth::Headers,
    crypto,
    db::{
        DbConn,
        models::{
            Membership, MembershipStatus, OrgPolicy, Organization, TwoFactor, TwoFactorType, User, WebAuthnCredential,
            WebAuthnCredentialId,
        },
    },
    error::Error,
    http_client::make_http_request,
    mail,
    util::{FeatureFlagFilter, get_uuid, parse_experimental_client_feature_flags},
};

pub fn routes() -> Vec<Route> {
    let mut eq_domains_routes = routes![get_settings_domains, post_settings_domains, put_settings_domains];
    let mut hibp_routes = routes![hibp_breach];
    let mut meta_routes = routes![
        alive,
        now,
        version,
        config,
        get_api_webauthn,
        post_api_webauthn,
        put_api_webauthn,
        post_api_webauthn_assertion_options,
        post_api_webauthn_attestation_options,
        post_api_webauthn_delete
    ];

    let mut routes = Vec::new();
    routes.append(&mut accounts::routes());
    routes.append(&mut ciphers::routes());
    routes.append(&mut emergency_access::routes());
    routes.append(&mut events::routes());
    routes.append(&mut folders::routes());
    routes.append(&mut organizations::routes());
    routes.append(&mut two_factor::routes());
    routes.append(&mut sends::routes());
    routes.append(&mut public::routes());
    routes.append(&mut eq_domains_routes);
    routes.append(&mut hibp_routes);
    routes.append(&mut meta_routes);

    routes
}

pub fn events_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.append(&mut events::main_routes());

    routes
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalDomain {
    r#type: i32,
    domains: Vec<String>,
    excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../static/global_domains.json");

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[get("/settings/domains")]
fn get_settings_domains(headers: Headers) -> Json<Value> {
    get_eq_domains(&headers, false)
}

fn get_eq_domains(headers: &Headers, no_excluded: bool) -> Json<Value> {
    use serde_json::from_str;

    let user = &headers.user;

    let equivalent_domains: Vec<Vec<String>> = from_str(&user.equivalent_domains).unwrap();
    let excluded_globals: Vec<i32> = from_str(&user.excluded_globals).unwrap();

    let mut globals: Vec<GlobalDomain> = from_str(GLOBAL_DOMAINS).unwrap();

    for global in &mut globals {
        global.excluded = excluded_globals.contains(&global.r#type);
    }

    if no_excluded {
        globals.retain(|g| !g.excluded);
    }

    Json(json!({
        "equivalentDomains": equivalent_domains,
        "globalEquivalentDomains": globals,
        "object": "domains",
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

#[post("/settings/domains", data = "<data>")]
async fn post_settings_domains(
    data: Json<EquivDomainData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    use serde_json::to_string;

    let data: EquivDomainData = data.into_inner();

    let excluded_globals = data.excluded_global_equivalent_domains.unwrap_or_default();
    let equivalent_domains = data.equivalent_domains.unwrap_or_default();

    let mut user = headers.user;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_owned());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_owned());

    user.save(&conn).await?;

    nt.send_user_update(UpdateType::SyncSettings, &user, headers.device.push_uuid.as_ref(), &conn).await;

    Ok(Json(json!({})))
}

#[put("/settings/domains", data = "<data>")]
async fn put_settings_domains(
    data: Json<EquivDomainData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_settings_domains(data, headers, conn, nt).await
}

#[get("/hibp/breach?<username>")]
async fn hibp_breach(username: &str, _headers: Headers) -> JsonResult {
    let username: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
    if let Some(api_key) = CONFIG.hibp_api_key() {
        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{username}?truncateResponse=false&includeUnverified=false"
        );

        let res = make_http_request(Method::GET, &url)?.header("hibp-api-key", api_key).send().await?;

        // If we get a 404, return a 404, it means no breached accounts
        if res.status() == 404 {
            return Err(Error::empty().with_code(404));
        }

        let value: Value = res.error_for_status()?.json().await?;
        Ok(Json(value))
    } else {
        Ok(Json(json!([{
            "name": "HaveIBeenPwned",
            "title": "Manual HIBP Check",
            "domain": "haveibeenpwned.com",
            "breachDate": "2019-08-18T00:00:00Z",
            "addedDate": "2019-08-18T00:00:00Z",
            "description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>"),
            "logoPath": "vw_static/hibp.png",
            "pwnCount": 0,
            "dataClasses": [
                "Error - No API key set!"
            ]
        }])))
    }
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
#[get("/alive")]
fn alive(_conn: DbConn) -> Json<String> {
    now()
}

#[get("/now")]
pub fn now() -> Json<String> {
    Json(crate::util::format_date(&chrono::Utc::now().naive_utc()))
}

#[get("/version")]
fn version() -> Json<&'static str> {
    Json(crate::VERSION.unwrap_or_default())
}

#[get("/webauthn")]
async fn get_api_webauthn(headers: Headers, conn: DbConn) -> Json<Value> {
    let user = headers.user;

    let data: Vec<Value> = WebAuthnCredential::find_by_user(&user.uuid, &conn)
        .await
        .into_iter()
        .map(|wac| {
            json!({
                "id": wac.uuid,
                "name": wac.name,
                // 0 = Enabled, 1 = Supported (PRF-capable, keyset not set up), 2 = Unsupported.
                "prfStatus": wac.prf_status(),
                "encryptedUserKey": wac.encrypted_user_key,
                "encryptedPublicKey": wac.encrypted_public_key,
                "object": "webauthnCredential",
            })
        })
        .collect();

    Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    }))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyRegistrationChallenge {
    token: String,
    state: PasskeyRegistration,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyAssertionChallenge {
    token: String,
    state: PasskeyAuthentication,
}

fn passkey_registration_challenge_state(data: &str, token: Option<&str>) -> ApiResult<PasskeyRegistration> {
    if let Ok(saved) = serde_json::from_str::<WebAuthnPasskeyRegistrationChallenge>(data) {
        if token != Some(saved.token.as_str()) {
            err!("Invalid registration challenge. Please try again.")
        }
        Ok(saved.state)
    } else {
        if token.is_some() {
            err!("Invalid registration challenge. Please try again.")
        }
        Ok(serde_json::from_str::<PasskeyRegistration>(data)?)
    }
}

fn passkey_assertion_challenge_state(data: &str, token: &str) -> ApiResult<PasskeyAuthentication> {
    let saved: WebAuthnPasskeyAssertionChallenge = serde_json::from_str(data)?;
    if token != saved.token.as_str() {
        err!("Invalid assertion challenge. Please try again.")
    }
    Ok(saved.state)
}

fn passkey_credential_id_hash(passkey: &Passkey) -> String {
    crypto::sha256_hex(passkey.cred_id().as_slice())
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_api_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    // Same gate the 2FA WebAuthn entry point uses; cleanly rejects requests
    // when DOMAIN is incompatible with WebAuthn rather than panicking inside
    // the `WEBAUTHN` `LazyLock` initializer.
    if !CONFIG.is_webauthn_2fa_supported() {
        err!("Configured `DOMAIN` is not compatible with Webauthn")
    }

    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("Passkeys cannot be created when SSO sign-in is required")
    }

    data.validate(&user, true, &conn).await?;

    let all_creds = WebAuthnCredential::find_by_user(&user.uuid, &conn).await;
    let existing_cred_ids: Vec<_> = all_creds
        .into_iter()
        .filter_map(|wac| {
            let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
            Some(passkey.cred_id().to_owned())
        })
        .collect();

    let user_uuid = uuid::Uuid::parse_str(&user.uuid)
        .map_err(|_| Error::new("Invalid user", "Could not parse user UUID for passkey registration"))?;

    let (mut challenge, state) =
        WEBAUTHN.start_passkey_registration(user_uuid, &user.email, user.display_name(), Some(existing_cred_ids))?;

    // For passkey login, we need discoverable credentials (resident keys)
    // and require user verification.
    // start_passkey_registration() defaults to require_resident_key=false, but passkey login
    // requires the credential to be discoverable (resident) so the authenticator can find it
    // without the server providing allowCredentials.
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Required;
        asc.require_resident_key = true;
        asc.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }

    // Drop any abandoned challenge from a previous, unfinished registration attempt
    // so these rows cannot accumulate in the database.
    if let Some(tf) =
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::WebauthnPasskeyRegisterChallenge as i32, &conn)
            .await
    {
        tf.delete(&conn).await?;
    }

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyRegistrationChallenge {
        token: token.clone(),
        state,
    };

    // Persist the registration state in the database (same pattern as 2FA webauthn)
    TwoFactor::new(
        user.uuid,
        TwoFactorType::WebauthnPasskeyRegisterChallenge,
        serde_json::to_string(&saved_challenge)?,
    )
    .save(&conn)
    .await?;

    let mut options = serde_json::to_value(challenge.public_key)?;
    options["status"] = "ok".into();
    options["errorMessage"] = "".into();

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webauthnCredentialCreateOptions"
    })))
}

#[post("/webauthn/assertion-options", data = "<data>")]
async fn post_api_webauthn_assertion_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    if !CONFIG.is_webauthn_2fa_supported() {
        err!("Configured `DOMAIN` is not compatible with Webauthn")
    }

    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("Passkeys cannot be updated when SSO sign-in is required")
    }

    data.validate(&user, true, &conn).await?;

    let credentials: Vec<Passkey> = WebAuthnCredential::find_by_user(&user.uuid, &conn)
        .await
        .into_iter()
        .filter(|wac| wac.supports_prf)
        .filter_map(|wac| serde_json::from_str(&wac.credential).ok())
        .collect();

    if credentials.is_empty() {
        err!("No PRF-capable passkeys registered")
    }

    let (response, state) = WEBAUTHN.start_passkey_authentication(&credentials)?;

    if let Some(tf) =
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::WebauthnPasskeyAssertionChallenge as i32, &conn)
            .await
    {
        tf.delete(&conn).await?;
    }

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyAssertionChallenge {
        token: token.clone(),
        state,
    };
    TwoFactor::new(
        user.uuid,
        TwoFactorType::WebauthnPasskeyAssertionChallenge,
        serde_json::to_string(&saved_challenge)?,
    )
    .save(&conn)
    .await?;

    Ok(Json(json!({
        "options": response.public_key,
        "token": token,
        "object": "webauthnCredentialAssertionOptions"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnLoginCredentialCreateRequest {
    device_response: RegisterPublicKeyCredentialCopy,
    name: String,
    token: Option<String>,
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[post("/webauthn", data = "<data>")]
async fn post_api_webauthn(
    data: Json<WebAuthnLoginCredentialCreateRequest>,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: WebAuthnLoginCredentialCreateRequest = data.into_inner();
    let user = headers.user;

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("Passkeys cannot be created when SSO sign-in is required")
    }

    // Atomically take the saved challenge state (single-use): concurrent
    // finishes for the same registration row cannot both succeed and create
    // duplicate `web_authn_credentials` entries — only the caller whose DELETE
    // removes the row proceeds.
    let type_ = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let Some(tf) = TwoFactor::take_by_user_and_type(&user.uuid, type_, &conn).await else {
        err!("No registration challenge found. Please try again.")
    };
    let state = passkey_registration_challenge_state(&tf.data, data.token.as_deref())?;
    let credential = WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state)?;
    let credential_id_hash = passkey_credential_id_hash(&credential);

    if WebAuthnCredential::credential_id_hash_exists(&credential_id_hash, &conn).await {
        err!("Passkey is already registered")
    }

    WebAuthnCredential::new(
        user.uuid,
        data.name,
        serde_json::to_string(&credential)?,
        credential_id_hash,
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
    )
    .save(&conn)
    .await?;

    Ok(Status::Ok)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnLoginCredentialUpdateRequest {
    device_response: PublicKeyCredentialCopy,
    token: String,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[put("/webauthn", data = "<data>")]
async fn put_api_webauthn(
    data: Json<WebAuthnLoginCredentialUpdateRequest>,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: WebAuthnLoginCredentialUpdateRequest = data.into_inner();
    let user = headers.user;

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("Passkeys cannot be updated when SSO sign-in is required")
    }

    let Some(encrypted_user_key) = data.encrypted_user_key else {
        err!("Encrypted user key is required")
    };
    let Some(encrypted_public_key) = data.encrypted_public_key else {
        err!("Encrypted public key is required")
    };
    let Some(encrypted_private_key) = data.encrypted_private_key else {
        err!("Encrypted private key is required")
    };

    // Atomically take the saved challenge state (single-use): concurrent
    // updates for the same assertion row cannot both succeed and apply
    // different blob payloads — only the caller whose DELETE removes the row
    // proceeds.
    let type_ = TwoFactorType::WebauthnPasskeyAssertionChallenge as i32;
    let Some(tf) = TwoFactor::take_by_user_and_type(&user.uuid, type_, &conn).await else {
        err!("No assertion challenge found. Please try again.")
    };
    let state = passkey_assertion_challenge_state(&tf.data, &data.token)?;

    let credential_response = data.device_response.into();
    let mut parsed_credentials: Vec<(WebAuthnCredential, Passkey)> =
        WebAuthnCredential::find_by_user(&user.uuid, &conn)
            .await
            .into_iter()
            .filter_map(|wac| {
                let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
                Some((wac, passkey))
            })
            .collect();

    if parsed_credentials.is_empty() {
        err!("No passkeys registered")
    }

    let authentication_result = WEBAUTHN.finish_passkey_authentication(&credential_response, &state)?;
    let Some((matched_wac, passkey)) = parsed_credentials
        .iter_mut()
        .find(|(_, passkey)| crypto::ct_eq(passkey.cred_id().as_slice(), authentication_result.cred_id().as_slice()))
    else {
        err!("Verified credential is not registered")
    };

    if !matched_wac.supports_prf {
        err!("Passkey does not support PRF")
    }

    if passkey.update_credential(&authentication_result) == Some(true) {
        matched_wac.credential = serde_json::to_string(passkey)?;
        matched_wac.update_credential(&conn).await?;
    }

    matched_wac.encrypted_user_key = Some(encrypted_user_key);
    matched_wac.encrypted_public_key = Some(encrypted_public_key);
    matched_wac.encrypted_private_key = Some(encrypted_private_key);
    matched_wac.update_prf_keyset(&conn).await?;

    Ok(Status::Ok)
}

#[post("/webauthn/<uuid>/delete", data = "<data>")]
async fn post_api_webauthn_delete(
    data: Json<PasswordOrOtpData>,
    uuid: WebAuthnCredentialId,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    WebAuthnCredential::delete_by_uuid_and_user(&uuid, &user.uuid, &conn).await?;

    Ok(Status::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs::prelude::{
        AttestationFormat, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, Credential, ECDSACurve, ParsedAttestation,
        Url, Webauthn, WebauthnBuilder,
    };
    use webauthn_rs_proto::{AuthenticatorTransport, RegisteredExtensions};

    fn webauthn() -> Webauthn {
        let origin = Url::parse("http://localhost").unwrap();
        WebauthnBuilder::new("localhost", &origin).unwrap().rp_name("localhost").build().unwrap()
    }

    fn passkey() -> Passkey {
        Credential {
            cred_id: [1, 2, 3, 4].into(),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [1; 32].into(),
                    y: [2; 32].into(),
                }),
            },
            counter: 0,
            transports: Some(vec![AuthenticatorTransport::Internal, AuthenticatorTransport::Hybrid]),
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Required,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation::default(),
            attestation_format: AttestationFormat::None,
        }
        .into()
    }

    fn registration_state() -> PasskeyRegistration {
        let user_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
        let (_challenge, state) =
            webauthn().start_passkey_registration(user_uuid, "user@example.com", "user", None).unwrap();
        state
    }

    #[test]
    fn registration_challenge_accepts_wrapped_state_with_matching_token() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("token")).is_ok());
    }

    #[test]
    fn registration_challenge_rejects_wrapped_state_without_matching_token() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("wrong")).is_err());
        assert!(passkey_registration_challenge_state(&data, None).is_err());
    }

    #[test]
    fn legacy_registration_challenge_rejects_finish_token() {
        let data = serde_json::to_string(&registration_state()).unwrap();

        assert!(passkey_registration_challenge_state(&data, None).is_ok());
        assert!(passkey_registration_challenge_state(&data, Some("token")).is_err());
    }

    #[test]
    fn assertion_challenge_rejects_mismatched_token() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let saved = WebAuthnPasskeyAssertionChallenge {
            token: String::from("token"),
            state,
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_assertion_challenge_state(&data, "token").is_ok());
        assert!(passkey_assertion_challenge_state(&data, "wrong").is_err());
    }

    #[test]
    fn passkey_credential_id_hash_uses_raw_credential_id_bytes() {
        assert_eq!(
            passkey_credential_id_hash(&passkey()),
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
        );
    }

    fn passkey_with_cred_id(cred_id: &[u8]) -> Passkey {
        Credential {
            cred_id: cred_id.to_vec().into(),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [1; 32].into(),
                    y: [2; 32].into(),
                }),
            },
            counter: 0,
            transports: None,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Required,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation::default(),
            attestation_format: AttestationFormat::None,
        }
        .into()
    }

    #[test]
    fn passkey_credential_id_hash_is_deterministic() {
        let cred_id: &[u8] = &[10, 20, 30, 40, 50];
        assert_eq!(
            passkey_credential_id_hash(&passkey_with_cred_id(cred_id)),
            passkey_credential_id_hash(&passkey_with_cred_id(cred_id)),
        );
    }

    #[test]
    fn passkey_credential_id_hash_distinguishes_different_credentials() {
        let a = passkey_credential_id_hash(&passkey_with_cred_id(&[1, 2, 3, 4]));
        let b = passkey_credential_id_hash(&passkey_with_cred_id(&[4, 3, 2, 1]));
        let c = passkey_credential_id_hash(&passkey_with_cred_id(&[1, 2, 3]));
        assert_ne!(a, b, "different bytes must produce different hashes");
        assert_ne!(a, c, "different lengths must produce different hashes");
        assert_ne!(b, c);
    }

    /// `passkey_assertion_challenge_state` has no legacy unwrapped fallback —
    /// the assertion-options endpoint was introduced together with the
    /// wrapping struct, so any persisted state must carry the binding token.
    #[test]
    fn assertion_challenge_rejects_unwrapped_legacy_state() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let bare = serde_json::to_string(&state).unwrap();

        assert!(passkey_assertion_challenge_state(&bare, "any-token").is_err());
        assert!(passkey_assertion_challenge_state(&bare, "").is_err());
    }
}

#[get("/config")]
fn config() -> Json<Value> {
    let domain = CONFIG.domain();
    // Official available feature flags can be found here:
    // Server (v2026.2.1): https://github.com/bitwarden/server/blob/0e42725d0837bd1c0dabd864ff621a579959744b/src/Core/Constants.cs#L135
    // Client (v2026.2.1): https://github.com/bitwarden/clients/blob/f96380c3138291a028bdd2c7a5fee540d5c98ba5/libs/common/src/enums/feature-flag.enum.ts#L12
    // Android (v2026.2.1): https://github.com/bitwarden/android/blob/6902c19c0093fa476bbf74ccaa70c9f14afbb82f/core/src/main/kotlin/com/bitwarden/core/data/manager/model/FlagKey.kt#L31
    // iOS (v2026.2.1): https://github.com/bitwarden/ios/blob/cdd9ba1770ca2ffc098d02d12cc3208e3a830454/BitwardenShared/Core/Platform/Models/Enum/FeatureFlag.swift#L7
    let mut feature_states = parse_experimental_client_feature_flags(
        &CONFIG.experimental_client_feature_flags(),
        &FeatureFlagFilter::ValidOnly,
    );
    feature_states.insert("pm-19148-innovation-archive".to_owned(), true);

    Json(json!({
        // Note: The clients use this version to handle backwards compatibility concerns
        // This means they expect a version that closely matches the Bitwarden server version
        // We should make sure that we keep this updated when we support the new server features
        // Version history:
        // - Individual cipher key encryption: 2024.2.0
        // - Mobile app support for MasterPasswordUnlockData: 2025.8.0
        "version": "2025.12.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": CONFIG.is_signup_disabled()
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "",
          "cloudRegion": null,
        },
        // Bitwarden uses this for the self-hosted servers to indicate the default push technology
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": feature_states,
        "object": "config",
    }))
}

pub fn catchers() -> Vec<Catcher> {
    catchers![api_not_found]
}

#[catch(404)]
fn api_not_found() -> Json<Value> {
    Json(json!({
        "error": {
            "code": 404,
            "reason": "Not Found",
            "description": "The requested resource could not be found."
        }
    }))
}

async fn accept_org_invite(
    user: &User,
    mut member: Membership,
    reset_password_key: Option<String>,
    conn: &DbConn,
) -> EmptyResult {
    if member.status != MembershipStatus::Invited as i32 {
        err!("User already accepted the invitation");
    }

    member.status = MembershipStatus::Accepted as i32;
    member.reset_password_key = reset_password_key;

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    OrgPolicy::check_user_allowed(&member, "join", conn).await?;

    member.save(conn).await?;

    if CONFIG.mail_enabled() {
        let Some(org) = Organization::find_by_uuid(&member.org_uuid, conn).await else {
            err!("Organization not found.")
        };
        // User was invited to an organization, so they must be confirmed manually after acceptance
        mail::send_invite_accepted(&user.email, &member.invited_by_email.unwrap_or(org.billing_email), &org.name)
            .await?;
    }

    Ok(())
}
