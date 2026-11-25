//! Log in with passkey. The login itself is the `webauthn` grant in `identity.rs`.
//!
//! The WebAuthn state of each step isn't stored: it goes to the client in a signed token, which comes back with the
//! next request. `WebauthnCredential::last_challenge_issued_at` makes each assertion single use.

use std::{net::IpAddr, str::FromStr, time::Duration};

use chrono::{TimeDelta, Utc};
use rocket::{Route, http::Status, serde::json::Json};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{CredentialID, DiscoverableAuthentication, DiscoverableKey, PasskeyRegistration},
};
use webauthn_rs_proto::{
    AuthenticatorSelectionCriteria, PublicKeyCredential, ResidentKeyRequirement, UserVerificationPolicy,
};

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult, PasswordOrOtpData,
        core::two_factor::webauthn::{PublicKeyCredentialCopy, RegisterPublicKeyCredentialCopy},
    },
    auth::{self, Headers, JWT_WEBAUTHN_ISSUER},
    db::{
        DbConn,
        models::{User, UserId, WebauthnCredential, WebauthnCredentialId, WebauthnPrfStatus},
    },
    error::MapResult,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_api_webauthn,
        post_attestation_options,
        post_assertion_options,
        post_credential,
        put_credential,
        delete_credential
    ]
}

const MAX_CREDENTIALS_PER_USER: usize = 5;

/// The origins besides the vault that passkey assertions may come from. Without a trailing `/`: the origin of a request
/// has none, so they would never match.
///
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/SharedWeb/Utilities/ServiceCollectionExtensions.cs#L644-L651>
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Constants.cs#L112-L118>
const WEBAUTHN_ORIGINS: [&str; 4] = [
    // Chrome Web Store, which Brave, Vivaldi and the other Chromium browsers install from too
    "chrome-extension://nngceckbapebfimnlniiiahkandclblb",
    // Chrome Web Store, beta
    "chrome-extension://hccnnhgbibccigepcmlgppchkpfdophk",
    // Microsoft Edge Add-ons
    "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh",
    // Opera add-ons
    "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn",
];

/// Built for each use, so that a change to `PASSKEY_LOGIN_EXTRA_ORIGINS` in the admin panel applies without a restart.
fn webauthn_login() -> ApiResult<Webauthn> {
    let domain = CONFIG.domain();
    let domain_origin = CONFIG.domain_origin();
    let rp_id = Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default();
    let rp_origin = Url::parse(&domain_origin).ok().map_res("Invalid DOMAIN")?;

    let mut webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?.rp_name(&domain).timeout(Duration::from_mins(1));
    let configured = CONFIG.passkey_login_extra_origins();
    let configured = configured.split(',').map(str::trim).filter(|o| !o.is_empty());
    for origin in WEBAUTHN_ORIGINS.into_iter().chain(configured) {
        // Invalid ones were refused when the config was loaded
        if let Ok(origin) = Url::parse(origin.trim_end_matches('/')) {
            webauthn = webauthn.append_allowed_origin(&origin);
        }
    }

    Ok(webauthn.build()?)
}

/// Passkeys would bypass SSO, so SSO_ONLY refuses them.
pub fn passkey_login_available() -> bool {
    CONFIG.is_webauthn_2fa_supported() && !(CONFIG.sso_enabled() && CONFIG.sso_only())
}

fn check_webauthn_supported() -> EmptyResult {
    if !CONFIG.is_webauthn_2fa_supported() {
        err!("Configured `DOMAIN` is not compatible with Webauthn")
    }
    Ok(())
}

fn check_passkey_creation_allowed() -> EmptyResult {
    check_webauthn_supported()?;
    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("Passkeys cannot be created for your account. SSO login is required.")
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum TokenScope {
    Authentication,
    UpdateKeySet,
    Registration,
}

impl TokenScope {
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Models/Business/Tokenables/WebAuthnCredentialCreateOptionsTokenable.cs#L11-L12>
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Models/Business/Tokenables/WebAuthnLoginAssertionOptionsTokenable.cs#L10-L14>
    fn lifetime(self) -> TimeDelta {
        match self {
            Self::Registration => TimeDelta::minutes(7),
            Self::Authentication | Self::UpdateKeySet => TimeDelta::minutes(17),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StateClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    scope: TokenScope,
    /// The only user who may use the token, none for logging in
    sub: Option<UserId>,
    /// When the challenge was issued, in milliseconds, see `WebauthnCredential::last_challenge_issued_at`
    issued_at: i64,
    /// The webauthn-rs state
    state: Value,
}

fn encode_state<T: Serialize>(scope: TokenScope, user: Option<&UserId>, state: &T) -> ApiResult<String> {
    let now = Utc::now();
    Ok(auth::encode_jwt(&StateClaims {
        nbf: now.timestamp(),
        exp: (now + scope.lifetime()).timestamp(),
        iss: JWT_WEBAUTHN_ISSUER.to_string(),
        scope,
        sub: user.cloned(),
        issued_at: now.timestamp_millis(),
        state: serde_json::to_value(state)?,
    }))
}

/// The token must be for this scope and this user, where `None` means a login token.
fn decode_state<T: DeserializeOwned>(token: &str, scope: TokenScope, user: Option<&UserId>) -> ApiResult<(i64, T)> {
    let claims = match auth::decode_jwt::<StateClaims>(token, JWT_WEBAUTHN_ISSUER.to_string()) {
        Ok(claims) if claims.scope == scope && claims.sub.as_ref() == user => claims,
        _ => err!(
            "The token associated with your request is invalid or has expired. A valid token is required to continue."
        ),
    };
    Ok((claims.issued_at, serde_json::from_value(claims.state)?))
}

fn assertion_options(scope: TokenScope, user: Option<&UserId>) -> JsonResult {
    let (challenge, state) = webauthn_login()?.start_discoverable_authentication()?;
    let token = encode_state(scope, user, &state)?;

    let mut options = serde_json::to_value(challenge.public_key)?;
    // The clients add the PRF extension themselves
    options["extensions"] = Value::Null;

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webAuthnLoginAssertionOptions",
    })))
}

pub fn login_assertion_options() -> JsonResult {
    assertion_options(TokenScope::Authentication, None)
}

pub async fn assert_login(
    token: &str,
    device_response: &str,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<(User, WebauthnCredential)> {
    let (issued_at, state) = decode_state(token, TokenScope::Authentication, None)?;
    let Ok(response) = serde_json::from_str::<PublicKeyCredentialCopy>(device_response) else {
        err!("Invalid credential", format!("IP: {ip}."))
    };
    assert_credential(issued_at, state, &response.into(), ip, conn).await
}

/// On success, the token's challenge is marked as answered and the passkey's new counter stored.
///
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/UserFeatures/WebAuthnLogin/Implementations/AssertWebAuthnLoginCredentialCommand.cs#L30-L82>
async fn assert_credential(
    issued_at: i64,
    state: DiscoverableAuthentication,
    response: &PublicKeyCredential,
    ip: &IpAddr,
    conn: &DbConn,
) -> ApiResult<(User, WebauthnCredential)> {
    let webauthn = webauthn_login()?;
    let Ok((user_uuid, credential_id)) = webauthn.identify_discoverable_authentication(response) else {
        err!("Invalid credential", format!("IP: {ip}."))
    };
    let Some(user) = User::find_by_uuid(&UserId::from(user_uuid.to_string()), conn).await else {
        err!("Invalid credential", format!("IP: {ip}."))
    };
    let credential_id = data_encoding::BASE64URL_NOPAD.encode(credential_id);
    let Some(credential) = WebauthnCredential::find_by_user_and_credential_id(&user.uuid, &credential_id, conn).await
    else {
        err!("Invalid credential", format!("IP: {ip}."))
    };

    let mut passkey = credential.passkey()?;
    let Ok(result) = webauthn.finish_discoverable_authentication(response, state, &[DiscoverableKey::from(&passkey)])
    else {
        err!("Invalid credential", format!("IP: {ip}."))
    };
    passkey.update_credential(&result);

    if !credential.use_challenge(issued_at, &passkey, conn).await? {
        err!("Invalid credential", format!("IP: {ip}."))
    }
    Ok((user, credential))
}

/// The user key is wrapped by an RSA key, the other keys by a symmetric one.
fn validate_prf_key(value: &str, field: &str, user_key: bool) -> EmptyResult {
    let valid_form = if user_key {
        crate::util::is_valid_rsa_encrypted_string(value)
    } else {
        crate::util::is_valid_symmetric_encrypted_string(value)
    };
    if !valid_form || value.len() > 2000 {
        err!(format!("The field {field} is not a valid encrypted string."))
    }
    Ok(())
}

#[get("/webauthn")]
async fn get_api_webauthn(headers: Headers, conn: DbConn) -> Json<Value> {
    let credentials: Vec<Value> = WebauthnCredential::find_by_user(&headers.user.uuid, &conn)
        .await
        .iter()
        .map(WebauthnCredential::to_json)
        .collect();

    Json(json!({
        "object": "list",
        "data": credentials,
        "continuationToken": null,
    }))
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_attestation_options(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    check_passkey_creation_allowed()?;
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;
    data.validate(&mut user, true, &conn).await?;

    let exclude = WebauthnCredential::find_by_user(&user.uuid, &conn)
        .await
        .iter()
        .filter_map(|c| data_encoding::BASE64URL_NOPAD.decode(c.credential_id.as_bytes()).ok())
        .map(CredentialID::from)
        .collect();

    let (mut challenge, state) = webauthn_login()?.start_passkey_registration(
        Uuid::from_str(&user.uuid).expect("Failed to parse UUID"),
        &user.email,
        user.display_name(),
        Some(exclude),
    )?;
    // Logging in without a username needs a discoverable credential, which webauthn-rs doesn't ask for
    challenge.public_key.authenticator_selection = Some(AuthenticatorSelectionCriteria {
        authenticator_attachment: None,
        resident_key: Some(ResidentKeyRequirement::Required),
        require_resident_key: true,
        user_verification: UserVerificationPolicy::Required,
    });
    let token = encode_state(TokenScope::Registration, Some(&user.uuid), &state)?;

    let mut options = serde_json::to_value(challenge.public_key)?;
    // The clients add the PRF extension themselves
    options["extensions"] = Value::Null;

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webauthnCredentialCreateOptions",
    })))
}

/// The first step of [`put_credential`].
#[post("/webauthn/assertion-options", data = "<data>")]
async fn post_assertion_options(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    check_webauthn_supported()?;
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;
    data.validate(&mut user, true, &conn).await?;

    assertion_options(TokenScope::UpdateKeySet, Some(&user.uuid))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCredentialData {
    device_response: RegisterPublicKeyCredentialCopy,
    name: String,
    token: String,
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[post("/webauthn", data = "<data>")]
async fn post_credential(data: Json<CreateCredentialData>, headers: Headers, conn: DbConn) -> JsonResult {
    check_passkey_creation_allowed()?;
    let data: CreateCredentialData = data.into_inner();
    let user = headers.user;

    let (_, state): (_, PasskeyRegistration) = decode_state(&data.token, TokenScope::Registration, Some(&user.uuid))?;
    if data.name.trim().is_empty() || data.name.encode_utf16().count() > 50 {
        err!("The field Name must be a string with a maximum length of 50.")
    }
    for (value, field, user_key) in [
        (&data.encrypted_user_key, "EncryptedUserKey", true),
        (&data.encrypted_public_key, "EncryptedPublicKey", false),
        (&data.encrypted_private_key, "EncryptedPrivateKey", false),
    ] {
        if let Some(value) = value {
            validate_prf_key(value, field, user_key)?;
        }
    }

    let existing = WebauthnCredential::find_by_user(&user.uuid, &conn).await;
    if existing.len() >= MAX_CREDENTIALS_PER_USER {
        err!("Unable to complete WebAuthn registration.")
    }
    let Ok(passkey) = webauthn_login()?.finish_passkey_registration(&data.device_response.into(), &state) else {
        err!("Unable to complete WebAuthn registration.")
    };

    let credential = WebauthnCredential::new(
        user.uuid,
        data.name,
        &passkey,
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
    )?;
    // A credential id is unique per user
    if credential.credential_id.len() > 256 || existing.iter().any(|c| c.credential_id == credential.credential_id) {
        err!("Unable to complete WebAuthn registration.")
    }
    credential.insert(&conn).await?;

    Ok(Json(credential.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCredentialData {
    device_response: PublicKeyCredentialCopy,
    token: String,
    encrypted_user_key: String,
    encrypted_public_key: String,
    encrypted_private_key: String,
}

/// Turns on vault unlock for an existing passkey that supports PRF.
#[put("/webauthn", data = "<data>")]
async fn put_credential(data: Json<UpdateCredentialData>, headers: Headers, conn: DbConn) -> EmptyResult {
    check_webauthn_supported()?;
    let data: UpdateCredentialData = data.into_inner();

    validate_prf_key(&data.encrypted_user_key, "EncryptedUserKey", true)?;
    validate_prf_key(&data.encrypted_public_key, "EncryptedPublicKey", false)?;
    validate_prf_key(&data.encrypted_private_key, "EncryptedPrivateKey", false)?;

    let (issued_at, state) = decode_state(&data.token, TokenScope::UpdateKeySet, Some(&headers.user.uuid))?;
    let (user, credential) =
        assert_credential(issued_at, state, &data.device_response.into(), &headers.ip.ip, &conn).await?;
    // The assertion names its own user, which must be the caller
    if user.uuid != headers.user.uuid || !credential.supports_prf {
        err!("Unable to update credential.")
    }

    credential.set_prf_keys(data.encrypted_user_key, data.encrypted_public_key, data.encrypted_private_key, &conn).await
}

#[post("/webauthn/<id>/delete", data = "<data>")]
async fn delete_credential(
    id: WebauthnCredentialId,
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;
    data.validate(&mut user, true, &conn).await?;

    if !WebauthnCredential::delete_by_uuid_and_user(&id, &user.uuid, &conn).await? {
        err_code!("Credential not found.", Status::NotFound.code)
    }
    Ok(())
}

/// `None` without any, so that the field is left out.
pub async fn sync_prf_options(user_uuid: &UserId, conn: &DbConn) -> Option<Value> {
    let options: Vec<Value> = WebauthnCredential::find_by_user(user_uuid, conn)
        .await
        .iter()
        .filter_map(WebauthnCredential::to_sync_prf_option)
        .collect();
    (!options.is_empty()).then_some(Value::Array(options))
}

pub async fn rotation_key_data(user_uuid: &UserId, conn: &DbConn) -> Vec<Value> {
    WebauthnCredential::find_by_user(user_uuid, conn)
        .await
        .iter()
        .filter(|c| c.prf_status() == WebauthnPrfStatus::Enabled)
        .map(|c| {
            json!({
                "id": c.uuid,
                "encryptedPublicKey": c.encrypted_public_key,
                "encryptedUserKey": c.encrypted_user_key,
                "object": "passkeyKeyData",
            })
        })
        .collect()
}

/// One entry of a rotation's `passkeyUnlockData`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUnlockData {
    id: WebauthnCredentialId,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
}

/// The new user key and public key of every passkey with a PRF key set.
///
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/KeyManagement/Validators/WebAuthnLoginKeyRotationValidator.cs#L22-L55>
pub fn validate_rotation(
    existing: Vec<WebauthnCredential>,
    unlock_data: &[PasskeyUnlockData],
) -> ApiResult<Vec<(WebauthnCredential, String, String)>> {
    let mut rotated = Vec::new();
    for credential in existing.into_iter().filter(|c| c.prf_status() == WebauthnPrfStatus::Enabled) {
        let Some(data) = unlock_data.iter().find(|d| d.id == credential.uuid) else {
            err!("All existing webauthn prf keys must be included in the rotation.")
        };
        let Some(encrypted_user_key) = data.encrypted_user_key.clone() else {
            err!("WebAuthn prf keys must have user-key during rotation.")
        };
        let Some(encrypted_public_key) = data.encrypted_public_key.clone() else {
            err!("WebAuthn prf keys must have public-key during rotation.")
        };
        validate_prf_key(&encrypted_user_key, "EncryptedUserKey", true)?;
        validate_prf_key(&encrypted_public_key, "EncryptedPublicKey", false)?;
        rotated.push((credential, encrypted_user_key, encrypted_public_key));
    }
    Ok(rotated)
}
