// Authenticated management adapted from Vaultwarden PR 7297 (AGPL-3.0),
// branch snapshot at 727fead3a06eabf477ae9abed2ff0328acba7a6f.
use chrono::Utc;
use rocket::{Route, http::Status, serde::json::Json, serde::json::Value};
use webauthn_rs::prelude::{
    Base64UrlSafeData, Credential as WebauthnCredentialData, Passkey, PasskeyAuthentication, PasskeyRegistration,
};
use webauthn_rs_proto::{
    AuthenticatorAttestationResponseRaw, AuthenticatorTransport, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, UserVerificationPolicy,
};

use crate::{
    CONFIG,
    api::{
        ApiResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::two_factor::webauthn::{PublicKeyCredentialCopy, WEBAUTHN},
    },
    auth::Headers,
    crypto,
    db::{
        DbConn,
        models::{PasskeyAccount, TwoFactor, TwoFactorType, User, WebAuthnCredential},
    },
    error::Error,
    util::get_uuid,
};

const WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS: i64 = 300;
const WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_WEBAUTHN_CREDENTIALS: usize = 5;

pub fn routes() -> Vec<Route> {
    routes![
        get_api_webauthn,
        post_api_webauthn,
        put_api_webauthn,
        post_api_webauthn_assertion_options,
        post_api_webauthn_attestation_options,
        post_api_webauthn_delete,
    ]
}

#[get("/webauthn")]
async fn get_api_webauthn(headers: Headers, conn: DbConn) -> JsonResult {
    let user = headers.user;

    let data: Vec<Value> = WebAuthnCredential::find_by_user(&user.uuid, &conn)
        .await?
        .into_iter()
        .map(|credential| credential_response(&credential))
        .collect();

    Ok(Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    })))
}

fn credential_response(credential: &WebAuthnCredential) -> Value {
    json!({"id":credential.uuid,"name":credential.name,"prfStatus":credential.prf_status(),
        "encryptedUserKey":credential.encrypted_user_key,"encryptedPublicKey":credential.encrypted_public_key,
        "object":"webauthnCredential"})
}

// EncString contract: bitwarden/server v2026.7.0 and v2026.9.1, AGPL source at
// src/Core/Utilities/EncryptedStringAttribute.cs and the WebAuthn request models.
// Retain the supported releases' legacy forms; validate IV/MAC dimensions too.
// Ciphertext stays opaque:
// structural validity cannot prove integrity or possession of the decryption key.
fn valid_wrapped_key(value: &str) -> bool {
    if value.is_empty() || value.len() > 2000 {
        return false;
    }
    let (scheme, body) = if let Some((header, body)) = value.split_once('.') {
        let scheme = header.trim().parse::<u8>().ok().or_else(|| match header.trim() {
            "AesCbc256_B64" => Some(0),
            "AesCbc128_HmacSha256_B64" => Some(1),
            "AesCbc256_HmacSha256_B64" => Some(2),
            "Rsa2048_OaepSha256_B64" => Some(3),
            "Rsa2048_OaepSha1_B64" => Some(4),
            "Rsa2048_OaepSha256_HmacSha256_B64" => Some(5),
            "Rsa2048_OaepSha1_HmacSha256_B64" => Some(6),
            "XChaCha20Poly1305_B64" | "CoseEncrypt0B64" => Some(7),
            _ => None,
        });
        let Some(scheme) = scheme else {
            return false;
        };
        (scheme, body)
    } else {
        (u8::from(value.matches('|').count() == 2), value)
    };
    // Zero means variable-length ciphertext, not an empty allowed component.
    let lengths: &[usize] = match scheme {
        0 => &[16, 0],
        1 | 2 => &[16, 0, 32],
        3 | 4 | 7 => &[0],
        5 | 6 => &[0, 0],
        _ => return false,
    };
    let mut specification = data_encoding::BASE64.specification();
    specification.check_trailing_bits = false;
    " \t\r\n".clone_into(&mut specification.ignore);
    let encoding = specification.encoding().expect("fixed base64 specification");
    let mut pieces = body.split('|');
    for length in lengths {
        let Some(piece) = pieces.next() else {
            return false;
        };
        let Ok(bytes) = encoding.decode(piece.as_bytes()) else {
            return false;
        };
        if bytes.is_empty() || (*length != 0 && bytes.len() != *length) {
            return false;
        }
    }
    pieces.next().is_none()
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyRegistrationChallenge {
    token: String,
    created_at: i64,
    user_security_stamp: String,
    device_uuid: String,
    account_key_binding: String,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyAssertionChallenge {
    token: String,
    created_at: i64,
    user_security_stamp: String,
    device_uuid: String,
    account_key_binding: String,
    state: PasskeyAuthentication,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterPublicKeyCredentialCopy {
    id: String,
    raw_id: Base64UrlSafeData,
    response: PasskeyAuthenticatorAttestationResponseRawCopy,
    #[serde(default, alias = "clientExtensionResults")]
    extensions: RegistrationExtensionsClientOutputs,
    r#type: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticatorAttestationResponseRawCopy {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    attestation_object: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: Base64UrlSafeData,
    transports: Option<Vec<AuthenticatorTransport>>,
}

impl From<PasskeyRegisterPublicKeyCredentialCopy> for RegisterPublicKeyCredential {
    fn from(r: PasskeyRegisterPublicKeyCredentialCopy) -> Self {
        Self {
            id: r.id,
            raw_id: r.raw_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: r.response.attestation_object,
                client_data_json: r.response.client_data_json,
                transports: r.response.transports,
            },
            type_: r.r#type,
            extensions: r.extensions,
        }
    }
}

fn passkey_management_challenge_is_fresh(created_at: i64) -> bool {
    passkey_management_challenge_is_fresh_at(created_at, Utc::now().timestamp())
}

fn passkey_management_challenge_is_fresh_at(created_at: i64, now: i64) -> bool {
    created_at >= now.saturating_sub(WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS)
        && created_at <= now.saturating_add(WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS)
}

fn passkey_registration_challenge_state(
    data: &str,
    token: Option<&str>,
    user_security_stamp: &str,
    device_uuid: &str,
    account_key_binding: &str,
) -> ApiResult<PasskeyRegistration> {
    let Ok(saved) = serde_json::from_str::<WebAuthnPasskeyRegistrationChallenge>(data) else {
        err!("Invalid registration challenge. Please try again.")
    };
    if !token.is_some_and(|t| crypto::ct_eq(t, &saved.token)) {
        err!("Invalid registration challenge. Please try again.")
    }
    if !passkey_management_challenge_is_fresh(saved.created_at) {
        err!("Invalid registration challenge. Please try again.")
    }
    if !crypto::ct_eq(user_security_stamp, &saved.user_security_stamp) {
        err!("Invalid registration challenge. Please try again.")
    }
    if !crypto::ct_eq(device_uuid, &saved.device_uuid)
        || !crypto::ct_eq(account_key_binding, &saved.account_key_binding)
    {
        err!("Account or session changed. Please try again.")
    }
    Ok(saved.state)
}

fn passkey_assertion_challenge_state(
    data: &str,
    token: &str,
    user_security_stamp: &str,
    device_uuid: &str,
    account_key_binding: &str,
) -> ApiResult<PasskeyAuthentication> {
    let Ok(saved) = serde_json::from_str::<WebAuthnPasskeyAssertionChallenge>(data) else {
        err!("Invalid assertion challenge. Please try again.")
    };
    if !crypto::ct_eq(token, &saved.token) {
        err!("Invalid assertion challenge. Please try again.")
    }
    if !passkey_management_challenge_is_fresh(saved.created_at) {
        err!("Invalid assertion challenge. Please try again.")
    }
    if !crypto::ct_eq(user_security_stamp, &saved.user_security_stamp) {
        err!("Invalid assertion challenge. Please try again.")
    }
    if !crypto::ct_eq(device_uuid, &saved.device_uuid)
        || !crypto::ct_eq(account_key_binding, &saved.account_key_binding)
    {
        err!("Account or session changed. Please try again.")
    }
    Ok(saved.state)
}

pub(crate) fn passkey_credential_id_hash(credential_id: &[u8]) -> String {
    crypto::sha256_hex(credential_id)
}

fn passkey_count_limit_reached(count: usize) -> bool {
    count >= MAX_WEBAUTHN_CREDENTIALS
}

pub(crate) fn account_passkeys_allowed() -> bool {
    CONFIG.passkeys_enabled() && CONFIG.is_webauthn_2fa_supported()
}

pub(crate) fn passkey_counter(passkey: &Passkey) -> u32 {
    let credential: WebauthnCredentialData = passkey.clone().into();
    credential.counter
}

#[derive(PartialEq)]
struct PasskeyRegistrationPrfData {
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

fn passkey_registration_prf_data(
    client_supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
) -> ApiResult<PasskeyRegistrationPrfData> {
    for key in [&encrypted_user_key, &encrypted_public_key, &encrypted_private_key].into_iter().flatten() {
        if !valid_wrapped_key(key) {
            err!("Invalid wrapped passkey key")
        }
    }
    let supports_prf = client_supports_prf;
    let has_key_material =
        encrypted_user_key.is_some() || encrypted_public_key.is_some() || encrypted_private_key.is_some();

    if !supports_prf {
        if has_key_material {
            err!("Passkey does not support PRF")
        }
        return Ok(PasskeyRegistrationPrfData {
            supports_prf: false,
            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
        });
    }

    if !has_key_material {
        return Ok(PasskeyRegistrationPrfData {
            supports_prf: true,
            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
        });
    }

    let Some(encrypted_user_key) = encrypted_user_key else {
        err!("Encrypted user key is required")
    };
    let Some(encrypted_public_key) = encrypted_public_key else {
        err!("Encrypted public key is required")
    };
    let Some(encrypted_private_key) = encrypted_private_key else {
        err!("Encrypted private key is required")
    };

    Ok(PasskeyRegistrationPrfData {
        supports_prf: true,
        encrypted_user_key: Some(encrypted_user_key),
        encrypted_public_key: Some(encrypted_public_key),
        encrypted_private_key: Some(encrypted_private_key),
    })
}

fn check_passkey_endpoint_preconditions(ip: &std::net::IpAddr, _action_verb: &str) -> ApiResult<()> {
    crate::ratelimit::check_limit_login(ip)?;
    if !account_passkeys_allowed() {
        err!("Passkeys are not enabled")
    }
    Ok(())
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_api_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    check_passkey_endpoint_preconditions(&headers.ip.ip, "created")?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    let all_creds = WebAuthnCredential::find_by_user(&user.uuid, &conn).await?;
    if passkey_count_limit_reached(all_creds.len()) {
        err!("Maximum number of passkeys reached")
    }

    let existing_cred_ids: Vec<_> = all_creds
        .into_iter()
        .filter_map(|wac| {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&wac.credential) {
                Some(passkey.cred_id().to_owned())
            } else {
                warn!("Skipping an invalid stored passkey");
                None
            }
        })
        .collect();

    let user_uuid = uuid::Uuid::parse_str(&user.uuid)
        .map_err(|_| Error::new("Invalid user", "Could not parse user UUID for passkey registration"))?;

    let (mut challenge, state) =
        WEBAUTHN.start_passkey_registration(user_uuid, &user.email, user.display_name(), Some(existing_cred_ids))?;

    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Required;
        asc.require_resident_key = true;
        asc.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyRegistrationChallenge {
        token: token.clone(),
        created_at: Utc::now().timestamp(),
        user_security_stamp: user.security_stamp.clone(),
        device_uuid: headers.device.uuid.to_string(),
        account_key_binding: PasskeyAccount::from_user(&user)?.binding(),
        state,
    };

    PasskeyAccount::from_user(&user)?
        .replace_challenge(
            TwoFactor::new(
                user.uuid.clone(),
                TwoFactorType::WebauthnPasskeyRegisterChallenge,
                serde_json::to_string(&saved_challenge)?,
            ),
            &conn,
        )
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
    check_passkey_endpoint_preconditions(&headers.ip.ip, "updated")?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    let credentials: Vec<Passkey> = WebAuthnCredential::find_by_user(&user.uuid, &conn)
        .await?
        .into_iter()
        .filter(|wac| wac.supports_prf)
        .filter_map(|wac| {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&wac.credential) {
                Some(passkey)
            } else {
                warn!("Skipping an invalid stored passkey");
                None
            }
        })
        .collect();

    if credentials.is_empty() {
        err!("No PRF-capable passkeys registered")
    }

    let (response, state) = WEBAUTHN.start_passkey_authentication(&credentials)?;

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyAssertionChallenge {
        token: token.clone(),
        created_at: Utc::now().timestamp(),
        user_security_stamp: user.security_stamp.clone(),
        device_uuid: headers.device.uuid.to_string(),
        account_key_binding: PasskeyAccount::from_user(&user)?.binding(),
        state,
    };
    PasskeyAccount::from_user(&user)?
        .replace_challenge(
            TwoFactor::new(
                user.uuid.clone(),
                TwoFactorType::WebauthnPasskeyAssertionChallenge,
                serde_json::to_string(&saved_challenge)?,
            ),
            &conn,
        )
        .await?;

    Ok(Json(json!({
        "options": response.public_key,
        "token": token,
        "object": "webAuthnLoginAssertionOptions"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnLoginCredentialCreateRequest {
    device_response: PasskeyRegisterPublicKeyCredentialCopy,
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
    nt: Notify<'_>,
) -> JsonResult {
    check_passkey_endpoint_preconditions(&headers.ip.ip, "created")?;

    let data: WebAuthnLoginCredentialCreateRequest = data.into_inner();
    let user = headers.user;

    let Some(mut current_user) = User::find_by_uuid(&user.uuid, &conn).await else {
        err!("User not found")
    };

    if passkey_count_limit_reached(WebAuthnCredential::find_by_user(&current_user.uuid, &conn).await?.len()) {
        err!("Maximum number of passkeys reached")
    }

    let type_ = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await else {
        err!("No registration challenge found. Please try again.")
    };
    let state = passkey_registration_challenge_state(
        &tf.data,
        data.token.as_deref(),
        &current_user.security_stamp,
        &headers.device.uuid.to_string(),
        &PasskeyAccount::from_user(&current_user)?.binding(),
    )?;
    if !WebAuthnCredential::consume_challenge(tf, &conn).await? {
        err!("No registration challenge found. Please try again.")
    }

    let credential = WEBAUTHN
        .finish_passkey_registration(&data.device_response.into(), &state)
        .map_err(|_| Error::new_msg("Invalid passkey registration"))?;
    let credential_id_hash = passkey_credential_id_hash(credential.cred_id().as_slice());
    let PasskeyRegistrationPrfData {
        supports_prf,
        encrypted_user_key,
        encrypted_public_key,
        encrypted_private_key,
    } = passkey_registration_prf_data(
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
    )?;

    let account = PasskeyAccount::from_user(&current_user)?;
    if data.name.is_empty() || data.name.len() > 256 {
        err!("Invalid passkey name")
    }
    let credential = WebAuthnCredential {
        uuid: WebAuthnCredential::id(),
        user_uuid: current_user.uuid.clone(),
        name: data.name,
        credential: serde_json::to_string(&credential)?,
        credential_id_hash,
        supports_prf,
        encrypted_user_key,
        encrypted_public_key,
        encrypted_private_key,
    };
    credential.insert(&account, &conn).await?;

    current_user.update_revision(&conn).await?;
    nt.send_user_update(UpdateType::SyncVault, &current_user, headers.device.push_uuid.as_ref(), &conn).await;

    Ok(Json(credential_response(&credential)))
}

#[derive(Deserialize)]
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
    nt: Notify<'_>,
) -> ApiResult<Status> {
    check_passkey_endpoint_preconditions(&headers.ip.ip, "updated")?;

    let data: WebAuthnLoginCredentialUpdateRequest = data.into_inner();
    let user = headers.user;

    let Some(encrypted_user_key) = data.encrypted_user_key else {
        err!("Encrypted user key is required")
    };
    let Some(encrypted_public_key) = data.encrypted_public_key else {
        err!("Encrypted public key is required")
    };
    let Some(encrypted_private_key) = data.encrypted_private_key else {
        err!("Encrypted private key is required")
    };

    let Some(mut current_user) = User::find_by_uuid(&user.uuid, &conn).await else {
        err!("User not found")
    };

    let type_ = TwoFactorType::WebauthnPasskeyAssertionChallenge as i32;
    let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await else {
        err!("No assertion challenge found. Please try again.")
    };
    let state = passkey_assertion_challenge_state(
        &tf.data,
        &data.token,
        &current_user.security_stamp,
        &headers.device.uuid.to_string(),
        &PasskeyAccount::from_user(&current_user)?.binding(),
    )?;
    if !WebAuthnCredential::consume_challenge(tf, &conn).await? {
        err!("No assertion challenge found. Please try again.")
    }

    for key in [&encrypted_user_key, &encrypted_public_key, &encrypted_private_key] {
        if !valid_wrapped_key(key) {
            err!("Invalid wrapped passkey key")
        }
    }
    let credential_response = data.device_response.into();

    let authentication_result = WEBAUTHN
        .finish_passkey_authentication(&credential_response, &state)
        .map_err(|_| Error::new_msg("Invalid passkey assertion"))?;
    let credential_id_hash = passkey_credential_id_hash(authentication_result.cred_id().as_slice());
    let Some(mut matched_wac) =
        WebAuthnCredential::find_by_user_and_credential_id_hash(&current_user.uuid, &credential_id_hash, &conn).await?
    else {
        err!("Verified credential is not registered")
    };

    if !matched_wac.supports_prf {
        err!("Passkey does not support PRF")
    }

    let previous_credential = matched_wac.credential.clone();
    let mut passkey: Passkey =
        serde_json::from_str(&previous_credential).map_err(|_| Error::new_msg("Invalid stored passkey"))?;

    let previous_counter = passkey_counter(&passkey);
    let updated_credential = passkey.update_credential(&authentication_result) == Some(true);
    let advanced_counter = updated_credential && authentication_result.counter() > previous_counter;
    if advanced_counter {
        matched_wac.credential = serde_json::to_string(&passkey)?;
    }
    matched_wac.encrypted_user_key = Some(encrypted_user_key);
    matched_wac.encrypted_public_key = Some(encrypted_public_key);
    matched_wac.encrypted_private_key = Some(encrypted_private_key);
    matched_wac.update_prf(&PasskeyAccount::from_user(&current_user)?, &previous_credential, &conn).await?;

    current_user.update_revision(&conn).await?;
    nt.send_user_update(UpdateType::SyncVault, &current_user, headers.device.push_uuid.as_ref(), &conn).await;

    Ok(Status::Ok)
}

#[post("/webauthn/<uuid>/delete", data = "<data>")]
async fn post_api_webauthn_delete(
    data: Json<PasswordOrOtpData>,
    uuid: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> ApiResult<Status> {
    crate::ratelimit::check_limit_login(&headers.ip.ip)?;

    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &conn).await?;

    let deleted = WebAuthnCredential::delete_by_uuid_and_user(&uuid, &user.uuid, &conn).await?;
    if deleted {
        user.update_revision(&conn).await?;
        nt.send_user_update(UpdateType::SyncVault, &user, headers.device.push_uuid.as_ref(), &conn).await;
    } else {
        debug!("post_api_webauthn_delete: credential {uuid} was not registered for user {}", user.uuid);
    }

    Ok(Status::Ok)
}

pub async fn sync_options(user: &User, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let mut options = Vec::new();
    if !account_passkeys_allowed() {
        return Ok(options);
    }
    for row in WebAuthnCredential::find_by_user(&user.uuid, conn).await? {
        if !row.has_prf_keyset() {
            continue;
        }
        let Ok(passkey) = serde_json::from_str::<Passkey>(&row.credential) else {
            warn!("Skipping an invalid stored passkey");
            continue;
        };
        let credential: WebauthnCredentialData = passkey.into();
        options.push(json!({"credentialId": credential.cred_id,
            "transports": credential.transports.unwrap_or_default(), "encryptedUserKey": row.encrypted_user_key,
            "encryptedPrivateKey": row.encrypted_private_key}));
    }
    Ok(options)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUnlockData {
    id: String,
    encrypted_public_key: String,
    encrypted_user_key: String,
}

pub async fn prepare_rotation(
    user: &User,
    data: Vec<PasskeyUnlockData>,
    conn: &DbConn,
) -> ApiResult<Vec<(WebAuthnCredential, String, String)>> {
    let mut existing = WebAuthnCredential::find_by_user(&user.uuid, conn)
        .await?
        .into_iter()
        .filter(WebAuthnCredential::has_prf_keyset)
        .map(|row| (row.uuid.clone(), row))
        .collect::<std::collections::HashMap<_, _>>();
    let mut prepared = Vec::new();
    for item in data {
        let Some(row) = existing.remove(&item.id) else {
            err!("Unknown or duplicate passkey in key rotation")
        };
        for key in [&item.encrypted_public_key, &item.encrypted_user_key] {
            if !valid_wrapped_key(key) {
                err!("Invalid wrapped passkey key")
            }
        }
        prepared.push((row, item.encrypted_user_key, item.encrypted_public_key));
    }
    if !existing.is_empty() {
        err!("All enabled passkeys must be included in key rotation")
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::valid_wrapped_key;

    #[test]
    fn wrapped_key_wire_contract_preserves_supported_encstring_forms() {
        let iv = data_encoding::BASE64.encode(&[0; 16]);
        let ct = data_encoding::BASE64.encode(&[1; 32]);
        let mac = data_encoding::BASE64.encode(&[2; 32]);
        for value in [
            format!("0.{iv}|{ct}"),
            format!("1.{iv}|{ct}|{mac}"),
            format!("2.{iv}|{ct}|{mac}"),
            format!("3.{ct}"),
            format!("4.{ct}"),
            format!("5.{ct}|{mac}"),
            format!("6.{ct}|{mac}"),
            format!("7.{ct}"),
            format!("{iv}|{ct}"),
            format!("{iv}|{ct}|{mac}"),
            format!("AesCbc256_HmacSha256_B64.{iv}|{ct}|{mac}"),
            // Native clients accept non-zero unused base64 padding bits.
            "0.AAECAwQFBgcICQoLDA0OD/==|lGD=".to_owned(),
        ] {
            assert!(valid_wrapped_key(&value));
        }
        for value in [
            String::new(),
            "plaintext".to_owned(),
            "9.AAAA".to_owned(),
            "2.AA==|AA==|AA==".to_owned(),
            format!("2.{iv}|{ct}|{mac}|{mac}"),
            "4.!not-base64!".to_owned(),
            format!("4.{}", "A".repeat(2000)),
        ] {
            assert!(!valid_wrapped_key(&value));
        }
    }
}
