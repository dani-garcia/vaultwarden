use chrono::Utc;
use rocket::{Route, http::Status, serde::json::Json, serde::json::Value};
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, Credential as WebauthnCredentialData, Passkey, PasskeyAuthentication,
    PasskeyRegistration,
};
use webauthn_rs_proto::{
    AuthenticatorAttestationResponseRaw, AuthenticatorTransport, ExtnState, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, RequestRegistrationExtensions, UserVerificationPolicy,
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
        models::{
            TwoFactor, TwoFactorType, User, WebAuthnCredential, WebAuthnCredentialId, is_concurrent_modification,
        },
    },
    error::Error,
    util::get_uuid,
};

const WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS: i64 = 300;
const WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS: i64 = 30;
// Bitwarden currently caps account-login passkeys at five per user.
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

    Ok(Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    })))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyRegistrationChallenge {
    token: String,
    created_at: i64,
    user_security_stamp: String,
    state: PasskeyRegistration,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnPasskeyAssertionChallenge {
    token: String,
    created_at: i64,
    user_security_stamp: String,
    state: PasskeyAuthentication,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterPublicKeyCredentialCopy {
    id: String,
    raw_id: Base64UrlSafeData,
    response: PasskeyAuthenticatorAttestationResponseRawCopy,
    #[serde(default, alias = "clientExtensionResults")]
    extensions: RegistrationExtensionsClientOutputs,
    r#type: String,
}

#[derive(Debug, Deserialize)]
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
    // The timestamp is server-stamped, so a future value only happens after a
    // clock step backwards or manual DB tampering. Allow a small skew window
    // for harmless corrections, but reject anything beyond it so a pre-step
    // challenge cannot remain valid for longer than the documented TTL.
    passkey_management_challenge_is_fresh_at(created_at, Utc::now().timestamp())
}

fn passkey_management_challenge_is_fresh_at(created_at: i64, now: i64) -> bool {
    crate::util::is_within_freshness_window(
        created_at,
        now,
        WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS,
        WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS,
    )
}

fn passkey_registration_challenge_state(
    data: &str,
    token: Option<&str>,
    user_security_stamp: &str,
) -> ApiResult<PasskeyRegistration> {
    // Persisted challenge rows are always the `{token, state}` wrapper —
    // nothing in the current code path writes the bare `PasskeyRegistration`
    // shape. Reject a row that doesn't deserialise (corrupted, stale schema)
    // with the same generic message we use for token mismatch, rather than
    // falling through to an un-tokened legacy path.
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
    Ok(saved.state)
}

fn passkey_assertion_challenge_state(
    data: &str,
    token: &str,
    user_security_stamp: &str,
) -> ApiResult<PasskeyAuthentication> {
    // Same shape contract as `passkey_registration_challenge_state` above —
    // reject undecodable rows with the generic message rather than leaking
    // the underlying serde error.
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
    Ok(saved.state)
}

pub(crate) fn passkey_credential_id_hash(credential_id: &[u8]) -> String {
    crypto::sha256_hex(credential_id)
}

fn passkey_count_limit_reached(count: usize) -> bool {
    count >= MAX_WEBAUTHN_CREDENTIALS
}

/// Single source of truth for whether the deployment posture permits account
/// passkeys — gates `/sync`'s `webAuthnPrfOptions`, `/api/config`'s
/// `pm-2035-passkey-unlock` flag, and [`check_passkey_endpoint_preconditions`]
/// so the lock-screen affordance the client renders agrees with the server's
/// actual acceptance posture.
pub(crate) fn account_passkeys_allowed() -> bool {
    account_passkeys_disabled_reason().is_none()
}

#[derive(Clone, Copy)]
enum AccountPasskeysDisabledReason {
    WebAuthnUnsupported,
    SsoOnly,
}

fn account_passkeys_disabled_reason() -> Option<AccountPasskeysDisabledReason> {
    if !CONFIG.is_webauthn_2fa_supported() {
        Some(AccountPasskeysDisabledReason::WebAuthnUnsupported)
    } else if CONFIG.sso_enabled() && CONFIG.sso_only() {
        Some(AccountPasskeysDisabledReason::SsoOnly)
    } else {
        None
    }
}

fn request_passkey_prf_extension(
    mut challenge: CreationChallengeResponse,
    state: &PasskeyRegistration,
) -> ApiResult<(CreationChallengeResponse, PasskeyRegistration)> {
    challenge.public_key.extensions.get_or_insert_with(RequestRegistrationExtensions::default).hmac_create_secret =
        Some(true);

    let mut state_value = serde_json::to_value(state)?;
    let Some(extensions) =
        state_value.get_mut("rs").and_then(|rs| rs.get_mut("extensions")).and_then(Value::as_object_mut)
    else {
        return Err(Error::new("Invalid passkey registration state", "Missing WebAuthn registration extensions"));
    };
    extensions.insert("hmacCreateSecret".to_owned(), Value::Bool(true));

    let state = serde_json::from_value(state_value)?;
    Ok((challenge, state))
}

fn passkey_supports_prf(passkey: &Passkey) -> bool {
    let credential: WebauthnCredentialData = passkey.clone().into();
    matches!(credential.extensions.hmac_create_secret, ExtnState::Set(true))
}

/// `webauthn-rs`'s `Passkey::cred` is `pub(crate)`, so there is no direct
/// accessor for the stored signature counter; the only path is to clone the
/// struct and convert into `Credential`. Centralised here so a future upstream
/// `Passkey::counter()` accessor is a one-line swap.
pub(crate) fn passkey_counter(passkey: &Passkey) -> u32 {
    let credential: WebauthnCredentialData = passkey.clone().into();
    credential.counter
}

#[derive(Debug, PartialEq)]
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
    server_supports_prf: bool,
) -> ApiResult<PasskeyRegistrationPrfData> {
    let supports_prf = client_supports_prf || server_supports_prf;
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

    // Chromium/CDP does not consistently reflect the registration PRF
    // extension in the attested credential, but the web vault still reports
    // whether the browser ceremony supports PRF. Store that client capability
    // signal; only the presence of wrapped key blobs controls unlock.
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

/// Gates the passkey-management MUTATION endpoints (POST/PUT `/webauthn` and
/// the two `*-options` endpoints) in order:
///   - `check_limit_login` - shared IP rate limit, FIRST so a misconfigured
///     DOMAIN can't become an uncapped error-log generator (a refused request
///     would otherwise short-circuit without consuming a rate-limit token).
///   - `is_webauthn_2fa_supported` - refuses cleanly when DOMAIN is
///     incompatible; must run before the `WEBAUTHN` LazyLock is touched, which
///     would otherwise panic.
///   - SSO_ONLY - refuses passkey mutations under required SSO (Bitwarden parity).
///
/// `get_api_webauthn` (read-only) and `post_api_webauthn_delete`
/// (capability-narrowing; gating it would strand credentials) are intentionally
/// NOT gated here. The unauthenticated `get_web_authn_assertion_options` in
/// `identity.rs` inlines the same checks but collapses them to the opaque
/// `PASSKEY_AUTH_FAILED` — the admin-facing wording below must not reach
/// anonymous callers. `action_verb` ("created"/"updated") keeps the SSO refusal
/// message precise.
pub(crate) fn check_passkey_endpoint_preconditions(ip: &std::net::IpAddr, action_verb: &str) -> ApiResult<()> {
    crate::ratelimit::check_limit_login(ip)?;
    match account_passkeys_disabled_reason() {
        Some(AccountPasskeysDisabledReason::WebAuthnUnsupported) => {
            err!("Webauthn is not supported on this server. Set `DOMAIN` to a valid URL with a parseable host.")
        }
        Some(AccountPasskeysDisabledReason::SsoOnly) => {
            err!(format!("Passkeys cannot be {action_verb} when SSO sign-in is required"))
        }
        None => Ok(()),
    }
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

    // Skip credentials whose stored blob fails to deserialize rather than
    // propagating: a single corrupt row would otherwise block the user from
    // enrolling ANY new passkey. The browser's excludeCredentials list ends
    // up missing those entries, but the UNIQUE(user_uuid, credential_id_hash)
    // constraint at `save_with_user_limit` still catches a re-enrolment of
    // the corrupt row's authenticator. Surface the corruption to ops via
    // `warn!` so the bad row can be investigated.
    let existing_cred_ids: Vec<_> = all_creds
        .into_iter()
        .filter_map(|wac| match serde_json::from_str::<Passkey>(&wac.credential) {
            Ok(passkey) => Some(passkey.cred_id().to_owned()),
            Err(e) => {
                warn!(
                    "post_api_webauthn_attestation_options: corrupt credential blob for {} (user {}), skipping from excludeCredentials: {e:#?}",
                    wac.uuid, wac.user_uuid
                );
                None
            }
        })
        .collect();

    let user_uuid = uuid::Uuid::parse_str(&user.uuid)
        .map_err(|_| Error::new("Invalid user", "Could not parse user UUID for passkey registration"))?;

    let (challenge, state) =
        WEBAUTHN.start_passkey_registration(user_uuid, &user.email, user.display_name(), Some(existing_cred_ids))?;
    let (mut challenge, state) = request_passkey_prf_extension(challenge, &state)?;

    // Ask the client for a discoverable (resident) credential with UV.
    // `start_passkey_registration` already pins UV=Required in `state`;
    // resident-key is NOT enforced server-side by webauthn-rs, so this is a
    // client-side hint on the challenge JSON only. A non-resident credential
    // would still be accepted here but later fail discoverable-login, so
    // tampering clients only hurt themselves.
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Required;
        asc.require_resident_key = true;
        asc.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }

    // Atomically drop any abandoned challenge from a previous, unfinished
    // registration attempt so only one in-flight challenge state per user
    // exists at any time.
    TwoFactor::take_by_user_and_type(&user.uuid, TwoFactorType::WebauthnPasskeyRegisterChallenge as i32, &conn).await?;

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyRegistrationChallenge {
        token: token.clone(),
        created_at: Utc::now().timestamp(),
        user_security_stamp: user.security_stamp,
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
    check_passkey_endpoint_preconditions(&headers.ip.ip, "updated")?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    // Skip credentials whose stored blob fails to deserialize rather than
    // propagating: a single corrupt PRF row would otherwise block the user
    // from EVER initiating PRF unlock with any other healthy passkey. Same
    // shape as `post_api_webauthn_attestation_options` above — surface the
    // corruption to ops via `warn!` so the bad row can be investigated.
    let credentials: Vec<Passkey> = WebAuthnCredential::find_by_user(&user.uuid, &conn)
        .await?
        .into_iter()
        .filter(|wac| wac.supports_prf)
        .filter_map(|wac| match serde_json::from_str::<Passkey>(&wac.credential) {
            Ok(passkey) => Some(passkey),
            Err(e) => {
                warn!(
                    "post_api_webauthn_assertion_options: corrupt credential blob for {} (user {}), skipping PRF-capable passkey: {e:#?}",
                    wac.uuid, wac.user_uuid
                );
                None
            }
        })
        .collect();

    if credentials.is_empty() {
        err!("No PRF-capable passkeys registered")
    }

    let (response, state) = WEBAUTHN.start_passkey_authentication(&credentials)?;

    // Atomically drop any abandoned challenge from a previous attempt — see
    // the comment on `post_api_webauthn_attestation_options`.
    TwoFactor::take_by_user_and_type(&user.uuid, TwoFactorType::WebauthnPasskeyAssertionChallenge as i32, &conn)
        .await?;

    let token = get_uuid();
    let saved_challenge = WebAuthnPasskeyAssertionChallenge {
        token: token.clone(),
        created_at: Utc::now().timestamp(),
        user_security_stamp: user.security_stamp,
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
        "object": "webAuthnLoginAssertionOptions"
    })))
}

#[derive(Debug, Deserialize)]
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
) -> ApiResult<Status> {
    check_passkey_endpoint_preconditions(&headers.ip.ip, "created")?;

    let data: WebAuthnLoginCredentialCreateRequest = data.into_inner();
    let user = headers.user;

    // Consume the exact challenge row only after token/security-stamp
    // validation, so a stale tab can't delete the user's current challenge
    // with an old token. A failed validation leaves the row until the next
    // options request replaces it; UNIQUE(user_uuid, atype) bounds it to one
    // stale-but-unredeemable row per user/type.
    let Some(mut current_user) = User::try_find_by_uuid(&user.uuid, &conn).await? else {
        err!("User not found")
    };

    if passkey_count_limit_reached(WebAuthnCredential::count_by_user(&current_user.uuid, &conn).await?) {
        err!("Maximum number of passkeys reached")
    }

    let type_ = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let Some(tf) = TwoFactor::try_find_by_user_and_type(&user.uuid, type_, &conn).await? else {
        err!("No registration challenge found. Please try again.")
    };
    let state = passkey_registration_challenge_state(&tf.data, data.token.as_deref(), &current_user.security_stamp)?;
    if !tf.delete_by_uuid(&conn).await? {
        err!("No registration challenge found. Please try again.")
    }

    let credential = WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state)?;
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
        passkey_supports_prf(&credential),
    )?;

    // Duplicate detection rests on the UNIQUE `(user_uuid, credential_id_hash)`
    // index: `save_with_user_limit` below maps the `UniqueViolation` to
    // "Passkey is already registered". Scoping it per-user means a cross-account
    // hash collision (trivial if an attacker echoes an observed cred_id) inserts
    // cleanly without signalling that another account holds that hash.

    WebAuthnCredential::new(
        current_user.uuid.clone(),
        data.name,
        serde_json::to_string(&credential)?,
        credential_id_hash,
        supports_prf,
        encrypted_user_key,
        encrypted_public_key,
        encrypted_private_key,
    )
    .save_with_user_limit(MAX_WEBAUTHN_CREDENTIALS, &conn)
    .await?;

    current_user.update_revision(&conn).await?;
    nt.send_user_update(UpdateType::SyncVault, &current_user, headers.device.push_uuid.as_ref(), &conn).await;

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

    // Consume the exact challenge row only after token/security-stamp
    // validation, so a stale tab can't delete the user's current challenge
    // with an old token. A failed validation leaves the row until the next
    // options request replaces it; UNIQUE(user_uuid, atype) bounds it to one
    // stale-but-unredeemable row per user/type.
    let Some(mut current_user) = User::try_find_by_uuid(&user.uuid, &conn).await? else {
        err!("User not found")
    };

    let type_ = TwoFactorType::WebauthnPasskeyAssertionChallenge as i32;
    let Some(tf) = TwoFactor::try_find_by_user_and_type(&user.uuid, type_, &conn).await? else {
        err!("No assertion challenge found. Please try again.")
    };
    let state = passkey_assertion_challenge_state(&tf.data, &data.token, &current_user.security_stamp)?;
    if !tf.delete_by_uuid(&conn).await? {
        err!("No assertion challenge found. Please try again.")
    }

    let credential_response = data.device_response.into();

    // Verify the assertion against the saved challenge state. `state`
    // already carries the credential set the challenge was issued against,
    // so we don't need to pass credentials again here. After verification
    // we know the exact cred_id and can index directly into the
    // credential table via the per-user UNIQUE on credential_id_hash —
    // avoiding the full passkey-set scan + N JSON parses the previous
    // shape did.
    let authentication_result = WEBAUTHN.finish_passkey_authentication(&credential_response, &state)?;
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
    let mut passkey: Passkey = serde_json::from_str(&previous_credential)?;

    // Persist the PRF keyset, optionally folding a signature-counter advance
    // into the same UPDATE. Backup-state-only WebAuthn changes are not written:
    // with blob storage, writing a stale backup-state toggle can roll back a
    // counter advanced by a parallel replica.
    let previous_counter = passkey_counter(&passkey);
    let updated_credential = passkey.update_credential(&authentication_result) == Some(true);
    let advanced_counter = updated_credential && authentication_result.counter() > previous_counter;
    if advanced_counter {
        matched_wac.credential = serde_json::to_string(&passkey)?;
    }
    matched_wac.encrypted_user_key = Some(encrypted_user_key);
    matched_wac.encrypted_public_key = Some(encrypted_public_key);
    matched_wac.encrypted_private_key = Some(encrypted_private_key);
    if let Err(e) = matched_wac
        .update_credential_and_prf_keyset(
            advanced_counter,
            advanced_counter.then_some(previous_credential.as_str()),
            &conn,
        )
        .await
    {
        // Surface a CAS-loser race as a 409 + retry hint. This INTENTIONALLY
        // diverges from `webauthn_login`, which is unauthenticated and masks CM
        // behind a generic 503/INFO so an attacker gets no retry signal; here
        // the caller is authenticated and can act on the 409, and operators
        // want ERROR-level visibility into PRF-enrol contention.
        if is_concurrent_modification(&e) {
            err_code!(
                "Passkey credential modified concurrently. Try again.",
                format!("user {} credential {}: {e:#?}", user.uuid, matched_wac.uuid),
                Status::Conflict.code
            )
        }
        return Err(e);
    }

    current_user.update_revision(&conn).await?;
    nt.send_user_update(UpdateType::SyncVault, &current_user, headers.device.push_uuid.as_ref(), &conn).await;

    Ok(Status::Ok)
}

// Intentionally NOT gated on SSO_ONLY or DOMAIN-misconfigured: delete
// narrows capability (revokes, never grants), the session is still
// SSO-authenticated when this handler runs, and delete never touches the
// `WEBAUTHN` LazyLock so DOMAIN parseability is irrelevant. Lets users
// clean up credentials regardless of later deployment-config changes.
#[post("/webauthn/<uuid>/delete", data = "<data>")]
async fn post_api_webauthn_delete(
    data: Json<PasswordOrOtpData>,
    uuid: WebAuthnCredentialId,
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

    #[test]
    fn passkey_register_public_key_credential_copy_preserves_transports() {
        let transports = vec![AuthenticatorTransport::Internal, AuthenticatorTransport::Hybrid];
        let copy = PasskeyRegisterPublicKeyCredentialCopy {
            id: String::from("credential"),
            raw_id: Base64UrlSafeData::from([1, 2, 3]),
            response: PasskeyAuthenticatorAttestationResponseRawCopy {
                attestation_object: Base64UrlSafeData::from([4, 5, 6]),
                client_data_json: Base64UrlSafeData::from([7, 8, 9]),
                transports: Some(transports.clone()),
            },
            extensions: RegistrationExtensionsClientOutputs::default(),
            r#type: String::from("public-key"),
        };

        let converted: RegisterPublicKeyCredential = copy.into();

        assert_eq!(converted.response.transports, Some(transports));
    }

    #[test]
    fn passkey_register_public_key_credential_copy_accepts_client_extension_results_alias() {
        let copy = serde_json::from_value::<PasskeyRegisterPublicKeyCredentialCopy>(json!({
            "id": "credential",
            "rawId": "AQID",
            "response": {
                "attestationObject": "BAUG",
                "clientDataJson": "BwgJ",
                "transports": ["internal"]
            },
            "clientExtensionResults": {},
            "type": "public-key"
        }))
        .unwrap();

        let converted: RegisterPublicKeyCredential = copy.into();

        assert_eq!(converted.id, "credential");
        assert_eq!(converted.response.transports, Some(vec![AuthenticatorTransport::Internal]));
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

    fn passkey_with_hmac_secret_state(hmac_create_secret: ExtnState<bool>) -> Passkey {
        let mut extensions = RegisteredExtensions::none();
        extensions.hmac_create_secret = hmac_create_secret;

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
            transports: None,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Required,
            extensions,
            attestation: ParsedAttestation::default(),
            attestation_format: AttestationFormat::None,
        }
        .into()
    }

    /// Regression guard: `request_passkey_prf_extension` drills into
    /// `webauthn-rs`'s `PasskeyRegistration` via the JSON-Value path
    /// `rs.extensions.hmacCreateSecret`. The `rs` field is `pub(crate)` in
    /// upstream and its serde name is the field identifier — any future
    /// webauthn-rs version that renames the wrapper, restructures
    /// `RegistrationState`, or moves the extensions sub-object out of it
    /// would silently break PRF registration with no compile-time signal.
    /// This test exercises the same path the production helper does and
    /// asserts the extension lands in both the client-facing challenge
    /// AND the round-tripped server-side state.
    #[test]
    fn request_passkey_prf_extension_marks_challenge_and_stored_state() {
        let user_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
        let (challenge, state) =
            webauthn().start_passkey_registration(user_uuid, "user@example.com", "user", None).unwrap();

        let (challenge, state) = request_passkey_prf_extension(challenge, &state).unwrap();

        assert_eq!(challenge.public_key.extensions.as_ref().and_then(|e| e.hmac_create_secret), Some(true));
        assert_eq!(serde_json::to_value(&state).unwrap()["rs"]["extensions"]["hmacCreateSecret"], Value::Bool(true));
    }

    #[test]
    fn passkey_supports_prf_only_when_requested_extension_was_set() {
        assert!(passkey_supports_prf(&passkey_with_hmac_secret_state(ExtnState::Set(true))));
        assert!(!passkey_supports_prf(&passkey_with_hmac_secret_state(ExtnState::Set(false))));
        assert!(!passkey_supports_prf(&passkey_with_hmac_secret_state(ExtnState::Ignored)));
        assert!(!passkey_supports_prf(&passkey_with_hmac_secret_state(ExtnState::Unsolicited(true))));
        assert!(!passkey_supports_prf(&passkey_with_hmac_secret_state(ExtnState::NotRequested)));
    }

    #[test]
    fn passkey_registration_prf_data_trusts_client_prf_support_when_keyset_is_complete() {
        assert_eq!(
            passkey_registration_prf_data(
                true,
                Some("user-key".to_owned()),
                Some("public-key".to_owned()),
                Some("private-key".to_owned()),
                false,
            )
            .unwrap(),
            PasskeyRegistrationPrfData {
                supports_prf: true,
                encrypted_user_key: Some("user-key".to_owned()),
                encrypted_public_key: Some("public-key".to_owned()),
                encrypted_private_key: Some("private-key".to_owned()),
            }
        );
    }

    #[test]
    fn passkey_registration_prf_data_requires_complete_keyset_when_any_prf_key_is_sent() {
        assert!(
            passkey_registration_prf_data(
                true,
                None,
                Some("public-key".to_owned()),
                Some("private-key".to_owned()),
                true
            )
            .is_err()
        );
        assert!(
            passkey_registration_prf_data(
                true,
                Some("user-key".to_owned()),
                None,
                Some("private-key".to_owned()),
                true
            )
            .is_err()
        );
        assert!(
            passkey_registration_prf_data(true, Some("user-key".to_owned()), Some("public-key".to_owned()), None, true)
                .is_err()
        );

        assert_eq!(
            passkey_registration_prf_data(
                true,
                Some("user-key".to_owned()),
                Some("public-key".to_owned()),
                Some("private-key".to_owned()),
                true,
            )
            .unwrap(),
            PasskeyRegistrationPrfData {
                supports_prf: true,
                encrypted_user_key: Some("user-key".to_owned()),
                encrypted_public_key: Some("public-key".to_owned()),
                encrypted_private_key: Some("private-key".to_owned()),
            }
        );
    }

    #[test]
    fn passkey_registration_prf_data_records_prf_support_even_without_client_keyset() {
        let only_support = |supports_prf| PasskeyRegistrationPrfData {
            supports_prf,
            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
        };
        assert_eq!(passkey_registration_prf_data(false, None, None, None, true).unwrap(), only_support(true));
        assert_eq!(passkey_registration_prf_data(true, None, None, None, false).unwrap(), only_support(true));
        assert_eq!(passkey_registration_prf_data(false, None, None, None, false).unwrap(), only_support(false));
    }

    #[test]
    fn passkey_registration_prf_data_rejects_key_material_without_prf_support() {
        assert!(
            passkey_registration_prf_data(
                false,
                Some("user-key".to_owned()),
                Some("public-key".to_owned()),
                Some("private-key".to_owned()),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn passkey_count_limit_matches_bitwarden_account_passkey_cap() {
        assert!(!passkey_count_limit_reached(MAX_WEBAUTHN_CREDENTIALS - 1));
        assert!(passkey_count_limit_reached(MAX_WEBAUTHN_CREDENTIALS));
        assert!(passkey_count_limit_reached(MAX_WEBAUTHN_CREDENTIALS + 1));
    }

    #[test]
    fn registration_challenge_accepts_wrapped_state_with_matching_token() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp(),
            user_security_stamp: String::from("stamp"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("token"), "stamp").is_ok());
    }

    #[test]
    fn registration_challenge_rejects_wrapped_state_without_matching_token() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp(),
            user_security_stamp: String::from("stamp"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("wrong"), "stamp").is_err());
        assert!(passkey_registration_challenge_state(&data, None, "stamp").is_err());
    }

    #[test]
    fn registration_challenge_rejects_expired_state() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp() - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS - 1,
            user_security_stamp: String::from("stamp"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("token"), "stamp").is_err());
    }

    #[test]
    fn registration_challenge_rejects_stale_account_revision() {
        let saved = WebAuthnPasskeyRegistrationChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp(),
            user_security_stamp: String::from("old-stamp"),
            state: registration_state(),
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_registration_challenge_state(&data, Some("token"), "new-stamp").is_err());
    }

    /// `passkey_registration_challenge_state` has no legacy unwrapped fallback —
    /// the only writer is the attestation-options endpoint, and it always
    /// persists the `{token, state}` wrapper. A bare `PasskeyRegistration`
    /// blob in `twofactor.data` (corrupted row, hand-crafted attack) must
    /// be rejected regardless of whether a token is sent — accepting it
    /// without a token would let an attacker bypass the token-binding
    /// check by writing the wrong shape.
    #[test]
    fn registration_challenge_rejects_unwrapped_legacy_state() {
        let data = serde_json::to_string(&registration_state()).unwrap();

        assert!(passkey_registration_challenge_state(&data, None, "stamp").is_err());
        assert!(passkey_registration_challenge_state(&data, Some("any-token"), "stamp").is_err());
        assert!(passkey_registration_challenge_state(&data, Some(""), "stamp").is_err());
    }

    #[test]
    fn assertion_challenge_rejects_mismatched_token() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let saved = WebAuthnPasskeyAssertionChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp(),
            user_security_stamp: String::from("stamp"),
            state,
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_assertion_challenge_state(&data, "token", "stamp").is_ok());
        assert!(passkey_assertion_challenge_state(&data, "wrong", "stamp").is_err());
    }

    #[test]
    fn assertion_challenge_rejects_expired_state() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let saved = WebAuthnPasskeyAssertionChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp() - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS - 1,
            user_security_stamp: String::from("stamp"),
            state,
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_assertion_challenge_state(&data, "token", "stamp").is_err());
    }

    #[test]
    fn assertion_challenge_rejects_stale_account_revision() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let saved = WebAuthnPasskeyAssertionChallenge {
            token: String::from("token"),
            created_at: Utc::now().timestamp(),
            user_security_stamp: String::from("old-stamp"),
            state,
        };
        let data = serde_json::to_string(&saved).unwrap();

        assert!(passkey_assertion_challenge_state(&data, "token", "new-stamp").is_err());
    }

    #[test]
    fn passkey_credential_id_hash_uses_raw_credential_id_bytes() {
        assert_eq!(
            passkey_credential_id_hash(passkey().cred_id().as_slice()),
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
        );
    }

    #[test]
    fn passkey_credential_id_hash_is_deterministic() {
        let cred_id: &[u8] = &[10, 20, 30, 40, 50];
        assert_eq!(passkey_credential_id_hash(cred_id), passkey_credential_id_hash(cred_id));
    }

    #[test]
    fn passkey_credential_id_hash_distinguishes_different_credentials() {
        let a = passkey_credential_id_hash(&[1, 2, 3, 4]);
        let b = passkey_credential_id_hash(&[4, 3, 2, 1]);
        let c = passkey_credential_id_hash(&[1, 2, 3]);
        assert_ne!(a, b, "different bytes must produce different hashes");
        assert_ne!(a, c, "different lengths must produce different hashes");
        assert_ne!(b, c);
    }

    #[test]
    fn passkey_management_challenge_freshness_allows_current_window() {
        let now = Utc::now().timestamp();

        assert!(passkey_management_challenge_is_fresh(now));
        assert!(passkey_management_challenge_is_fresh(now - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS + 5));
        assert!(passkey_management_challenge_is_fresh(now + WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS - 5));
    }

    #[test]
    fn passkey_management_challenge_freshness_rejects_old_or_far_future_rows() {
        let now = Utc::now().timestamp();

        assert!(!passkey_management_challenge_is_fresh(now - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS - 1));
        assert!(!passkey_management_challenge_is_fresh(now + WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS + 1));
    }

    /// Exact-boundary coverage. The production wrapper reads `Utc::now()`
    /// inside the function, so a test against `now - TTL` would race the
    /// internal clock read and assert FALSE for the row that should be
    /// inclusive. `_is_fresh_at` takes `now` as a parameter so the inclusive
    /// `>=` / `<=` boundaries are exercised deterministically.
    #[test]
    fn passkey_management_challenge_freshness_inclusive_at_both_boundaries() {
        let now = Utc::now().timestamp();

        assert!(
            passkey_management_challenge_is_fresh_at(now - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS, now),
            "created_at exactly TTL old must remain fresh (`>=` is inclusive)"
        );
        assert!(
            passkey_management_challenge_is_fresh_at(now + WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS, now),
            "created_at exactly skew seconds ahead must remain fresh (`<=` is inclusive)"
        );
        assert!(
            !passkey_management_challenge_is_fresh_at(now - WEBAUTHN_PASSKEY_CHALLENGE_TTL_SECONDS - 1, now),
            "one second past TTL must reject"
        );
        assert!(
            !passkey_management_challenge_is_fresh_at(now + WEBAUTHN_PASSKEY_CHALLENGE_CLOCK_SKEW_SECONDS + 1, now),
            "one second past skew must reject"
        );
    }

    /// `passkey_assertion_challenge_state` has no legacy unwrapped fallback —
    /// the assertion-options endpoint was introduced together with the
    /// wrapping struct, so any persisted state must carry the binding token.
    #[test]
    fn assertion_challenge_rejects_unwrapped_legacy_state() {
        let (_response, state) = webauthn().start_passkey_authentication(&[passkey()]).unwrap();
        let bare = serde_json::to_string(&state).unwrap();

        assert!(passkey_assertion_challenge_state(&bare, "any-token", "stamp").is_err());
        assert!(passkey_assertion_challenge_state(&bare, "", "stamp").is_err());
    }
}
