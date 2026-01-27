use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, PasswordOrOtpData,
    },
    auth::Headers,
    crypto::ct_eq,
    db::{
        models::{EventType, TwoFactor, TwoFactorType, UserId},
        DbConn,
    },
    error::Error,
    util::NumberOrString,
    CONFIG,
};
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{Base64UrlSafeData, Credential, Passkey, PasskeyAuthentication, PasskeyRegistration};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
    PublicKeyCredential, RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs,
    RequestAuthenticationExtensions, UserVerificationPolicy,
};

static WEBAUTHN: LazyLock<Webauthn> = LazyLock::new(|| {
    let domain = CONFIG.domain();
    let domain_origin = CONFIG.domain_origin();
    let rp_id = Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default();
    let rp_origin = Url::parse(&domain_origin).unwrap();

    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("Creating WebauthnBuilder failed")
        .rp_name(&domain)
        .timeout(Duration::from_millis(60000));

    webauthn.build().expect("Building Webauthn failed")
});

pub fn routes() -> Vec<Route> {
    routes![get_webauthn, generate_webauthn_challenge, activate_webauthn, activate_webauthn_put, delete_webauthn,]
}

// Some old u2f structs still needed for migrating from u2f to WebAuthn
// Both `struct Registration` and `struct U2FRegistration` can be removed if we remove the u2f to WebAuthn migration
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_handle: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub attestation_cert: Option<Vec<u8>>,
    pub device_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct U2FRegistration {
    pub id: i32,
    pub name: String,
    #[serde(with = "Registration")]
    pub reg: Registration,
    pub counter: u32,
    compromised: bool,
    pub migrated: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    pub migrated: bool,

    pub credential: Passkey,
}

impl WebauthnRegistration {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "migrated": self.migrated,
        })
    }

    fn set_backup_eligible(&mut self, backup_eligible: bool, backup_state: bool) -> bool {
        let mut changed = false;
        let mut cred: Credential = self.credential.clone().into();

        if cred.backup_state != backup_state {
            cred.backup_state = backup_state;
            changed = true;
        }

        if backup_eligible && !cred.backup_eligible {
            cred.backup_eligible = true;
            changed = true;
        }

        self.credential = cred.into();
        changed
    }
}

#[post("/two-factor/get-webauthn", data = "<data>")]
async fn get_webauthn(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.domain_set() {
        err!("`DOMAIN` environment variable is not set. Webauthn disabled")
    }

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let (enabled, registrations) = get_webauthn_registrations(&user.uuid, &conn).await?;
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": enabled,
        "keys": registrations_json,
        "object": "twoFactorWebAuthn"
    })))
}

#[post("/two-factor/get-webauthn-challenge", data = "<data>")]
async fn generate_webauthn_challenge(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let registrations = get_webauthn_registrations(&user.uuid, &conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id().to_owned()) // We return the credentialIds to the clients to avoid double registering
        .collect();

    let (mut challenge, state) = WEBAUTHN.start_passkey_registration(
        Uuid::from_str(&user.uuid).expect("Failed to parse UUID"), // Should never fail
        &user.email,
        user.display_name(),
        Some(registrations),
    )?;

    let mut state = serde_json::to_value(&state)?;
    state["rs"]["policy"] = Value::String("discouraged".to_string());
    state["rs"]["extensions"].as_object_mut().unwrap().clear();

    let type_ = TwoFactorType::WebauthnRegisterChallenge;
    TwoFactor::new(user.uuid.clone(), type_, serde_json::to_string(&state)?).save(&conn).await?;

    // Because for this flow we abuse the passkeys as 2FA, and use it more like a securitykey
    // we need to modify some of the default settings defined by `start_passkey_registration()`.
    challenge.public_key.extensions = None;
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    }

    let mut challenge_value = serde_json::to_value(challenge.public_key)?;
    challenge_value["status"] = "ok".into();
    challenge_value["errorMessage"] = "".into();
    Ok(Json(challenge_value))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableWebauthnData {
    id: NumberOrString, // 1..5
    name: String,
    device_response: RegisterPublicKeyCredentialCopy,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAttestationResponseRawCopy,
    pub r#type: String,
}

// This is copied from AuthenticatorAttestationResponseRaw to change clientDataJSON to clientDataJson
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponseRawCopy {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
}

impl From<RegisterPublicKeyCredentialCopy> for RegisterPublicKeyCredential {
    fn from(r: RegisterPublicKeyCredentialCopy) -> Self {
        Self {
            id: r.id,
            raw_id: r.raw_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: r.response.attestation_object,
                client_data_json: r.response.client_data_json,
                transports: None,
            },
            type_: r.r#type,
            extensions: RegistrationExtensionsClientOutputs::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAssertionResponseRawCopy,
    pub extensions: AuthenticationExtensionsClientOutputs,
    pub r#type: String,
}

// This is copied from AuthenticatorAssertionResponseRaw to change clientDataJSON to clientDataJson
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponseRawCopy {
    pub authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
    pub signature: Base64UrlSafeData,
    pub user_handle: Option<Base64UrlSafeData>,
}

impl From<PublicKeyCredentialCopy> for PublicKeyCredential {
    fn from(r: PublicKeyCredentialCopy) -> Self {
        Self {
            id: r.id,
            raw_id: r.raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: r.response.authenticator_data,
                client_data_json: r.response.client_data_json,
                signature: r.response.signature,
                user_handle: r.response.user_handle,
            },
            extensions: r.extensions,
            type_: r.r#type,
        }
    }
}

#[post("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn(data: Json<EnableWebauthnData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableWebauthnData = data.into_inner();
    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &conn)
    .await?;

    // Retrieve and delete the saved challenge state
    let type_ = TwoFactorType::WebauthnRegisterChallenge as i32;
    let state = match TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await {
        Some(tf) => {
            let state: PasskeyRegistration = serde_json::from_str(&tf.data)?;
            tf.delete(&conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let credential = WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state)?;

    let mut registrations: Vec<_> = get_webauthn_registrations(&user.uuid, &conn).await?.1;
    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.id.into_i32()?,
        name: data.name,
        migrated: false,

        credential,
    });

    // Save the registrations and return them
    TwoFactor::new(user.uuid.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
        .save(&conn)
        .await?;
    _generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    let keys_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();
    Ok(Json(json!({
        "enabled": true,
        "keys": keys_json,
        "object": "twoFactorU2f"
    })))
}

#[put("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn_put(data: Json<EnableWebauthnData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_webauthn(data, headers, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteU2FData {
    id: NumberOrString,
    master_password_hash: String,
}

#[delete("/two-factor/webauthn", data = "<data>")]
async fn delete_webauthn(data: Json<DeleteU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    let id = data.id.into_i32()?;
    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    let Some(mut tf) =
        TwoFactor::find_by_user_and_type(&headers.user.uuid, TwoFactorType::Webauthn as i32, &conn).await
    else {
        err!("Webauthn data not found!")
    };

    let mut data: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data)?;

    let Some(item_pos) = data.iter().position(|r| r.id == id) else {
        err!("Webauthn entry not found")
    };

    let removed_item = data.remove(item_pos);
    tf.data = serde_json::to_string(&data)?;
    tf.save(&conn).await?;
    drop(tf);

    // If entry is migrated from u2f, delete the u2f entry as well
    if let Some(mut u2f) = TwoFactor::find_by_user_and_type(&headers.user.uuid, TwoFactorType::U2f as i32, &conn).await
    {
        let mut data: Vec<U2FRegistration> = match serde_json::from_str(&u2f.data) {
            Ok(d) => d,
            Err(_) => err!("Error parsing U2F data"),
        };

        data.retain(|r| r.reg.key_handle != removed_item.credential.cred_id().as_slice());
        let new_data_str = serde_json::to_string(&data)?;

        u2f.data = new_data_str;
        u2f.save(&conn).await?;
    }

    let keys_json: Vec<Value> = data.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": true,
        "keys": keys_json,
        "object": "twoFactorU2f"
    })))
}

pub async fn get_webauthn_registrations(
    user_id: &UserId,
    conn: &DbConn,
) -> Result<(bool, Vec<WebauthnRegistration>), Error> {
    let type_ = TwoFactorType::Webauthn as i32;
    match TwoFactor::find_by_user_and_type(user_id, type_, conn).await {
        Some(tf) => Ok((tf.enabled, serde_json::from_str(&tf.data)?)),
        None => Ok((false, Vec::new())), // If no data, return empty list
    }
}

pub async fn generate_webauthn_login(user_id: &UserId, conn: &DbConn) -> JsonResult {
    // Load saved credentials
    let creds: Vec<Passkey> =
        get_webauthn_registrations(user_id, conn).await?.1.into_iter().map(|r| r.credential).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let (mut response, state) = WEBAUTHN.start_passkey_authentication(&creds)?;

    // Modify to discourage user verification
    let mut state = serde_json::to_value(&state)?;
    state["ast"]["policy"] = Value::String("discouraged".to_string());

    // Add appid, this is only needed for U2F compatibility, so maybe it can be removed as well
    let app_id = format!("{}/app-id.json", &CONFIG.domain());
    state["ast"]["appid"] = Value::String(app_id.clone());

    response.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    response
        .public_key
        .extensions
        .get_or_insert(RequestAuthenticationExtensions {
            appid: None,
            uvm: None,
            hmac_get_secret: None,
        })
        .appid = Some(app_id);

    // Save the challenge state for later validation
    TwoFactor::new(user_id.clone(), TwoFactorType::WebauthnLoginChallenge, serde_json::to_string(&state)?)
        .save(conn)
        .await?;

    // Return challenge to the clients
    Ok(Json(serde_json::to_value(response.public_key)?))
}

pub async fn validate_webauthn_login(user_id: &UserId, response: &str, conn: &DbConn) -> EmptyResult {
    let type_ = TwoFactorType::WebauthnLoginChallenge as i32;
    let mut state = match TwoFactor::find_by_user_and_type(user_id, type_, conn).await {
        Some(tf) => {
            let state: PasskeyAuthentication = serde_json::from_str(&tf.data)?;
            tf.delete(conn).await?;
            state
        }
        None => err!(
            "Can't recover login challenge",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
    };

    let rsp: PublicKeyCredentialCopy = serde_json::from_str(response)?;
    let rsp: PublicKeyCredential = rsp.into();

    let mut registrations = get_webauthn_registrations(user_id, conn).await?.1;

    // We need to check for and update the backup_eligible flag when needed.
    // Vaultwarden did not have knowledge of this flag prior to migrating to webauthn-rs v0.5.x
    // Because of this we check the flag at runtime and update the registrations and state when needed
    check_and_update_backup_eligible(user_id, &rsp, &mut registrations, &mut state, conn).await?;

    let authentication_result = WEBAUTHN.finish_passkey_authentication(&rsp, &state)?;

    for reg in &mut registrations {
        if ct_eq(reg.credential.cred_id(), authentication_result.cred_id()) {
            // If the cred id matches and the credential is updated, Some(true) is returned
            // In those cases, update the record, else leave it alone
            if reg.credential.update_credential(&authentication_result) == Some(true) {
                TwoFactor::new(user_id.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
                    .save(conn)
                    .await?;
            }
            return Ok(());
        }
    }

    err!(
        "Credential not present",
        ErrorEvent {
            event: EventType::UserFailedLogIn2fa
        }
    )
}

async fn check_and_update_backup_eligible(
    user_id: &UserId,
    rsp: &PublicKeyCredential,
    registrations: &mut Vec<WebauthnRegistration>,
    state: &mut PasskeyAuthentication,
    conn: &DbConn,
) -> EmptyResult {
    // The feature flags from the response
    // For details see: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
    const FLAG_BACKUP_ELIGIBLE: u8 = 0b0000_1000;
    const FLAG_BACKUP_STATE: u8 = 0b0001_0000;

    if let Some(bits) = rsp.response.authenticator_data.get(32) {
        let backup_eligible = 0 != (bits & FLAG_BACKUP_ELIGIBLE);
        let backup_state = 0 != (bits & FLAG_BACKUP_STATE);

        // If the current key is backup eligible, then we probably need to update one of the keys already stored in the database
        // This is needed because Vaultwarden didn't store this information when using the previous version of webauthn-rs since it was a new addition to the protocol
        // Because we store multiple keys in one json string, we need to fetch the correct key first, and update its information before we let it verify
        if backup_eligible {
            let rsp_id = rsp.raw_id.as_slice();
            for reg in &mut *registrations {
                if ct_eq(reg.credential.cred_id().as_slice(), rsp_id) {
                    // Try to update the key, and if needed also update the database, before the actual state check is done
                    if reg.set_backup_eligible(backup_eligible, backup_state) {
                        TwoFactor::new(
                            user_id.clone(),
                            TwoFactorType::Webauthn,
                            serde_json::to_string(&registrations)?,
                        )
                        .save(conn)
                        .await?;

                        // We also need to adjust the current state which holds the challenge used to start the authentication verification
                        // Because Vaultwarden supports multiple keys, we need to loop through the deserialized state and check which key to update
                        let mut raw_state = serde_json::to_value(&state)?;
                        if let Some(credentials) = raw_state
                            .get_mut("ast")
                            .and_then(|v| v.get_mut("credentials"))
                            .and_then(|v| v.as_array_mut())
                        {
                            for cred in credentials.iter_mut() {
                                if cred.get("cred_id").is_some_and(|v| {
                                    // Deserialize to a [u8] so it can be compared using `ct_eq` with the `rsp_id`
                                    let cred_id_slice: Base64UrlSafeData = serde_json::from_value(v.clone()).unwrap();
                                    ct_eq(cred_id_slice, rsp_id)
                                }) {
                                    cred["backup_eligible"] = Value::Bool(backup_eligible);
                                    cred["backup_state"] = Value::Bool(backup_state);
                                }
                            }
                        }

                        *state = serde_json::from_value(raw_state)?;
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}
