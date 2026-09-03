use std::{collections::HashSet, str::FromStr, sync::LazyLock, time::Duration};

use rocket::{Route, serde::json::Json};
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Base64UrlSafeData, Credential, Passkey, PasskeyAuthentication, PasskeyRegistration},
};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw,
    PublicKeyCredential, RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs,
    RequestAuthenticationExtensions, UserVerificationPolicy,
};

use crate::{
    CONFIG,
    api::{
        EmptyResult, JsonResult, PasswordOrOtpData,
        core::{
            log_user_event,
            two_factor::{VerificationTokenData, generate_recover_code},
        },
    },
    auth::{Headers, two_factor},
    crypto::ct_eq,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType, UserId},
    },
    error::Error,
};

static WEBAUTHN: LazyLock<Webauthn> = LazyLock::new(|| {
    let domain = CONFIG.domain();
    let domain_origin = CONFIG.domain_origin();
    let rp_id = Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default();
    let rp_origin = Url::parse(&domain_origin).unwrap();

    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("Creating WebauthnBuilder failed")
        .rp_name(&domain)
        .timeout(Duration::from_mins(1));

    webauthn.build().expect("Building Webauthn failed")
});

pub fn routes() -> Vec<Route> {
    routes![
        get_webauthn,
        generate_webauthn_challenge,
        activate_webauthn,
        activate_webauthn_put,
        delete_webauthn,
        delete_webauthns
    ]
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
    if !CONFIG.is_webauthn_2fa_supported() {
        err!("Configured `DOMAIN` is not compatible with Webauthn")
    }

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let (enabled, registrations) = get_webauthn_registrations(&user.uuid, &conn).await?;
    let keys: Vec<i32> = registrations.iter().map(|r| r.id).collect();
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "webAuthn": json!({
            "enabled": enabled,
            "keys": registrations_json,
        }),
        "userVerificationToken": two_factor::webauthn_token(user.uuid, keys, enabled),
    })))
}

#[post("/two-factor/get-webauthn-challenge", data = "<data>")]
async fn generate_webauthn_challenge(data: Json<VerificationTokenData>, headers: Headers, conn: DbConn) -> JsonResult {
    let user = headers.user;

    let (enabled, registrations) = get_webauthn_registrations(&user.uuid, &conn).await?;
    let keys: Vec<i32> = registrations.iter().map(|r| r.id).collect();
    let creds = registrations
        .into_iter()
        .map(|r| r.credential.cred_id().to_owned()) // We return the credentialIds to the clients to avoid double registering
        .collect();

    two_factor::validate_webauthn(&data.user_verification_token, &user.uuid, &keys, enabled)?;

    let (mut challenge, state) = WEBAUTHN.start_passkey_registration(
        Uuid::from_str(&user.uuid).expect("Failed to parse UUID"), // Should never fail
        &user.email,
        user.display_name(),
        Some(creds),
    )?;

    let mut state = serde_json::to_value(&state)?;
    state["rs"]["policy"] = Value::String("discouraged".to_owned());
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

    Ok(Json(json!({
        "options": challenge_value
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableWebauthnData {
    id: i32,
    name: String,
    device_response: RegisterPublicKeyCredentialCopy,
    user_verification_token: String,
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

    let mut registrations: Vec<_> = get_webauthn_registrations(&user.uuid, &conn).await?.1;
    let keys: Vec<i32> = registrations.iter().map(|r| r.id).collect();
    two_factor::validate_webauthn(&data.user_verification_token, &user.uuid, &keys, !keys.is_empty())?;

    // Retrieve and delete the saved challenge state
    let state = if let Some(tf) =
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::WebauthnRegisterChallenge, &conn).await
    {
        let state: PasskeyRegistration = serde_json::from_str(&tf.data)?;
        tf.delete(&conn).await?;
        state
    } else {
        err!("Can't recover challenge")
    };

    // Verify the credentials with the saved state
    let credential = WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state)?;

    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.id,
        name: data.name,
        migrated: false,

        credential,
    });

    // Save the registrations and return them
    TwoFactor::new(user.uuid.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
        .save(&conn)
        .await?;
    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    let keys_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "webAuthn": json!({
            "enabled": true,
            "keys": keys_json,
        }),
    })))
}

#[put("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn_put(data: Json<EnableWebauthnData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_webauthn(data, headers, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteWebauthnData {
    id: i32,
    user_verification_token: String,
}

#[delete("/two-factor/webauthn", data = "<data>")]
async fn delete_webauthn(data: Json<DeleteWebauthnData>, headers: Headers, conn: DbConn) -> EmptyResult {
    inner_delete_webauthns(&data.user_verification_token, |key| key.id != data.id, headers, &conn).await
}

#[delete("/two-factor/webauthn/all", data = "<data>")]
async fn delete_webauthns(data: Json<VerificationTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    inner_delete_webauthns(&data.user_verification_token, |_| false, headers, &conn).await
}

async fn inner_delete_webauthns(
    token: &str,
    retain: impl Fn(&WebauthnRegistration) -> bool,
    headers: Headers,
    conn: &DbConn,
) -> EmptyResult {
    let user = headers.user;

    let Some(mut tf) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Webauthn, conn).await else {
        err!("Webauthn data not found!")
    };

    let mut keys: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data)?;
    let keys_id: Vec<i32> = keys.iter().map(|r| r.id).collect();

    two_factor::validate_webauthn(token, &user.uuid, &keys_id, true)?;

    let mut removed: HashSet<Vec<u8>> = HashSet::new();
    let mut migrated = false;

    keys.retain(|key| {
        let retained = retain(key);
        if !retained {
            removed.insert(key.credential.cred_id().to_vec());
            migrated = migrated || key.migrated;
        }
        retained
    });

    if removed.is_empty() {
        err!("Webauthn entry not found")
    }

    if keys.is_empty() {
        tf.delete(conn).await?;
        log_user_event(EventType::UserDisabled2fa, &user.uuid, headers.device.atype, &headers.ip.ip, conn).await;
    } else {
        tf.data = serde_json::to_string(&keys)?;
        tf.save(conn).await?;
        drop(tf);
    }

    // If entry is migrated from u2f, delete the u2f entry as well
    if migrated && let Some(mut u2f) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::U2f, conn).await {
        let Ok(mut data) = serde_json::from_str::<Vec<U2FRegistration>>(&u2f.data) else {
            err!("Error parsing U2F data")
        };

        data.retain(|old| !removed.contains(&old.reg.key_handle));

        if data.is_empty() {
            u2f.delete(conn).await?;
        } else {
            let new_data_str = serde_json::to_string(&data)?;
            u2f.data = new_data_str;
            u2f.save(conn).await?;
        }
    }

    if keys.is_empty() && TwoFactor::find_by_user(&user.uuid, conn).await.is_empty() {
        super::enforce_2fa_policy(&user, &user.uuid, headers.device.atype, &headers.ip.ip, conn).await?;
    }

    Ok(())
}

pub async fn get_webauthn_registrations(
    user_id: &UserId,
    conn: &DbConn,
) -> Result<(bool, Vec<WebauthnRegistration>), Error> {
    match TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Webauthn, conn).await {
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
    state["ast"]["policy"] = Value::String("discouraged".to_owned());

    // Add appid, this is only needed for U2F compatibility, so maybe it can be removed as well
    let app_id = format!("{}/app-id.json", CONFIG.domain());
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
    let mut state = if let Some(tf) =
        TwoFactor::find_by_user_and_type(user_id, TwoFactorType::WebauthnLoginChallenge, conn).await
    {
        let state: PasskeyAuthentication = serde_json::from_str(&tf.data)?;
        tf.delete(conn).await?;
        state
    } else {
        err!(
            "Can't recover login challenge",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };

    let rsp: PublicKeyCredentialCopy = serde_json::from_str(response)?;
    let rsp: PublicKeyCredential = rsp.into();

    let mut registrations = get_webauthn_registrations(user_id, conn).await?.1;

    // We need to check for and update the backup_eligible flag when needed.
    // Vaultwarden did not have knowledge of this flag prior to migrating to webauthn-rs v0.5.x
    // Because of this we check the flag at runtime and update the registrations and state when needed
    let backup_flags_updated = check_and_update_backup_eligible(&rsp, &mut registrations, &mut state)?;

    let authentication_result = WEBAUTHN.finish_passkey_authentication(&rsp, &state)?;

    for reg in &mut registrations {
        if ct_eq(reg.credential.cred_id(), authentication_result.cred_id()) {
            // If the cred id matches and the credential is updated, Some(true) is returned
            // In those cases, update the record, else leave it alone
            let credential_updated = reg.credential.update_credential(&authentication_result) == Some(true);
            if credential_updated || backup_flags_updated {
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

fn check_and_update_backup_eligible(
    rsp: &PublicKeyCredential,
    registrations: &mut Vec<WebauthnRegistration>,
    state: &mut PasskeyAuthentication,
) -> Result<bool, Error> {
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
                    if reg.set_backup_eligible(backup_eligible, backup_state) {
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
                        return Ok(true);
                    }
                    break;
                }
            }
        }
    }
    Ok(false)
}
