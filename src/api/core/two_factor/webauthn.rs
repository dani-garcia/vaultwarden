use std::str::FromStr;
use std::sync::Arc;
use once_cell::sync::Lazy;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs::prelude::{Base64UrlSafeData, Passkey, PasskeyAuthentication, PasskeyRegistration};
use webauthn_rs_proto::{AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, UserVerificationPolicy};
use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, PasswordOrOtpData,
    },
    auth::Headers,
    db::{
        models::{EventType, TwoFactor, TwoFactorType, UserId},
        DbConn,
    },
    error::Error,
    util::NumberOrString,
    CONFIG,
};

pub static WEBAUTHN_2FA_CONFIG: Lazy<Arc<Webauthn>> = Lazy::new(|| {
    let domain = CONFIG.domain();
    let domain_origin = CONFIG.domain_origin();
    let rp_id = Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default();
    let rp_origin = Url::parse(&domain_origin).unwrap();

    let webauthn = WebauthnBuilder::new(
        &rp_id,
        &rp_origin,
    ).expect("Creating WebauthnBuilder failed")
        .rp_name(&domain);

    // TODO check what happened to get_require_uv_consistency()

    // TODO check if there is a better way to handle these errors (would they instantly through or only when used?)
    Arc::new(webauthn.build().expect("Building Webauthn failed"))
});

pub type Webauthn2FaConfig<'a> = &'a rocket::State<Arc<Webauthn>>;

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

    // TODO should this be renamed or just stay this way
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
}

#[post("/two-factor/get-webauthn", data = "<data>")]
async fn get_webauthn(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    if !CONFIG.domain_set() {
        err!("`DOMAIN` environment variable is not set. Webauthn disabled")
    }

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let (enabled, registrations) = get_webauthn_registrations(&user.uuid, &mut conn).await?;
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": enabled,
        "keys": registrations_json,
        "object": "twoFactorWebAuthn"
    })))
}

#[post("/two-factor/get-webauthn-challenge", data = "<data>")]
async fn generate_webauthn_challenge(data: Json<PasswordOrOtpData>, headers: Headers, webauthn: Webauthn2FaConfig<'_>, mut conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let registrations = get_webauthn_registrations(&user.uuid, &mut conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id().to_owned()) // We return the credentialIds to the clients to avoid double registering
        .collect();

    // TODO handle errors
    let (mut challenge, state) = webauthn.start_passkey_registration(
        Uuid::from_str(&*user.uuid).unwrap(),
        &user.email,
        &user.name,
        Some(registrations),
    )?;

    // this is done since `start_passkey_registration()` always sets this to `Required` which shouldn't be needed for 2FA
    challenge.public_key.extensions = None;
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    }

    let mut state = serde_json::to_value(&state)?;
    state["rs"]["policy"] = Value::String("discouraged".to_string());
    state["rs"]["extensions"].as_object_mut().unwrap().clear();

    let type_ = TwoFactorType::WebauthnRegisterChallenge;
    TwoFactor::new(user.uuid.clone(), type_, serde_json::to_string(&state)?).save(&mut conn).await?;

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
async fn activate_webauthn(data: Json<EnableWebauthnData>, headers: Headers, webauthn: Webauthn2FaConfig<'_>, mut conn: DbConn) -> JsonResult {
    let data: EnableWebauthnData = data.into_inner();
    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &mut conn)
    .await?;

    // Retrieve and delete the saved challenge state
    let type_ = TwoFactorType::WebauthnRegisterChallenge as i32;
    let state = match TwoFactor::find_by_user_and_type(&user.uuid, type_, &mut conn).await {
        Some(tf) => {
            let state: PasskeyRegistration = serde_json::from_str(&tf.data)?;
            tf.delete(&mut conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let credential = webauthn
        .finish_passkey_registration(&data.device_response.into(), &state)?;

    let mut registrations: Vec<_> = get_webauthn_registrations(&user.uuid, &mut conn).await?.1;
    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.id.into_i32()?,
        name: data.name,
        migrated: false,

        credential,
    });

    // Save the registrations and return them
    TwoFactor::new(user.uuid.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
        .save(&mut conn)
        .await?;
    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    let keys_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();
    Ok(Json(json!({
        "enabled": true,
        "keys": keys_json,
        "object": "twoFactorU2f"
    })))
}

#[put("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn_put(data: Json<EnableWebauthnData>, headers: Headers, webauthn: Webauthn2FaConfig<'_>, conn: DbConn) -> JsonResult {
    activate_webauthn(data, headers, webauthn, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteU2FData {
    id: NumberOrString,
    master_password_hash: String,
}

#[delete("/two-factor/webauthn", data = "<data>")]
async fn delete_webauthn(data: Json<DeleteU2FData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let id = data.id.into_i32()?;
    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    let Some(mut tf) =
        TwoFactor::find_by_user_and_type(&headers.user.uuid, TwoFactorType::Webauthn as i32, &mut conn).await
    else {
        err!("Webauthn data not found!")
    };

    let mut data: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data)?;

    let Some(item_pos) = data.iter().position(|r| r.id == id) else {
        err!("Webauthn entry not found")
    };

    let removed_item = data.remove(item_pos);
    tf.data = serde_json::to_string(&data)?;
    tf.save(&mut conn).await?;
    drop(tf);

    // If entry is migrated from u2f, delete the u2f entry as well
    if let Some(mut u2f) =
        TwoFactor::find_by_user_and_type(&headers.user.uuid, TwoFactorType::U2f as i32, &mut conn).await
    {
        let mut data: Vec<U2FRegistration> = match serde_json::from_str(&u2f.data) {
            Ok(d) => d,
            Err(_) => err!("Error parsing U2F data"),
        };

        data.retain(|r| r.reg.key_handle != removed_item.credential.cred_id().as_slice());
        let new_data_str = serde_json::to_string(&data)?;

        u2f.data = new_data_str;
        u2f.save(&mut conn).await?;
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
    conn: &mut DbConn,
) -> Result<(bool, Vec<WebauthnRegistration>), Error> {
    let type_ = TwoFactorType::Webauthn as i32;
    match TwoFactor::find_by_user_and_type(user_id, type_, conn).await {
        Some(tf) => Ok((tf.enabled, serde_json::from_str(&tf.data)?)),
        None => Ok((false, Vec::new())), // If no data, return empty list
    }
}

pub async fn generate_webauthn_login(user_id: &UserId, webauthn: Webauthn2FaConfig<'_>, conn: &mut DbConn) -> JsonResult {
    // Load saved credentials
    let creds: Vec<_> =
        get_webauthn_registrations(user_id, conn).await?.1.into_iter().map(|r| r.credential).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let (mut response, state) = webauthn.start_passkey_authentication(&creds)?;

    // Modify to discourage user verification
    let mut state = serde_json::to_value(&state)?;
    state["ast"]["policy"] = Value::String("discouraged".to_string());
    state["ast"]["appid"] = Value::String(format!("{}/app-id.json", &CONFIG.domain()));
    response.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;

    // Save the challenge state for later validation
    TwoFactor::new(user_id.clone(), TwoFactorType::WebauthnLoginChallenge, serde_json::to_string(&state)?)
        .save(conn)
        .await?;

    // Return challenge to the clients
    Ok(Json(serde_json::to_value(response.public_key)?))
}

pub async fn validate_webauthn_login(user_id: &UserId, response: &str, webauthn: Webauthn2FaConfig<'_>, conn: &mut DbConn) -> EmptyResult {
    let type_ = TwoFactorType::WebauthnLoginChallenge as i32;
    let state = match TwoFactor::find_by_user_and_type(user_id, type_, conn).await {
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

    let authentication_result = webauthn.finish_passkey_authentication(&rsp, &state)?;

    for reg in &mut registrations {
        if reg.credential.cred_id() == authentication_result.cred_id() && authentication_result.needs_update() {
            reg.credential.update_credential(&authentication_result);

            TwoFactor::new(user_id.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
                .save(conn)
                .await?;
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
