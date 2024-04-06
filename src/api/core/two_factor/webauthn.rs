use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use webauthn_rs::prelude::*;

use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, PasswordOrOtpData,
    },
    auth::Headers,
    db::{
        models::{EventType, TwoFactor, TwoFactorType},
        DbConn,
    },
    error::Error,
    util::NumberOrString,
    CONFIG, WEBAUTHN,
};

pub fn routes() -> Vec<Route> {
    routes![get_webauthn, generate_webauthn_challenge, activate_webauthn, activate_webauthn_put, delete_webauthn,]
}

// Some old u2f structs still needed for migrating from u2f to WebAuthn
// Both `struct Registration` and `struct U2FRegistration` can be removed if we remove the u2f to WebAuthn migration
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_handle: CredentialID,
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

    pub credential: Credential,
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
async fn generate_webauthn_challenge(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let registrations: Vec<CredentialID> = get_webauthn_registrations(&user.uuid, &mut conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id.clone()) // We return the credentialIds to the clients to avoid double registering
        .collect();

    let user_uuid = Uuid::parse_str(&user.uuid)?;
    let (challenge, state) =
        WEBAUTHN.start_securitykey_registration(user_uuid, &user.email, &user.name, Some(registrations), None, None)?;

    let type_ = TwoFactorType::WebauthnRegisterChallenge;
    TwoFactor::new(user.uuid, type_, serde_json::to_string(&state)?).save(&mut conn).await?;

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
    device_response: RegisterPublicKeyCredential,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[post("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn(data: Json<EnableWebauthnData>, headers: Headers, mut conn: DbConn) -> JsonResult {
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
            let state: SecurityKeyRegistration = serde_json::from_str(&tf.data)?;
            tf.delete(&mut conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let credential = WEBAUTHN.finish_securitykey_registration(&data.device_response, &state)?;

    let mut registrations: Vec<_> = get_webauthn_registrations(&user.uuid, &mut conn).await?.1;
    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.id.into_i32()?,
        name: data.name,
        migrated: false,

        credential: credential.into(),
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
async fn delete_webauthn(data: Json<DeleteU2FData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let id = data.id.into_i32()?;
    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    let mut tf =
        match TwoFactor::find_by_user_and_type(&headers.user.uuid, TwoFactorType::Webauthn as i32, &mut conn).await {
            Some(tf) => tf,
            None => err!("Webauthn data not found!"),
        };

    let mut data: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data)?;

    let item_pos = match data.iter().position(|r| r.id == id) {
        Some(p) => p,
        None => err!("Webauthn entry not found"),
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

        data.retain(|r| r.reg.key_handle != removed_item.credential.cred_id);
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
    user_uuid: &str,
    conn: &mut DbConn,
) -> Result<(bool, Vec<WebauthnRegistration>), Error> {
    let type_ = TwoFactorType::Webauthn as i32;
    match TwoFactor::find_by_user_and_type(user_uuid, type_, conn).await {
        Some(tf) => Ok((tf.enabled, serde_json::from_str(&tf.data)?)),
        None => Ok((false, Vec::new())), // If no data, return empty list
    }
}

pub async fn generate_webauthn_login(user_uuid: &str, conn: &mut DbConn) -> JsonResult {
    // Load saved credentials
    let creds: Vec<SecurityKey> =
        get_webauthn_registrations(user_uuid, conn).await?.1.into_iter().map(|r| r.credential.into()).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let (response, state) = WEBAUTHN.start_securitykey_authentication(&creds)?; //, Some(ext))?;

    // Save the challenge state for later validation
    TwoFactor::new(user_uuid.into(), TwoFactorType::WebauthnLoginChallenge, serde_json::to_string(&state)?)
        .save(conn)
        .await?;

    // Return challenge to the clients
    Ok(Json(serde_json::to_value(response.public_key)?))
}

pub async fn validate_webauthn_login(user_uuid: &str, response: &str, conn: &mut DbConn) -> EmptyResult {
    let type_ = TwoFactorType::WebauthnLoginChallenge as i32;
    let state = match TwoFactor::find_by_user_and_type(user_uuid, type_, conn).await {
        Some(tf) => {
            let state: SecurityKeyAuthentication = serde_json::from_str(&tf.data)?;
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

    let rsp: PublicKeyCredential = serde_json::from_str(response)?;

    let mut registrations = get_webauthn_registrations(user_uuid, conn).await?.1;

    let auth_result = WEBAUTHN.finish_securitykey_authentication(&rsp, &state)?;

    for reg in &mut registrations {
        let mut security_key = SecurityKey::from(reg.credential.clone());
        if security_key.cred_id() == auth_result.cred_id() && security_key.update_credential(&auth_result).is_some() {
            TwoFactor::new(user_uuid.to_string(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
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
