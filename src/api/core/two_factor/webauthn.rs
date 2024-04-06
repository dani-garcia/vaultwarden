use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use webauthn_rs::prelude::*;

use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, JsonUpcase, PasswordOrOtpData,
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

#[post("/two-factor/get-webauthn", data = "<data>")]
async fn get_webauthn(data: JsonUpcase<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    if !CONFIG.domain_set() {
        err!("`DOMAIN` environment variable is not set. Webauthn disabled")
    }

    let data: PasswordOrOtpData = data.into_inner().data;
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let (enabled, registrations) = get_webauthn_registrations(&user.uuid, &mut conn).await?;
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "Enabled": enabled,
        "Keys": registrations_json,
        "Object": "twoFactorWebAuthn"
    })))
}

#[post("/two-factor/get-webauthn-challenge", data = "<data>")]
async fn generate_webauthn_challenge(
    data: JsonUpcase<PasswordOrOtpData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner().data;
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let registrations: Vec<Base64UrlSafeData> = get_webauthn_registrations(&user.uuid, &mut conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.security_key.cred_id().clone()) // We return the credentialIds to the clients to avoid double registering
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
#[allow(non_snake_case)]
struct EnableWebauthnData {
    Id: NumberOrString, // 1..5
    Name: String,
    DeviceResponse: RegisterPublicKeyCredential,
    MasterPasswordHash: Option<String>,
    Otp: Option<String>,
}

#[post("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn(data: JsonUpcase<EnableWebauthnData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: EnableWebauthnData = data.into_inner().data;
    let mut user = headers.user;

    PasswordOrOtpData {
        MasterPasswordHash: data.MasterPasswordHash,
        Otp: data.Otp,
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
    let security_key = WEBAUTHN.finish_securitykey_registration(&data.DeviceResponse, &state)?;

    let mut registrations: Vec<_> = get_webauthn_registrations(&user.uuid, &mut conn).await?.1;
    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.Id.into_i32()?,
        name: data.Name,
        migrated: false,

        security_key,
    });

    // Save the registrations and return them
    TwoFactor::new(user.uuid.clone(), TwoFactorType::Webauthn, serde_json::to_string(&registrations)?)
        .save(&mut conn)
        .await?;
    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    let keys_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();
    Ok(Json(json!({
        "Enabled": true,
        "Keys": keys_json,
        "Object": "twoFactorU2f"
    })))
}

#[put("/two-factor/webauthn", data = "<data>")]
async fn activate_webauthn_put(data: JsonUpcase<EnableWebauthnData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_webauthn(data, headers, conn).await
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct DeleteU2FData {
    Id: NumberOrString,
    MasterPasswordHash: String,
}

#[delete("/two-factor/webauthn", data = "<data>")]
async fn delete_webauthn(data: JsonUpcase<DeleteU2FData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let id = data.data.Id.into_i32()?;
    if !headers.user.check_valid_password(&data.data.MasterPasswordHash) {
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

    let _removed_item = data.remove(item_pos);
    tf.data = serde_json::to_string(&data)?;
    tf.save(&mut conn).await?;
    drop(tf);

    let keys_json: Vec<Value> = data.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "Enabled": true,
        "Keys": keys_json,
        "Object": "twoFactorU2f"
    })))
}

#[derive(Debug, Serialize, Deserialize)]
struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    pub migrated: bool,

    pub security_key: SecurityKey,
}

impl WebauthnRegistration {
    fn to_json(&self) -> Value {
        json!({
            "Id": self.id,
            "Name": self.name,
            "migrated": self.migrated,
        })
    }
}

async fn get_webauthn_registrations(
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
        get_webauthn_registrations(user_uuid, conn).await?.1.into_iter().map(|r| r.security_key).collect();

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
        if reg.security_key.cred_id() == auth_result.cred_id()
            && reg.security_key.update_credential(&auth_result).is_some()
        {
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
