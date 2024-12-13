use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use url::Url;
use webauthn_rs::{base64_data::Base64UrlSafeData, proto::*, AuthenticationState, RegistrationState, Webauthn};

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
    CONFIG,
};

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

struct WebauthnConfig {
    url: String,
    origin: Url,
    rpid: String,
}

impl WebauthnConfig {
    fn load() -> Webauthn<Self> {
        let domain = CONFIG.domain();
        let domain_origin = CONFIG.domain_origin();
        Webauthn::new(Self {
            rpid: Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default(),
            url: domain,
            origin: Url::parse(&domain_origin).unwrap(),
        })
    }
}

impl webauthn_rs::WebauthnConfig for WebauthnConfig {
    fn get_relying_party_name(&self) -> &str {
        &self.url
    }

    fn get_origin(&self) -> &Url {
        &self.origin
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rpid
    }

    /// We have WebAuthn configured to discourage user verification
    /// if we leave this enabled, it will cause verification issues when a keys send UV=1.
    /// Upstream (the library they use) ignores this when set to discouraged, so we should too.
    fn get_require_uv_consistency(&self) -> bool {
        false
    }
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

    let registrations = get_webauthn_registrations(&user.uuid, &mut conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id) // We return the credentialIds to the clients to avoid double registering
        .collect();

    let (challenge, state) = WebauthnConfig::load().generate_challenge_register_options(
        user.uuid.as_bytes().to_vec(),
        user.email,
        user.name,
        Some(registrations),
        None,
        None,
    )?;

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
            },
            type_: r.r#type,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAssertionResponseRawCopy,
    pub extensions: Option<AuthenticationExtensionsClientOutputs>,
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
            let state: RegistrationState = serde_json::from_str(&tf.data)?;
            tf.delete(&mut conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let (credential, _data) =
        WebauthnConfig::load().register_credential(&data.device_response.into(), &state, |_| Ok(false))?;

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
    let creds: Vec<Credential> =
        get_webauthn_registrations(user_uuid, conn).await?.1.into_iter().map(|r| r.credential).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let ext = RequestAuthenticationExtensions::builder().appid(format!("{}/app-id.json", &CONFIG.domain())).build();
    let (response, state) = WebauthnConfig::load().generate_challenge_authenticate_options(creds, Some(ext))?;

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
            let state: AuthenticationState = serde_json::from_str(&tf.data)?;
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

    let mut registrations = get_webauthn_registrations(user_uuid, conn).await?.1;

    // If the credential we received is migrated from U2F, enable the U2F compatibility
    //let use_u2f = registrations.iter().any(|r| r.migrated && r.credential.cred_id == rsp.raw_id.0);
    let (cred_id, auth_data) = WebauthnConfig::load().authenticate_credential(&rsp, &state)?;

    for reg in &mut registrations {
        if &reg.credential.cred_id == cred_id {
            reg.credential.counter = auth_data.counter;

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
