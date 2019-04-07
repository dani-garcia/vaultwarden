use data_encoding::{BASE32, BASE64};
use rocket_contrib::json::Json;
use serde_json;
use serde_json::Value;

use crate::api::{ApiResult, EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData};
use crate::auth::Headers;
use crate::crypto;
use crate::db::{
    models::{TwoFactor, TwoFactorType, User},
    DbConn,
};
use crate::error::{Error, MapResult};

use rocket::Route;

pub fn routes() -> Vec<Route> {
    routes![
        get_twofactor,
        get_recover,
        recover,
        disable_twofactor,
        disable_twofactor_put,
        generate_authenticator,
        activate_authenticator,
        activate_authenticator_put,
        generate_u2f,
        generate_u2f_challenge,
        activate_u2f,
        activate_u2f_put,
        generate_yubikey,
        activate_yubikey,
        activate_yubikey_put,
        get_duo,
        activate_duo,
        activate_duo_put,
    ]
}

#[get("/two-factor")]
fn get_twofactor(headers: Headers, conn: DbConn) -> JsonResult {
    let twofactors = TwoFactor::find_by_user(&headers.user.uuid, &conn);
    let twofactors_json: Vec<Value> = twofactors.iter().map(TwoFactor::to_json_list).collect();

    Ok(Json(json!({
        "Data": twofactors_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[post("/two-factor/get-recover", data = "<data>")]
fn get_recover(data: JsonUpcase<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": user.totp_recover,
        "Object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RecoverTwoFactor {
    MasterPasswordHash: String,
    Email: String,
    RecoveryCode: String,
}

#[post("/two-factor/recover", data = "<data>")]
fn recover(data: JsonUpcase<RecoverTwoFactor>, conn: DbConn) -> JsonResult {
    let data: RecoverTwoFactor = data.into_inner().data;

    use crate::db::models::User;

    // Get the user
    let mut user = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.RecoveryCode) {
        err!("Recovery code is incorrect. Try again.")
    }

    // Remove all twofactors from the user
    for twofactor in TwoFactor::find_by_user(&user.uuid, &conn) {
        twofactor.delete(&conn)?;
    }

    // Remove the recovery code, not needed without twofactors
    user.totp_recover = None;
    user.save(&conn)?;
    Ok(Json(json!({})))
}

fn _generate_recover_code(user: &mut User, conn: &DbConn) {
    if user.totp_recover.is_none() {
        let totp_recover = BASE32.encode(&crypto::get_random(vec![0u8; 20]));
        user.totp_recover = Some(totp_recover);
        user.save(conn).ok();
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DisableTwoFactorData {
    MasterPasswordHash: String,
    Type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
fn disable_twofactor(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let type_ = data.Type.into_i32()?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn) {
        twofactor.delete(&conn)?;
    }

    Ok(Json(json!({
        "Enabled": false,
        "Type": type_,
        "Object": "twoFactorProvider"
    })))
}

#[put("/two-factor/disable", data = "<data>")]
fn disable_twofactor_put(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    disable_twofactor(data, headers, conn)
}

#[post("/two-factor/get-authenticator", data = "<data>")]
fn generate_authenticator(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Authenticator as i32;
    let twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn);

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data),
        _ => (false, BASE32.encode(&crypto::get_random(vec![0u8; 20]))),
    };

    Ok(Json(json!({
        "Enabled": enabled,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EnableAuthenticatorData {
    MasterPasswordHash: String,
    Key: String,
    Token: NumberOrString,
}

#[post("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator(data: JsonUpcase<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let key = data.Key;
    let token = data.Token.into_i32()? as u64;

    let mut user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = match BASE32.decode(key.as_bytes()) {
        Ok(decoded) => decoded,
        _ => err!("Invalid totp secret"),
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    let type_ = TwoFactorType::Authenticator;
    let twofactor = TwoFactor::new(user.uuid.clone(), type_, key.to_uppercase());

    // Validate the token provided with the key
    validate_totp_code(token, &twofactor.data)?;

    _generate_recover_code(&mut user, &conn);
    twofactor.save(&conn)?;

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[put("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator_put(data: JsonUpcase<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_authenticator(data, headers, conn)
}

pub fn validate_totp_code_str(totp_code: &str, secret: &str) -> EmptyResult {
    let totp_code: u64 = match totp_code.parse() {
        Ok(code) => code,
        _ => err!("TOTP code is not a number"),
    };

    validate_totp_code(totp_code, secret)
}

pub fn validate_totp_code(totp_code: u64, secret: &str) -> EmptyResult {
    use oath::{totp_raw_now, HashType};

    let decoded_secret = match BASE32.decode(secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid TOTP secret"),
    };

    let generated = totp_raw_now(&decoded_secret, 6, 0, 30, &HashType::SHA1);
    if generated != totp_code {
        err!("Invalid TOTP code");
    }

    Ok(())
}

use u2f::messages::{RegisterResponse, SignResponse, U2fSignRequest};
use u2f::protocol::{Challenge, U2f};
use u2f::register::Registration;

use crate::CONFIG;

const U2F_VERSION: &str = "U2F_V2";

lazy_static! {
    static ref APP_ID: String = format!("{}/app-id.json", &CONFIG.domain());
    static ref U2F: U2f = U2f::new(APP_ID.clone());
}

#[post("/two-factor/get-u2f", data = "<data>")]
fn generate_u2f(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.domain_set() {
        err!("`DOMAIN` environment variable is not set. U2F disabled")
    }
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let (enabled, keys) = get_u2f_registrations(&headers.user.uuid, &conn)?;
    let keys_json: Vec<Value> = keys.iter().map(U2FRegistration::to_json).collect();

    Ok(Json(json!({
        "Enabled": enabled,
        "Keys": keys_json,
        "Object": "twoFactorU2f"
    })))
}

#[post("/two-factor/get-u2f-challenge", data = "<data>")]
fn generate_u2f_challenge(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let _type = TwoFactorType::U2fRegisterChallenge;
    let challenge = _create_u2f_challenge(&headers.user.uuid, _type, &conn).challenge;

    Ok(Json(json!({
        "UserId": headers.user.uuid,
        "AppId": APP_ID.to_string(),
        "Challenge": challenge,
        "Version": U2F_VERSION,
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EnableU2FData {
    Id: NumberOrString, // 1..5
    Name: String,
    MasterPasswordHash: String,
    DeviceResponse: String,
}

// This struct is referenced from the U2F lib
// because it doesn't implement Deserialize
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(remote = "Registration")]
struct RegistrationDef {
    key_handle: Vec<u8>,
    pub_key: Vec<u8>,
    attestation_cert: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct U2FRegistration {
    id: i32,
    name: String,
    #[serde(with = "RegistrationDef")]
    reg: Registration,
    counter: u32,
    compromised: bool,
}

impl U2FRegistration {
    fn to_json(&self) -> Value {
        json!({
            "Id": self.id,
            "Name": self.name,
            "Compromised": self.compromised,
        })
    }
}

// This struct is copied from the U2F lib
// to add an optional error code
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponseCopy {
    pub registration_data: String,
    pub version: String,
    pub client_data: String,

    pub error_code: Option<NumberOrString>,
}

impl Into<RegisterResponse> for RegisterResponseCopy {
    fn into(self) -> RegisterResponse {
        RegisterResponse {
            registration_data: self.registration_data,
            version: self.version,
            client_data: self.client_data,
        }
    }
}

#[post("/two-factor/u2f", data = "<data>")]
fn activate_u2f(data: JsonUpcase<EnableU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableU2FData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let tf_type = TwoFactorType::U2fRegisterChallenge as i32;
    let tf_challenge = match TwoFactor::find_by_user_and_type(&user.uuid, tf_type, &conn) {
        Some(c) => c,
        None => err!("Can't recover challenge"),
    };

    let challenge: Challenge = serde_json::from_str(&tf_challenge.data)?;
    tf_challenge.delete(&conn)?;

    let response: RegisterResponseCopy = serde_json::from_str(&data.DeviceResponse)?;

    let error_code = response
        .error_code
        .clone()
        .map_or("0".into(), NumberOrString::into_string);

    if error_code != "0" {
        err!("Error registering U2F token")
    }

    let registration = U2F.register_response(challenge.clone(), response.into())?;
    let full_registration = U2FRegistration {
        id: data.Id.into_i32()?,
        name: data.Name,
        reg: registration,
        compromised: false,
        counter: 0,
    };

    let mut regs = get_u2f_registrations(&user.uuid, &conn)?.1;

    // TODO: Check that there is no repeat Id
    regs.push(full_registration);
    save_u2f_registrations(&user.uuid, &regs, &conn)?;

    _generate_recover_code(&mut user, &conn);

    let keys_json: Vec<Value> = regs.iter().map(U2FRegistration::to_json).collect();
    Ok(Json(json!({
        "Enabled": true,
        "Keys": keys_json,
        "Object": "twoFactorU2f"
    })))
}

#[put("/two-factor/u2f", data = "<data>")]
fn activate_u2f_put(data: JsonUpcase<EnableU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_u2f(data, headers, conn)
}

fn _create_u2f_challenge(user_uuid: &str, type_: TwoFactorType, conn: &DbConn) -> Challenge {
    let challenge = U2F.generate_challenge().unwrap();

    TwoFactor::new(user_uuid.into(), type_, serde_json::to_string(&challenge).unwrap())
        .save(conn)
        .expect("Error saving challenge");

    challenge
}

fn save_u2f_registrations(user_uuid: &str, regs: &[U2FRegistration], conn: &DbConn) -> EmptyResult {
    TwoFactor::new(user_uuid.into(), TwoFactorType::U2f, serde_json::to_string(regs)?).save(&conn)
}

fn get_u2f_registrations(user_uuid: &str, conn: &DbConn) -> Result<(bool, Vec<U2FRegistration>), Error> {
    let type_ = TwoFactorType::U2f as i32;
    let (enabled, regs) = match TwoFactor::find_by_user_and_type(user_uuid, type_, conn) {
        Some(tf) => (tf.enabled, tf.data),
        None => return Ok((false, Vec::new())), // If no data, return empty list
    };

    let data = match serde_json::from_str(&regs) {
        Ok(d) => d,
        Err(_) => {
            // If error, try old format
            let mut old_regs = _old_parse_registrations(&regs);

            if old_regs.len() != 1 {
                err!("The old U2F format only allows one device")
            }

            // Convert to new format
            let new_regs = vec![U2FRegistration {
                id: 1,
                name: "Unnamed U2F key".into(),
                reg: old_regs.remove(0),
                compromised: false,
                counter: 0,
            }];

            // Save new format
            save_u2f_registrations(user_uuid, &new_regs, &conn)?;

            new_regs
        }
    };

    Ok((enabled, data))
}

fn _old_parse_registrations(registations: &str) -> Vec<Registration> {
    #[derive(Deserialize)]
    struct Helper(#[serde(with = "RegistrationDef")] Registration);

    let regs: Vec<Value> = serde_json::from_str(registations).expect("Can't parse Registration data");

    regs.into_iter()
        .map(|r| serde_json::from_value(r).unwrap())
        .map(|Helper(r)| r)
        .collect()
}

pub fn generate_u2f_login(user_uuid: &str, conn: &DbConn) -> ApiResult<U2fSignRequest> {
    let challenge = _create_u2f_challenge(user_uuid, TwoFactorType::U2fLoginChallenge, conn);

    let registrations: Vec<_> = get_u2f_registrations(user_uuid, conn)?
        .1
        .into_iter()
        .map(|r| r.reg)
        .collect();

    if registrations.is_empty() {
        err!("No U2F devices registered")
    }

    Ok(U2F.sign_request(challenge, registrations))
}

pub fn validate_u2f_login(user_uuid: &str, response: &str, conn: &DbConn) -> EmptyResult {
    let challenge_type = TwoFactorType::U2fLoginChallenge as i32;
    let tf_challenge = TwoFactor::find_by_user_and_type(user_uuid, challenge_type, &conn);

    let challenge = match tf_challenge {
        Some(tf_challenge) => {
            let challenge: Challenge = serde_json::from_str(&tf_challenge.data)?;
            tf_challenge.delete(&conn)?;
            challenge
        }
        None => err!("Can't recover login challenge"),
    };
    let response: SignResponse = serde_json::from_str(response)?;
    let mut registrations = get_u2f_registrations(user_uuid, conn)?.1;
    if registrations.is_empty() {
        err!("No U2F devices registered")
    }

    for reg in &mut registrations {
        let response = U2F.sign_response(challenge.clone(), reg.reg.clone(), response.clone(), reg.counter);
        match response {
            Ok(new_counter) => {
                reg.counter = new_counter;
                save_u2f_registrations(user_uuid, &registrations, &conn)?;

                return Ok(());
            }
            Err(u2f::u2ferror::U2fError::CounterTooLow) => {
                reg.compromised = true;
                save_u2f_registrations(user_uuid, &registrations, &conn)?;

                err!("This device might be compromised!");
            }
            Err(e) => {
                warn!("E {:#}", e);
                // break;
            }
        }
    }
    err!("error verifying response")
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EnableYubikeyData {
    MasterPasswordHash: String,
    Key1: Option<String>,
    Key2: Option<String>,
    Key3: Option<String>,
    Key4: Option<String>,
    Key5: Option<String>,
    Nfc: bool,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct YubikeyMetadata {
    Keys: Vec<String>,
    pub Nfc: bool,
}

use yubico::config::Config;
use yubico::Yubico;

fn parse_yubikeys(data: &EnableYubikeyData) -> Vec<String> {
    let data_keys = [&data.Key1, &data.Key2, &data.Key3, &data.Key4, &data.Key5];

    data_keys.iter().filter_map(|e| e.as_ref().cloned()).collect()
}

fn jsonify_yubikeys(yubikeys: Vec<String>) -> serde_json::Value {
    let mut result = json!({});

    for (i, key) in yubikeys.into_iter().enumerate() {
        result[format!("Key{}", i + 1)] = Value::String(key);
    }

    result
}

fn get_yubico_credentials() -> Result<(String, String), Error> {
    match (CONFIG.yubico_client_id(), CONFIG.yubico_secret_key()) {
        (Some(id), Some(secret)) => Ok((id, secret)),
        _ => err!("`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled"),
    }
}

fn verify_yubikey_otp(otp: String) -> EmptyResult {
    let (yubico_id, yubico_secret) = get_yubico_credentials()?;

    let yubico = Yubico::new();
    let config = Config::default().set_client_id(yubico_id).set_key(yubico_secret);

    match CONFIG.yubico_server() {
        Some(server) => yubico.verify(otp, config.set_api_hosts(vec![server])),
        None => yubico.verify(otp, config),
    }
    .map_res("Failed to verify OTP")
    .and(Ok(()))
}

#[post("/two-factor/get-yubikey", data = "<data>")]
fn generate_yubikey(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    // Make sure the credentials are set
    get_yubico_credentials()?;

    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let user_uuid = &user.uuid;
    let yubikey_type = TwoFactorType::YubiKey as i32;

    let r = TwoFactor::find_by_user_and_type(user_uuid, yubikey_type, &conn);

    if let Some(r) = r {
        let yubikey_metadata: YubikeyMetadata = serde_json::from_str(&r.data)?;

        let mut result = jsonify_yubikeys(yubikey_metadata.Keys);

        result["Enabled"] = Value::Bool(true);
        result["Nfc"] = Value::Bool(yubikey_metadata.Nfc);
        result["Object"] = Value::String("twoFactorU2f".to_owned());

        Ok(Json(result))
    } else {
        Ok(Json(json!({
            "Enabled": false,
            "Object": "twoFactorU2f",
        })))
    }
}

#[post("/two-factor/yubikey", data = "<data>")]
fn activate_yubikey(data: JsonUpcase<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableYubikeyData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    // Check if we already have some data
    let mut yubikey_data = match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &conn) {
        Some(data) => data,
        None => TwoFactor::new(user.uuid.clone(), TwoFactorType::YubiKey, String::new()),
    };

    let yubikeys = parse_yubikeys(&data);

    if yubikeys.is_empty() {
        return Ok(Json(json!({
            "Enabled": false,
            "Object": "twoFactorU2f",
        })));
    }

    // Ensure they are valid OTPs
    for yubikey in &yubikeys {
        if yubikey.len() == 12 {
            // YubiKey ID
            continue;
        }

        verify_yubikey_otp(yubikey.to_owned()).map_res("Invalid Yubikey OTP provided")?;
    }

    let yubikey_ids: Vec<String> = yubikeys.into_iter().map(|x| (&x[..12]).to_owned()).collect();

    let yubikey_metadata = YubikeyMetadata {
        Keys: yubikey_ids,
        Nfc: data.Nfc,
    };

    yubikey_data.data = serde_json::to_string(&yubikey_metadata).unwrap();
    yubikey_data.save(&conn)?;

    _generate_recover_code(&mut user, &conn);

    let mut result = jsonify_yubikeys(yubikey_metadata.Keys);

    result["Enabled"] = Value::Bool(true);
    result["Nfc"] = Value::Bool(yubikey_metadata.Nfc);
    result["Object"] = Value::String("twoFactorU2f".to_owned());

    Ok(Json(result))
}

#[put("/two-factor/yubikey", data = "<data>")]
fn activate_yubikey_put(data: JsonUpcase<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_yubikey(data, headers, conn)
}

pub fn validate_yubikey_login(response: &str, twofactor_data: &str) -> EmptyResult {
    if response.len() != 44 {
        err!("Invalid Yubikey OTP length");
    }

    let yubikey_metadata: YubikeyMetadata = serde_json::from_str(twofactor_data).expect("Can't parse Yubikey Metadata");
    let response_id = &response[..12];

    if !yubikey_metadata.Keys.contains(&response_id.to_owned()) {
        err!("Given Yubikey is not registered");
    }

    let result = verify_yubikey_otp(response.to_owned());

    match result {
        Ok(_answer) => Ok(()),
        Err(_e) => err!("Failed to verify Yubikey against OTP server"),
    }
}

#[post("/two-factor/get-duo", data = "<data>")]
fn get_duo(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    if CONFIG.duo_host().is_none() {
        err!("Duo is disabled. Refer to the Wiki for instructions in how to enable it")
    }

    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Duo as i32;
    let twofactor = TwoFactor::find_by_user_and_type(&headers.user.uuid, type_, &conn);

    let (enabled, msg) = match twofactor {
        Some(_) => (true, "<secret>"),
        _ => (false, "<Ignore this, click enable, then log out and log back in to activate>"),
    };

    Ok(Json(json!({
        "Enabled": enabled,
        "Host": msg,
        "SecretKey": msg,
        "IntegrationKey": msg,
        "Object": "twoFactorDuo"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case, dead_code)]
struct EnableDuoData {
    MasterPasswordHash: String,
    Host: String,
    SecretKey: String,
    IntegrationKey: String,
}

#[post("/two-factor/duo", data = "<data>")]
fn activate_duo(data: JsonUpcase<EnableDuoData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableDuoData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Duo;
    let twofactor = TwoFactor::new(headers.user.uuid.clone(), type_, String::new());
    twofactor.save(&conn)?;

    Ok(Json(json!({
        "Enabled": true,
        "Host": "<secret>",
        "SecretKey": "<secret>",
        "IntegrationKey": "<secret>",
        "Object": "twoFactorDuo"
    })))
}

#[put("/two-factor/duo", data = "<data>")]
fn activate_duo_put(data: JsonUpcase<EnableDuoData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_duo(data, headers, conn)
}

// duo_api_request("GET", "/auth/v2/check", "", &data)?;
fn _duo_api_request(method: &str, path: &str, params: &str) -> EmptyResult {
    const AGENT: &str = "bitwarden_rs:Duo/1.0 (Rust)";

    use std::str::FromStr;

    use chrono::Utc;
    use reqwest::{header::*, Client, Method};

    let ik = CONFIG.duo_ikey().unwrap();
    let sk = CONFIG.duo_skey().unwrap();
    let host = CONFIG.duo_host().unwrap();

    let url = format!("https://{}{}", host, path);
    let date = Utc::now().to_rfc2822();
    let username = &ik;
    let fields = [&date, method, &host, path, params];
    let password = crypto::hmac_sign(&sk, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    Client::new()
        .request(m, &url)
        .basic_auth(username, Some(password))
        .header(USER_AGENT, AGENT)
        .header(DATE, date)
        .send()?
        .error_for_status()?;

    Ok(())
}

const DUO_EXPIRE: i64 = 300;
const APP_EXPIRE: i64 = 3600;

const AUTH_PREFIX: &str = "AUTH";
const DUO_PREFIX: &str = "TX";
const APP_PREFIX: &str = "APP";

use chrono::Utc;

pub fn generate_duo_signature(email: &str) -> String {
    let now = Utc::now().timestamp();

    let ik = CONFIG.duo_ikey().unwrap();
    let sk = CONFIG.duo_skey().unwrap();
    let ak = CONFIG.duo_akey().unwrap();

    let duo_sign = sign_duo_values(&sk, email, &ik, DUO_PREFIX, now + DUO_EXPIRE);
    let app_sign = sign_duo_values(&ak, email, &ik, APP_PREFIX, now + APP_EXPIRE);

    format!("{}:{}", duo_sign, app_sign)
}

fn sign_duo_values(key: &str, email: &str, ikey: &str, prefix: &str, expire: i64) -> String {
    let val = format!("{}|{}|{}", email, ikey, expire);
    let cookie = format!("{}|{}", prefix, BASE64.encode(val.as_bytes()));

    format!("{}|{}", cookie, crypto::hmac_sign(key, &cookie))
}

pub fn validate_duo_login(email: &str, response: &str) -> EmptyResult {
    let split: Vec<&str> = response.split(':').collect();
    if split.len() != 2 {
        err!("Invalid response length");
    }

    let auth_sig = split[0];
    let app_sig = split[1];

    let now = Utc::now().timestamp();

    let ik = CONFIG.duo_ikey().unwrap();
    let sk = CONFIG.duo_skey().unwrap();
    let ak = CONFIG.duo_akey().unwrap();

    let auth_user = parse_duo_values(&sk, auth_sig, &ik, AUTH_PREFIX, now)?;
    let app_user = parse_duo_values(&ak, app_sig, &ik, APP_PREFIX, now)?;

    if !crypto::ct_eq(&auth_user, app_user) || !crypto::ct_eq(&auth_user, email) {
        err!("Error validating duo authentication")
    }

    Ok(())
}

fn parse_duo_values(key: &str, val: &str, ikey: &str, prefix: &str, time: i64) -> ApiResult<String> {
    let split: Vec<&str> = val.split('|').collect();
    if split.len() != 3 {
        err!("Invalid value length")
    }

    let u_prefix = split[0];
    let u_b64 = split[1];
    let u_sig = split[2];

    let sig = crypto::hmac_sign(key, &format!("{}|{}", u_prefix, u_b64));

    if !crypto::ct_eq(crypto::hmac_sign(key, &sig), crypto::hmac_sign(key, u_sig)) {
        err!("Duo signatures don't match")
    }

    if u_prefix != prefix {
        err!("Prefixes don't match")
    }

    let cookie_vec = match BASE64.decode(u_b64.as_bytes()) {
        Ok(c) => c,
        Err(_) => err!("Invalid Duo cookie encoding"),
    };

    let cookie = match String::from_utf8(cookie_vec) {
        Ok(c) => c,
        Err(_) => err!("Invalid Duo cookie encoding"),
    };

    let cookie_split: Vec<&str> = cookie.split('|').collect();
    if cookie_split.len() != 3 {
        err!("Invalid cookie length")
    }

    let username = cookie_split[0];
    let u_ikey = cookie_split[1];
    let expire = cookie_split[2];

    if !crypto::ct_eq(ikey, u_ikey) {
        err!("Invalid ikey")
    }

    let expire = match expire.parse() {
        Ok(e) => e,
        Err(_) => err!("Invalid expire time"),
    };

    if time >= expire {
        err!("Expired authorization")
    }

    Ok(username.into())
}
