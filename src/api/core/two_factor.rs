use data_encoding::BASE32;
use rocket_contrib::json::Json;
use serde_json;
use serde_json::Value;


use crate::db::{
    models::{TwoFactor, TwoFactorType, User},
    DbConn,
};

use crate::crypto;

use crate::api::{ApiResult, EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData};
use crate::auth::Headers;

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
    ]
}

#[get("/two-factor")]
fn get_twofactor(headers: Headers, conn: DbConn) -> JsonResult {
    let twofactors = TwoFactor::find_by_user(&headers.user.uuid, &conn);
    let twofactors_json: Vec<Value> = twofactors.iter().map(|c| c.to_json_list()).collect();

    Ok(Json(json!({
        "Data": twofactors_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[post("/two-factor/get-recover", data = "<data>")]
fn get_recover(data: JsonUpcase<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": headers.user.totp_recover,
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
        twofactor.delete(&conn).expect("Error deleting twofactor");
    }

    // Remove the recovery code, not needed without twofactors
    user.totp_recover = None;
    user.save(&conn)?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DisableTwoFactorData {
    MasterPasswordHash: String,
    Type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
fn disable_twofactor(
    data: JsonUpcase<DisableTwoFactorData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let type_ = data.Type.into_i32().expect("Invalid type");

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&headers.user.uuid, type_, &conn) {
        twofactor.delete(&conn).expect("Error deleting twofactor");
    }

    Ok(Json(json!({
        "Enabled": false,
        "Type": type_,
        "Object": "twoFactorProvider"
    })))
}

#[put("/two-factor/disable", data = "<data>")]
fn disable_twofactor_put(
    data: JsonUpcase<DisableTwoFactorData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    disable_twofactor(data, headers, conn)
}

#[post("/two-factor/get-authenticator", data = "<data>")]
fn generate_authenticator(
    data: JsonUpcase<PasswordData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Authenticator as i32;
    let twofactor = TwoFactor::find_by_user_and_type(&headers.user.uuid, type_, &conn);

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
fn activate_authenticator(
    data: JsonUpcase<EnableAuthenticatorData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let key = data.Key;
    let token = match data.Token.into_i32() {
        Some(n) => n as u64,
        None => err!("Malformed token"),
    };

    if !headers.user.check_valid_password(&password_hash) {
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
    let twofactor = TwoFactor::new(headers.user.uuid.clone(), type_, key.to_uppercase());

    // Validate the token provided with the key
    if !twofactor.check_totp_code(token) {
        err!("Invalid totp code")
    }

    let mut user = headers.user;
    _generate_recover_code(&mut user, &conn);
    twofactor.save(&conn).expect("Error saving twofactor");

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[put("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator_put(
    data: JsonUpcase<EnableAuthenticatorData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    activate_authenticator(data, headers, conn)
}

fn _generate_recover_code(user: &mut User, conn: &DbConn) {
    if user.totp_recover.is_none() {
        let totp_recover = BASE32.encode(&crypto::get_random(vec![0u8; 20]));
        user.totp_recover = Some(totp_recover);
        user.save(conn).ok();
    }
}

use u2f::messages::{RegisterResponse, SignResponse, U2fSignRequest};
use u2f::protocol::{Challenge, U2f};
use u2f::register::Registration;

use crate::CONFIG;

const U2F_VERSION: &str = "U2F_V2";

lazy_static! {
    static ref APP_ID: String = format!("{}/app-id.json", &CONFIG.domain);
    static ref U2F: U2f = U2f::new(APP_ID.clone());
}

#[post("/two-factor/get-u2f", data = "<data>")]
fn generate_u2f(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.domain_set {
        err!("`DOMAIN` environment variable is not set. U2F disabled")
    }

    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let user_uuid = &headers.user.uuid;

    let u2f_type = TwoFactorType::U2f as i32;
    let enabled = TwoFactor::find_by_user_and_type(user_uuid, u2f_type, &conn).is_some();

    Ok(Json(json!({
        "Enabled": enabled,
        "Object": "twoFactorU2f"
    })))
}

#[post("/two-factor/get-u2f-challenge", data = "<data>")]
fn generate_u2f_challenge(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let user_uuid = &headers.user.uuid;

    let challenge = _create_u2f_challenge(user_uuid, TwoFactorType::U2fRegisterChallenge, &conn).challenge;

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
    MasterPasswordHash: String,
    DeviceResponse: String,
}

// This struct is copied from the U2F lib
// because challenge is not always sent
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterResponseCopy {
    pub registration_data: String,
    pub version: String,
    pub challenge: Option<String>,
    pub error_code: Option<NumberOrString>,
    pub client_data: String,
}

impl RegisterResponseCopy {
    fn into_response(self, challenge: String) -> RegisterResponse {
        RegisterResponse {
            registration_data: self.registration_data,
            version: self.version,
            challenge,
            client_data: self.client_data,
        }
    }
}

#[post("/two-factor/u2f", data = "<data>")]
fn activate_u2f(data: JsonUpcase<EnableU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableU2FData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let tf_challenge = TwoFactor::find_by_user_and_type(
        &headers.user.uuid,
        TwoFactorType::U2fRegisterChallenge as i32,
        &conn,
    );

    if let Some(tf_challenge) = tf_challenge {
        let challenge: Challenge = serde_json::from_str(&tf_challenge.data)?;

        tf_challenge.delete(&conn)?;

        let response_copy: RegisterResponseCopy = serde_json::from_str(&data.DeviceResponse)?;

        let error_code = response_copy
            .error_code
            .clone()
            .map_or("0".into(), NumberOrString::into_string);

        if error_code != "0" {
            err!("Error registering U2F token")
        }

        let response = response_copy.into_response(challenge.challenge.clone());

        let registration = U2F.register_response(challenge.clone(), response)?;
        // TODO: Allow more than one U2F device
        let mut registrations = Vec::new();
        registrations.push(registration);

        let tf_registration = TwoFactor::new(
            headers.user.uuid.clone(),
            TwoFactorType::U2f,
            serde_json::to_string(&registrations).unwrap(),
        );
        tf_registration.save(&conn)?;

        let mut user = headers.user;
        _generate_recover_code(&mut user, &conn);

        Ok(Json(json!({
            "Enabled": true,
            "Challenge": {
                "UserId": user.uuid,
                "AppId": APP_ID.to_string(),
                "Challenge": challenge,
                "Version": U2F_VERSION,
            },
            "Object": "twoFactorU2f"
        })))
    } else {
        err!("Can't recover challenge")
    }
}

#[put("/two-factor/u2f", data = "<data>")]
fn activate_u2f_put(data: JsonUpcase<EnableU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_u2f(data,headers, conn)
}

fn _create_u2f_challenge(user_uuid: &str, type_: TwoFactorType, conn: &DbConn) -> Challenge {
    let challenge = U2F.generate_challenge().unwrap();

    TwoFactor::new(
        user_uuid.into(),
        type_,
        serde_json::to_string(&challenge).unwrap(),
    ).save(conn)
        .expect("Error saving challenge");

    challenge
}

// This struct is copied from the U2F lib
// because it doesn't implement Deserialize
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RegistrationCopy {
    pub key_handle: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub attestation_cert: Option<Vec<u8>>,
}

impl Into<Registration> for RegistrationCopy {
    fn into(self) -> Registration {
        Registration {
            key_handle: self.key_handle,
            pub_key: self.pub_key,
            attestation_cert: self.attestation_cert,
        }
    }
}

fn _parse_registrations(registations: &str) -> Vec<Registration> {
    let registrations_copy: Vec<RegistrationCopy> =
        serde_json::from_str(registations).expect("Can't parse RegistrationCopy data");

    registrations_copy.into_iter().map(Into::into).collect()
}

pub fn generate_u2f_login(user_uuid: &str, conn: &DbConn) -> ApiResult<U2fSignRequest> {
    let challenge = _create_u2f_challenge(user_uuid, TwoFactorType::U2fLoginChallenge, conn);

    let type_ = TwoFactorType::U2f as i32;
    let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, type_, conn) {
        Some(tf) => tf,
        None => err!("No U2F devices registered"),
    };

    let registrations = _parse_registrations(&twofactor.data);
    let signed_request: U2fSignRequest = U2F.sign_request(challenge, registrations);

    Ok(signed_request)
}

pub fn validate_u2f_login(user_uuid: &str, response: &str, conn: &DbConn) -> EmptyResult {
    let challenge_type = TwoFactorType::U2fLoginChallenge as i32;
    let u2f_type = TwoFactorType::U2f as i32;

    let tf_challenge = TwoFactor::find_by_user_and_type(user_uuid, challenge_type, &conn);

    let challenge = match tf_challenge {
        Some(tf_challenge) => {
            let challenge: Challenge = serde_json::from_str(&tf_challenge.data)?;
            tf_challenge.delete(&conn)?;
            challenge
        }
        None => err!("Can't recover login challenge"),
    };

    let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, u2f_type, conn) {
        Some(tf) => tf,
        None => err!("No U2F devices registered"),
    };

    let registrations = _parse_registrations(&twofactor.data);

    let response: SignResponse = serde_json::from_str(response)?;

    let mut _counter: u32 = 0;
    for registration in registrations {
        let response =
            U2F.sign_response(challenge.clone(), registration, response.clone(), _counter);
        match response {
            Ok(new_counter) => {
                _counter = new_counter;
                info!("O {:#}", new_counter);
                return Ok(());
            }
            Err(e) => {
                info!("E {:#}", e);
                break;
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

use yubico::Yubico;
use yubico::config::Config;

fn parse_yubikeys(data: &EnableYubikeyData) -> Vec<String> {
    let mut yubikeys: Vec<String> = Vec::new();

    if data.Key1.is_some() {
        yubikeys.push(data.Key1.as_ref().unwrap().to_owned());
    }

    if data.Key2.is_some() {
        yubikeys.push(data.Key2.as_ref().unwrap().to_owned());
    }

    if data.Key3.is_some() {
        yubikeys.push(data.Key3.as_ref().unwrap().to_owned());
    }

    if data.Key4.is_some() {
        yubikeys.push(data.Key4.as_ref().unwrap().to_owned());
    }

    if data.Key5.is_some() {
        yubikeys.push(data.Key5.as_ref().unwrap().to_owned());
    }

    yubikeys
}

fn jsonify_yubikeys(yubikeys: Vec<String>) -> serde_json::Value {
    let mut result = json!({});

    for (i, key) in yubikeys.into_iter().enumerate() {
        result[format!("Key{}", i+1)] = Value::String(key);
    }

    result
}

fn verify_yubikey_otp(otp: String) -> JsonResult {
    if !CONFIG.yubico_cred_set {
        err!("`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. \
               Yubikey OTP Disabled")
    }

    let yubico = Yubico::new();
    let config = Config::default().set_client_id(CONFIG.yubico_client_id.to_owned()).set_key(CONFIG.yubico_secret_key.to_owned());

    let result = match CONFIG.yubico_server {
        Some(ref server) => yubico.verify(otp, config.set_api_hosts(vec![server.to_owned()])),
        None => yubico.verify(otp, config)
    };

    match result {
        Ok(_answer) => Ok(Json(json!({}))),
        Err(_e) => err!("Failed to verify OTP"),
    }
}

#[post("/two-factor/get-yubikey", data = "<data>")]
fn generate_yubikey(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.yubico_cred_set {
        err!("`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. \
               Yubikey OTP Disabled")
    }

    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let user_uuid = &headers.user.uuid;
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

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    // Check if we already have some data
    let yubikey_data = TwoFactor::find_by_user_and_type(
        &headers.user.uuid,
        TwoFactorType::YubiKey as i32,
        &conn,
    );

    if let Some(yubikey_data) = yubikey_data {
        yubikey_data.delete(&conn)?;
    }

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
            continue
        }

        let result = verify_yubikey_otp(yubikey.to_owned());

        if let Err(_e) = result {
            err!("Invalid Yubikey OTP provided");
        }
    }

    let yubikey_ids: Vec<String> = yubikeys.into_iter().map(|x| (&x[..12]).to_owned()).collect();

    let yubikey_metadata = YubikeyMetadata {
        Keys: yubikey_ids,
        Nfc: data.Nfc,
    };

    let yubikey_registration = TwoFactor::new(
        headers.user.uuid.clone(),
        TwoFactorType::YubiKey,
        serde_json::to_string(&yubikey_metadata).unwrap(),
    );
    yubikey_registration.save(&conn)?;

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

pub fn validate_yubikey_login(user_uuid: &str, response: &str, conn: &DbConn) -> EmptyResult {
    if response.len() != 44 {
        err!("Invalid Yubikey OTP length");
    }

    let yubikey_type = TwoFactorType::YubiKey as i32;

    let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, yubikey_type, &conn) {
        Some(tf) => tf,
        None => err!("No YubiKey devices registered"),
    };

    let yubikey_metadata: YubikeyMetadata = serde_json::from_str(&twofactor.data).expect("Can't parse Yubikey Metadata");
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
