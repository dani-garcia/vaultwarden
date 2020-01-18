use rocket::Route;
use rocket_contrib::json::Json;
use serde_json;
use serde_json::Value;
use u2f::messages::{RegisterResponse, SignResponse, U2fSignRequest};
use u2f::protocol::{Challenge, U2f};
use u2f::register::Registration;

use crate::api::core::two_factor::_generate_recover_code;
use crate::api::{ApiResult, EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData};
use crate::auth::Headers;
use crate::db::{
    models::{TwoFactor, TwoFactorType},
    DbConn,
};
use crate::error::Error;
use crate::CONFIG;

const U2F_VERSION: &str = "U2F_V2";

lazy_static! {
    static ref APP_ID: String = format!("{}/app-id.json", &CONFIG.domain());
    static ref U2F: U2f = U2f::new(APP_ID.clone());
}

pub fn routes() -> Vec<Route> {
    routes![
        generate_u2f,
        generate_u2f_challenge,
        activate_u2f,
        activate_u2f_put,
        delete_u2f,
    ]
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
    Id: NumberOrString,
    // 1..5
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
    device_name: Option<String>,
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

    let registration = U2F.register_response(challenge, response.into())?;
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

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct DeleteU2FData {
    Id: NumberOrString,
    MasterPasswordHash: String,
}

#[delete("/two-factor/u2f", data = "<data>")]
fn delete_u2f(data: JsonUpcase<DeleteU2FData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: DeleteU2FData = data.into_inner().data;

    let id = data.Id.into_i32()?;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::U2f as i32;
    let mut tf = match TwoFactor::find_by_user_and_type(&headers.user.uuid, type_, &conn) {
        Some(tf) => tf,
        None => err!("U2F data not found!"),
    };

    let mut data: Vec<U2FRegistration> = match serde_json::from_str(&tf.data) {
        Ok(d) => d,
        Err(_) => err!("Error parsing U2F data"),
    };

    data.retain(|r| r.id != id);

    let new_data_str = serde_json::to_string(&data)?;

    tf.data = new_data_str;
    tf.save(&conn)?;

    let keys_json: Vec<Value> = data.iter().map(U2FRegistration::to_json).collect();

    Ok(Json(json!({
        "Enabled": true,
        "Keys": keys_json,
        "Object": "twoFactorU2f"
    })))
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
