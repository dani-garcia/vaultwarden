use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use yubico::{config::Config, verify};

use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, JsonUpcase, PasswordData,
    },
    auth::Headers,
    db::{
        models::{EventType, TwoFactor, TwoFactorType},
        DbConn,
    },
    error::{Error, MapResult},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![generate_yubikey, activate_yubikey, activate_yubikey_put,]
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

fn parse_yubikeys(data: &EnableYubikeyData) -> Vec<String> {
    let data_keys = [&data.Key1, &data.Key2, &data.Key3, &data.Key4, &data.Key5];

    data_keys.iter().filter_map(|e| e.as_ref().cloned()).collect()
}

fn jsonify_yubikeys(yubikeys: Vec<String>) -> serde_json::Value {
    let mut result = Value::Object(serde_json::Map::new());

    for (i, key) in yubikeys.into_iter().enumerate() {
        result[format!("Key{}", i + 1)] = Value::String(key);
    }

    result
}

fn get_yubico_credentials() -> Result<(String, String), Error> {
    if !CONFIG._enable_yubico() {
        err!("Yubico support is disabled");
    }

    match (CONFIG.yubico_client_id(), CONFIG.yubico_secret_key()) {
        (Some(id), Some(secret)) => Ok((id, secret)),
        _ => err!("`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled"),
    }
}

async fn verify_yubikey_otp(otp: String) -> EmptyResult {
    let (yubico_id, yubico_secret) = get_yubico_credentials()?;

    let config = Config::default().set_client_id(yubico_id).set_key(yubico_secret);

    match CONFIG.yubico_server() {
        Some(server) => {
            tokio::task::spawn_blocking(move || verify(otp, config.set_api_hosts(vec![server]))).await.unwrap()
        }
        None => tokio::task::spawn_blocking(move || verify(otp, config)).await.unwrap(),
    }
    .map_res("Failed to verify OTP")
    .and(Ok(()))
}

#[post("/two-factor/get-yubikey", data = "<data>")]
async fn generate_yubikey(data: JsonUpcase<PasswordData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    // Make sure the credentials are set
    get_yubico_credentials()?;

    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let user_uuid = &user.uuid;
    let yubikey_type = TwoFactorType::YubiKey as i32;

    let r = TwoFactor::find_by_user_and_type(user_uuid, yubikey_type, &mut conn).await;

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
async fn activate_yubikey(data: JsonUpcase<EnableYubikeyData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: EnableYubikeyData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    // Check if we already have some data
    let mut yubikey_data =
        match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &mut conn).await {
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

        verify_yubikey_otp(yubikey.to_owned()).await.map_res("Invalid Yubikey OTP provided")?;
    }

    let yubikey_ids: Vec<String> = yubikeys.into_iter().map(|x| (x[..12]).to_owned()).collect();

    let yubikey_metadata = YubikeyMetadata {
        Keys: yubikey_ids,
        Nfc: data.Nfc,
    };

    yubikey_data.data = serde_json::to_string(&yubikey_metadata).unwrap();
    yubikey_data.save(&mut conn).await?;

    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    let mut result = jsonify_yubikeys(yubikey_metadata.Keys);

    result["Enabled"] = Value::Bool(true);
    result["Nfc"] = Value::Bool(yubikey_metadata.Nfc);
    result["Object"] = Value::String("twoFactorU2f".to_owned());

    Ok(Json(result))
}

#[put("/two-factor/yubikey", data = "<data>")]
async fn activate_yubikey_put(data: JsonUpcase<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_yubikey(data, headers, conn).await
}

pub async fn validate_yubikey_login(response: &str, twofactor_data: &str) -> EmptyResult {
    if response.len() != 44 {
        err!("Invalid Yubikey OTP length");
    }

    let yubikey_metadata: YubikeyMetadata = serde_json::from_str(twofactor_data).expect("Can't parse Yubikey Metadata");
    let response_id = &response[..12];

    if !yubikey_metadata.Keys.contains(&response_id.to_owned()) {
        err!("Given Yubikey is not registered");
    }

    let result = verify_yubikey_otp(response.to_owned()).await;

    match result {
        Ok(_answer) => Ok(()),
        Err(_e) => err!("Failed to verify Yubikey against OTP server"),
    }
}
