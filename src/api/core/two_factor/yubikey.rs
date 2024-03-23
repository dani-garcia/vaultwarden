use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use yubico::{config::Config, verify_async};

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
    error::{Error, MapResult},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![generate_yubikey, activate_yubikey, activate_yubikey_put,]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableYubikeyData {
    key1: Option<String>,
    key2: Option<String>,
    key3: Option<String>,
    key4: Option<String>,
    key5: Option<String>,
    nfc: bool,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct YubikeyMetadata {
    #[serde(rename = "keys", alias = "Keys")]
    keys: Vec<String>,
    #[serde(rename = "nfc", alias = "Nfc")]
    pub nfc: bool,
}

fn parse_yubikeys(data: &EnableYubikeyData) -> Vec<String> {
    let data_keys = [&data.key1, &data.key2, &data.key3, &data.key4, &data.key5];

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
        Some(server) => verify_async(otp, config.set_api_hosts(vec![server])).await,
        None => verify_async(otp, config).await,
    }
    .map_res("Failed to verify OTP")
}

#[post("/two-factor/get-yubikey", data = "<data>")]
async fn generate_yubikey(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    // Make sure the credentials are set
    get_yubico_credentials()?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let user_uuid = &user.uuid;
    let yubikey_type = TwoFactorType::YubiKey as i32;

    let r = TwoFactor::find_by_user_and_type(user_uuid, yubikey_type, &mut conn).await;

    if let Some(r) = r {
        let yubikey_metadata: YubikeyMetadata = serde_json::from_str(&r.data)?;

        let mut result = jsonify_yubikeys(yubikey_metadata.keys);

        result["enabled"] = Value::Bool(true);
        result["nfc"] = Value::Bool(yubikey_metadata.nfc);
        result["object"] = Value::String("twoFactorU2f".to_owned());

        Ok(Json(result))
    } else {
        Ok(Json(json!({
            "enabled": false,
            "object": "twoFactorU2f",
        })))
    }
}

#[post("/two-factor/yubikey", data = "<data>")]
async fn activate_yubikey(data: Json<EnableYubikeyData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: EnableYubikeyData = data.into_inner();
    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash.clone(),
        otp: data.otp.clone(),
    }
    .validate(&user, true, &mut conn)
    .await?;

    // Check if we already have some data
    let mut yubikey_data =
        match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &mut conn).await {
            Some(data) => data,
            None => TwoFactor::new(user.uuid.clone(), TwoFactorType::YubiKey, String::new()),
        };

    let yubikeys = parse_yubikeys(&data);

    if yubikeys.is_empty() {
        return Ok(Json(json!({
            "enabled": false,
            "object": "twoFactorU2f",
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
        keys: yubikey_ids,
        nfc: data.nfc,
    };

    yubikey_data.data = serde_json::to_string(&yubikey_metadata).unwrap();
    yubikey_data.save(&mut conn).await?;

    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    let mut result = jsonify_yubikeys(yubikey_metadata.keys);

    result["enabled"] = Value::Bool(true);
    result["nfc"] = Value::Bool(yubikey_metadata.nfc);
    result["object"] = Value::String("twoFactorU2f".to_owned());

    Ok(Json(result))
}

#[put("/two-factor/yubikey", data = "<data>")]
async fn activate_yubikey_put(data: Json<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_yubikey(data, headers, conn).await
}

pub async fn validate_yubikey_login(response: &str, twofactor_data: &str) -> EmptyResult {
    if response.len() != 44 {
        err!("Invalid Yubikey OTP length");
    }

    let yubikey_metadata: YubikeyMetadata = serde_json::from_str(twofactor_data).expect("Can't parse Yubikey Metadata");
    let response_id = &response[..12];

    if !yubikey_metadata.keys.contains(&response_id.to_owned()) {
        err!("Given Yubikey is not registered");
    }

    verify_yubikey_otp(response.to_owned()).await.map_res("Failed to verify Yubikey against OTP server")?;
    Ok(())
}
