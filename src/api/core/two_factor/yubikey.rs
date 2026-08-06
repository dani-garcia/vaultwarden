use rocket::{Route, serde::json::Json};
use serde_json::Value;
use yubico_ng::{
    Verifier, YubicoError,
    config::Config,
    transport::{AsyncTransport, Response},
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
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType},
    },
    error::{Error, MapResult},
    http_client,
};

pub fn routes() -> Vec<Route> {
    routes![generate_yubikey, activate_yubikey, activate_yubikey_put, delete_yubikeys,]
}

struct HttpClientTransport {
    client: reqwest::Client,
}

impl HttpClientTransport {
    fn new() -> Result<Self, reqwest::Error> {
        http_client::get_reqwest_client_builder(false).redirect(reqwest::redirect::Policy::none()).build().map(
            |client| Self {
                client,
            },
        )
    }
}

impl AsyncTransport for HttpClientTransport {
    type Error = YubicoError;

    async fn yubico_get(&self, url: &str) -> Result<Response, Self::Error> {
        let response = self.client.get(url).send().await.map_err(YubicoError::transport)?;
        Ok(Response {
            status: response.status().as_u16(),
            body: response.text().await.map_err(YubicoError::transport)?,
        })
    }
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
    user_verification_token: String,
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
    data_keys.into_iter().flatten().filter(|e| !e.is_empty()).cloned().collect()
}

fn jsonify_yubikeys(yubikeys: Vec<String>) -> Value {
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

    if let (Some(id), Some(secret)) = (CONFIG.yubico_client_id(), CONFIG.yubico_secret_key()) {
        Ok((id, secret))
    } else {
        err!("`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled")
    }
}

async fn verify_yubikey_otp(otp: String) -> EmptyResult {
    let (yubico_id, yubico_secret) = get_yubico_credentials()?;

    let mut config = Config::default().set_client_id(yubico_id).set_key(yubico_secret)?;
    if let Some(yubico_server) = CONFIG.yubico_server() {
        config = config.set_api_host(yubico_server);
    }

    let client = HttpClientTransport::new()?;
    let verifier = Verifier::with_client(config, client)?;

    verifier.verify(otp).await.map_res("Failed to verify OTP")
}

#[post("/two-factor/get-yubikey", data = "<data>")]
async fn generate_yubikey(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    // Make sure the credentials are set
    get_yubico_credentials()?;

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let user_id = &user.uuid;
    let yubikey_type = TwoFactorType::YubiKey as i32;

    let (enabled, keys, yubikey_json) =
        if let Some(r) = TwoFactor::find_by_user_and_type(user_id, yubikey_type, &conn).await {
            let yubikey_metadata: YubikeyMetadata = serde_json::from_str(&r.data)?;
            let enabled = !yubikey_metadata.keys.is_empty();
            let mut result = jsonify_yubikeys(yubikey_metadata.keys.clone());
            result["enabled"] = Value::Bool(enabled);
            result["nfc"] = Value::Bool(yubikey_metadata.nfc);
            (enabled, yubikey_metadata.keys, result)
        } else {
            (false, Vec::new(), json!({"enabled": false}))
        };
    Ok(Json(json!({
        "yubiKey": yubikey_json,
        "userVerificationToken": two_factor::yubikey_token(user.uuid, keys, enabled),
    })))
}

#[post("/two-factor/yubikey", data = "<data>")]
async fn activate_yubikey(data: Json<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableYubikeyData = data.into_inner();
    let yubikeys = parse_yubikeys(&data);
    let mut user = headers.user;

    two_factor::validate_yubikey(&data.user_verification_token, &user.uuid, &yubikeys, yubikeys.is_empty())?;

    // Check if we already have some data
    let mut yubikey_data =
        match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &conn).await {
            Some(data) => data,
            None => TwoFactor::new(user.uuid.clone(), TwoFactorType::YubiKey, String::new()),
        };

    if yubikeys.is_empty() {
        // Return an error to prevent saving empty keys which would cause users not being able to login anymore.
        // To remove all keys users should click the `Deactivate all keys` button
        err!("A key is required.");
    }

    // Ensure they are valid OTPs
    for yubikey in &yubikeys {
        if yubikey.is_empty() || yubikey.len() == 12 {
            continue;
        }

        verify_yubikey_otp(yubikey.to_owned()).await.map_res("Invalid Yubikey OTP provided")?;
    }

    let yubikey_ids: Vec<String> = yubikeys.into_iter().filter_map(|x| x.get(..12).map(str::to_owned)).collect();

    let yubikey_metadata = YubikeyMetadata {
        keys: yubikey_ids,
        nfc: data.nfc,
    };

    yubikey_data.data = serde_json::to_string(&yubikey_metadata).unwrap();
    yubikey_data.save(&conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    let mut result = jsonify_yubikeys(yubikey_metadata.keys);
    result["enabled"] = Value::Bool(true);
    result["nfc"] = Value::Bool(yubikey_metadata.nfc);
    Ok(Json(json!({"yubiKey": result})))
}

#[put("/two-factor/yubikey", data = "<data>")]
async fn activate_yubikey_put(data: Json<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_yubikey(data, headers, conn).await
}

#[delete("/two-factor/yubikey", data = "<data>")]
async fn delete_yubikeys(data: Json<VerificationTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let user = headers.user;

    if let Some(r) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &conn).await {
        let yubikey_metadata: YubikeyMetadata = serde_json::from_str(&r.data)?;
        two_factor::validate_yubikey(&data.user_verification_token, &user.uuid, &yubikey_metadata.keys, true)?;

        r.delete(&conn).await?;
        log_user_event(EventType::UserDisabled2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
            .await;
    }

    if TwoFactor::find_by_user(&user.uuid, &conn).await.is_empty() {
        super::enforce_2fa_policy(&user, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await?;
    }

    Ok(())
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
