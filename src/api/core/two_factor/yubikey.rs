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
        core::{log_user_event, two_factor::generate_recover_code},
    },
    auth::Headers,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType},
    },
    error::{Error, MapResult},
    http_client,
};

pub fn routes() -> Vec<Route> {
    routes![generate_yubikey, activate_yubikey, activate_yubikey_put,]
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

    let r = TwoFactor::find_by_user_and_type(user_id, yubikey_type, &conn).await;

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
async fn activate_yubikey(data: Json<EnableYubikeyData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableYubikeyData = data.into_inner();
    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash.clone(),
        otp: data.otp.clone(),
    }
    .validate(&user, true, &conn)
    .await?;

    // Check if we already have some data
    let mut yubikey_data =
        match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::YubiKey as i32, &conn).await {
            Some(data) => data,
            None => TwoFactor::new(user.uuid.clone(), TwoFactorType::YubiKey, String::new()),
        };

    let yubikeys = parse_yubikeys(&data);

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
