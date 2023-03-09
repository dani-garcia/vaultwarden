use chrono::Utc;
use data_encoding::BASE64;
use rocket::serde::json::Json;
use rocket::Route;

use crate::{
    api::{
        core::log_user_event, core::two_factor::_generate_recover_code, ApiResult, EmptyResult, JsonResult, JsonUpcase,
        PasswordData,
    },
    auth::Headers,
    crypto,
    db::{
        models::{EventType, TwoFactor, TwoFactorType, User},
        DbConn,
    },
    error::MapResult,
    util::get_reqwest_client,
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![get_duo, activate_duo, activate_duo_put,]
}

#[derive(Serialize, Deserialize)]
struct DuoData {
    host: String, // Duo API hostname
    ik: String,   // integration key
    sk: String,   // secret key
}

impl DuoData {
    fn global() -> Option<Self> {
        match (CONFIG._enable_duo(), CONFIG.duo_host()) {
            (true, Some(host)) => Some(Self {
                host,
                ik: CONFIG.duo_ikey().unwrap(),
                sk: CONFIG.duo_skey().unwrap(),
            }),
            _ => None,
        }
    }
    fn msg(s: &str) -> Self {
        Self {
            host: s.into(),
            ik: s.into(),
            sk: s.into(),
        }
    }
    fn secret() -> Self {
        Self::msg("<global_secret>")
    }
    fn obscure(self) -> Self {
        let mut host = self.host;
        let mut ik = self.ik;
        let mut sk = self.sk;

        let digits = 4;
        let replaced = "************";

        host.replace_range(digits.., replaced);
        ik.replace_range(digits.., replaced);
        sk.replace_range(digits.., replaced);

        Self {
            host,
            ik,
            sk,
        }
    }
}

enum DuoStatus {
    Global(DuoData),
    // Using the global duo config
    User(DuoData),
    // Using the user's config
    Disabled(bool), // True if there is a global setting
}

impl DuoStatus {
    fn data(self) -> Option<DuoData> {
        match self {
            DuoStatus::Global(data) => Some(data),
            DuoStatus::User(data) => Some(data),
            DuoStatus::Disabled(_) => None,
        }
    }
}

const DISABLED_MESSAGE_DEFAULT: &str = "<To use the global Duo keys, please leave these fields untouched>";

#[post("/two-factor/get-duo", data = "<data>")]
async fn get_duo(data: JsonUpcase<PasswordData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let data = get_user_duo_data(&headers.user.uuid, &mut conn).await;

    let (enabled, data) = match data {
        DuoStatus::Global(_) => (true, Some(DuoData::secret())),
        DuoStatus::User(data) => (true, Some(data.obscure())),
        DuoStatus::Disabled(true) => (false, Some(DuoData::msg(DISABLED_MESSAGE_DEFAULT))),
        DuoStatus::Disabled(false) => (false, None),
    };

    let json = if let Some(data) = data {
        json!({
            "Enabled": enabled,
            "Host": data.host,
            "SecretKey": data.sk,
            "IntegrationKey": data.ik,
            "Object": "twoFactorDuo"
        })
    } else {
        json!({
            "Enabled": enabled,
            "Object": "twoFactorDuo"
        })
    };

    Ok(Json(json))
}

#[derive(Deserialize)]
#[allow(non_snake_case, dead_code)]
struct EnableDuoData {
    MasterPasswordHash: String,
    Host: String,
    SecretKey: String,
    IntegrationKey: String,
}

impl From<EnableDuoData> for DuoData {
    fn from(d: EnableDuoData) -> Self {
        Self {
            host: d.Host,
            ik: d.IntegrationKey,
            sk: d.SecretKey,
        }
    }
}

fn check_duo_fields_custom(data: &EnableDuoData) -> bool {
    fn empty_or_default(s: &str) -> bool {
        let st = s.trim();
        st.is_empty() || s == DISABLED_MESSAGE_DEFAULT
    }

    !empty_or_default(&data.Host) && !empty_or_default(&data.SecretKey) && !empty_or_default(&data.IntegrationKey)
}

#[post("/two-factor/duo", data = "<data>")]
async fn activate_duo(data: JsonUpcase<EnableDuoData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: EnableDuoData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let (data, data_str) = if check_duo_fields_custom(&data) {
        let data_req: DuoData = data.into();
        let data_str = serde_json::to_string(&data_req)?;
        duo_api_request("GET", "/auth/v2/check", "", &data_req).await.map_res("Failed to validate Duo credentials")?;
        (data_req.obscure(), data_str)
    } else {
        (DuoData::secret(), String::new())
    };

    let type_ = TwoFactorType::Duo;
    let twofactor = TwoFactor::new(user.uuid.clone(), type_, data_str);
    twofactor.save(&mut conn).await?;

    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    Ok(Json(json!({
        "Enabled": true,
        "Host": data.host,
        "SecretKey": data.sk,
        "IntegrationKey": data.ik,
        "Object": "twoFactorDuo"
    })))
}

#[put("/two-factor/duo", data = "<data>")]
async fn activate_duo_put(data: JsonUpcase<EnableDuoData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_duo(data, headers, conn).await
}

async fn duo_api_request(method: &str, path: &str, params: &str, data: &DuoData) -> EmptyResult {
    use reqwest::{header, Method};
    use std::str::FromStr;

    // https://duo.com/docs/authapi#api-details
    let url = format!("https://{}{}", &data.host, path);
    let date = Utc::now().to_rfc2822();
    let username = &data.ik;
    let fields = [&date, method, &data.host, path, params];
    let password = crypto::hmac_sign(&data.sk, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    let client = get_reqwest_client();

    client
        .request(m, &url)
        .basic_auth(username, Some(password))
        .header(header::USER_AGENT, "vaultwarden:Duo/1.0 (Rust)")
        .header(header::DATE, date)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

const DUO_EXPIRE: i64 = 300;
const APP_EXPIRE: i64 = 3600;

const AUTH_PREFIX: &str = "AUTH";
const DUO_PREFIX: &str = "TX";
const APP_PREFIX: &str = "APP";

async fn get_user_duo_data(uuid: &str, conn: &mut DbConn) -> DuoStatus {
    let type_ = TwoFactorType::Duo as i32;

    // If the user doesn't have an entry, disabled
    let twofactor = match TwoFactor::find_by_user_and_type(uuid, type_, conn).await {
        Some(t) => t,
        None => return DuoStatus::Disabled(DuoData::global().is_some()),
    };

    // If the user has the required values, we use those
    if let Ok(data) = serde_json::from_str(&twofactor.data) {
        return DuoStatus::User(data);
    }

    // Otherwise, we try to use the globals
    if let Some(global) = DuoData::global() {
        return DuoStatus::Global(global);
    }

    // If there are no globals configured, just disable it
    DuoStatus::Disabled(false)
}

// let (ik, sk, ak, host) = get_duo_keys();
async fn get_duo_keys_email(email: &str, conn: &mut DbConn) -> ApiResult<(String, String, String, String)> {
    let data = match User::find_by_mail(email, conn).await {
        Some(u) => get_user_duo_data(&u.uuid, conn).await.data(),
        _ => DuoData::global(),
    }
    .map_res("Can't fetch Duo Keys")?;

    Ok((data.ik, data.sk, CONFIG.get_duo_akey(), data.host))
}

pub async fn generate_duo_signature(email: &str, conn: &mut DbConn) -> ApiResult<(String, String)> {
    let now = Utc::now().timestamp();

    let (ik, sk, ak, host) = get_duo_keys_email(email, conn).await?;

    let duo_sign = sign_duo_values(&sk, email, &ik, DUO_PREFIX, now + DUO_EXPIRE);
    let app_sign = sign_duo_values(&ak, email, &ik, APP_PREFIX, now + APP_EXPIRE);

    Ok((format!("{duo_sign}:{app_sign}"), host))
}

fn sign_duo_values(key: &str, email: &str, ikey: &str, prefix: &str, expire: i64) -> String {
    let val = format!("{email}|{ikey}|{expire}");
    let cookie = format!("{}|{}", prefix, BASE64.encode(val.as_bytes()));

    format!("{}|{}", cookie, crypto::hmac_sign(key, &cookie))
}

pub async fn validate_duo_login(email: &str, response: &str, conn: &mut DbConn) -> EmptyResult {
    // email is as entered by the user, so it needs to be normalized before
    // comparison with auth_user below.
    let email = &email.to_lowercase();

    let split: Vec<&str> = response.split(':').collect();
    if split.len() != 2 {
        err!(
            "Invalid response length",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        );
    }

    let auth_sig = split[0];
    let app_sig = split[1];

    let now = Utc::now().timestamp();

    let (ik, sk, ak, _host) = get_duo_keys_email(email, conn).await?;

    let auth_user = parse_duo_values(&sk, auth_sig, &ik, AUTH_PREFIX, now)?;
    let app_user = parse_duo_values(&ak, app_sig, &ik, APP_PREFIX, now)?;

    if !crypto::ct_eq(&auth_user, app_user) || !crypto::ct_eq(&auth_user, email) {
        err!(
            "Error validating duo authentication",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
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

    let sig = crypto::hmac_sign(key, &format!("{u_prefix}|{u_b64}"));

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

    let expire: i64 = match expire.parse() {
        Ok(e) => e,
        Err(_) => err!("Invalid expire time"),
    };

    if time >= expire {
        err!("Expired authorization")
    }

    Ok(username.into())
}
