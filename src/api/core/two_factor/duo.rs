use chrono::Utc;
use rocket::{Route, serde::json::Json};

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult, PasswordOrOtpData, core::log_user_event,
        core::two_factor::generate_recover_code,
    },
    auth::Headers,
    crypto,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType, User, UserId},
    },
    error::MapResult,
    http_client::make_http_request,
};

pub fn routes() -> Vec<Route> {
    routes![get_duo, activate_duo, activate_duo_put,]
}

#[derive(Serialize, Deserialize)]
struct DuoData {
    host: String, // Duo API hostname
    ik: String,   // client id
    sk: String,   // client secret
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
            DuoStatus::Global(data) | DuoStatus::User(data) => Some(data),
            DuoStatus::Disabled(_) => None,
        }
    }
}

const DISABLED_MESSAGE_DEFAULT: &str = "<To use the global Duo keys, please leave these fields untouched>";

#[post("/two-factor/get-duo", data = "<data>")]
async fn get_duo(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let data = get_user_duo_data(&user.uuid, &conn).await;

    let (enabled, data) = match data {
        DuoStatus::Global(_) => (true, Some(DuoData::secret())),
        DuoStatus::User(data) => (true, Some(data.obscure())),
        DuoStatus::Disabled(true) => (false, Some(DuoData::msg(DISABLED_MESSAGE_DEFAULT))),
        DuoStatus::Disabled(false) => (false, None),
    };

    let json = if let Some(data) = data {
        json!({
            "enabled": enabled,
            "host": data.host,
            "clientSecret": data.sk,
            "clientId": data.ik,
            "object": "twoFactorDuo"
        })
    } else {
        json!({
            "enabled": enabled,
            "host": null,
            "clientSecret": null,
            "clientId": null,
            "object": "twoFactorDuo"
        })
    };

    Ok(Json(json))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableDuoData {
    host: String,
    client_secret: String,
    client_id: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl From<EnableDuoData> for DuoData {
    fn from(d: EnableDuoData) -> Self {
        Self {
            host: d.host,
            ik: d.client_id,
            sk: d.client_secret,
        }
    }
}

fn check_duo_fields_custom(data: &EnableDuoData) -> bool {
    fn empty_or_default(s: &str) -> bool {
        let st = s.trim();
        st.is_empty() || s == DISABLED_MESSAGE_DEFAULT
    }

    !empty_or_default(&data.host) && !empty_or_default(&data.client_secret) && !empty_or_default(&data.client_id)
}

#[post("/two-factor/duo", data = "<data>")]
async fn activate_duo(data: Json<EnableDuoData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableDuoData = data.into_inner();
    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash.clone(),
        otp: data.otp.clone(),
    }
    .validate(&user, true, &conn)
    .await?;

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
    twofactor.save(&conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    Ok(Json(json!({
        "enabled": true,
        "host": data.host,
        "clientSecret": data.sk,
        "clientId": data.ik,
        "object": "twoFactorDuo"
    })))
}

#[put("/two-factor/duo", data = "<data>")]
async fn activate_duo_put(data: Json<EnableDuoData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_duo(data, headers, conn).await
}

async fn duo_api_request(method: &str, path: &str, params: &str, data: &DuoData) -> EmptyResult {
    use reqwest::{Method, header};
    use std::str::FromStr;

    // https://duo.com/docs/authapi#api-details
    let url = format!("https://{}{path}", data.host);
    let dt = Utc::now().to_rfc2822();
    let username = &data.ik;
    let fields = [&dt, method, &data.host, path, params];
    let password = crypto::hmac_sign(&data.sk, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    make_http_request(m, &url)?
        .basic_auth(username, Some(password))
        .header(header::USER_AGENT, "vaultwarden:Duo/1.0 (Rust)")
        .header(header::DATE, dt)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn get_user_duo_data(user_id: &UserId, conn: &DbConn) -> DuoStatus {
    let type_ = TwoFactorType::Duo as i32;

    // If the user doesn't have an entry, disabled
    let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, type_, conn).await else {
        return DuoStatus::Disabled(DuoData::global().is_some());
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

// let (ik, sk, host) = get_duo_keys_email();
pub(crate) async fn get_duo_keys_email(email: &str, conn: &DbConn) -> ApiResult<(String, String, String)> {
    let data = match User::find_by_mail(email, conn).await {
        Some(u) => get_user_duo_data(&u.uuid, conn).await.data(),
        _ => DuoData::global(),
    }
    .map_res("Can't fetch Duo Keys")?;

    Ok((data.ik, data.sk, data.host))
}
