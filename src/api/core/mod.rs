pub mod accounts;
mod ciphers;
mod emergency_access;
mod events;
mod folders;
mod organizations;
mod sends;
pub mod two_factor;

pub use ciphers::{purge_trashed_ciphers, CipherData, CipherSyncData, CipherSyncType};
pub use emergency_access::{emergency_notification_reminder_job, emergency_request_timeout_job};
pub use events::{event_cleanup_job, log_event, log_user_event};
pub use sends::purge_sends;
pub use two_factor::send_incomplete_2fa_notifications;

pub fn routes() -> Vec<Route> {
    let mut device_token_routes = routes![clear_device_token, put_device_token];
    let mut eq_domains_routes = routes![get_eq_domains, post_eq_domains, put_eq_domains];
    let mut hibp_routes = routes![hibp_breach];
    let mut meta_routes = routes![alive, now, version, config];

    let mut routes = Vec::new();
    routes.append(&mut accounts::routes());
    routes.append(&mut ciphers::routes());
    routes.append(&mut emergency_access::routes());
    routes.append(&mut events::routes());
    routes.append(&mut folders::routes());
    routes.append(&mut organizations::routes());
    routes.append(&mut two_factor::routes());
    routes.append(&mut sends::routes());
    routes.append(&mut device_token_routes);
    routes.append(&mut eq_domains_routes);
    routes.append(&mut hibp_routes);
    routes.append(&mut meta_routes);

    routes
}

pub fn events_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.append(&mut events::main_routes());

    routes
}

//
// Move this somewhere else
//
use rocket::{serde::json::Json, Catcher, Route};
use serde_json::Value;

use crate::{
    api::{JsonResult, JsonUpcase, Notify, UpdateType},
    auth::Headers,
    db::DbConn,
    error::Error,
    util::get_reqwest_client,
};

#[put("/devices/identifier/<uuid>/clear-token")]
fn clear_device_token(uuid: String) -> &'static str {
    // This endpoint doesn't have auth header

    let _ = uuid;
    // uuid is not related to deviceId

    // This only clears push token
    // https://github.com/bitwarden/core/blob/master/src/Api/Controllers/DevicesController.cs#L109
    // https://github.com/bitwarden/core/blob/master/src/Core/Services/Implementations/DeviceService.cs#L37
    ""
}

#[put("/devices/identifier/<uuid>/token", data = "<data>")]
fn put_device_token(uuid: String, data: JsonUpcase<Value>, headers: Headers) -> Json<Value> {
    let _data: Value = data.into_inner().data;
    // Data has a single string value "PushToken"
    let _ = uuid;
    // uuid is not related to deviceId

    // TODO: This should save the push token, but we don't have push functionality

    Json(json!({
        "Id": headers.device.uuid,
        "Name": headers.device.name,
        "Type": headers.device.atype,
        "Identifier": headers.device.uuid,
        "CreationDate": crate::util::format_date(&headers.device.created_at),
    }))
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct GlobalDomain {
    Type: i32,
    Domains: Vec<String>,
    Excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../static/global_domains.json");

#[get("/settings/domains")]
fn get_eq_domains(headers: Headers) -> Json<Value> {
    _get_eq_domains(headers, false)
}

fn _get_eq_domains(headers: Headers, no_excluded: bool) -> Json<Value> {
    let user = headers.user;
    use serde_json::from_str;

    let equivalent_domains: Vec<Vec<String>> = from_str(&user.equivalent_domains).unwrap();
    let excluded_globals: Vec<i32> = from_str(&user.excluded_globals).unwrap();

    let mut globals: Vec<GlobalDomain> = from_str(GLOBAL_DOMAINS).unwrap();

    for global in &mut globals {
        global.Excluded = excluded_globals.contains(&global.Type);
    }

    if no_excluded {
        globals.retain(|g| !g.Excluded);
    }

    Json(json!({
        "EquivalentDomains": equivalent_domains,
        "GlobalEquivalentDomains": globals,
        "Object": "domains",
    }))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EquivDomainData {
    ExcludedGlobalEquivalentDomains: Option<Vec<i32>>,
    EquivalentDomains: Option<Vec<Vec<String>>>,
}

#[post("/settings/domains", data = "<data>")]
async fn post_eq_domains(
    data: JsonUpcase<EquivDomainData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: EquivDomainData = data.into_inner().data;

    let excluded_globals = data.ExcludedGlobalEquivalentDomains.unwrap_or_default();
    let equivalent_domains = data.EquivalentDomains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_string());

    user.save(&mut conn).await?;

    nt.send_user_update(UpdateType::SyncSettings, &user).await;

    Ok(Json(json!({})))
}

#[put("/settings/domains", data = "<data>")]
async fn put_eq_domains(
    data: JsonUpcase<EquivDomainData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_eq_domains(data, headers, conn, nt).await
}

#[get("/hibp/breach?<username>")]
async fn hibp_breach(username: String) -> JsonResult {
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{username}?truncateResponse=false&includeUnverified=false"
    );

    if let Some(api_key) = crate::CONFIG.hibp_api_key() {
        let hibp_client = get_reqwest_client();

        let res = hibp_client.get(&url).header("hibp-api-key", api_key).send().await?;

        // If we get a 404, return a 404, it means no breached accounts
        if res.status() == 404 {
            return Err(Error::empty().with_code(404));
        }

        let value: Value = res.error_for_status()?.json().await?;
        Ok(Json(value))
    } else {
        Ok(Json(json!([{
            "Name": "HaveIBeenPwned",
            "Title": "Manual HIBP Check",
            "Domain": "haveibeenpwned.com",
            "BreachDate": "2019-08-18T00:00:00Z",
            "AddedDate": "2019-08-18T00:00:00Z",
            "Description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>"),
            "LogoPath": "vw_static/hibp.png",
            "PwnCount": 0,
            "DataClasses": [
                "Error - No API key set!"
            ]
        }])))
    }
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
#[get("/alive")]
fn alive(_conn: DbConn) -> Json<String> {
    now()
}

#[get("/now")]
pub fn now() -> Json<String> {
    Json(crate::util::format_date(&chrono::Utc::now().naive_utc()))
}

#[get("/version")]
fn version() -> Json<&'static str> {
    Json(crate::VERSION.unwrap_or_default())
}

#[get("/config")]
fn config() -> Json<Value> {
    let domain = crate::CONFIG.domain();
    Json(json!({
        "version": crate::VERSION,
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "",
        },
        "object": "config",
    }))
}

pub fn catchers() -> Vec<Catcher> {
    catchers![api_not_found]
}

#[catch(404)]
fn api_not_found() -> Json<Value> {
    Json(json!({
        "error": {
            "code": 404,
            "reason": "Not Found",
            "description": "The requested resource could not be found."
        }
    }))
}
