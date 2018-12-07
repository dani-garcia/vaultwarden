mod accounts;
mod ciphers;
mod folders;
mod organizations;
pub(crate) mod two_factor;

pub fn routes() -> Vec<Route> {
    let mut mod_routes = routes![
        clear_device_token,
        put_device_token,

        get_eq_domains,
        post_eq_domains,
        put_eq_domains,
    ];

    let mut routes = Vec::new();
    routes.append(&mut accounts::routes());
    routes.append(&mut ciphers::routes());
    routes.append(&mut folders::routes());
    routes.append(&mut organizations::routes());
    routes.append(&mut two_factor::routes());
    routes.append(&mut mod_routes);

    routes
}

///
/// Move this somewhere else
///

use rocket::Route;

use rocket_contrib::json::Json;
use serde_json::Value;

use crate::db::DbConn;
use crate::db::models::*;

use crate::api::{JsonResult, EmptyResult, JsonUpcase};
use crate::auth::Headers;

#[put("/devices/identifier/<uuid>/clear-token")]
fn clear_device_token(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    let device = match Device::find_by_uuid(&uuid, &conn) {
        Some(device) => device,
        None => err!("Device not found")
    };

    if device.user_uuid != headers.user.uuid {
        err!("Device not owned by user")
    }

    // This only clears push token
    // https://github.com/bitwarden/core/blob/master/src/Api/Controllers/DevicesController.cs#L109
    // https://github.com/bitwarden/core/blob/master/src/Core/Services/Implementations/DeviceService.cs#L37
    Ok(())
}

#[put("/devices/identifier/<uuid>/token", data = "<data>")]
fn put_device_token(uuid: String, data: JsonUpcase<Value>, headers: Headers, conn: DbConn) -> JsonResult {
    let _data: Value = data.into_inner().data;

    let device = match Device::find_by_uuid(&uuid, &conn) {
        Some(device) => device,
        None => err!("Device not found")
    };

    if device.user_uuid != headers.user.uuid {
        err!("Device not owned by user")
    }

    // This should save the push token, but we don't have push functionality

    use crate::util::format_date;

    Ok(Json(json!({
        "Id": device.uuid,
        "Name": device.name,
        "Type": device.type_,
        "Identifier": device.uuid,
        "CreationDate": format_date(&device.created_at),
    })))
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct GlobalDomain {
    Type: i32,
    Domains: Vec<String>,
    Excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("global_domains.json");

#[get("/settings/domains")]
fn get_eq_domains(headers: Headers) -> JsonResult {
    let user = headers.user;
    use serde_json::from_str;

    let equivalent_domains: Vec<Vec<String>> = from_str(&user.equivalent_domains).unwrap();
    let excluded_globals: Vec<i32> = from_str(&user.excluded_globals).unwrap();

    let mut globals: Vec<GlobalDomain> = from_str(GLOBAL_DOMAINS).unwrap();

    for global in &mut globals {
        global.Excluded = excluded_globals.contains(&global.Type);
    }

    Ok(Json(json!({
        "EquivalentDomains": equivalent_domains,
        "GlobalEquivalentDomains": globals,
        "Object": "domains",
    })))
}


#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EquivDomainData {
    ExcludedGlobalEquivalentDomains: Option<Vec<i32>>,
    EquivalentDomains: Option<Vec<Vec<String>>>,
}

#[post("/settings/domains", data = "<data>")]
fn post_eq_domains(data: JsonUpcase<EquivDomainData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EquivDomainData = data.into_inner().data;

    let excluded_globals = data.ExcludedGlobalEquivalentDomains.unwrap_or_default();
    let equivalent_domains = data.EquivalentDomains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or("[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or("[]".to_string());

    match user.save(&conn) {
        Ok(()) => Ok(Json(json!({}))),
        Err(_) => err!("Failed to save user")
    }

}

#[put("/settings/domains", data = "<data>")]
fn put_eq_domains(data: JsonUpcase<EquivDomainData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_eq_domains(data, headers, conn)
}
