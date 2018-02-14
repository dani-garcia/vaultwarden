mod accounts;
mod ciphers;
mod folders;
mod two_factor;

use self::accounts::*;
use self::ciphers::*;
use self::folders::*;
use self::two_factor::*;

pub fn routes() -> Vec<Route> {
    routes![
        register,
        profile,
        post_keys,
        post_password,
        post_sstamp,
        post_email,
        delete_account,
        revision_date,

        sync,

        get_ciphers,
        get_cipher,
        post_ciphers,
        post_ciphers_import,
        post_attachment,
        delete_attachment_post,
        delete_attachment,
        post_cipher,
        put_cipher,
        delete_cipher,
        delete_all,

        get_folders,
        get_folder,
        post_folders,
        post_folder,
        put_folder,
        delete_folder_post,
        delete_folder,

        get_twofactor,
        get_recover,
        generate_authenticator,
        activate_authenticator,
        disable_authenticator,

        get_collections,

        clear_device_token,
        put_device_token,

        get_eq_domains,
        post_eq_domains
    ]
}

///
/// Move this somewhere else
///

use rocket::Route;
use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;
use util;

use auth::Headers;


// GET /api/collections?writeOnly=false
#[get("/collections")]
fn get_collections() -> Result<Json, BadRequest<Json>> {
    Ok(Json(json!({
        "Data": [],
        "Object": "list"
    })))
}


#[put("/devices/identifier/<uuid>/clear-token")]
fn clear_device_token(uuid: String) -> Result<Json, BadRequest<Json>> { err!("Not implemented") }

#[put("/devices/identifier/<uuid>/token")]
fn put_device_token(uuid: String) -> Result<Json, BadRequest<Json>> { err!("Not implemented") }


#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EquivDomainData {
    ExcludedGlobalEquivalentDomains: Vec<i32>,
    EquivalentDomains: Vec<Vec<String>>,
}

#[get("/settings/domains")]
fn get_eq_domains() -> Result<Json, BadRequest<Json>> {
    err!("Not implemented")
}

#[post("/settings/domains", data = "<data>")]
fn post_eq_domains(data: Json<EquivDomainData>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let excluded_globals = &data.ExcludedGlobalEquivalentDomains;
    let equivalent_domains = &data.EquivalentDomains;

    let mut user = headers.user;


    //BODY. "{\"ExcludedGlobalEquivalentDomains\":[2],\"EquivalentDomains\":[[\"uoc.edu\",\"uoc.es\"]]}"

    err!("Not implemented")
}
