mod accounts;
mod ciphers;
mod folders;
mod organizations;
mod two_factor;

use self::accounts::*;
use self::ciphers::*;
use self::folders::*;
use self::organizations::*;
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
        delete_cipher_post,
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
        recover,
        generate_authenticator,
        activate_authenticator,
        disable_authenticator,

        get_user_collections,

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

use rocket_contrib::{Json, Value};

use db::DbConn;

use api::JsonResult;
use auth::Headers;

#[put("/devices/identifier/<uuid>/clear-token")]
fn clear_device_token(uuid: String, conn: DbConn) -> JsonResult {
    err!("Not implemented")
}

#[put("/devices/identifier/<uuid>/token")]
fn put_device_token(uuid: String, conn: DbConn) -> JsonResult {
    err!("Not implemented")
}


#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EquivDomainData {
    ExcludedGlobalEquivalentDomains: Vec<i32>,
    EquivalentDomains: Vec<Vec<String>>,
}

#[get("/settings/domains")]
fn get_eq_domains() -> JsonResult {
    err!("Not implemented")
}

#[post("/settings/domains", data = "<data>")]
fn post_eq_domains(data: Json<EquivDomainData>, headers: Headers, conn: DbConn) -> JsonResult {
    let excluded_globals = &data.ExcludedGlobalEquivalentDomains;
    let equivalent_domains = &data.EquivalentDomains;

    let user = headers.user;

    //BODY. "{\"ExcludedGlobalEquivalentDomains\":[2],\"EquivalentDomains\":[[\"example.org\",\"example.net\"]]}"

    err!("Not implemented")
}
