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
        get_public_keys,
        post_keys,
        post_password,
        post_sstamp,
        post_email,
        delete_account,
        revision_date,

        sync,

        get_ciphers,
        get_cipher,
        get_cipher_admin,
        get_cipher_details,
        post_ciphers,
        post_ciphers_admin,
        post_ciphers_import,
        post_attachment,
        delete_attachment_post,
        delete_attachment,
        post_cipher_admin,
        post_cipher_share,
        post_cipher,
        put_cipher,
        delete_cipher_post,
        delete_cipher,
        delete_cipher_selected,
        delete_all,
        move_cipher_selected,

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

        get_organization,
        create_organization,
        delete_organization,
        get_user_collections,
        get_org_collections,
        get_org_collection_detail,
        get_collection_users,
        post_organization,
        post_organization_collections,
        post_organization_collection_update,
        post_organization_collection_delete,
        post_collections_update,
        post_collections_admin,
        get_org_details,
        get_org_users,
        send_invite,
        confirm_invite,
        get_user,
        edit_user,
        delete_user,

        clear_device_token,
        put_device_token,

        get_eq_domains,
        post_eq_domains,

    ]
}

///
/// Move this somewhere else
///

use rocket::Route;

use rocket_contrib::Json;

use db::DbConn;

use api::{JsonResult, EmptyResult};
use auth::Headers;

#[put("/devices/identifier/<uuid>/clear-token")]
fn clear_device_token(uuid: String, conn: DbConn) -> JsonResult {
    err!("Not implemented")
}

#[put("/devices/identifier/<uuid>/token")]
fn put_device_token(uuid: String, conn: DbConn) -> JsonResult {
    err!("Not implemented")
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct GlobalDomain {
    Type: i32,
    Domains: Vec<String>,
    Excluded: bool,
}

const GLOBAL_DOMAINS: &'static str = include_str!("global_domains.json");

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
fn post_eq_domains(data: Json<EquivDomainData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: EquivDomainData = data.into_inner();

    let excluded_globals = data.ExcludedGlobalEquivalentDomains.unwrap_or(Vec::new());
    let equivalent_domains = data.EquivalentDomains.unwrap_or(Vec::new());

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or("[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or("[]".to_string());

    user.save(&conn);

    Ok(())
}
