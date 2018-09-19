mod accounts;
mod ciphers;
mod folders;
mod organizations;
pub(crate) mod two_factor;

use self::accounts::*;
use self::ciphers::*;
use self::folders::*;
use self::organizations::*;
use self::two_factor::*;

pub fn routes() -> Vec<Route> {
    routes![
        register,
        profile,
        put_profile,
        post_profile,
        get_public_keys,
        post_keys,
        post_password,
        post_kdf,
        post_sstamp,
        post_email_token,
        post_email,
        delete_account,
        post_delete_account,
        revision_date,
        password_hint,
        prelogin,

        sync,

        get_ciphers,
        get_cipher,
        get_cipher_admin,
        get_cipher_details,
        post_ciphers,
        put_cipher_admin,
        post_ciphers_admin,
        post_ciphers_import,
        post_attachment,
        post_attachment_admin,
        post_attachment_share,
        delete_attachment_post,
        delete_attachment_post_admin,
        delete_attachment,
        delete_attachment_admin,
        post_cipher_admin,
        post_cipher_share,
        put_cipher_share,
        put_cipher_share_seleted,
        post_cipher,
        put_cipher,
        delete_cipher_post,
        delete_cipher_post_admin,
        delete_cipher,
        delete_cipher_admin,
        delete_cipher_selected,
        delete_cipher_selected_post,
        delete_all,
        move_cipher_selected,
        move_cipher_selected_put,

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
        disable_twofactor,
        disable_twofactor_put,
        generate_authenticator,
        activate_authenticator,
        activate_authenticator_put,
        generate_u2f,
        activate_u2f,
        activate_u2f_put,

        get_organization,
        create_organization,
        delete_organization,
        post_delete_organization,
        leave_organization,
        get_user_collections,
        get_org_collections,
        get_org_collection_detail,
        get_collection_users,
        put_organization,
        post_organization,
        post_organization_collections,
        delete_organization_collection_user,
        post_organization_collection_delete_user,
        post_organization_collection_update,
        put_organization_collection_update,
        delete_organization_collection,
        post_organization_collection_delete,
        post_collections_update,
        post_collections_admin,
        put_collections_admin,
        get_org_details,
        get_org_users,
        send_invite,
        confirm_invite,
        get_user,
        edit_user,
        put_organization_user,
        delete_user,
        post_delete_user,
        post_org_import,

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

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use api::{JsonResult, EmptyResult, JsonUpcase};
use auth::Headers;

#[put("/devices/identifier/<uuid>/clear-token", data = "<data>")]
fn clear_device_token(uuid: String, data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let _data: Value = data.into_inner();
    
    let device = match Device::find_by_uuid(&uuid, &conn) {
        Some(device) => device,
        None => err!("Device not found")
    };

    if device.user_uuid != headers.user.uuid {
        err!("Device not owned by user")
    }

    device.delete(&conn);

    Ok(())
}

#[put("/devices/identifier/<uuid>/token", data = "<data>")]
fn put_device_token(uuid: String, data: Json<Value>, headers: Headers, conn: DbConn) -> JsonResult {
    let _data: Value = data.into_inner();
    
    let device = match Device::find_by_uuid(&uuid, &conn) {
        Some(device) => device,
        None => err!("Device not found")
    };

    if device.user_uuid != headers.user.uuid {
        err!("Device not owned by user")
    }

    // TODO: What does this do?

    err!("Not implemented")
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
fn post_eq_domains(data: JsonUpcase<EquivDomainData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: EquivDomainData = data.into_inner().data;

    let excluded_globals = data.ExcludedGlobalEquivalentDomains.unwrap_or_default();
    let equivalent_domains = data.EquivalentDomains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or("[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or("[]".to_string());

    user.save(&conn);

    Ok(())
}
