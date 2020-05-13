use data_encoding::BASE32;
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::api::{JsonResult, JsonUpcase, NumberOrString, PasswordData};
use crate::auth::Headers;
use crate::crypto;
use crate::db::{
    models::{TwoFactor, User},
    DbConn,
};

pub mod authenticator;
pub mod duo;
pub mod email;
pub mod u2f;
pub mod yubikey;

pub fn routes() -> Vec<Route> {
    let mut routes = routes![
        get_twofactor,
        get_recover,
        recover,
        disable_twofactor,
        disable_twofactor_put,
    ];

    routes.append(&mut authenticator::routes());
    routes.append(&mut duo::routes());
    routes.append(&mut email::routes());
    routes.append(&mut u2f::routes());
    routes.append(&mut yubikey::routes());

    routes
}

#[get("/two-factor")]
fn get_twofactor(headers: Headers, conn: DbConn) -> JsonResult {
    let twofactors = TwoFactor::find_by_user(&headers.user.uuid, &conn);
    let twofactors_json: Vec<Value> = twofactors.iter().map(TwoFactor::to_json_provider).collect();

    Ok(Json(json!({
        "Data": twofactors_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[post("/two-factor/get-recover", data = "<data>")]
fn get_recover(data: JsonUpcase<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": user.totp_recover,
        "Object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RecoverTwoFactor {
    MasterPasswordHash: String,
    Email: String,
    RecoveryCode: String,
}

#[post("/two-factor/recover", data = "<data>")]
fn recover(data: JsonUpcase<RecoverTwoFactor>, conn: DbConn) -> JsonResult {
    let data: RecoverTwoFactor = data.into_inner().data;

    use crate::db::models::User;

    // Get the user
    let mut user = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.RecoveryCode) {
        err!("Recovery code is incorrect. Try again.")
    }

    // Remove all twofactors from the user
    TwoFactor::delete_all_by_user(&user.uuid, &conn)?;

    // Remove the recovery code, not needed without twofactors
    user.totp_recover = None;
    user.save(&conn)?;
    Ok(Json(json!({})))
}

fn _generate_recover_code(user: &mut User, conn: &DbConn) {
    if user.totp_recover.is_none() {
        let totp_recover = BASE32.encode(&crypto::get_random(vec![0u8; 20]));
        user.totp_recover = Some(totp_recover);
        user.save(conn).ok();
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DisableTwoFactorData {
    MasterPasswordHash: String,
    Type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
fn disable_twofactor(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let type_ = data.Type.into_i32()?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn) {
        twofactor.delete(&conn)?;
    }

    Ok(Json(json!({
        "Enabled": false,
        "Type": type_,
        "Object": "twoFactorProvider"
    })))
}

#[put("/two-factor/disable", data = "<data>")]
fn disable_twofactor_put(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    disable_twofactor(data, headers, conn)
}
