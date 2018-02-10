use rocket::Route;
use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;
use util;

use auth::Headers;

use CONFIG;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct RegisterData {
    email: String,
    key: String,
    keys: Option<KeysData>,
    masterPasswordHash: String,
    masterPasswordHint: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct KeysData {
    encryptedPrivateKey: String,
    publicKey: String,
}

#[post("/accounts/register", data = "<data>")]
fn register(data: Json<RegisterData>, conn: DbConn) -> Result<(), BadRequest<Json>> {
    if CONFIG.signups_allowed {
        err!(format!("Signups not allowed"))
    }
    println!("DEBUG - {:#?}", data);

    if let Some(_) = User::find_by_mail(&data.email, &conn) {
        err!("Email already exists")
    }

    let mut user = User::new(data.email.clone(),
                             data.key.clone(),
                             data.masterPasswordHash.clone());

    // Add extra fields if present
    if let Some(name) = data.name.clone() {
        user.name = name;
    }

    if let Some(hint) = data.masterPasswordHint.clone() {
        user.password_hint = Some(hint);
    }

    if let Some(ref keys) = data.keys {
        user.private_key = Some(keys.encryptedPrivateKey.clone());
        user.public_key = Some(keys.publicKey.clone());
    }

    user.save(&conn);

    Ok(())
}

#[get("/accounts/profile")]
fn profile(headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    Ok(Json(headers.user.to_json()))
}

#[post("/accounts/keys", data = "<data>")]
fn post_keys(data: Json<KeysData>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let mut user = headers.user;

    user.private_key = Some(data.encryptedPrivateKey.clone());
    user.public_key = Some(data.publicKey.clone());

    user.save(&conn);

    Ok(Json(user.to_json()))
}

#[post("/accounts/password", data = "<data>")]
fn post_password(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let key = data["key"].as_str().unwrap();
    let password_hash = data["masterPasswordHash"].as_str().unwrap();
    let new_password_hash = data["newMasterPasswordHash"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    user.set_password(new_password_hash);
    user.key = key.to_string();

    user.save(&conn);

    Ok(Json(json!({})))
}

#[post("/accounts/security-stamp", data = "<data>")]
fn post_sstamp(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    user.reset_security_stamp();

    Ok(Json(json!({})))
}

#[post("/accounts/email-token", data = "<data>")]
fn post_email(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    println!("{:#?}", data);
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    err!("Not implemented")
}

#[post("/accounts/delete", data = "<data>")]
fn delete_account(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    err!("Not implemented")
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers, conn: DbConn) -> Result<String, BadRequest<Json>> {
    let revision_date = headers.user.updated_at.timestamp();
    Ok(revision_date.to_string())
}
