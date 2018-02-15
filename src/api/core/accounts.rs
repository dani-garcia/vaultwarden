use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

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
    if !CONFIG.signups_allowed {
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
fn profile(headers: Headers) -> Result<Json, BadRequest<Json>> {
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
fn post_password(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
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

    Ok(())
}

#[post("/accounts/security-stamp", data = "<data>")]
fn post_sstamp(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    user.reset_security_stamp();
    user.save(&conn);

    Ok(())
}

#[post("/accounts/email-token", data = "<data>")]
fn post_email(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();
    let new_email = data["newEmail"].as_str().unwrap();

    let mut user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(new_email, &conn).is_some() {
        err!("Email already in use");
    }

    user.email = new_email.to_string();
    user.save(&conn);

    Ok(())
}

#[post("/accounts/delete", data = "<data>")]
fn delete_account(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    // Delete ciphers and their attachments
    for cipher in Cipher::find_by_user(&user.uuid, &conn) {
        for a in Attachment::find_by_cipher(&cipher.uuid, &conn) { a.delete(&conn); }

        cipher.delete(&conn);
    }

    // Delete folders
    for f in Folder::find_by_user(&user.uuid, &conn) { f.delete(&conn); }

    // Delete devices
    for d in Device::find_by_user(&user.uuid, &conn) { d.delete(&conn); }

    // Delete user
    user.delete(&conn);

    Ok(())
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> Result<String, BadRequest<Json>> {
    let revision_date = headers.user.updated_at.timestamp();
    Ok(revision_date.to_string())
}
