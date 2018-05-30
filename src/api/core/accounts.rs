use rocket_contrib::Json;

use db::DbConn;
use db::models::*;

use api::{PasswordData, JsonResult, EmptyResult};
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
fn register(data: Json<RegisterData>, conn: DbConn) -> EmptyResult {
    let data: RegisterData = data.into_inner();

    if !CONFIG.signups_allowed {
        err!(format!("Signups not allowed"))
    }

    if let Some(_) = User::find_by_mail(&data.email, &conn) {
        err!("Email already exists")
    }

    let mut user = User::new(data.email, data.key, data.masterPasswordHash);

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(hint) = data.masterPasswordHint {
        user.password_hint = Some(hint);
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encryptedPrivateKey);
        user.public_key = Some(keys.publicKey);
    }

    user.save(&conn);

    Ok(())
}

#[get("/accounts/profile")]
fn profile(headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(headers.user.to_json(&conn)))
}

#[get("/users/<uuid>/public-key")]
fn get_public_keys(uuid: String, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist")
    };

    Ok(Json(json!({
        "UserId": user.uuid,
        "PublicKey": user.public_key,
        "Object":"userKey"
    })))
}

#[post("/accounts/keys", data = "<data>")]
fn post_keys(data: Json<KeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner();

    let mut user = headers.user;

    user.private_key = Some(data.encryptedPrivateKey);
    user.public_key = Some(data.publicKey);

    user.save(&conn);

    Ok(Json(user.to_json(&conn)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangePassData {
    masterPasswordHash: String,
    newMasterPasswordHash: String,
    key: String,
}

#[post("/accounts/password", data = "<data>")]
fn post_password(data: Json<ChangePassData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password")
    }

    user.set_password(&data.newMasterPasswordHash);
    user.key = data.key;
    user.save(&conn);

    Ok(())
}

#[post("/accounts/security-stamp", data = "<data>")]
fn post_sstamp(data: Json<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password")
    }

    user.reset_security_stamp();
    user.save(&conn);

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangeEmailData {
    masterPasswordHash: String,
    newEmail: String,
}


#[post("/accounts/email-token", data = "<data>")]
fn post_email(data: Json<ChangeEmailData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ChangeEmailData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.newEmail, &conn).is_some() {
        err!("Email already in use");
    }

    user.email = data.newEmail;
    user.save(&conn);

    Ok(())
}

#[post("/accounts/delete", data = "<data>")]
fn delete_account(data: Json<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner();
    let user = headers.user;

    if !user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password")
    }

    // Delete ciphers and their attachments
    for cipher in Cipher::find_owned_by_user(&user.uuid, &conn) {
        match cipher.delete(&conn) {
            Ok(()) => (),
            Err(_) => err!("Failed deleting cipher")
        }
    }

    // Delete folders
    for f in Folder::find_by_user(&user.uuid, &conn) {
        match f.delete(&conn) {
            Ok(()) => (),
            Err(_) => err!("Failed deleting folder")
        } 
    }

    // Delete devices
    for d in Device::find_by_user(&user.uuid, &conn) { d.delete(&conn); }

    // Delete user
    user.delete(&conn);

    Ok(())
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> String {
    let revision_date = headers.user.updated_at.timestamp();
    revision_date.to_string()
}
