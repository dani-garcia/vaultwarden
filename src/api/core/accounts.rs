use rocket_contrib::json::Json;

use crate::db::models::*;
use crate::db::DbConn;

use crate::api::{EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData, UpdateType, WebSocketUsers};
use crate::auth::{Headers, decode_invite_jwt, InviteJWTClaims};
use crate::mail;

use crate::CONFIG;

use rocket::{Route, State};

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
        post_rotatekey,
        post_sstamp,
        post_email_token,
        post_email,
        delete_account,
        post_delete_account,
        revision_date,
        password_hint,
        prelogin,
    ]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct RegisterData {
    Email: String,
    Kdf: Option<i32>,
    KdfIterations: Option<i32>,
    Key: String,
    Keys: Option<KeysData>,
    MasterPasswordHash: String,
    MasterPasswordHint: Option<String>,
    Name: Option<String>,
    Token: Option<String>,
    OrganizationUserId: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct KeysData {
    EncryptedPrivateKey: String,
    PublicKey: String,
}

#[post("/accounts/register", data = "<data>")]
fn register(data: JsonUpcase<RegisterData>, conn: DbConn) -> EmptyResult {
    let data: RegisterData = data.into_inner().data;

    let mut user = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => {
            if Invitation::find_by_mail(&data.Email, &conn).is_some() {
                if CONFIG.mail.is_none() {
                    for mut user_org in UserOrganization::find_invited_by_user(&user.uuid, &conn).iter_mut() {
                        user_org.status = UserOrgStatus::Accepted as i32;
                        user_org.save(&conn)?;
                    }
                    if !Invitation::take(&data.Email, &conn) {
                        err!("Error accepting invitation")
                    }
                    user
                } else {
                    let token = match &data.Token {
                        Some(token) => token,
                        None => err!("No valid invite token")
                    };
                    let claims: InviteJWTClaims = match decode_invite_jwt(&token) {
                        Ok(claims) => claims,
                        Err(msg) => err!("Invalid claim: {:#?}", msg),
                    };
                    if &claims.email == &data.Email {
                        user
                    } else {
                        err!("Registration email does not match invite email")
                    }
                }
            } else if CONFIG.signups_allowed {
                    err!("Account with this email already exists")
            } else {
                err!("Registration not allowed")
            }
        }
        None => {
            if CONFIG.signups_allowed || (CONFIG.mail.is_none() && Invitation::take(&data.Email, &conn)) {
                User::new(data.Email)
            } else {
                err!("Registration not allowed")
            }
        }
    };

    if let Some(client_kdf_iter) = data.KdfIterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    if let Some(client_kdf_type) = data.Kdf {
        user.client_kdf_type = client_kdf_type;
    }

    user.set_password(&data.MasterPasswordHash);
    user.key = data.Key;

    // Add extra fields if present
    if let Some(name) = data.Name {
        user.name = name;
    }

    if let Some(hint) = data.MasterPasswordHint {
        user.password_hint = Some(hint);
    }

    if let Some(keys) = data.Keys {
        user.private_key = Some(keys.EncryptedPrivateKey);
        user.public_key = Some(keys.PublicKey);
    }

    user.save(&conn)
}

#[get("/accounts/profile")]
fn profile(headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(headers.user.to_json(&conn)))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct ProfileData {
    #[serde(rename = "Culture")]
    _Culture: String, // Ignored, always use en-US
    MasterPasswordHint: Option<String>,
    Name: String,
}

#[put("/accounts/profile", data = "<data>")]
fn put_profile(data: JsonUpcase<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn)
}

#[post("/accounts/profile", data = "<data>")]
fn post_profile(data: JsonUpcase<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner().data;

    let mut user = headers.user;

    user.name = data.Name;
    user.password_hint = match data.MasterPasswordHint {
        Some(ref h) if h.is_empty() => None,
        _ => data.MasterPasswordHint,
    };
    user.save(&conn)?;
    Ok(Json(user.to_json(&conn)))
}

#[get("/users/<uuid>/public-key")]
fn get_public_keys(uuid: String, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    Ok(Json(json!({
        "UserId": user.uuid,
        "PublicKey": user.public_key,
        "Object":"userKey"
    })))
}

#[post("/accounts/keys", data = "<data>")]
fn post_keys(data: JsonUpcase<KeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner().data;

    let mut user = headers.user;

    user.private_key = Some(data.EncryptedPrivateKey);
    user.public_key = Some(data.PublicKey);

    user.save(&conn)?;
    Ok(Json(user.to_json(&conn)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangePassData {
    MasterPasswordHash: String,
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/accounts/password", data = "<data>")]
fn post_password(data: JsonUpcase<ChangePassData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ChangePassData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.set_password(&data.NewMasterPasswordHash);
    user.key = data.Key;
    user.save(&conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangeKdfData {
    Kdf: i32,
    KdfIterations: i32,

    MasterPasswordHash: String,
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/accounts/kdf", data = "<data>")]
fn post_kdf(data: JsonUpcase<ChangeKdfData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.client_kdf_iter = data.KdfIterations;
    user.client_kdf_type = data.Kdf;
    user.set_password(&data.NewMasterPasswordHash);
    user.key = data.Key;
    user.save(&conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct UpdateFolderData {
    Id: String,
    Name: String,
}

use super::ciphers::CipherData;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct KeyData {
    Ciphers: Vec<CipherData>,
    Folders: Vec<UpdateFolderData>,
    Key: String,
    PrivateKey: String,
    MasterPasswordHash: String,
}

#[post("/accounts/key", data = "<data>")]
fn post_rotatekey(data: JsonUpcase<KeyData>, headers: Headers, conn: DbConn, ws: State<WebSocketUsers>) -> EmptyResult {
    let data: KeyData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    let user_uuid = &headers.user.uuid;

    // Update folder data
    for folder_data in data.Folders {
        let mut saved_folder = match Folder::find_by_uuid(&folder_data.Id, &conn) {
            Some(folder) => folder,
            None => err!("Folder doesn't exist"),
        };

        if &saved_folder.user_uuid != user_uuid {
            err!("The folder is not owned by the user")
        }

        saved_folder.name = folder_data.Name;
        saved_folder.save(&conn)?
    }

    // Update cipher data
    use super::ciphers::update_cipher_from_data;

    for cipher_data in data.Ciphers {
        let mut saved_cipher = match Cipher::find_by_uuid(cipher_data.Id.as_ref().unwrap(), &conn) {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        if saved_cipher.user_uuid.as_ref().unwrap() != user_uuid {
            err!("The cipher is not owned by the user")
        }

        update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, false, &conn, &ws, UpdateType::SyncCipherUpdate)?
    }

    // Update user data
    let mut user = headers.user;

    user.key = data.Key;
    user.private_key = Some(data.PrivateKey);
    user.reset_security_stamp();

    user.save(&conn)
}

#[post("/accounts/security-stamp", data = "<data>")]
fn post_sstamp(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.reset_security_stamp();
    user.save(&conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EmailTokenData {
    MasterPasswordHash: String,
    NewEmail: String,
}

#[post("/accounts/email-token", data = "<data>")]
fn post_email_token(data: JsonUpcase<EmailTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: EmailTokenData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.NewEmail, &conn).is_some() {
        err!("Email already in use");
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangeEmailData {
    MasterPasswordHash: String,
    NewEmail: String,

    Key: String,
    NewMasterPasswordHash: String,
    #[serde(rename = "Token")]
    _Token: NumberOrString,
}

#[post("/accounts/email", data = "<data>")]
fn post_email(data: JsonUpcase<ChangeEmailData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ChangeEmailData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.NewEmail, &conn).is_some() {
        err!("Email already in use");
    }

    user.email = data.NewEmail;

    user.set_password(&data.NewMasterPasswordHash);
    user.key = data.Key;

    user.save(&conn)
}

#[post("/accounts/delete", data = "<data>")]
fn post_delete_account(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_account(data, headers, conn)
}

#[delete("/accounts", data = "<data>")]
fn delete_account(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.delete(&conn)
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> String {
    let revision_date = headers.user.updated_at.timestamp_millis();
    revision_date.to_string()
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PasswordHintData {
    Email: String,
}

#[post("/accounts/password-hint", data = "<data>")]
fn password_hint(data: JsonUpcase<PasswordHintData>, conn: DbConn) -> EmptyResult {
    let data: PasswordHintData = data.into_inner().data;

    let hint = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => user.password_hint,
        None => return Ok(()),
    };

    if let Some(ref mail_config) = CONFIG.mail {
        mail::send_password_hint(&data.Email, hint, mail_config)?;
    } else if CONFIG.show_password_hint {
        if let Some(hint) = hint {
            err!(format!("Your password hint is: {}", &hint));
        } else {
            err!("Sorry, you have no password hint...");
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PreloginData {
    Email: String,
}

#[post("/accounts/prelogin", data = "<data>")]
fn prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> JsonResult {
    let data: PreloginData = data.into_inner().data;

    let (kdf_type, kdf_iter) = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT),
    };

    Ok(Json(json!({
        "Kdf": kdf_type,
        "KdfIterations": kdf_iter
    })))
}
