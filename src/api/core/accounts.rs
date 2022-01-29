use chrono::Utc;
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, Notify, NumberOrString, PasswordData, UpdateType},
    auth::{decode_delete, decode_invite, decode_verify_email, Headers},
    crypto,
    db::{models::*, DbConn},
    mail, CONFIG,
};

pub fn routes() -> Vec<rocket::Route> {
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
        post_verify_email,
        post_verify_email_token,
        post_delete_recover,
        post_delete_recover_token,
        delete_account,
        post_delete_account,
        revision_date,
        password_hint,
        prelogin,
        verify_password,
        api_key,
        rotate_api_key,
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
    #[allow(dead_code)]
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
    let email = data.Email.to_lowercase();

    let mut user = match User::find_by_mail(&email, &conn) {
        Some(user) => {
            if !user.password_hash.is_empty() {
                if CONFIG.is_signup_allowed(&email) {
                    err!("User already exists")
                } else {
                    err!("Registration not allowed or user already exists")
                }
            }

            if let Some(token) = data.Token {
                let claims = decode_invite(&token)?;
                if claims.email == email {
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &conn) {
                for mut user_org in UserOrganization::find_invited_by_user(&user.uuid, &conn).iter_mut() {
                    user_org.status = UserOrgStatus::Accepted as i32;
                    user_org.save(&conn)?;
                }
                user
            } else if EmergencyAccess::find_invited_by_grantee_email(&email, &conn).is_some() {
                user
            } else if CONFIG.is_signup_allowed(&email) {
                err!("Account with this email already exists")
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
        None => {
            // Order is important here; the invitation check must come first
            // because the vaultwarden admin can invite anyone, regardless
            // of other signup restrictions.
            if Invitation::take(&email, &conn) || CONFIG.is_signup_allowed(&email) {
                User::new(email.clone())
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &conn);

    if let Some(client_kdf_iter) = data.KdfIterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    if let Some(client_kdf_type) = data.Kdf {
        user.client_kdf_type = client_kdf_type;
    }

    user.set_password(&data.MasterPasswordHash, None);
    user.akey = data.Key;

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

    if CONFIG.mail_enabled() {
        if CONFIG.signups_verify() {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, &user.uuid) {
                error!("Error sending welcome email: {:#?}", e);
            }

            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email) {
            error!("Error sending welcome email: {:#?}", e);
        }
    }

    user.save(&conn)
}

#[get("/accounts/profile")]
fn profile(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&conn))
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

    Ok(Json(json!({
        "PrivateKey": user.private_key,
        "PublicKey": user.public_key,
        "Object":"keys"
    })))
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

    user.set_password(
        &data.NewMasterPasswordHash,
        Some(vec![String::from("post_rotatekey"), String::from("get_contacts"), String::from("get_public_keys")]),
    );
    user.akey = data.Key;
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
    user.set_password(&data.NewMasterPasswordHash, None);
    user.akey = data.Key;
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
fn post_rotatekey(data: JsonUpcase<KeyData>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
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

        // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
        // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
        update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, false, &conn, &nt, UpdateType::None)?
    }

    // Update user data
    let mut user = headers.user;

    user.akey = data.Key;
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

    Device::delete_all_by_user(&user.uuid, &conn)?;
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
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.NewEmail, &conn).is_some() {
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.NewEmail) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.NewEmail, &token) {
            error!("Error sending change-email email: {:#?}", e);
        }
    }

    user.email_new = Some(data.NewEmail);
    user.email_new_token = Some(token);
    user.save(&conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangeEmailData {
    MasterPasswordHash: String,
    NewEmail: String,

    Key: String,
    NewMasterPasswordHash: String,
    Token: NumberOrString,
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

    match user.email_new {
        Some(ref val) => {
            if val != &data.NewEmail {
                err!("Email change mismatch");
            }
        }
        None => err!("No email change pending"),
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        match user.email_new_token {
            Some(ref val) => {
                if *val != data.Token.into_string() {
                    err!("Token mismatch");
                }
            }
            None => err!("No email change pending"),
        }
        user.verified_at = Some(Utc::now().naive_utc());
    } else {
        user.verified_at = None;
    }

    user.email = data.NewEmail;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.NewMasterPasswordHash, None);
    user.akey = data.Key;

    user.save(&conn)
}

#[post("/accounts/verify-email")]
fn post_verify_email(headers: Headers) -> EmptyResult {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, &user.uuid) {
        error!("Error sending verify_email email: {:#?}", e);
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct VerifyEmailTokenData {
    UserId: String,
    Token: String,
}

#[post("/accounts/verify-email-token", data = "<data>")]
fn post_verify_email_token(data: JsonUpcase<VerifyEmailTokenData>, conn: DbConn) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner().data;

    let mut user = match User::find_by_uuid(&data.UserId, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_verify_email(&data.Token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };
    if claims.sub != user.uuid {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now().naive_utc());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    if let Err(e) = user.save(&conn) {
        error!("Error saving email verification: {:#?}", e);
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DeleteRecoverData {
    Email: String,
}

#[post("/accounts/delete-recover", data = "<data>")]
fn post_delete_recover(data: JsonUpcase<DeleteRecoverData>, conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverData = data.into_inner().data;

    let user = User::find_by_mail(&data.Email, &conn);

    if CONFIG.mail_enabled() {
        if let Some(user) = user {
            if let Err(e) = mail::send_delete_account(&user.email, &user.uuid) {
                error!("Error sending delete account email: {:#?}", e);
            }
        }
        Ok(())
    } else {
        // We don't support sending emails, but we shouldn't allow anybody
        // to delete accounts without at least logging in... And if the user
        // cannot remember their password then they will need to contact
        // the administrator to delete it...
        err!("Please contact the administrator to delete your account");
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DeleteRecoverTokenData {
    UserId: String,
    Token: String,
}

#[post("/accounts/delete-recover-token", data = "<data>")]
fn post_delete_recover_token(data: JsonUpcase<DeleteRecoverTokenData>, conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner().data;

    let user = match User::find_by_uuid(&data.UserId, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_delete(&data.Token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };
    if claims.sub != user.uuid {
        err!("Invalid claim");
    }
    user.delete(&conn)
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
    if !CONFIG.mail_enabled() && !CONFIG.show_password_hint() {
        err!("This server is not configured to provide password hints.");
    }

    const NO_HINT: &str = "Sorry, you have no password hint...";

    let data: PasswordHintData = data.into_inner().data;
    let email = &data.Email;

    match User::find_by_mail(email, &conn) {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::{thread_rng, Rng};
                let mut rng = thread_rng();
                let base = 1000;
                let delta: i32 = 100;
                let sleep_ms = (base + rng.gen_range(-delta..=delta)) as u64;
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                Ok(())
            } else {
                err!(NO_HINT);
            }
        }
        Some(user) => {
            let hint: Option<String> = user.password_hint;
            if CONFIG.mail_enabled() {
                mail::send_password_hint(email, hint)?;
                Ok(())
            } else if let Some(hint) = hint {
                err!(format!("Your password hint is: {}", hint));
            } else {
                err!(NO_HINT);
            }
        }
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PreloginData {
    Email: String,
}

#[post("/accounts/prelogin", data = "<data>")]
fn prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> Json<Value> {
    let data: PreloginData = data.into_inner().data;

    let (kdf_type, kdf_iter) = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT),
    };

    Json(json!({
        "Kdf": kdf_type,
        "KdfIterations": kdf_iter
    }))
}

// https://github.com/bitwarden/server/blob/master/src/Api/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SecretVerificationRequest {
    MasterPasswordHash: String,
}

#[post("/accounts/verify-password", data = "<data>")]
fn verify_password(data: JsonUpcase<SecretVerificationRequest>, headers: Headers) -> EmptyResult {
    let data: SecretVerificationRequest = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    Ok(())
}

fn _api_key(data: JsonUpcase<SecretVerificationRequest>, rotate: bool, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SecretVerificationRequest = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&conn).expect("Error saving API key");
    }

    Ok(Json(json!({
      "ApiKey": user.api_key,
      "Object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
fn api_key(data: JsonUpcase<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, false, headers, conn)
}

#[post("/accounts/rotate-api-key", data = "<data>")]
fn rotate_api_key(data: JsonUpcase<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, true, headers, conn)
}
