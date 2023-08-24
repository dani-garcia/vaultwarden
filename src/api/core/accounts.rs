use crate::db::DbPool;
use chrono::Utc;
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{
        core::log_user_event, register_push_device, unregister_push_device, AnonymousNotify, EmptyResult, JsonResult,
        JsonUpcase, Notify, NumberOrString, PasswordData, UpdateType,
    },
    auth::{decode_delete, decode_invite, decode_verify_email, ClientHeaders, Headers},
    crypto,
    db::{models::*, DbConn},
    mail, CONFIG,
};

use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
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
        post_device_token,
        delete_account,
        post_delete_account,
        revision_date,
        password_hint,
        prelogin,
        verify_password,
        api_key,
        rotate_api_key,
        get_known_device,
        get_known_device_from_path,
        put_avatar,
        put_device_token,
        put_clear_device_token,
        post_clear_device_token,
        post_auth_request,
        get_auth_request,
        put_auth_request,
        get_auth_request_response,
        get_auth_requests,
    ]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct RegisterData {
    Email: String,
    Kdf: Option<i32>,
    KdfIterations: Option<i32>,
    KdfMemory: Option<i32>,
    KdfParallelism: Option<i32>,
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

/// Trims whitespace from password hints, and converts blank password hints to `None`.
fn clean_password_hint(password_hint: &Option<String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => match h.trim() {
            "" => None,
            ht => Some(ht.to_string()),
        },
    }
}

fn enforce_password_hint_setting(password_hint: &Option<String>) -> EmptyResult {
    if password_hint.is_some() && !CONFIG.password_hints_allowed() {
        err!("Password hints have been disabled by the administrator. Remove the hint and try again.");
    }
    Ok(())
}

#[post("/accounts/register", data = "<data>")]
async fn register(data: JsonUpcase<RegisterData>, conn: DbConn) -> JsonResult {
    _register(data, conn).await
}

pub async fn _register(data: JsonUpcase<RegisterData>, conn: DbConn) -> JsonResult {
    let data: RegisterData = data.into_inner().data;
    let email = data.Email.to_lowercase();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = data.Name {
        if name.len() > 50 {
            err!("The field Name must be a string with a maximum length of 50.");
        }
    }

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.MasterPasswordHint);
    enforce_password_hint_setting(&password_hint)?;

    let mut verified_by_invite = false;

    let mut user = match User::find_by_mail(&email, &conn).await {
        Some(mut user) => {
            if !user.password_hash.is_empty() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.Token {
                let claims = decode_invite(&token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    verified_by_invite = true;
                    user.verified_at = Some(Utc::now().naive_utc());
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &conn).await {
                for user_org in UserOrganization::find_invited_by_user(&user.uuid, &conn).await.iter_mut() {
                    user_org.status = UserOrgStatus::Accepted as i32;
                    user_org.save(&conn).await?;
                }
                user
            } else if CONFIG.is_signup_allowed(&email)
                || EmergencyAccess::find_invited_by_grantee_email(&email, &conn).await.is_some()
            {
                user
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
        None => {
            // Order is important here; the invitation check must come first
            // because the vaultwarden admin can invite anyone, regardless
            // of other signup restrictions.
            if Invitation::take(&email, &conn).await || CONFIG.is_signup_allowed(&email) {
                User::new(email.clone())
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &conn).await;

    if let Some(client_kdf_type) = data.Kdf {
        user.client_kdf_type = client_kdf_type;
    }

    if let Some(client_kdf_iter) = data.KdfIterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    user.client_kdf_memory = data.KdfMemory;
    user.client_kdf_parallelism = data.KdfParallelism;

    user.set_password(&data.MasterPasswordHash, Some(data.Key), true, None);
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.Name {
        user.name = name;
    }

    if let Some(keys) = data.Keys {
        user.private_key = Some(keys.EncryptedPrivateKey);
        user.public_key = Some(keys.PublicKey);
    }

    if CONFIG.mail_enabled() {
        if CONFIG.signups_verify() && !verified_by_invite {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, &user.uuid).await {
                error!("Error sending welcome email: {:#?}", e);
            }

            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email).await {
            error!("Error sending welcome email: {:#?}", e);
        }
    }

    user.save(&conn).await?;
    Ok(Json(json!({
      "Object": "register",
      "CaptchaBypassToken": "",
    })))
}

#[get("/accounts/profile")]
async fn profile(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&conn).await)
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct ProfileData {
    // Culture: String, // Ignored, always use en-US
    // MasterPasswordHint: Option<String>, // Ignored, has been moved to ChangePassData
    Name: String,
}

#[put("/accounts/profile", data = "<data>")]
async fn put_profile(data: JsonUpcase<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn).await
}

#[post("/accounts/profile", data = "<data>")]
async fn post_profile(data: JsonUpcase<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner().data;

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.Name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.Name;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AvatarData {
    AvatarColor: Option<String>,
}

#[put("/accounts/avatar", data = "<data>")]
async fn put_avatar(data: JsonUpcase<AvatarData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: AvatarData = data.into_inner().data;

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.AvatarColor {
        if color.len() != 7 {
            err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
        }
    }

    let mut user = headers.user;
    user.avatar_color = data.AvatarColor;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[get("/users/<uuid>/public-key")]
async fn get_public_keys(uuid: &str, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(uuid, &conn).await {
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
async fn post_keys(data: JsonUpcase<KeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner().data;

    let mut user = headers.user;

    user.private_key = Some(data.EncryptedPrivateKey);
    user.public_key = Some(data.PublicKey);

    user.save(&conn).await?;

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
    MasterPasswordHint: Option<String>,
    Key: String,
}

#[post("/accounts/password", data = "<data>")]
async fn post_password(
    data: JsonUpcase<ChangePassData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data: ChangePassData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.password_hint = clean_password_hint(&data.MasterPasswordHint);
    enforce_password_hint_setting(&user.password_hint)?;

    log_user_event(EventType::UserChangedPassword as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    user.set_password(
        &data.NewMasterPasswordHash,
        Some(data.Key),
        true,
        Some(vec![String::from("post_rotatekey"), String::from("get_contacts"), String::from("get_public_keys")]),
    );

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ChangeKdfData {
    Kdf: i32,
    KdfIterations: i32,
    KdfMemory: Option<i32>,
    KdfParallelism: Option<i32>,

    MasterPasswordHash: String,
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/accounts/kdf", data = "<data>")]
async fn post_kdf(data: JsonUpcase<ChangeKdfData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if data.Kdf == UserKdfType::Pbkdf2 as i32 && data.KdfIterations < 100_000 {
        err!("PBKDF2 KDF iterations must be at least 100000.")
    }

    if data.Kdf == UserKdfType::Argon2id as i32 {
        if data.KdfIterations < 1 {
            err!("Argon2 KDF iterations must be at least 1.")
        }
        if let Some(m) = data.KdfMemory {
            if !(15..=1024).contains(&m) {
                err!("Argon2 memory must be between 15 MB and 1024 MB.")
            }
            user.client_kdf_memory = data.KdfMemory;
        } else {
            err!("Argon2 memory parameter is required.")
        }
        if let Some(p) = data.KdfParallelism {
            if !(1..=16).contains(&p) {
                err!("Argon2 parallelism must be between 1 and 16.")
            }
            user.client_kdf_parallelism = data.KdfParallelism;
        } else {
            err!("Argon2 parallelism parameter is required.")
        }
    } else {
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    }
    user.client_kdf_iter = data.KdfIterations;
    user.client_kdf_type = data.Kdf;
    user.set_password(&data.NewMasterPasswordHash, Some(data.Key), true, None);
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
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
async fn post_rotatekey(data: JsonUpcase<KeyData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: KeyData = data.into_inner().data;

    if !headers.user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_notes(&data.Ciphers)?;

    let user_uuid = &headers.user.uuid;

    // Update folder data
    for folder_data in data.Folders {
        let mut saved_folder = match Folder::find_by_uuid(&folder_data.Id, &conn).await {
            Some(folder) => folder,
            None => err!("Folder doesn't exist"),
        };

        if &saved_folder.user_uuid != user_uuid {
            err!("The folder is not owned by the user")
        }

        saved_folder.name = folder_data.Name;
        saved_folder.save(&conn).await?
    }

    // Update cipher data
    use super::ciphers::update_cipher_from_data;

    for cipher_data in data.Ciphers {
        let mut saved_cipher = match Cipher::find_by_uuid(cipher_data.Id.as_ref().unwrap(), &conn).await {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        if saved_cipher.user_uuid.as_ref().unwrap() != user_uuid {
            err!("The cipher is not owned by the user")
        }

        // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
        // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
        // We force the users to logout after the user has been saved to try and prevent these issues.
        update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, false, &conn, &nt, UpdateType::None).await?
    }

    // Update user data
    let mut user = headers.user;

    user.akey = data.Key;
    user.private_key = Some(data.PrivateKey);
    user.reset_security_stamp();

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
}

#[post("/accounts/security-stamp", data = "<data>")]
async fn post_sstamp(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    Device::delete_all_by_user(&user.uuid, &conn).await?;
    user.reset_security_stamp();
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None).await;

    save_result
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EmailTokenData {
    MasterPasswordHash: String,
    NewEmail: String,
}

#[post("/accounts/email-token", data = "<data>")]
async fn post_email_token(data: JsonUpcase<EmailTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: EmailTokenData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.NewEmail, &conn).await.is_some() {
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.NewEmail) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.NewEmail, &token).await {
            error!("Error sending change-email email: {:#?}", e);
        }
    }

    user.email_new = Some(data.NewEmail);
    user.email_new_token = Some(token);
    user.save(&conn).await
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
async fn post_email(data: JsonUpcase<ChangeEmailData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: ChangeEmailData = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.NewEmail, &conn).await.is_some() {
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

    user.set_password(&data.NewMasterPasswordHash, Some(data.Key), true, None);

    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None).await;

    save_result
}

#[post("/accounts/verify-email")]
async fn post_verify_email(headers: Headers) -> EmptyResult {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
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
async fn post_verify_email_token(data: JsonUpcase<VerifyEmailTokenData>, conn: DbConn) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner().data;

    let mut user = match User::find_by_uuid(&data.UserId, &conn).await {
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
    if let Err(e) = user.save(&conn).await {
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
async fn post_delete_recover(data: JsonUpcase<DeleteRecoverData>, conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverData = data.into_inner().data;

    if CONFIG.mail_enabled() {
        if let Some(user) = User::find_by_mail(&data.Email, &conn).await {
            if let Err(e) = mail::send_delete_account(&user.email, &user.uuid).await {
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
async fn post_delete_recover_token(data: JsonUpcase<DeleteRecoverTokenData>, conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner().data;

    let user = match User::find_by_uuid(&data.UserId, &conn).await {
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
    user.delete(&conn).await
}

#[post("/accounts/delete", data = "<data>")]
async fn post_delete_account(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_account(data, headers, conn).await
}

#[delete("/accounts", data = "<data>")]
async fn delete_account(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    user.delete(&conn).await
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> JsonResult {
    let revision_date = headers.user.updated_at.timestamp_millis();
    Ok(Json(json!(revision_date)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PasswordHintData {
    Email: String,
}

#[post("/accounts/password-hint", data = "<data>")]
async fn password_hint(data: JsonUpcase<PasswordHintData>, conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() && !CONFIG.show_password_hint() {
        err!("This server is not configured to provide password hints.");
    }

    const NO_HINT: &str = "Sorry, you have no password hint...";

    let data: PasswordHintData = data.into_inner().data;
    let email = &data.Email;

    match User::find_by_mail(email, &conn).await {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::{rngs::SmallRng, Rng, SeedableRng};
                let mut rng = SmallRng::from_entropy();
                let delta: i32 = 100;
                let sleep_ms = (1_000 + rng.gen_range(-delta..=delta)) as u64;
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
                Ok(())
            } else {
                err!(NO_HINT);
            }
        }
        Some(user) => {
            let hint: Option<String> = user.password_hint;
            if CONFIG.mail_enabled() {
                mail::send_password_hint(email, hint).await?;
                Ok(())
            } else if let Some(hint) = hint {
                err!(format!("Your password hint is: {hint}"));
            } else {
                err!(NO_HINT);
            }
        }
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct PreloginData {
    Email: String,
}

#[post("/accounts/prelogin", data = "<data>")]
async fn prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> Json<Value> {
    _prelogin(data, conn).await
}

pub async fn _prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> Json<Value> {
    let data: PreloginData = data.into_inner().data;

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&data.Email, &conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    };

    let result = json!({
        "Kdf": kdf_type,
        "KdfIterations": kdf_iter,
        "KdfMemory": kdf_mem,
        "KdfParallelism": kdf_para,
    });

    Json(result)
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

async fn _api_key(
    data: JsonUpcase<SecretVerificationRequest>,
    rotate: bool,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    use crate::util::format_date;

    let data: SecretVerificationRequest = data.into_inner().data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password")
    }

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&conn).await.expect("Error saving API key");
    }

    Ok(Json(json!({
      "ApiKey": user.api_key,
      "RevisionDate": format_date(&user.updated_at),
      "Object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
async fn api_key(data: JsonUpcase<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, false, headers, conn).await
}

#[post("/accounts/rotate-api-key", data = "<data>")]
async fn rotate_api_key(data: JsonUpcase<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, true, headers, conn).await
}

// This variant is deprecated: https://github.com/bitwarden/server/pull/2682
#[get("/devices/knowndevice/<email>/<uuid>")]
async fn get_known_device_from_path(email: &str, uuid: &str, conn: DbConn) -> JsonResult {
    // This endpoint doesn't have auth header
    let mut result = false;
    if let Some(user) = User::find_by_mail(email, &conn).await {
        result = Device::find_by_uuid_and_user(uuid, &user.uuid, &conn).await.is_some();
    }
    Ok(Json(json!(result)))
}

#[get("/devices/knowndevice")]
async fn get_known_device(device: KnownDevice, conn: DbConn) -> JsonResult {
    get_known_device_from_path(&device.email, &device.uuid, conn).await
}

struct KnownDevice {
    email: String,
    uuid: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for KnownDevice {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let email = if let Some(email_b64) = req.headers().get_one("X-Request-Email") {
            let email_bytes = match data_encoding::BASE64URL_NOPAD.decode(email_b64.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Outcome::Failure((
                        Status::BadRequest,
                        "X-Request-Email value failed to decode as base64url",
                    ));
                }
            };
            match String::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(_) => {
                    return Outcome::Failure((Status::BadRequest, "X-Request-Email value failed to decode as UTF-8"));
                }
            }
        } else {
            return Outcome::Failure((Status::BadRequest, "X-Request-Email value is required"));
        };

        let uuid = if let Some(uuid) = req.headers().get_one("X-Device-Identifier") {
            uuid.to_string()
        } else {
            return Outcome::Failure((Status::BadRequest, "X-Device-Identifier value is required"));
        };

        Outcome::Success(KnownDevice {
            email,
            uuid,
        })
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PushToken {
    PushToken: String,
}

#[post("/devices/identifier/<uuid>/token", data = "<data>")]
async fn post_device_token(uuid: &str, data: JsonUpcase<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    put_device_token(uuid, data, headers, conn).await
}

#[put("/devices/identifier/<uuid>/token", data = "<data>")]
async fn put_device_token(uuid: &str, data: JsonUpcase<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    let data = data.into_inner().data;
    let token = data.PushToken;
    let mut device = match Device::find_by_uuid_and_user(&headers.device.uuid, &headers.user.uuid, &conn).await {
        Some(device) => device,
        None => err!(format!("Error: device {uuid} should be present before a token can be assigned")),
    };
    device.push_token = Some(token);
    if device.push_uuid.is_none() {
        device.push_uuid = Some(uuid::Uuid::new_v4().to_string());
    }
    if let Err(e) = device.save(&conn).await {
        err!(format!("An error occurred while trying to save the device push token: {e}"));
    }
    if let Err(e) = register_push_device(headers.user.uuid, device).await {
        err!(format!("An error occurred while proceeding registration of a device: {e}"));
    }

    Ok(())
}

#[put("/devices/identifier/<uuid>/clear-token")]
async fn put_clear_device_token(uuid: &str, conn: DbConn) -> EmptyResult {
    // This only clears push token
    // https://github.com/bitwarden/core/blob/master/src/Api/Controllers/DevicesController.cs#L109
    // https://github.com/bitwarden/core/blob/master/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    if let Some(device) = Device::find_by_uuid(uuid, &conn).await {
        Device::clear_push_token_by_uuid(uuid, &conn).await?;
        unregister_push_device(device.uuid).await?;
    }

    Ok(())
}

// On upstream server, both PUT and POST are declared. Implementing the POST method in case it would be useful somewhere
#[post("/devices/identifier/<uuid>/clear-token")]
async fn post_clear_device_token(uuid: &str, conn: DbConn) -> EmptyResult {
    put_clear_device_token(uuid, conn).await
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct AuthRequestRequest {
    accessCode: String,
    deviceIdentifier: String,
    email: String,
    publicKey: String,
    #[serde(alias = "type")]
    _type: i32,
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    headers: ClientHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();

    let user = match User::find_by_mail(&data.email, &conn).await {
        Some(user) => user,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    let mut auth_request = AuthRequest::new(
        user.uuid.clone(),
        data.deviceIdentifier.clone(),
        headers.device_type,
        headers.ip.ip.to_string(),
        data.accessCode,
        data.publicKey,
    );
    auth_request.save(&conn).await?;

    nt.send_auth_request(&user.uuid, &auth_request.uuid, &data.deviceIdentifier, &conn).await;

    Ok(Json(json!({
        "id": auth_request.uuid,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": null,
        "masterPasswordHash": null,
        "creationDate": auth_request.creation_date.and_utc(),
        "responseDate": null,
        "requestApproved": false,
        "origin": CONFIG.domain_origin(),
        "object": "auth-request"
    })))
}

#[get("/auth-requests/<uuid>")]
async fn get_auth_request(uuid: &str, conn: DbConn) -> JsonResult {
    let auth_request = match AuthRequest::find_by_uuid(uuid, &conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    let response_date_utc = auth_request.response_date.map(|response_date| response_date.and_utc());

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc(),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct AuthResponseRequest {
    deviceIdentifier: String,
    key: String,
    masterPasswordHash: Option<String>,
    requestApproved: bool,
}

#[put("/auth-requests/<uuid>", data = "<data>")]
async fn put_auth_request(
    uuid: &str,
    data: Json<AuthResponseRequest>,
    conn: DbConn,
    ant: AnonymousNotify<'_>,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();
    let mut auth_request: AuthRequest = match AuthRequest::find_by_uuid(uuid, &conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    auth_request.approved = Some(data.requestApproved);
    auth_request.enc_key = Some(data.key);
    auth_request.master_password_hash = data.masterPasswordHash;
    auth_request.response_device_id = Some(data.deviceIdentifier.clone());
    auth_request.save(&conn).await?;

    if auth_request.approved.unwrap_or(false) {
        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, data.deviceIdentifier, &conn).await;
    }

    let response_date_utc = auth_request.response_date.map(|response_date| response_date.and_utc());

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc(),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[get("/auth-requests/<uuid>/response?<code>")]
async fn get_auth_request_response(uuid: &str, code: &str, conn: DbConn) -> JsonResult {
    let auth_request = match AuthRequest::find_by_uuid(uuid, &conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    if !auth_request.check_access_code(code) {
        err!("Access code invalid doesn't exist")
    }

    let response_date_utc = auth_request.response_date.map(|response_date| response_date.and_utc());

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc(),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[get("/auth-requests")]
async fn get_auth_requests(headers: Headers, conn: DbConn) -> JsonResult {
    let auth_requests = AuthRequest::find_by_user(&headers.user.uuid, &conn).await;

    Ok(Json(json!({
        "data": auth_requests
            .iter()
            .filter(|request| request.approved.is_none())
            .map(|request| {
            let response_date_utc = request.response_date.map(|response_date| response_date.and_utc());

            json!({
                "id": request.uuid,
                "publicKey": request.public_key,
                "requestDeviceType": DeviceType::from_i32(request.device_type).to_string(),
                "requestIpAddress": request.request_ip,
                "key": request.enc_key,
                "masterPasswordHash": request.master_password_hash,
                "creationDate": request.creation_date.and_utc(),
                "responseDate": response_date_utc,
                "requestApproved": request.approved,
                "origin": CONFIG.domain_origin(),
                "object":"auth-request"
            })
        }).collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list"
    })))
}

pub async fn purge_auth_requests(pool: DbPool) {
    debug!("Purging auth requests");
    if let Ok(conn) = pool.get().await {
        AuthRequest::purge_expired_auth_requests(&conn).await;
    } else {
        error!("Failed to get DB connection while purging trashed ciphers")
    }
}
