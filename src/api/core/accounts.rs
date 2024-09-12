use crate::db::DbPool;
use chrono::{SecondsFormat, Utc};
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{
        core::{log_user_event, two_factor::email},
        register_push_device, unregister_push_device, AnonymousNotify, ApiResult, EmptyResult, JsonResult, Notify,
        PasswordOrOtpData, UpdateType,
    },
    auth::{decode_delete, decode_invite, decode_verify_email, ClientHeaders, Headers},
    crypto,
    db::{models::*, DbConn},
    mail,
    util::NumberOrString,
    CONFIG,
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
        post_set_password,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    name: Option<String>,
    token: Option<String>,
    #[allow(dead_code)]
    organization_user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    // org_identifier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
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
async fn is_email_2fa_required(org_user_uuid: Option<String>, conn: &mut DbConn) -> bool {
    if !CONFIG._enable_email_2fa() {
        return false;
    }
    if CONFIG.email_2fa_enforce_on_verified_invite() {
        return true;
    }
    if org_user_uuid.is_some() {
        return OrgPolicy::is_enabled_by_org(&org_user_uuid.unwrap(), OrgPolicyType::TwoFactorAuthentication, conn)
            .await;
    }
    false
}

#[post("/accounts/register", data = "<data>")]
async fn register(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    _register(data, conn).await
}

pub async fn _register(data: Json<RegisterData>, mut conn: DbConn) -> JsonResult {
    let data: RegisterData = data.into_inner();
    let email = data.email.to_lowercase();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = data.name {
        if name.len() > 50 {
            err!("The field Name must be a string with a maximum length of 50.");
        }
    }

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&password_hint)?;

    let mut verified_by_invite = false;

    let mut user = match User::find_by_mail(&email, &mut conn).await {
        Some(mut user) => {
            if !user.password_hash.is_empty() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.token {
                let claims = decode_invite(&token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    verified_by_invite = true;
                    user.verified_at = Some(Utc::now().naive_utc());
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &mut conn).await {
                UserOrganization::confirm_user_invitations(&user.uuid, &mut conn).await?;
                user
            } else if CONFIG.is_signup_allowed(&email)
                || (CONFIG.emergency_access_allowed()
                    && EmergencyAccess::find_invited_by_grantee_email(&email, &mut conn).await.is_some())
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
            if Invitation::take(&email, &mut conn).await || CONFIG.is_signup_allowed(&email) {
                User::new(email.clone(), None)
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &mut conn).await;

    if let Some(client_kdf_type) = data.kdf {
        user.client_kdf_type = client_kdf_type;
    }

    if let Some(client_kdf_iter) = data.kdf_iterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;

    user.set_password(&data.master_password_hash, Some(data.key), true, None);
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
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

        if verified_by_invite && is_email_2fa_required(data.organization_user_id, &mut conn).await {
            let _ = email::activate_email_2fa(&user, &mut conn).await;
        }
    }

    user.save(&mut conn).await?;

    // accept any open emergency access invitations
    if !CONFIG.mail_enabled() && CONFIG.emergency_access_allowed() {
        for mut emergency_invite in EmergencyAccess::find_all_invited_by_grantee_email(&user.email, &mut conn).await {
            let _ = emergency_invite.accept_invite(&user.uuid, &user.email, &mut conn).await;
        }
    }

    Ok(Json(json!({
      "object": "register",
      "captchaBypassToken": "",
    })))
}

#[post("/accounts/set-password", data = "<data>")]
async fn post_set_password(data: Json<SetPasswordData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: SetPasswordData = data.into_inner();
    let mut user = headers.user;

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&password_hint)?;

    if let Some(client_kdf_iter) = data.kdf_iterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    if let Some(client_kdf_type) = data.kdf {
        user.client_kdf_type = client_kdf_type;
    }

    // We need to allow revision-date to use the old security_timestamp
    let routes = ["revision_date"];
    let routes: Option<Vec<String>> = Some(routes.iter().map(ToString::to_string).collect());

    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;

    user.set_password(&data.master_password_hash, Some(data.key), false, routes);
    user.password_hint = password_hint;

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    if CONFIG.mail_enabled() {
        mail::send_set_password(&user.email.to_lowercase(), &user.name).await?;
    }

    user.save(&mut conn).await?;
    Ok(Json(json!({
      "Object": "set-password",
      "CaptchaBypassToken": "",
    })))
}

#[get("/accounts/profile")]
async fn profile(headers: Headers, mut conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&mut conn).await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    // culture: String, // Ignored, always use en-US
    // masterPasswordHint: Option<String>, // Ignored, has been moved to ChangePassData
    name: String,
}

#[put("/accounts/profile", data = "<data>")]
async fn put_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn).await
}

#[post("/accounts/profile", data = "<data>")]
async fn post_profile(data: Json<ProfileData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.name;

    user.save(&mut conn).await?;
    Ok(Json(user.to_json(&mut conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    avatar_color: Option<String>,
}

#[put("/accounts/avatar", data = "<data>")]
async fn put_avatar(data: Json<AvatarData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: AvatarData = data.into_inner();

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.avatar_color {
        if color.len() != 7 {
            err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
        }
    }

    let mut user = headers.user;
    user.avatar_color = data.avatar_color;

    user.save(&mut conn).await?;
    Ok(Json(user.to_json(&mut conn).await))
}

#[get("/users/<uuid>/public-key")]
async fn get_public_keys(uuid: &str, _headers: Headers, mut conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(uuid, &mut conn).await {
        Some(user) if user.public_key.is_some() => user,
        Some(_) => err_code!("User has no public_key", Status::NotFound.code),
        None => err_code!("User doesn't exist", Status::NotFound.code),
    };

    Ok(Json(json!({
        "userId": user.uuid,
        "publicKey": user.public_key,
        "object":"userKey"
    })))
}

#[post("/accounts/keys", data = "<data>")]
async fn post_keys(data: Json<KeysData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner();

    let mut user = headers.user;

    user.private_key = Some(data.encrypted_private_key);
    user.public_key = Some(data.public_key);

    user.save(&mut conn).await?;

    Ok(Json(json!({
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "object":"keys"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassData {
    master_password_hash: String,
    new_master_password_hash: String,
    master_password_hint: Option<String>,
    key: String,
}

#[post("/accounts/password", data = "<data>")]
async fn post_password(data: Json<ChangePassData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    user.password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&user.password_hint)?;

    log_user_event(EventType::UserChangedPassword as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn)
        .await;

    user.set_password(
        &data.new_master_password_hash,
        Some(data.key),
        true,
        Some(vec![String::from("post_rotatekey"), String::from("get_contacts"), String::from("get_public_keys")]),
    );

    let save_result = user.save(&mut conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdfData {
    kdf: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,

    master_password_hash: String,
    new_master_password_hash: String,
    key: String,
}

#[post("/accounts/kdf", data = "<data>")]
async fn post_kdf(data: Json<ChangeKdfData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if data.kdf == UserKdfType::Pbkdf2 as i32 && data.kdf_iterations < 100_000 {
        err!("PBKDF2 KDF iterations must be at least 100000.")
    }

    if data.kdf == UserKdfType::Argon2id as i32 {
        if data.kdf_iterations < 1 {
            err!("Argon2 KDF iterations must be at least 1.")
        }
        if let Some(m) = data.kdf_memory {
            if !(15..=1024).contains(&m) {
                err!("Argon2 memory must be between 15 MB and 1024 MB.")
            }
            user.client_kdf_memory = data.kdf_memory;
        } else {
            err!("Argon2 memory parameter is required.")
        }
        if let Some(p) = data.kdf_parallelism {
            if !(1..=16).contains(&p) {
                err!("Argon2 parallelism must be between 1 and 16.")
            }
            user.client_kdf_parallelism = data.kdf_parallelism;
        } else {
            err!("Argon2 parallelism parameter is required.")
        }
    } else {
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    }
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_type = data.kdf;
    user.set_password(&data.new_master_password_hash, Some(data.key), true, None);
    let save_result = user.save(&mut conn).await;

    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow a Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmergencyAccessData {
    id: String,
    key_encrypted: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateResetPasswordData {
    organization_id: String,
    reset_password_key: String,
}

use super::ciphers::CipherData;
use super::sends::{update_send_from_data, SendData};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<SendData>,
    emergency_access_keys: Vec<UpdateEmergencyAccessData>,
    reset_password_keys: Vec<UpdateResetPasswordData>,
    key: String,
    master_password_hash: String,
    private_key: String,
}

#[post("/accounts/key", data = "<data>")]
async fn post_rotatekey(data: Json<KeyData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    // TODO: See if we can wrap everything within a SQL Transaction. If something fails it should revert everything.
    let data: KeyData = data.into_inner();

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    let user_uuid = &headers.user.uuid;

    // Update folder data
    for folder_data in data.folders {
        // Skip `null` folder id entries.
        // See: https://github.com/bitwarden/clients/issues/8453
        if let Some(folder_id) = folder_data.id {
            let mut saved_folder = match Folder::find_by_uuid(&folder_id, &mut conn).await {
                Some(folder) => folder,
                None => err!("Folder doesn't exist"),
            };

            if &saved_folder.user_uuid != user_uuid {
                err!("The folder is not owned by the user")
            }

            saved_folder.name = folder_data.name;
            saved_folder.save(&mut conn).await?
        }
    }

    // Update emergency access data
    for emergency_access_data in data.emergency_access_keys {
        let mut saved_emergency_access =
            match EmergencyAccess::find_by_uuid_and_grantor_uuid(&emergency_access_data.id, user_uuid, &mut conn).await
            {
                Some(emergency_access) => emergency_access,
                None => err!("Emergency access doesn't exist or is not owned by the user"),
            };

        saved_emergency_access.key_encrypted = Some(emergency_access_data.key_encrypted);
        saved_emergency_access.save(&mut conn).await?
    }

    // Update reset password data
    for reset_password_data in data.reset_password_keys {
        let mut user_org =
            match UserOrganization::find_by_user_and_org(user_uuid, &reset_password_data.organization_id, &mut conn)
                .await
            {
                Some(reset_password) => reset_password,
                None => err!("Reset password doesn't exist"),
            };

        user_org.reset_password_key = Some(reset_password_data.reset_password_key);
        user_org.save(&mut conn).await?
    }

    // Update send data
    for send_data in data.sends {
        let mut send = match Send::find_by_uuid(send_data.id.as_ref().unwrap(), &mut conn).await {
            Some(send) => send,
            None => err!("Send doesn't exist"),
        };

        update_send_from_data(&mut send, send_data, &headers, &mut conn, &nt, UpdateType::None).await?;
    }

    // Update cipher data
    use super::ciphers::update_cipher_from_data;

    for cipher_data in data.ciphers {
        if cipher_data.organization_id.is_none() {
            let mut saved_cipher = match Cipher::find_by_uuid(cipher_data.id.as_ref().unwrap(), &mut conn).await {
                Some(cipher) => cipher,
                None => err!("Cipher doesn't exist"),
            };

            if saved_cipher.user_uuid.as_ref().unwrap() != user_uuid {
                err!("The cipher is not owned by the user")
            }

            // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
            // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
            // We force the users to logout after the user has been saved to try and prevent these issues.
            update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, None, &mut conn, &nt, UpdateType::None)
                .await?
        }
    }

    // Update user data
    let mut user = headers.user;

    user.akey = data.key;
    user.private_key = Some(data.private_key);
    user.reset_security_stamp();

    let save_result = user.save(&mut conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(headers.device.uuid)).await;

    save_result
}

#[post("/accounts/security-stamp", data = "<data>")]
async fn post_sstamp(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &mut conn).await?;

    Device::delete_all_by_user(&user.uuid, &mut conn).await?;
    user.reset_security_stamp();
    let save_result = user.save(&mut conn).await;

    nt.send_logout(&user, None).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailTokenData {
    master_password_hash: String,
    new_email: String,
}

#[post("/accounts/email-token", data = "<data>")]
async fn post_email_token(data: Json<EmailTokenData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: EmailTokenData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.new_email, &mut conn).await.is_some() {
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.new_email) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.new_email, &token).await {
            error!("Error sending change-email email: {:#?}", e);
        }
    } else {
        debug!("Email change request for user ({}) to email ({}) with token ({})", user.uuid, data.new_email, token);
    }

    user.email_new = Some(data.new_email);
    user.email_new_token = Some(token);
    user.save(&mut conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailData {
    master_password_hash: String,
    new_email: String,

    key: String,
    new_master_password_hash: String,
    token: NumberOrString,
}

#[post("/accounts/email", data = "<data>")]
async fn post_email(data: Json<ChangeEmailData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: ChangeEmailData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.new_email, &mut conn).await.is_some() {
        err!("Email already in use");
    }

    match user.email_new {
        Some(ref val) => {
            if val != &data.new_email {
                err!("Email change mismatch");
            }
        }
        None => err!("No email change pending"),
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        match user.email_new_token {
            Some(ref val) => {
                if *val != data.token.into_string() {
                    err!("Token mismatch");
                }
            }
            None => err!("No email change pending"),
        }
        user.verified_at = Some(Utc::now().naive_utc());
    } else {
        user.verified_at = None;
    }

    user.email = data.new_email;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None);

    let save_result = user.save(&mut conn).await;

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
#[serde(rename_all = "camelCase")]
struct VerifyEmailTokenData {
    user_id: String,
    token: String,
}

#[post("/accounts/verify-email-token", data = "<data>")]
async fn post_verify_email_token(data: Json<VerifyEmailTokenData>, mut conn: DbConn) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner();

    let mut user = match User::find_by_uuid(&data.user_id, &mut conn).await {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_verify_email(&data.token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };
    if claims.sub != user.uuid {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now().naive_utc());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    if let Err(e) = user.save(&mut conn).await {
        error!("Error saving email verification: {:#?}", e);
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverData {
    email: String,
}

#[post("/accounts/delete-recover", data = "<data>")]
async fn post_delete_recover(data: Json<DeleteRecoverData>, mut conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverData = data.into_inner();

    if CONFIG.mail_enabled() {
        if let Some(user) = User::find_by_mail(&data.email, &mut conn).await {
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
#[serde(rename_all = "camelCase")]
struct DeleteRecoverTokenData {
    user_id: String,
    token: String,
}

#[post("/accounts/delete-recover-token", data = "<data>")]
async fn post_delete_recover_token(data: Json<DeleteRecoverTokenData>, mut conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner();

    let user = match User::find_by_uuid(&data.user_id, &mut conn).await {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_delete(&data.token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };
    if claims.sub != user.uuid {
        err!("Invalid claim");
    }
    user.delete(&mut conn).await
}

#[post("/accounts/delete", data = "<data>")]
async fn post_delete_account(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_account(data, headers, conn).await
}

#[delete("/accounts", data = "<data>")]
async fn delete_account(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &mut conn).await?;

    user.delete(&mut conn).await
}

#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> JsonResult {
    let revision_date = headers.user.updated_at.and_utc().timestamp_millis();
    Ok(Json(json!(revision_date)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordHintData {
    email: String,
}

#[post("/accounts/password-hint", data = "<data>")]
async fn password_hint(data: Json<PasswordHintData>, mut conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() && !CONFIG.show_password_hint() {
        err!("This server is not configured to provide password hints.");
    }

    const NO_HINT: &str = "Sorry, you have no password hint...";

    let data: PasswordHintData = data.into_inner();
    let email = &data.email;

    match User::find_by_mail(email, &mut conn).await {
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
#[serde(rename_all = "camelCase")]
pub struct PreloginData {
    email: String,
}

#[post("/accounts/prelogin", data = "<data>")]
async fn prelogin(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    _prelogin(data, conn).await
}

pub async fn _prelogin(data: Json<PreloginData>, mut conn: DbConn) -> Json<Value> {
    let data: PreloginData = data.into_inner();

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&data.email, &mut conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    };

    let result = json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
    });

    Json(result)
}

// https://github.com/bitwarden/server/blob/master/src/Api/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretVerificationRequest {
    master_password_hash: String,
}

// Change the KDF Iterations if necessary
pub async fn kdf_upgrade(user: &mut User, pwd_hash: &str, conn: &mut DbConn) -> ApiResult<()> {
    if user.password_iterations != CONFIG.password_iterations() {
        user.password_iterations = CONFIG.password_iterations();
        user.set_password(pwd_hash, None, false, None);

        if let Err(e) = user.save(conn).await {
            error!("Error updating user: {:#?}", e);
        }
    }
    Ok(())
}

#[post("/accounts/verify-password", data = "<data>")]
async fn verify_password(data: Json<SecretVerificationRequest>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: SecretVerificationRequest = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    kdf_upgrade(&mut user, &data.master_password_hash, &mut conn).await?;

    Ok(Json(json!({
      "MasterPasswordPolicy": {}, // Required for SSO login with mobile apps
    })))
}

async fn _api_key(data: Json<PasswordOrOtpData>, rotate: bool, headers: Headers, mut conn: DbConn) -> JsonResult {
    use crate::util::format_date;

    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &mut conn).await?;

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&mut conn).await.expect("Error saving API key");
    }

    Ok(Json(json!({
      "apiKey": user.api_key,
      "revisionDate": format_date(&user.updated_at),
      "object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
async fn api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, false, headers, conn).await
}

#[post("/accounts/rotate-api-key", data = "<data>")]
async fn rotate_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    _api_key(data, true, headers, conn).await
}

#[get("/devices/knowndevice")]
async fn get_known_device(device: KnownDevice, mut conn: DbConn) -> JsonResult {
    let mut result = false;
    if let Some(user) = User::find_by_mail(&device.email, &mut conn).await {
        result = Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &mut conn).await.is_some();
    }
    Ok(Json(json!(result)))
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
                    return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as base64url"));
                }
            };
            match String::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(_) => {
                    return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as UTF-8"));
                }
            }
        } else {
            return Outcome::Error((Status::BadRequest, "X-Request-Email value is required"));
        };

        let uuid = if let Some(uuid) = req.headers().get_one("X-Device-Identifier") {
            uuid.to_string()
        } else {
            return Outcome::Error((Status::BadRequest, "X-Device-Identifier value is required"));
        };

        Outcome::Success(KnownDevice {
            email,
            uuid,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

#[post("/devices/identifier/<uuid>/token", data = "<data>")]
async fn post_device_token(uuid: &str, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    put_device_token(uuid, data, headers, conn).await
}

#[put("/devices/identifier/<uuid>/token", data = "<data>")]
async fn put_device_token(uuid: &str, data: Json<PushToken>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let token = data.push_token;

    let mut device = match Device::find_by_uuid_and_user(&headers.device.uuid, &headers.user.uuid, &mut conn).await {
        Some(device) => device,
        None => err!(format!("Error: device {uuid} should be present before a token can be assigned")),
    };

    // if the device already has been registered
    if device.is_registered() {
        // check if the new token is the same as the registered token
        if device.push_token.is_some() && device.push_token.unwrap() == token.clone() {
            debug!("Device {} is already registered and token is the same", uuid);
            return Ok(());
        } else {
            // Try to unregister already registered device
            let _ = unregister_push_device(device.push_uuid).await;
        }
        // clear the push_uuid
        device.push_uuid = None;
    }
    device.push_token = Some(token);
    if let Err(e) = device.save(&mut conn).await {
        err!(format!("An error occurred while trying to save the device push token: {e}"));
    }

    register_push_device(&mut device, &mut conn).await?;

    Ok(())
}

#[put("/devices/identifier/<uuid>/clear-token")]
async fn put_clear_device_token(uuid: &str, mut conn: DbConn) -> EmptyResult {
    // This only clears push token
    // https://github.com/bitwarden/core/blob/master/src/Api/Controllers/DevicesController.cs#L109
    // https://github.com/bitwarden/core/blob/master/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    if let Some(device) = Device::find_by_uuid(uuid, &mut conn).await {
        Device::clear_push_token_by_uuid(uuid, &mut conn).await?;
        unregister_push_device(device.push_uuid).await?;
    }

    Ok(())
}

// On upstream server, both PUT and POST are declared. Implementing the POST method in case it would be useful somewhere
#[post("/devices/identifier/<uuid>/clear-token")]
async fn post_clear_device_token(uuid: &str, conn: DbConn) -> EmptyResult {
    put_clear_device_token(uuid, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequestRequest {
    access_code: String,
    device_identifier: String,
    email: String,
    public_key: String,
    #[serde(alias = "type")]
    _type: i32,
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    headers: ClientHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();

    let user = match User::find_by_mail(&data.email, &mut conn).await {
        Some(user) => user,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    let mut auth_request = AuthRequest::new(
        user.uuid.clone(),
        data.device_identifier.clone(),
        headers.device_type,
        headers.ip.ip.to_string(),
        data.access_code,
        data.public_key,
    );
    auth_request.save(&mut conn).await?;

    nt.send_auth_request(&user.uuid, &auth_request.uuid, &data.device_identifier, &mut conn).await;

    Ok(Json(json!({
        "id": auth_request.uuid,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": null,
        "masterPasswordHash": null,
        "creationDate": auth_request.creation_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true),
        "responseDate": null,
        "requestApproved": false,
        "origin": CONFIG.domain_origin(),
        "object": "auth-request"
    })))
}

#[get("/auth-requests/<uuid>")]
async fn get_auth_request(uuid: &str, mut conn: DbConn) -> JsonResult {
    let auth_request = match AuthRequest::find_by_uuid(uuid, &mut conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    let response_date_utc = auth_request
        .response_date
        .map(|response_date| response_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true));

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseRequest {
    device_identifier: String,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}

#[put("/auth-requests/<uuid>", data = "<data>")]
async fn put_auth_request(
    uuid: &str,
    data: Json<AuthResponseRequest>,
    mut conn: DbConn,
    ant: AnonymousNotify<'_>,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();
    let mut auth_request: AuthRequest = match AuthRequest::find_by_uuid(uuid, &mut conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    auth_request.approved = Some(data.request_approved);
    auth_request.enc_key = Some(data.key);
    auth_request.master_password_hash = data.master_password_hash;
    auth_request.response_device_id = Some(data.device_identifier.clone());
    auth_request.save(&mut conn).await?;

    if auth_request.approved.unwrap_or(false) {
        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, data.device_identifier, &mut conn).await;
    }

    let response_date_utc = auth_request
        .response_date
        .map(|response_date| response_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true));

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[get("/auth-requests/<uuid>/response?<code>")]
async fn get_auth_request_response(uuid: &str, code: &str, mut conn: DbConn) -> JsonResult {
    let auth_request = match AuthRequest::find_by_uuid(uuid, &mut conn).await {
        Some(auth_request) => auth_request,
        None => {
            err!("AuthRequest doesn't exist")
        }
    };

    if !auth_request.check_access_code(code) {
        err!("Access code invalid doesn't exist")
    }

    let response_date_utc = auth_request
        .response_date
        .map(|response_date| response_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true));

    Ok(Json(json!(
        {
            "id": uuid,
            "publicKey": auth_request.public_key,
            "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
            "requestIpAddress": auth_request.request_ip,
            "key": auth_request.enc_key,
            "masterPasswordHash": auth_request.master_password_hash,
            "creationDate": auth_request.creation_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true),
            "responseDate": response_date_utc,
            "requestApproved": auth_request.approved,
            "origin": CONFIG.domain_origin(),
            "object":"auth-request"
        }
    )))
}

#[get("/auth-requests")]
async fn get_auth_requests(headers: Headers, mut conn: DbConn) -> JsonResult {
    let auth_requests = AuthRequest::find_by_user(&headers.user.uuid, &mut conn).await;

    Ok(Json(json!({
        "data": auth_requests
            .iter()
            .filter(|request| request.approved.is_none())
            .map(|request| {
            let response_date_utc = request.response_date.map(|response_date| response_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true));

            json!({
                "id": request.uuid,
                "publicKey": request.public_key,
                "requestDeviceType": DeviceType::from_i32(request.device_type).to_string(),
                "requestIpAddress": request.request_ip,
                "key": request.enc_key,
                "masterPasswordHash": request.master_password_hash,
                "creationDate": request.creation_date.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true),
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
    if let Ok(mut conn) = pool.get().await {
        AuthRequest::purge_expired_auth_requests(&mut conn).await;
    } else {
        error!("Failed to get DB connection while purging trashed ciphers")
    }
}
