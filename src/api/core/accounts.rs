use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        AnonymousNotify, ApiResult, EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::{accept_org_invite, log_user_event, two_factor::email},
        master_password_policy, register_push_device, unregister_push_device,
    },
    auth::{ClientHeaders, ClientIp, Headers, decode_delete, decode_invite, decode_verify_email},
    crypto,
    db::{
        DbConn, DbPool,
        models::{
            AuthRequest, AuthRequestId, AuthRequestType, Cipher, CipherId, Device, DeviceId, DeviceType,
            DeviceWithAuthRequest, EmergencyAccess, EmergencyAccessId, EventType, Folder, FolderId, Invitation,
            Membership, MembershipId, OrgPolicy, OrgPolicyType, Organization, OrganizationId, Send, SendId, User,
            UserId, UserKdfType,
        },
    },
    mail,
    util::{NumberOrString, deser_opt_nonempty_str, format_date},
};

use super::{
    ciphers::{CipherData, update_cipher_from_data},
    sends::{SendData, update_send_from_data},
};

pub fn routes() -> Vec<rocket::Route> {
    routes![
        profile,
        put_profile,
        post_profile,
        put_avatar,
        get_public_keys,
        post_keys,
        post_password,
        post_set_password,
        put_update_tde_offboarding_password,
        post_kdf,
        post_rotatekey,
        post_sstamp,
        post_email_token,
        post_email,
        post_verify_email,
        post_verify_email_token,
        post_delete_recover,
        post_delete_recover_token,
        post_delete_account,
        delete_account,
        revision_date,
        password_hint,
        post_prelogin,
        verify_password,
        post_api_key,
        rotate_api_key,
        get_known_device,
        get_all_devices,
        get_device,
        post_device_token,
        put_device_token,
        put_clear_device_token,
        post_clear_device_token,
        put_device_keys,
        post_device_keys,
        post_device_retrieve_keys,
        post_devices_update_trust,
        post_devices_untrust,
        post_devices_lost_trust,
        get_tasks,
        post_auth_request,
        post_admin_auth_request,
        get_auth_request,
        put_auth_request,
        get_auth_request_response,
        get_auth_requests,
        get_auth_requests_pending,
    ]
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KDFData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,

    #[serde(flatten)]
    compat: RegisterDataCompat,

    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,

    master_password_hint: Option<String>,

    name: Option<String>,

    organization_user_id: Option<MembershipId>,

    // Used only from the register/finish endpoint
    email_verification_token: Option<String>,
    accept_emergency_access_id: Option<EmergencyAccessId>,
    accept_emergency_access_invite_token: Option<String>,
    #[serde(alias = "token")]
    org_invite_token: Option<String>,
}

impl RegisterData {
    fn hash(&self) -> String {
        self.compat.fold(|rdc| &rdc.master_password_hash, |rdcu| &rdcu.master_password_authentication.hash).to_owned()
    }

    fn kdf(&self) -> &KDFData {
        self.compat.fold(|rdc| &rdc.kdf, |rdcu| &rdcu.master_password_authentication.kdf)
    }

    fn key(&self) -> String {
        self.compat.fold(|rdc| &rdc.key, |rdcu| &rdcu.master_password_unlock.key).to_owned()
    }

    // When comparing with salt, email need to be normalized:
    //  - https://github.com/bitwarden/clients/blob/web-v2026.5.0/libs/common/src/key-management/master-password/services/master-password.service.ts#L171
    fn unprocessable(&self) -> bool {
        let mut unprocessable = false;
        *self.compat.fold(
            |_| &false,
            |rdcu| {
                let email = self.email.trim().to_lowercase();
                unprocessable = rdcu.master_password_authentication.kdf != rdcu.master_password_unlock.kdf
                    || rdcu.master_password_authentication.salt != email
                    || rdcu.master_password_unlock.salt != email;
                &unprocessable
            },
        )
    }
}

#[derive(Debug, Deserialize)]
struct RegisterDataOld {
    #[serde(flatten)]
    kdf: KDFData,

    #[serde(alias = "userSymmetricKey")]
    key: String,

    #[serde(alias = "masterPasswordHash")]
    master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDataCur {
    master_password_authentication: MasterPasswordAuthentication,
    master_password_unlock: MasterPasswordUnlock,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterDataCompat {
    RegisterDataOld(RegisterDataOld),
    RegisterDataCur(RegisterDataCur),
}

impl RegisterDataCompat {
    fn fold<'a, T>(
        &'a self,
        fct: impl FnOnce(&'a RegisterDataOld) -> &'a T,
        fcu: impl FnOnce(&'a RegisterDataCur) -> &'a T,
    ) -> &'a T {
        match self {
            RegisterDataCompat::RegisterDataOld(rdc) => fct(rdc),
            RegisterDataCompat::RegisterDataCur(rdcu) => fcu(rdcu),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordAuthentication {
    kdf: KDFData,
    salt: String,

    #[serde(alias = "masterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlock {
    kdf: KDFData,
    salt: String,

    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    #[serde(flatten)]
    kdf: KDFData,

    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    org_identifier: Option<String>,
}

/// Trims whitespace from password hints, and converts blank password hints to `None`.
fn clean_password_hint(password_hint: Option<&String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => match h.trim() {
            "" => None,
            ht => Some(ht.to_owned()),
        },
    }
}

fn enforce_password_hint_setting(password_hint: Option<&String>) -> EmptyResult {
    if password_hint.is_some() && !CONFIG.password_hints_allowed() {
        err!("Password hints have been disabled by the administrator. Remove the hint and try again.");
    }
    Ok(())
}
async fn is_email_2fa_required(member_id: Option<MembershipId>, conn: &DbConn) -> bool {
    if !CONFIG._enable_email_2fa() {
        return false;
    }
    if CONFIG.email_2fa_enforce_on_verified_invite() {
        return true;
    }
    if let Some(member_id) = member_id {
        return OrgPolicy::is_enabled_for_member(&member_id, OrgPolicyType::TwoFactorAuthentication, conn).await;
    }
    false
}

pub async fn register(data: Json<RegisterData>, email_verification: bool, conn: DbConn) -> JsonResult {
    let mut data: RegisterData = data.into_inner();
    let email = data.email.to_lowercase();

    let mut email_verified = false;

    let mut pending_emergency_access = None;

    if data.unprocessable() {
        err_code!("Unexpected RegisterData format", Status::UnprocessableEntity.code);
    }

    // First, validate the provided verification tokens
    if email_verification {
        match (
            &data.email_verification_token,
            &data.accept_emergency_access_id,
            &data.accept_emergency_access_invite_token,
            &data.organization_user_id,
            &data.org_invite_token,
        ) {
            // Normal user registration, when email verification is required
            (Some(email_verification_token), None, None, None, None) => {
                let claims = crate::auth::decode_register_verify(email_verification_token)?;
                if claims.sub != data.email {
                    err!("Email verification token does not match email");
                }

                // During this call we don't get the name, so extract it from the claims
                if claims.name.is_some() {
                    data.name = claims.name;
                }
                email_verified = claims.verified;
            }
            // Emergency access registration
            (None, Some(accept_emergency_access_id), Some(accept_emergency_access_invite_token), None, None) => {
                if !CONFIG.emergency_access_allowed() {
                    err!("Emergency access is not enabled.")
                }

                let claims = crate::auth::decode_emergency_access_invite(accept_emergency_access_invite_token)?;

                if claims.email != data.email {
                    err!("Claim email does not match email")
                }
                if &claims.emer_id != accept_emergency_access_id {
                    err!("Claim emer_id does not match accept_emergency_access_id")
                }

                pending_emergency_access = Some((accept_emergency_access_id, claims));
                email_verified = true;
            }
            // Org invite
            (None, None, None, Some(organization_user_id), Some(org_invite_token)) => {
                let claims = decode_invite(org_invite_token)?;

                if claims.email != data.email {
                    err!("Claim email does not match email")
                }

                if &claims.member_id != organization_user_id {
                    err!("Claim org_user_id does not match organization_user_id")
                }

                email_verified = true;
            }

            _ => {
                err!("Registration is missing required parameters")
            }
        }
    }

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = data.name
        && name.len() > 50
    {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    let mut user = match User::find_by_mail(&email, &conn).await {
        Some(user) => {
            if !user.password_hash.is_empty() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.org_invite_token.as_ref() {
                let claims = decode_invite(token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    email_verified = true;
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &conn).await {
                Membership::accept_user_invitations(&user.uuid, &conn).await?;
                user
            } else if CONFIG.is_signup_allowed(&email)
                || (CONFIG.emergency_access_allowed()
                    && EmergencyAccess::find_invited_by_grantee_email(&email, &conn).await.is_some())
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
            if Invitation::take(&email, &conn).await
                || CONFIG.is_signup_allowed(&email)
                || pending_emergency_access.is_some()
            {
                User::new(&email, None)
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &conn).await;

    set_kdf_data(&mut user, data.kdf())?;

    user.set_password(&data.hash(), Some(data.key()), true, None, &conn).await?;
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    if email_verified {
        user.verified_at = Some(Utc::now().naive_utc());
    }

    if CONFIG.mail_enabled() {
        if CONFIG.signups_verify() && !email_verified {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, &user.uuid).await {
                error!("Error sending welcome email: {e:#?}");
            }
            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email).await {
            error!("Error sending welcome email: {e:#?}");
        }

        if email_verified && is_email_2fa_required(data.organization_user_id, &conn).await {
            email::activate_email_2fa(&user, &conn).await.ok();
        }
    }

    user.save(&conn).await?;

    // accept any open emergency access invitations
    if !CONFIG.mail_enabled() && CONFIG.emergency_access_allowed() {
        for mut emergency_invite in EmergencyAccess::find_all_invited_by_grantee_email(&user.email, &conn).await {
            emergency_invite.accept_invite(&user.uuid, &user.email, &conn).await.ok();
        }
    }

    Ok(Json(json!({
      "object": "register",
      "captchaBypassToken": "",
    })))
}

#[post("/accounts/set-password", data = "<data>")]
async fn post_set_password(data: Json<SetPasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SetPasswordData = data.into_inner();
    let mut user = headers.user;

    // A trusted device account already has its key pair but no master password, and must still be
    // able to add one later, for instance once the server stops offering trusted device encryption.
    // What this must never do is hand out a fresh master password for an account that has one.
    if !user.password_hash.is_empty() {
        err!("Account already has a master password")
    }

    // Check against the password hint setting here so if it fails,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    // Same reasoning as in `post_keys`: the existing ciphers are encrypted under the existing key
    // pair, so an account that has one only gets a password, never new keys.
    let keys = match (data.keys, user.private_key.is_some() || user.public_key.is_some()) {
        (Some(keys), false) => Some(keys),
        (Some(keys), true)
            if user.private_key.as_ref() != Some(&keys.encrypted_private_key)
                || user.public_key.as_ref() != Some(&keys.public_key) =>
        {
            err!("Account already initialized, cannot replace the account keys")
        }
        _ => None,
    };

    set_kdf_data(&mut user, &data.kdf)?;

    user.set_password(
        &data.master_password_hash,
        Some(data.key),
        false,
        Some(vec![String::from("revision_date")]), // We need to allow revision-date to use the old security_timestamp
        &conn,
    )
    .await?;
    user.password_hint = password_hint;

    if let Some(keys) = keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    if let Some(identifier) = data.org_identifier
        && identifier != crate::sso::FAKE_SSO_IDENTIFIER
        && identifier != crate::api::admin::FAKE_ADMIN_UUID
    {
        let Some(org) = Organization::find_by_uuid(&identifier.into(), &conn).await else {
            err!("Failed to retrieve the associated organization")
        };

        let Some(membership) = Membership::find_by_user_and_org(&user.uuid, &org.uuid, &conn).await else {
            err!("Failed to retrieve the invitation")
        };

        accept_org_invite(&user, membership, None, &conn).await?;
    }

    if CONFIG.mail_enabled() {
        mail::send_welcome(&user.email.to_lowercase()).await?;
    } else {
        Membership::accept_user_invitations(&user.uuid, &conn).await?;
    }

    log_user_event(EventType::UserChangedPassword as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    user.save(&conn).await?;

    Ok(Json(json!({
      "object": "set-password",
      "captchaBypassToken": "",
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTdeOffboardingPasswordData {
    new_master_password_hash: String,
    /// The user key the account already has, re-wrapped for the master key derived from the new
    /// password. The vault is not re-encrypted, so this is the only thing that changes about it.
    key: String,
    master_password_hint: Option<String>,
}

/// Gives an account that unlocks with a trusted device the master password it needs once the server
/// stops offering trusted devices.
///
/// This is the endpoint the clients take when a login answered `IsTdeOffboarding`, see
/// `trusted_device_option`. It is deliberately not `/accounts/set-password`: the account is fully
/// set up by this point, so the only thing being added is a second way to unlock the user key it
/// already has. The account key pair and the vault are left exactly as they are, and unlike
/// `/accounts/keys` there is nothing here that could replace them.
///
/// Upstream keys this on the organization having switched its SSO member decryption away from
/// trusted devices; Vaultwarden configures SSO for the whole server, so the same state is
/// `SSO_ENABLED` without `SSO_TRUSTED_DEVICE_ENCRYPTION`, which is exactly when a login starts
/// answering `IsTdeOffboarding`.
/// https://github.com/bitwarden/server/blob/main/src/Core/Auth/UserFeatures/TdeOffboardingPassword/TdeOffboardingPasswordCommand.cs
#[put("/accounts/update-tde-offboarding-password", data = "<data>")]
async fn put_update_tde_offboarding_password(
    data: Json<UpdateTdeOffboardingPasswordData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let mut user = headers.user;

    // Adding a master password to an account that has one is changing it, which is
    // `/accounts/password` and asks for the current one first. Without this an authenticated caller
    // could replace the password of the account they are on, and a second offboarding call would
    // overwrite the password the first one just set.
    if !user.password_hash.is_empty() {
        err!("Account already has a master password")
    }

    // The way out of trusted devices only exists while the server still takes SSO logins but no
    // longer offers trusted devices. A server that still offers them has nothing to offboard from,
    // and one without SSO never had the flow at all.
    if !CONFIG.sso_enabled() || CONFIG.sso_trusted_device_encryption() {
        err!("Trusted device offboarding is not available on this server")
    }

    // A user key that is not an encrypted string unlocks nothing, and this is the only copy the
    // master password can reach. Storing it would leave an account that logs in and then cannot
    // open its own vault.
    if !crate::util::is_valid_enc_string(&data.key) {
        err!("key is not a valid encrypted string")
    }

    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    // The KDF is left alone: the client derived the master key from the settings the account
    // already has, and sends nothing to change them by, as upstream does here.
    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;
    user.password_hint = password_hint;

    log_user_event(
        EventType::UserTdeOffboardingPasswordSet as i32,
        &user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    user.save(&conn).await?;

    // Upstream logs every session out at this point. The account unlocks a different way from now
    // on, so the sessions that were opened against a trusted device do not carry over.
    nt.send_logout(&user, None, &conn).await;

    Ok(())
}

#[get("/accounts/profile")]
async fn profile(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&conn).await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    // culture: String, // Ignored, always use en-US
    name: String,
}

#[put("/accounts/profile", data = "<data>")]
async fn put_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn).await
}

#[post("/accounts/profile", data = "<data>")]
async fn post_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.name;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    avatar_color: Option<String>,
}

#[put("/accounts/avatar", data = "<data>")]
async fn put_avatar(data: Json<AvatarData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: AvatarData = data.into_inner();

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.avatar_color
        && color.len() != 7
    {
        err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
    }

    let mut user = headers.user;
    user.avatar_color = data.avatar_color;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[get("/users/<user_id>/public-key")]
async fn get_public_keys(user_id: UserId, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&user_id, &conn).await {
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
async fn post_keys(data: Json<KeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: KeysData = data.into_inner();

    let mut user = headers.user;

    // Replacing the key pair of an initialized account would make every existing cipher
    // undecryptable, so only accept it while the account has none yet. The clients call this during
    // account creation, including the trusted device flow, where a stale client state could
    // otherwise send us here for an account that is already set up. Repeating the same keys stays
    // allowed so a retried request does not fail. Mirrors the guard in `post_set_password`.
    if user.private_key.is_some() || user.public_key.is_some() {
        if user.private_key.as_ref() != Some(&data.encrypted_private_key)
            || user.public_key.as_ref() != Some(&data.public_key)
        {
            err!("Account already initialized, cannot replace the account keys")
        }

        return Ok(Json(json!({
            "privateKey": user.private_key,
            "publicKey": user.public_key,
            "object":"keys"
        })));
    }

    user.private_key = Some(data.encrypted_private_key);
    user.public_key = Some(data.public_key);

    user.save(&conn).await?;

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
async fn post_password(data: Json<ChangePassData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    user.password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(user.password_hint.as_ref())?;

    log_user_event(EventType::UserChangedPassword as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    user.set_password(
        &data.new_master_password_hash,
        Some(data.key),
        true,
        Some(vec![
            String::from("post_rotatekey"),
            String::from("get_contacts"),
            String::from("get_public_keys"),
            String::from("get_api_webauthn"),
        ]),
        &conn,
    )
    .await?;

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

fn set_kdf_data(user: &mut User, data: &KDFData) -> EmptyResult {
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

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationData {
    salt: String,
    kdf: KDFData,
    master_password_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockData {
    salt: String,
    kdf: KDFData,
    master_key_wrapped_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdfData {
    authentication_data: AuthenticationData,
    unlock_data: UnlockData,
    master_password_hash: String,
}

#[post("/accounts/kdf", data = "<data>")]
async fn post_kdf(data: Json<ChangeKdfData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner();

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if data.authentication_data.kdf != data.unlock_data.kdf {
        err!("KDF settings must be equal for authentication and unlock")
    }

    if headers.user.email != data.authentication_data.salt || headers.user.email != data.unlock_data.salt {
        err!("Invalid master password salt")
    }

    let mut user = headers.user;

    set_kdf_data(&mut user, &data.unlock_data.kdf)?;

    user.set_password(
        &data.authentication_data.master_password_authentication_hash,
        Some(data.unlock_data.master_key_wrapped_user_key),
        true,
        None,
        &conn,
    )
    .await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow a Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    #[serde(default, deserialize_with = "deser_opt_nonempty_str")]
    id: Option<FolderId>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmergencyAccessData {
    id: EmergencyAccessId,
    key_encrypted: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateResetPasswordData {
    organization_id: OrganizationId,
    reset_password_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyData {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: RotateAccountKeys,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    emergency_access_unlock_data: Vec<UpdateEmergencyAccessData>,
    master_password_unlock_data: MasterPasswordUnlockData,
    organization_account_recovery_unlock_data: Vec<UpdateResetPasswordData>,
    /// The user key, re-wrapped for every device that unlocks the vault without a master password.
    ///
    /// Absent rather than empty tells the two generations of clients apart: one that sends this
    /// rotates the trust of its devices right here, an older one does it afterwards through
    /// `POST /devices/update-trust` and leaves this out entirely. See `post_rotatekey`.
    device_key_unlock_data: Option<Vec<UpdateDeviceKeysData>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDeviceKeysData {
    device_id: DeviceId,
    encrypted_user_key: String,
    encrypted_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlockData {
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_parallelism: Option<i32>,
    kdf_memory: Option<i32>,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountKeys {
    user_key_encrypted_account_private_key: String,
    account_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<SendData>,
}

/// Works out what a key rotation has to write to the user's devices.
///
/// Returns the devices that keep their trust, each with the user key freshly wrapped for it.
/// Whatever the user owns beyond that list ends up untrusted, so the caller can hand the result to
/// `Device::replace_trust` and be done in one transaction.
///
/// Mirrors `DeviceRotationValidator` upstream, which refuses a rotation that would quietly drop the
/// trust of a device the user still relies on. Untrusting is the client's own separate step, and
/// the current ones take it before they get here.
/// https://github.com/bitwarden/server/blob/main/src/Api/KeyManagement/Validators/DeviceRotationValidator.cs
fn validate_device_keydata(
    updates: &[UpdateDeviceKeysData],
    existing_devices: &[Device],
) -> ApiResult<Vec<(DeviceId, String, String)>> {
    // Everything the client sent is checked before any of it is used, so a request that is
    // malformed anywhere is refused as a whole rather than answered in part.
    let mut listed: HashMap<&DeviceId, &UpdateDeviceKeysData> = HashMap::with_capacity(updates.len());

    for update in updates {
        if listed.insert(&update.device_id, update).is_some() {
            err!("A device was listed more than once in the rotation")
        }

        if !existing_devices.iter().any(|device| device.uuid == update.device_id) {
            err!(format!("Device {} does not belong to this user", update.device_id))
        }

        validate_enc_strings(&[
            ("encryptedUserKey", &update.encrypted_user_key),
            ("encryptedPublicKey", &update.encrypted_public_key),
        ])?;
    }

    // Walked over the devices that are trusted right now rather than over what was sent, because a
    // rotation may only carry an existing trust over to the new user key. Trusting a device is a
    // step of its own, `PUT /devices/<id>/keys`, taken by the device itself once it holds the
    // device key that these two keys are wrapped for. An entry for anything else is passed over,
    // as upstream does; the clients only ever send the devices we reported as trusted.
    let mut rotated = Vec::new();

    for device in existing_devices.iter().filter(|device| device.is_trusted()) {
        let Some(update) = listed.get(&device.uuid) else {
            err!("All existing trusted devices must be included in the rotation")
        };

        rotated.push((device.uuid.clone(), update.encrypted_user_key.clone(), update.encrypted_public_key.clone()));
    }

    Ok(rotated)
}

fn validate_keydata(
    data: &KeyData,
    existing_ciphers: &[Cipher],
    existing_folders: &[Folder],
    existing_emergency_access: &[EmergencyAccess],
    existing_memberships: &[Membership],
    existing_sends: &[Send],
    user: &User,
) -> EmptyResult {
    if user.client_kdf_type != data.account_unlock_data.master_password_unlock_data.kdf_type
        || user.client_kdf_iter != data.account_unlock_data.master_password_unlock_data.kdf_iterations
        || user.client_kdf_memory != data.account_unlock_data.master_password_unlock_data.kdf_memory
        || user.client_kdf_parallelism != data.account_unlock_data.master_password_unlock_data.kdf_parallelism
        || user.email != data.account_unlock_data.master_password_unlock_data.email
    {
        err!("Changing the kdf variant or email is not supported during key rotation");
    }
    if user.public_key.as_ref() != Some(&data.account_keys.account_public_key) {
        err!("Changing the asymmetric keypair is not possible during key rotation")
    }

    // Check that we're correctly rotating all the user's ciphers
    let existing_cipher_ids = existing_ciphers.iter().map(|c| &c.uuid).collect::<HashSet<&CipherId>>();
    let provided_cipher_ids = data
        .account_data
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .filter_map(|c| c.id.as_ref())
        .collect::<HashSet<&CipherId>>();
    if !provided_cipher_ids.is_superset(&existing_cipher_ids) {
        err!("All existing ciphers must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's folders
    let existing_folder_ids = existing_folders.iter().map(|f| &f.uuid).collect::<HashSet<&FolderId>>();
    let provided_folder_ids =
        data.account_data.folders.iter().filter_map(|f| f.id.as_ref()).collect::<HashSet<&FolderId>>();
    if !provided_folder_ids.is_superset(&existing_folder_ids) {
        err!("All existing folders must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's emergency access keys
    let existing_emergency_access_ids =
        existing_emergency_access.iter().map(|ea| &ea.uuid).collect::<HashSet<&EmergencyAccessId>>();
    let provided_emergency_access_ids = data
        .account_unlock_data
        .emergency_access_unlock_data
        .iter()
        .map(|ea| &ea.id)
        .collect::<HashSet<&EmergencyAccessId>>();
    if !provided_emergency_access_ids.is_superset(&existing_emergency_access_ids) {
        err!("All existing emergency access keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's reset password keys
    let existing_reset_password_ids =
        existing_memberships.iter().map(|m| &m.org_uuid).collect::<HashSet<&OrganizationId>>();
    let provided_reset_password_ids = data
        .account_unlock_data
        .organization_account_recovery_unlock_data
        .iter()
        .map(|rp| &rp.organization_id)
        .collect::<HashSet<&OrganizationId>>();
    if !provided_reset_password_ids.is_superset(&existing_reset_password_ids) {
        err!("All existing reset password keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's sends
    let existing_send_ids = existing_sends.iter().map(|s| &s.uuid).collect::<HashSet<&SendId>>();
    let provided_send_ids = data.account_data.sends.iter().filter_map(|s| s.id.as_ref()).collect::<HashSet<&SendId>>();
    if !provided_send_ids.is_superset(&existing_send_ids) {
        err!("All existing sends must be included in the rotation")
    }

    Ok(())
}

#[post("/accounts/key-management/rotate-user-account-keys", data = "<data>")]
async fn post_rotatekey(data: Json<KeyData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    // TODO: See if we can wrap everything within a SQL Transaction. If something fails it should revert everything.
    let data: KeyData = data.into_inner();

    if !headers.user.check_valid_password(&data.old_master_key_authentication_hash) {
        err!("Invalid password")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.account_data.ciphers)?;

    let user_id = &headers.user.uuid;

    // TODO: Ideally we'd do everything after this point in a single transaction.

    let mut existing_ciphers = Cipher::find_owned_by_user(user_id, &conn).await;
    let mut existing_folders = Folder::find_by_user(user_id, &conn).await;
    let mut existing_emergency_access = EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await;
    let mut existing_memberships = Membership::find_by_user(user_id, &conn).await;
    // We only rotate the reset password key if it is set.
    existing_memberships.retain(|m| m.reset_password_key.is_some());
    let mut existing_sends = Send::find_by_user(user_id, &conn).await;
    let existing_devices = Device::find_by_user(user_id, &conn).await;

    validate_keydata(
        &data,
        &existing_ciphers,
        &existing_folders,
        &existing_emergency_access,
        &existing_memberships,
        &existing_sends,
        &headers.user,
    )?;

    let rotated_devices = match data.account_unlock_data.device_key_unlock_data.as_deref() {
        Some(updates) => Some(validate_device_keydata(updates, &existing_devices)?),
        None => None,
    };

    // Update folder data
    for folder_data in data.account_data.folders {
        // Skip `null` folder id entries.
        // See: https://github.com/bitwarden/clients/issues/8453
        if let Some(folder_id) = folder_data.id {
            let Some(saved_folder) = existing_folders.iter_mut().find(|f| f.uuid == folder_id) else {
                err!("Folder doesn't exist")
            };

            saved_folder.name = folder_data.name;
            saved_folder.save(&conn).await?;
        }
    }

    // Update emergency access data
    for emergency_access_data in data.account_unlock_data.emergency_access_unlock_data {
        let Some(saved_emergency_access) =
            existing_emergency_access.iter_mut().find(|ea| ea.uuid == emergency_access_data.id)
        else {
            err!("Emergency access doesn't exist or is not owned by the user")
        };

        saved_emergency_access.key_encrypted = Some(emergency_access_data.key_encrypted);
        saved_emergency_access.save(&conn).await?;
    }

    // Update reset password data
    for reset_password_data in data.account_unlock_data.organization_account_recovery_unlock_data {
        let Some(membership) =
            existing_memberships.iter_mut().find(|m| m.org_uuid == reset_password_data.organization_id)
        else {
            err!("Reset password doesn't exist")
        };

        membership.reset_password_key = Some(reset_password_data.reset_password_key);
        membership.save(&conn).await?;
    }

    // Update send data
    for send_data in data.account_data.sends {
        let Some(send) = existing_sends.iter_mut().find(|s| &s.uuid == send_data.id.as_ref().unwrap()) else {
            err!("Send doesn't exist")
        };

        update_send_from_data(send, send_data, &headers, &conn, &nt, UpdateType::None).await?;
    }

    // Update cipher data
    for cipher_data in data.account_data.ciphers {
        if cipher_data.organization_id.is_none() {
            let Some(saved_cipher) = existing_ciphers.iter_mut().find(|c| &c.uuid == cipher_data.id.as_ref().unwrap())
            else {
                err!("Cipher doesn't exist")
            };

            // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
            // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
            // We force the users to logout after the user has been saved to try and prevent these issues.
            update_cipher_from_data(saved_cipher, cipher_data, &headers, None, &conn, &nt, UpdateType::None).await?;
        }
    }

    // Every device holds the previous user key wrapped for itself, which unlocks nothing anymore.
    // Settle that here rather than after the account itself: by this point the ciphers have already
    // been rewritten under the new user key, so a device that holds the new one is the half that
    // still works if what follows fails. The other order would leave a device counting itself
    // trusted while handing its owner the key it just stopped needing.
    match rotated_devices {
        // The current clients send the re-wrapped user key for every trusted device along with the
        // rotation, so their trust survives it. Anything they left out is untrusted here.
        Some(rotated) => Device::replace_trust(&headers.user.uuid, rotated, &conn).await?,
        // A client old enough to leave the field out does this afterwards through
        // `POST /devices/update-trust`. Until it does, no device counts as trusted, so the worst it
        // costs its owner is another login rather than an unlock that fails.
        None => Device::invalidate_wrapped_user_keys(&headers.user.uuid, &conn).await?,
    }

    // Update user data
    let mut user = headers.user;

    user.private_key = Some(data.account_keys.user_key_encrypted_account_private_key);
    user.set_password(
        &data.account_unlock_data.master_password_unlock_data.master_key_authentication_hash,
        Some(data.account_unlock_data.master_password_unlock_data.master_key_encrypted_user_key),
        true,
        None,
        &conn,
    )
    .await?;

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

#[post("/accounts/security-stamp", data = "<data>")]
async fn post_sstamp(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &conn).await?;

    user.reset_security_stamp(&conn).await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    Device::delete_all_by_user(&user.uuid, &conn).await?;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailTokenData {
    master_password_hash: String,
    new_email: String,
}

#[post("/accounts/email-token", data = "<data>")]
async fn post_email_token(data: Json<EmailTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: EmailTokenData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if let Some(existing_user) = User::find_by_mail(&data.new_email, &conn).await {
        if CONFIG.mail_enabled() {
            // check if existing_user has already registered
            if existing_user.password_hash.is_empty() {
                // inform an invited user about how to delete their temporary account if the
                // request was done intentionally and they want to update their mail address
                if let Err(e) = mail::send_change_email_invited(&data.new_email, &user.email).await {
                    error!("Error sending change-email-invited email: {e:#?}");
                }
            } else {
                // inform existing user about the failed attempt to change their mail address
                if let Err(e) = mail::send_change_email_existing(&data.new_email, &user.email).await {
                    error!("Error sending change-email-existing email: {e:#?}");
                }
            }
        }
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.new_email) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.new_email, &token).await {
            error!("Error sending change-email email: {e:#?}");
        }
    } else {
        debug!("Email change request for user ({}) to email ({}) with token ({token})", user.uuid, data.new_email);
    }

    user.email_new = Some(data.new_email);
    user.email_new_token = Some(token);
    user.save(&conn).await
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
async fn post_email(data: Json<ChangeEmailData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: ChangeEmailData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.new_email, &conn).await.is_some() {
        err!("Email already in use");
    }

    if let Some(ref val) = user.email_new {
        if val != &data.new_email {
            err!("Email change mismatch");
        }
    } else {
        err!("No email change pending")
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        if let Some(ref val) = user.email_new_token {
            if *val != data.token.into_string() {
                err!("Token mismatch");
            }
        } else {
            err!("No email change pending")
        }
        user.verified_at = Some(Utc::now().naive_utc());
    } else {
        user.verified_at = None;
    }

    user.email = data.new_email;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;

    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    save_result
}

#[post("/accounts/verify-email")]
async fn post_verify_email(headers: Headers) -> EmptyResult {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
        error!("Error sending verify_email email: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailTokenData {
    user_id: UserId,
    token: String,
}

#[post("/accounts/verify-email-token", data = "<data>")]
async fn post_verify_email_token(data: Json<VerifyEmailTokenData>, conn: DbConn) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner();

    let Some(mut user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    let Ok(claims) = decode_verify_email(&data.token) else {
        err!("Invalid claim")
    };
    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now().naive_utc());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    if let Err(e) = user.save(&conn).await {
        error!("Error saving email verification: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverData {
    email: String,
}

#[post("/accounts/delete-recover", data = "<data>")]
async fn post_delete_recover(data: Json<DeleteRecoverData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data: DeleteRecoverData = data.into_inner();

    if CONFIG.mail_enabled() {
        if let Some(user) = User::find_by_mail(&data.email, &conn).await
            && let Err(e) = mail::send_delete_account(&user.email, &user.uuid).await
        {
            error!("Error sending delete account email: {e:#?}");
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
    user_id: UserId,
    token: String,
}

#[post("/accounts/delete-recover-token", data = "<data>")]
async fn post_delete_recover_token(data: Json<DeleteRecoverTokenData>, conn: DbConn) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner();

    let Ok(claims) = decode_delete(&data.token) else {
        err!("Invalid claim")
    };

    let Some(user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }
    user.delete(&conn).await
}

#[post("/accounts/delete", data = "<data>")]
async fn post_delete_account(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_account(data, headers, conn).await
}

#[delete("/accounts", data = "<data>")]
async fn delete_account(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &conn).await?;

    user.delete(&conn).await
}

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
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
async fn password_hint(data: Json<PasswordHintData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    const NO_HINT: &str = "Sorry, you have no password hint...";

    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    if !CONFIG.password_hints_allowed() || (!CONFIG.mail_enabled() && !CONFIG.show_password_hint()) {
        err!("This server is not configured to provide password hints.");
    }

    let data: PasswordHintData = data.into_inner();
    let email = &data.email;

    match User::find_by_mail(email, &conn).await {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::{RngExt, rngs::SmallRng};
                let mut rng: SmallRng = rand::make_rng();
                let sleep_ms: u64 = rng.random_range(900..=1100);
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
async fn post_prelogin(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    prelogin(data, conn).await
}

pub async fn prelogin(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    let data: PreloginData = data.into_inner();

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&data.email, &conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    };

    Json(json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
        "kdfSettings": {
            "iterations": kdf_iter,
            "kdfType": kdf_type,
            "memory": kdf_mem,
            "parallelism": kdf_para
        },
        "salt": null,
    }))
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Auth/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretVerificationRequest {
    master_password_hash: String,
}

// Change the KDF Iterations if necessary
pub async fn kdf_upgrade(user: &mut User, pwd_hash: &str, conn: &DbConn) -> ApiResult<()> {
    if user.password_iterations < CONFIG.password_iterations() {
        user.password_iterations = CONFIG.password_iterations();
        user.set_password(pwd_hash, None, false, None, conn).await?;

        if let Err(e) = user.save(conn).await {
            error!("Error updating user: {e:#?}");
        }
    }
    Ok(())
}

#[post("/accounts/verify-password", data = "<data>")]
async fn verify_password(data: Json<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SecretVerificationRequest = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    kdf_upgrade(&mut user, &data.master_password_hash, &conn).await?;

    Ok(Json(master_password_policy(&user, &conn).await))
}

async fn update_api_key(data: Json<PasswordOrOtpData>, rotate: bool, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&user, true, &conn).await?;

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&conn).await.expect("Error saving API key");
    }

    Ok(Json(json!({
      "apiKey": user.api_key,
      "revisionDate": format_date(&user.updated_at),
      "object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
async fn post_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, false, headers, conn).await
}

#[post("/accounts/rotate-api-key", data = "<data>")]
async fn rotate_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, true, headers, conn).await
}

#[get("/devices/knowndevice")]
async fn get_known_device(device: KnownDevice, conn: DbConn) -> JsonResult {
    let result = if let Some(user) = User::find_by_mail(&device.email, &conn).await {
        Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.is_some()
    } else {
        false
    };
    Ok(Json(json!(result)))
}

struct KnownDevice {
    email: String,
    uuid: DeviceId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for KnownDevice {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let email = if let Some(email_b64) = req.headers().get_one("X-Request-Email") {
            // Bitwarden seems to send padded Base64 strings since 2026.2.1
            // Since these values are not streamed and Headers are always split by newlines
            // we can safely ignore padding here and remove any '=' appended.
            let email_b64 = email_b64.trim_end_matches('=');

            let Ok(email_bytes) = data_encoding::BASE64URL_NOPAD.decode(email_b64.as_bytes()) else {
                return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as base64url"));
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
            uuid.to_owned().into()
        } else {
            return Outcome::Error((Status::BadRequest, "X-Device-Identifier value is required"));
        };

        Outcome::Success(KnownDevice {
            email,
            uuid,
        })
    }
}

#[get("/devices")]
async fn get_all_devices(headers: Headers, conn: DbConn) -> JsonResult {
    let devices = Device::find_with_auth_request_by_user(&headers.user.uuid, &conn).await;
    let devices = devices.iter().map(DeviceWithAuthRequest::to_json).collect::<Vec<Value>>();

    Ok(Json(json!({
        "data": devices,
        "continuationToken": null,
        "object": "list"
    })))
}

#[get("/devices/identifier/<device_id>")]
async fn get_device(device_id: DeviceId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err!("No device found");
    };
    Ok(Json(device.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

#[post("/devices/identifier/<device_id>/token", data = "<data>")]
async fn post_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    put_device_token(device_id, data, headers, conn).await
}

#[put("/devices/identifier/<device_id>/token", data = "<data>")]
async fn put_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let token = data.push_token;

    let Some(mut device) = Device::find_by_uuid_and_user(&headers.device.uuid, &headers.user.uuid, &conn).await else {
        err!(format!("Error: device {device_id} should be present before a token can be assigned"))
    };

    // Check if the new token is the same as the registered token
    // Although upstream seems to always register a device on login, we do not.
    // Unless this causes issues, lets keep it this way, else we might need to also register on every login.
    if device.push_token.as_ref() == Some(&token) {
        debug!("Device {device_id} for user {} is already registered and token is identical", headers.user.uuid);
        return Ok(());
    }

    device.push_token = Some(token);
    if let Err(e) = device.save(true, &conn).await {
        err!(format!("An error occurred while trying to save the device push token: {e}"));
    }

    register_push_device(&mut device, &conn).await?;

    Ok(())
}

#[put("/devices/identifier/<device_id>/clear-token")]
async fn put_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    // This only clears push token
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Controllers/DevicesController.cs#L215
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    // 2025: Also, it looks like it only clears the first found device upstream, which is probably faulty.
    //       This because currently multiple accounts could be on the same device/app and that would cause issues.
    //       Vaultwarden removes the push-token for all devices, but this probably means we should also unregister all these devices.
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    if let Some(device) = Device::find_by_uuid(&device_id, &conn).await {
        Device::clear_push_token_by_uuid(&device_id, &conn).await?;
        unregister_push_device(device.push_uuid.as_ref()).await?;
    }

    Ok(())
}

// On upstream server, both PUT and POST are declared. Implementing the POST method in case it would be useful somewhere
#[post("/devices/identifier/<device_id>/clear-token")]
async fn post_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    put_clear_device_token(device_id, ip, conn).await
}

// Trusted device encryption, see https://bitwarden.com/help/login-with-sso-trusted-devices/
// The three key blobs below are generated and encrypted by the client, the server only stores them
// and hands them back on the next login of that same device. It never learns the device key that
// unwraps `encrypted_private_key`, so a stored trust is worth nothing without the device itself.
// https://github.com/bitwarden/server/blob/main/src/Api/Controllers/DevicesController.cs

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedDeviceKeysData {
    encrypted_user_key: String,
    encrypted_public_key: String,
    encrypted_private_key: String,
}

/// Refuses anything that does not even have the shape of an `EncString`.
///
/// The server cannot tell whether a blob decrypts, but storing something that certainly does not
/// only leaves a device that calls itself trusted and fails its owner at the next unlock. Upstream
/// puts `[EncryptedString]` on the same fields.
fn validate_enc_strings(values: &[(&str, &str)]) -> EmptyResult {
    for (name, value) in values {
        if !crate::util::is_valid_enc_string(value) {
            err!(format!("{name} is not a valid encrypted string"))
        }
    }
    Ok(())
}

/// Marks a device of the current user as trusted.
///
/// Upstream keys this on the device identifier and does not require it to be the device the request
/// was authenticated with, so neither do we. The keys only ever unlock the vault on the device that
/// holds the matching device key, so writing them for another of your own devices gains nothing.
#[put("/devices/<device_id>/keys", data = "<data>")]
async fn put_device_keys(
    device_id: DeviceId,
    data: Json<TrustedDeviceKeysData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data = data.into_inner();

    validate_enc_strings(&[
        ("encryptedUserKey", &data.encrypted_user_key),
        ("encryptedPublicKey", &data.encrypted_public_key),
        ("encryptedPrivateKey", &data.encrypted_private_key),
    ])?;

    let Some(mut device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err!("No device found")
    };

    device.encrypted_user_key = Some(data.encrypted_user_key);
    device.encrypted_public_key = Some(data.encrypted_public_key);
    device.encrypted_private_key = Some(data.encrypted_private_key);
    device.save(true, &conn).await?;

    Ok(Json(device.to_json()))
}

// Deprecated upstream in favour of the PUT variant, but still served for older clients
#[post("/devices/<device_id>/keys", data = "<data>")]
async fn post_device_keys(
    device_id: DeviceId,
    data: Json<TrustedDeviceKeysData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    put_device_keys(device_id, data, headers, conn).await
}

/// The public half of a device's trust, needed by the clients to re-wrap the user key for every
/// trusted device during a key rotation.
#[post("/devices/<device_id>/retrieve-keys")]
async fn post_device_retrieve_keys(device_id: DeviceId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err!("No device found")
    };

    Ok(Json(device.to_protected_json()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceTrustUpdateData {
    encrypted_user_key: String,
    encrypted_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OtherDeviceTrustUpdateData {
    device_id: DeviceId,
    #[serde(flatten)]
    keys: DeviceTrustUpdateData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDevicesTrustData {
    #[serde(flatten)]
    secret: PasswordOrOtpData,
    current_device: DeviceTrustUpdateData,
    #[serde(default)]
    other_devices: Vec<OtherDeviceTrustUpdateData>,
}

/// Re-wraps the user key for the trusted devices after it was replaced by a key rotation.
///
/// Every trusted device that is not listed loses its trust: its stored copy of the user key is the
/// old one and would no longer unlock anything.
///
/// The current clients do this as part of the rotation itself and never come here; this is the
/// route the older ones take, and the only one that can rotate the trust of a single device without
/// rotating the account. See `post_rotatekey`.
#[post("/devices/update-trust", data = "<data>")]
async fn post_devices_update_trust(data: Json<UpdateDevicesTrustData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();

    data.secret.validate(&headers.user, true, &conn).await?;

    validate_enc_strings(&[
        ("encryptedUserKey", &data.current_device.encrypted_user_key),
        ("encryptedPublicKey", &data.current_device.encrypted_public_key),
    ])?;

    let devices = Device::find_by_user(&headers.user.uuid, &conn).await;
    if !devices.iter().any(|device| device.uuid == headers.device.uuid) {
        err!("No device found")
    }

    // The current device is written whatever it holds now, as upstream does: it is the one the
    // caller is speaking from and just proved it can unlock.
    let mut updates = vec![(
        headers.device.uuid.clone(),
        data.current_device.encrypted_user_key,
        data.current_device.encrypted_public_key,
    )];
    let mut listed: HashSet<DeviceId> = HashSet::from([headers.device.uuid.clone()]);

    // Validate everything before writing anything, so one bad entry cannot leave the devices
    // wrapping a mix of the old and the new user key.
    for other in data.other_devices {
        if !listed.insert(other.device_id.clone()) {
            if other.device_id == headers.device.uuid {
                err!("The current device cannot also be part of the optional rotation")
            }
            err!("A device was listed more than once in the rotation")
        }

        let Some(device) = devices.iter().find(|device| device.uuid == other.device_id) else {
            err!(format!("Device {} does not belong to this user", other.device_id))
        };

        validate_enc_strings(&[
            ("encryptedUserKey", &other.keys.encrypted_user_key),
            ("encryptedPublicKey", &other.keys.encrypted_public_key),
        ])?;

        // A rotation clears the wrapped user key of every device, so the listed ones are not
        // trusted at this point; their key pair is what they are restored from. Without it there is
        // nothing the two keys could belong to, so the device is left to be untrusted instead.
        if device.holds_private_key() {
            updates.push((other.device_id, other.keys.encrypted_user_key, other.keys.encrypted_public_key));
        }
    }

    Device::replace_trust(&headers.user.uuid, updates, &conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UntrustDevicesData {
    devices: Vec<DeviceId>,
}

#[post("/devices/untrust", data = "<data>")]
async fn post_devices_untrust(data: Json<UntrustDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();

    let owned: HashSet<DeviceId> =
        Device::find_by_user(&headers.user.uuid, &conn).await.into_iter().map(|device| device.uuid).collect();

    // Check that the user owns all of them first, so a single foreign id does not leave the request
    // half applied.
    if let Some(unknown) = data.devices.iter().find(|device_id| !owned.contains(*device_id)) {
        err!(format!("Device {unknown} does not belong to this user"))
    }

    Device::untrust_many(&headers.user.uuid, data.devices, &conn).await
}

/// Reported by a client that still holds a device key but did not get any keys back from us.
///
/// There is nothing left to clean up at this point, the device already counts as untrusted here.
/// Upstream only writes a log line as well, since this points at the client and the server having
/// drifted apart.
#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[post("/devices/lost-trust")]
fn post_devices_lost_trust(headers: Headers) -> EmptyResult {
    warn!(
        "Device {} ({}) of user {} still holds a device key, but has no trusted device keys on the server",
        headers.device.uuid,
        DeviceType::from_i32(headers.device.atype),
        headers.user.uuid
    );

    Ok(())
}

#[get("/tasks")]
fn get_tasks(_client_headers: ClientHeaders) -> JsonResult {
    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequestRequest {
    access_code: String,
    device_identifier: DeviceId,
    email: String,
    public_key: String,
    #[serde(default, rename = "type")]
    atype: i32,
}

/// Upstream puts `[StringLength(25)]` on the access code, so no client sends more than that.
/// https://github.com/bitwarden/server/blob/main/src/Core/Auth/Models/Api/Request/AuthRequest/AuthRequestCreateRequestModel.cs
const MAX_ACCESS_CODE_LENGTH: usize = 25;

/// A base64 SPKI RSA-4096 public key is under a kilobyte; this leaves room for whatever comes next.
const MAX_REQUEST_PUBLIC_KEY_LENGTH: usize = 4096;

impl AuthRequestRequest {
    /// Both of these end up stored, and the admin approval route stores a copy per organization the
    /// user belongs to, so neither may be unbounded. The public key is handed to the answering
    /// client as base64 to wrap a key against; one that is not base64 at all would break the page
    /// listing the requests rather than just this one.
    fn validate(&self) -> EmptyResult {
        if self.access_code.is_empty() || self.access_code.len() > MAX_ACCESS_CODE_LENGTH {
            err!("Invalid access code")
        }

        if self.public_key.is_empty()
            || self.public_key.len() > MAX_REQUEST_PUBLIC_KEY_LENGTH
            || data_encoding::BASE64.decode(self.public_key.as_bytes()).is_err()
        {
            err!("Invalid public key")
        }

        Ok(())
    }
}

fn auth_request_json(auth_request: &AuthRequest) -> Value {
    json!({
        "id": auth_request.uuid,
        "publicKey": auth_request.public_key,
        "type": auth_request.atype,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        // The clients read the raw enum value as well, to pick an icon for the asking device.
        "requestDeviceTypeValue": auth_request.device_type,
        "requestDeviceIdentifier": auth_request.request_device_identifier,
        "requestIpAddress": auth_request.request_ip,
        // Not recorded here, but the clients read it, so it is answered rather than missing.
        "requestCountryName": null,
        "key": auth_request.enc_key,
        "masterPasswordHash": auth_request.master_password_hash,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": auth_request.response_date.as_ref().map(format_date),
        "requestApproved": auth_request.approved.unwrap_or(false),
        "origin": CONFIG.domain_origin(),
        "object": "auth-request"
    })
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    client_headers: ClientHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();

    // Asking an administrator for approval means telling them who is asking, so that one is only
    // available to a caller who has already proven who they are. See `post_admin_auth_request`.
    if AuthRequestType::from_i32(data.atype) == Some(AuthRequestType::AdminApproval) {
        err!("You must be authenticated to create a request of that type")
    }

    data.validate()?;

    let Some(user) = User::find_by_mail(&data.email, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    // Validate device uuid and type
    let device = match Device::find_by_uuid_and_user(&data.device_identifier, &user.uuid, &conn).await {
        Some(device) if device.atype == client_headers.device_type => device,
        _ => err!("AuthRequest doesn't exist", "Device verification failed"),
    };

    let Some(atype) = AuthRequestType::from_i32(data.atype) else {
        err!("Unknown auth request type")
    };

    let mut auth_request = AuthRequest::new(
        user.uuid.clone(),
        None,
        atype,
        data.device_identifier.clone(),
        client_headers.device_type,
        client_headers.ip.ip.to_string(),
        data.access_code,
        data.public_key,
    );
    auth_request.save(&conn).await?;

    nt.send_auth_request(&user.uuid, &auth_request.uuid, &device, &conn).await;

    log_user_event(
        EventType::UserRequestedDeviceApproval as i32,
        &user.uuid,
        client_headers.device_type,
        &client_headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(auth_request_json(&auth_request)))
}

/// Asks the administrators of every organization the user belongs to to let this device in.
///
/// The way out for someone who unlocks with trusted devices and has no other device left to ask.
/// One request per organization, so whichever administrator gets there first can answer.
/// https://github.com/bitwarden/server/blob/main/src/Api/Auth/Controllers/AuthRequestsController.cs
#[post("/auth-requests/admin-request", data = "<data>")]
async fn post_admin_auth_request(data: Json<AuthRequestRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    // Every call mails all administrators of every organization involved, so it is worth a limit of
    // its own even though the caller is authenticated.
    crate::ratelimit::check_limit_unauthenticated(&headers.ip.ip)?;

    let data = data.into_inner();

    if AuthRequestType::from_i32(data.atype) != Some(AuthRequestType::AdminApproval) {
        err!("Invalid auth request type, expected admin approval")
    }

    if data.device_identifier != headers.device.uuid {
        err!("AuthRequest doesn't exist", "Device verification failed")
    }

    data.validate()?;

    // Only an organization that could actually answer is asked. Approving means handing the member
    // their own user key, which an administrator can only do with the key that enrolling into
    // account recovery left them, so an organization without one has nothing to offer and does not
    // need the email address, the address and the device of the asker.
    let memberships: Vec<Membership> = Membership::find_by_user(&headers.user.uuid, &conn)
        .await
        .into_iter()
        .filter(Membership::can_use_admin_approval)
        .collect();
    if memberships.is_empty() {
        err!("User does not belong to any organization that could approve a device")
    }

    log_user_event(
        EventType::UserRequestedDeviceApproval as i32,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    let mut first_request = None;
    for membership in memberships {
        // Repeating the very same request is answered with the row it already has, so a client that
        // sends it twice does not pile up rows and does not mail the administrators again.
        //
        // What identifies the request is the key pair the client generated for it: an approval is
        // the user key wrapped for that public key, and the fingerprint an administrator reads out
        // is derived from it. A client that asks again with a new key pair is therefore asking
        // something else, and giving it the id of the pending request would let an administrator
        // who is still looking at the old one approve it for a key the requester has thrown away.
        // Upstream never reuses a request at all, it creates one per attempt.
        // https://github.com/bitwarden/server/blob/main/src/Core/Auth/Services/Implementations/AuthRequestService.cs
        let existing = AuthRequest::find_pending_admin_approval(
            &headers.user.uuid,
            &data.device_identifier,
            &membership.org_uuid,
            &conn,
        )
        .await
        .filter(|request| request.public_key == data.public_key && request.access_code == data.access_code);
        let is_new = existing.is_none();

        let mut auth_request = match existing {
            Some(mut auth_request) => {
                // Only what says where the request is being made from, never the keys it is made
                // with; those are what the id stands for.
                auth_request.device_type = headers.device.atype;
                auth_request.request_ip = headers.ip.ip.to_string();
                auth_request.creation_date = Utc::now().naive_utc();
                auth_request
            }
            None => AuthRequest::new(
                headers.user.uuid.clone(),
                Some(membership.org_uuid.clone()),
                AuthRequestType::AdminApproval,
                data.device_identifier.clone(),
                headers.device.atype,
                headers.ip.ip.to_string(),
                data.access_code.clone(),
                data.public_key.clone(),
            ),
        };
        auth_request.save(&conn).await?;

        if is_new {
            notify_device_approval_requested(&headers.user, &membership.org_uuid, &conn).await;
        }

        if first_request.is_none() {
            first_request = Some(auth_request);
        }
    }

    // Guaranteed by the emptiness check above
    let auth_request = first_request.expect("at least one organization");
    Ok(Json(auth_request_json(&auth_request)))
}

/// Mails everyone in the organization who could answer the request. Failing to reach them must not
/// undo the request itself, so problems are logged rather than returned.
async fn notify_device_approval_requested(user: &User, org_id: &OrganizationId, conn: &DbConn) {
    if !CONFIG.mail_enabled() {
        return;
    }

    let Some(org) = Organization::find_by_uuid(org_id, conn).await else {
        return;
    };

    // The same set that may answer the request, see `ManageResetPasswordHeaders`. Mailing anyone
    // else would tell them who is asking for something they cannot do anything about.
    let approvers = Membership::find_confirmed_by_org(org_id, conn)
        .await
        .into_iter()
        .filter(Membership::can_manage_reset_password_now);

    for approver in approvers {
        let Some(admin) = User::find_by_uuid(&approver.user_uuid, conn).await else {
            continue;
        };

        if let Err(e) =
            mail::send_device_approval_requested(&admin.email, org_id, &org.name, &user.email, &user.name).await
        {
            error!("Error sending device approval request email: {e:#?}");
        }
    }
}

#[get("/auth-requests/<auth_request_id>")]
async fn get_auth_request(auth_request_id: AuthRequestId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err!("AuthRequest doesn't exist", "Record not found or user uuid does not match")
    };

    // The anonymous lookup refuses an expired request, and so does this one: the window an approval
    // stays usable in should not depend on which of the two the client happens to poll.
    if auth_request.is_expired() {
        err!("AuthRequest doesn't exist", "Request has expired")
    }

    Ok(Json(auth_request_json(&auth_request)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseRequest {
    device_identifier: DeviceId,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}

#[put("/auth-requests/<auth_request_id>", data = "<data>")]
async fn put_auth_request(
    auth_request_id: AuthRequestId,
    data: Json<AuthResponseRequest>,
    headers: Headers,
    conn: DbConn,
    ant: AnonymousNotify<'_>,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();
    let Some(mut auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err!("AuthRequest doesn't exist", "Record not found or user uuid does not match")
    };

    // A request addressed to an administrator is answered through the organization, where the
    // permission to do so can actually be checked. Letting the asking user answer it here would
    // make the whole detour pointless.
    if auth_request.is_admin_approval() {
        err!("AuthRequest doesn't exist", "Admin approval requests are answered by the organization")
    }

    if headers.device.uuid != data.device_identifier {
        err!("AuthRequest doesn't exist", "Device verification failed")
    }

    if auth_request.approved.is_some() {
        err!("An authentication request with the same device already exists")
    }

    if auth_request.is_expired() {
        err!("AuthRequest doesn't exist", "Request has expired")
    }

    // Only the newest request of a device may be approved. Anyone can create a request for a known
    // device, so without this an older one could still be sitting there when the user approves what
    // their screen shows, and the answer would go to whoever left it. Same check as upstream.
    if data.request_approved
        && AuthRequest::find_by_user_and_requested_device(
            &headers.user.uuid,
            &auth_request.request_device_identifier,
            &conn,
        )
        .await
        .is_none_or(|newest| newest.uuid != auth_request.uuid)
    {
        err!("This request is no longer valid. Make sure to approve the most recent request.")
    }

    let response_date = Utc::now().naive_utc();

    if data.request_approved {
        auth_request.approved = Some(data.request_approved);
        auth_request.enc_key = Some(data.key);
        auth_request.master_password_hash = data.master_password_hash;
        auth_request.response_device_id = Some(data.device_identifier.clone());
        auth_request.response_date = Some(response_date);
        auth_request.save(&conn).await?;

        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, Some(&headers.device), &conn).await;

        log_user_event(
            EventType::OrganizationUserApprovedAuthRequest as i32,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    } else {
        // If denied, there's no reason to keep the request
        auth_request.delete(&conn).await?;
        log_user_event(
            EventType::OrganizationUserRejectedAuthRequest as i32,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    }

    Ok(Json(auth_request_json(&auth_request)))
}

#[get("/auth-requests/<auth_request_id>/response?<code>")]
async fn get_auth_request_response(
    auth_request_id: AuthRequestId,
    code: &str,
    client_headers: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    let Some(auth_request) = AuthRequest::find_by_uuid(&auth_request_id, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    if auth_request.device_type != client_headers.device_type
        || auth_request.request_ip != client_headers.ip.ip.to_string()
        || !auth_request.check_access_code(code)
    {
        err!("AuthRequest doesn't exist", "Invalid device, IP or code")
    }

    if auth_request.is_expired() {
        err!("AuthRequest doesn't exist", "Request has expired")
    }

    Ok(Json(auth_request_json(&auth_request)))
}

// Now unused but not yet removed
// cf https://github.com/bitwarden/clients/blob/9b2fbdba1c028bf3394064609630d2ec224baefa/libs/common/src/services/api.service.ts#L245
#[get("/auth-requests")]
async fn get_auth_requests(headers: Headers, conn: DbConn) -> JsonResult {
    get_auth_requests_pending(headers, conn).await
}

#[get("/auth-requests/pending")]
async fn get_auth_requests_pending(headers: Headers, conn: DbConn) -> JsonResult {
    let auth_requests = AuthRequest::find_by_user(&headers.user.uuid, &conn).await;

    Ok(Json(json!({
        "data": auth_requests
            .iter()
            // The same set a device answers for itself, see `find_by_user_and_requested_device`.
            .filter(|request| request.approved.is_none() && !request.is_admin_approval() && !request.is_expired())
            .map(|request| {
            let response_date_utc = request.response_date.map(|response_date| format_date(&response_date));

            json!({
                "id": request.uuid,
                "publicKey": request.public_key,
                "requestDeviceType": DeviceType::from_i32(request.device_type).to_string(),
                "requestIpAddress": request.request_ip,
                "key": request.enc_key,
                "masterPasswordHash": request.master_password_hash,
                "creationDate": format_date(&request.creation_date),
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
        error!("Failed to get DB connection while purging auth requests");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, trusted: bool) -> Device {
        let mut device = Device::new(id.to_owned().into(), String::from("user").into(), String::new(), 9);
        if trusted {
            device.encrypted_user_key = Some(String::from("4.b2xkdXNlcmtleQ=="));
            device.encrypted_public_key = Some(String::from("2.aXY=|Y2lwaGVy|bWFj"));
            device.encrypted_private_key = Some(String::from("2.aXY=|Y2lwaGVy|bWFj"));
        }
        device
    }

    fn update(device_id: &str) -> UpdateDeviceKeysData {
        UpdateDeviceKeysData {
            device_id: device_id.to_owned().into(),
            encrypted_user_key: String::from("4.bmV3dXNlcmtleQ=="),
            encrypted_public_key: String::from("2.aXY=|bmV3|bWFj"),
        }
    }

    /// The ids and keys the rotation would write, so a test can say what it expects in one line.
    fn rotated(result: &[(DeviceId, String, String)]) -> Vec<String> {
        result.iter().map(|(device_id, user_key, _)| format!("{device_id}={user_key}")).collect()
    }

    #[test]
    fn a_trusted_device_that_is_listed_keeps_its_trust() {
        let devices = [device("a", true), device("b", true)];
        let updates = [update("a"), update("b")];

        let result = validate_device_keydata(&updates, &devices).unwrap();
        assert_eq!(
            rotated(&result),
            ["a=4.bmV3dXNlcmtleQ==", "b=4.bmV3dXNlcmtleQ=="],
            "both are re-wrapped, neither keeps the previous user key"
        );
    }

    #[test]
    fn a_trusted_device_that_is_left_out_takes_the_rotation_down_with_it() {
        // Silently dropping the trust of a device the user still relies on is not the server's call
        // to make; the client untrusts it first if that is what it means.
        let devices = [device("a", true), device("b", true)];

        let err = validate_device_keydata(&[update("a")], &devices).unwrap_err();
        assert!(format!("{err}").contains("All existing trusted devices must be included"));
    }

    #[test]
    fn a_device_of_somebody_else_is_refused() {
        let devices = [device("a", true)];

        let err = validate_device_keydata(&[update("a"), update("stranger")], &devices).unwrap_err();
        assert!(format!("{err}").contains("does not belong to this user"));
    }

    #[test]
    fn the_same_device_may_not_be_listed_twice() {
        // Two entries for one device means one of the two keys is dropped without anyone noticing
        // which, so neither is taken.
        let devices = [device("a", true)];

        let err = validate_device_keydata(&[update("a"), update("a")], &devices).unwrap_err();
        assert!(format!("{err}").contains("listed more than once"));
    }

    #[test]
    fn a_key_that_is_not_an_encrypted_string_is_refused() {
        let devices = [device("a", true)];

        let mut broken = update("a");
        broken.encrypted_user_key = String::from("not an enc string");
        let err = validate_device_keydata(&[broken], &devices).unwrap_err();
        assert!(format!("{err}").contains("encryptedUserKey"));

        let mut broken = update("a");
        broken.encrypted_public_key = String::new();
        let err = validate_device_keydata(&[broken], &devices).unwrap_err();
        assert!(format!("{err}").contains("encryptedPublicKey"));
    }

    #[test]
    fn a_device_without_its_own_key_pair_is_not_given_a_user_key() {
        // Half a trust is worth nothing to the client and would only fail at the next unlock, so
        // the device is dropped from the rotation and ends up untrusted instead.
        let devices = [device("a", true), device("b", false)];

        let result = validate_device_keydata(&[update("a"), update("b")], &devices).unwrap();
        assert_eq!(rotated(&result), ["a=4.bmV3dXNlcmtleQ=="]);
    }

    #[test]
    fn a_user_who_trusts_no_device_rotates_nothing() {
        let devices = [device("a", false)];

        let result = validate_device_keydata(&[], &devices).unwrap();
        assert!(result.is_empty(), "and the leftovers of `a` are cleared by the write that follows");
    }

    #[test]
    fn a_partially_trusted_device_does_not_have_to_be_listed() {
        // It cannot unlock anything as it stands, so leaving it out is not the loss of a trust.
        let devices = [device("a", true), half_trusted("b")];

        let result = validate_device_keydata(&[update("a")], &devices).unwrap();
        assert_eq!(rotated(&result), ["a=4.bmV3dXNlcmtleQ=="]);
    }

    /// A device left holding nothing but its own key pair, which is what a rotation by a client too
    /// old to send `deviceKeyUnlockData` leaves behind. It does not unlock anything as it stands.
    fn half_trusted(id: &str) -> Device {
        let mut device = device(id, true);
        device.encrypted_user_key = None;
        device.encrypted_public_key = None;
        assert!(!device.is_trusted(), "not trusted");
        assert!(device.holds_private_key(), "but still holds its key pair");
        device
    }

    #[test]
    fn a_rotation_does_not_trust_a_device_that_was_not_trusted() {
        // Trusting a device is `PUT /devices/<id>/keys`, taken by the device itself once it holds
        // the device key these blobs are wrapped for. A rotation only carries an existing trust
        // over to the new user key, so listing an untrusted device here gains it nothing, even
        // though its key pair is still around for the trust it could be given later.
        let devices = [device("a", true), half_trusted("b")];

        let result = validate_device_keydata(&[update("a"), update("b")], &devices).unwrap();
        assert_eq!(rotated(&result), ["a=4.bmV3dXNlcmtleQ=="], "`b` is passed over and cleared by the write");
    }

    #[test]
    fn a_rotation_cannot_hand_a_user_their_first_trusted_device() {
        // The same the other way round: with nothing to carry over, a rotation writes no trust at
        // all, however much the request offers.
        let devices = [half_trusted("a"), half_trusted("b")];

        let result = validate_device_keydata(&[update("a"), update("b")], &devices).unwrap();
        assert!(result.is_empty(), "no device was trusted before the rotation, so none is after it");
    }
}
