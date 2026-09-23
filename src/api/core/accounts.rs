use std::collections::HashSet;

use chrono::Utc;
use num_traits::FromPrimitive;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        AnonymousNotify, ApiResult, EmptyResult, JsonResult, LogOutReason, Notify, PasswordOrOtpData, UpdateType,
        core::{accept_org_invite, log_user_event, two_factor::email},
        master_password_policy, register_push_device, unregister_push_device,
    },
    auth::{ClientHeaders, ClientIp, Headers, decode_delete, decode_invite, decode_verify_email},
    crypto,
    db::{
        DbConn, DbPool,
        models::{
            AuthRequest, AuthRequestId, Cipher, CipherId, Device, DeviceId, DeviceType, DeviceWithAuthRequest,
            EmergencyAccess, EmergencyAccessId, EventType, Folder, FolderId, Invitation, KeyId, Membership,
            MembershipId, OrgPolicy, OrgPolicyType, Organization, OrganizationId, Send, SendId, SignatureAlgorithm,
            User, UserId, UserKdfType, UserSignatureKeyPair,
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
        get_account_public_keys,
        get_keys,
        post_keys,
        post_password,
        post_set_password,
        post_kdf,
        get_key_rotation_data,
        post_rotatekey,
        post_user_key,
        post_rotate_user_keys,
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
        get_tasks,
        post_auth_request,
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

    // Supersedes `keys`, and the only way a v2 account can be registered.
    account_keys: Option<AccountKeysData>,

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

    fn hash(&self) -> String {
        self.fold(|rdc| &rdc.master_password_hash, |rdcu| &rdcu.master_password_authentication.hash).to_owned()
    }

    fn kdf(&self) -> &KDFData {
        self.fold(|rdc| &rdc.kdf, |rdcu| &rdcu.master_password_authentication.kdf)
    }

    fn key(&self) -> String {
        self.fold(|rdc| &rdc.key, |rdcu| &rdcu.master_password_unlock.key).to_owned()
    }

    /// The id of the user key, which only the current format carries.
    fn key_id(&self) -> Option<KeyId> {
        match self {
            RegisterDataCompat::RegisterDataOld(_) => None,
            RegisterDataCompat::RegisterDataCur(rdcu) => rdcu.master_password_unlock.contained_key_id.clone(),
        }
    }

    // When comparing with salt, email need to be normalized:
    //  - https://github.com/bitwarden/clients/blob/web-v2026.5.0/libs/common/src/key-management/master-password/services/master-password.service.ts#L171
    fn unprocessable(&self, email: &str) -> bool {
        let mut unprocessable = false;
        *self.fold(
            |_| &false,
            |rdcu| {
                let email = email.trim().to_lowercase();
                unprocessable = rdcu.master_password_authentication.kdf != rdcu.master_password_unlock.kdf
                    || rdcu.master_password_authentication.salt != email
                    || rdcu.master_password_unlock.salt != email;
                &unprocessable
            },
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

/// The `accountKeys` payload, which replaces the flat `keys`/`userAsymmetricKeys` object.
///
/// It carries either a "v1" state (just the encryption key pair) or a "v2" one, which adds a
/// signature key pair, a signed public key, and a signed security state. The two deprecated
/// top-level fields are still sent by the SDK alongside the nested ones and are only used as a
/// fallback for clients that don't send `publicKeyEncryptionKeyPair` yet.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/Models/Api/Request/AccountKeysRequestModel.cs>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeysData {
    user_key_encrypted_account_private_key: Option<String>,
    account_public_key: Option<String>,

    public_key_encryption_key_pair: Option<PublicKeyEncryptionKeyPairData>,
    signature_key_pair: Option<SignatureKeyPairData>,
    security_state: Option<SecurityStateData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyEncryptionKeyPairData {
    wrapped_private_key: String,
    public_key: String,
    signed_public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureKeyPairData {
    signature_algorithm: String,
    wrapped_signing_key: String,
    verifying_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityStateData {
    security_state: String,
    security_version: i32,
}

pub struct ValidatedAccountKeys {
    private_key: String,
    public_key: String,
    v2: Option<ValidatedV2AccountKeys>,
}

struct ValidatedV2AccountKeys {
    signed_public_key: String,
    signing_key: String,
    verifying_key: String,
    signature_algorithm: SignatureAlgorithm,
    security_state: String,
    security_version: i32,
}

impl AccountKeysData {
    /// Checks that the payload describes a complete account cryptographic state.
    ///
    /// The v2 fields have to be all present or all absent: a client that receives a COSE-wrapped
    /// private key without the matching signature key pair and security state refuses to unlock the
    /// vault, so storing half a state would produce an account nobody can log into.
    pub fn validate(self) -> ApiResult<ValidatedAccountKeys> {
        let (private_key, public_key, signed_public_key) = if let Some(key_pair) = self.public_key_encryption_key_pair {
            (key_pair.wrapped_private_key, key_pair.public_key, key_pair.signed_public_key)
        // Older clients only send the deprecated top-level fields, which are always v1.
        } else if let (Some(private_key), Some(public_key)) =
            (self.user_key_encrypted_account_private_key, self.account_public_key)
        {
            (private_key, public_key, None)
        } else {
            err!("The account keys are missing an encryption key pair")
        };

        let v2 = match (signed_public_key, self.signature_key_pair, self.security_state) {
            (Some(signed_public_key), Some(signature_key_pair), Some(security_state)) => {
                let Some(signature_algorithm) = SignatureAlgorithm::parse(&signature_key_pair.signature_algorithm)
                else {
                    err!(format!("Unsupported signature algorithm: {}", signature_key_pair.signature_algorithm))
                };

                Some(ValidatedV2AccountKeys {
                    signed_public_key,
                    signing_key: signature_key_pair.wrapped_signing_key,
                    verifying_key: signature_key_pair.verifying_key,
                    signature_algorithm,
                    security_state: security_state.security_state,
                    security_version: security_state.security_version,
                })
            }
            (None, None, None) => None,
            _ => err!(
                "Invalid account keys: the signed public key, signature key pair and security state must either all be present or all be absent"
            ),
        };

        Ok(ValidatedAccountKeys {
            private_key,
            public_key,
            v2,
        })
    }
}

impl WrappedAccountCryptographicState {
    /// This shape is v2-only: the key pairs and security state were already required by the
    /// deserializer, so a missing signed public key fails the all-or-nothing check in
    /// [`AccountKeysData::validate`] rather than falling back to v1, which would silently turn a
    /// rotation into a downgrade.
    fn validate(self) -> ApiResult<ValidatedAccountKeys> {
        AccountKeysData {
            user_key_encrypted_account_private_key: None,
            account_public_key: None,
            public_key_encryption_key_pair: Some(self.public_key_encryption_key_pair),
            signature_key_pair: Some(self.signature_key_pair),
            security_state: Some(self.security_state),
        }
        .validate()
    }
}

impl From<KeysData> for ValidatedAccountKeys {
    fn from(keys: KeysData) -> Self {
        Self {
            private_key: keys.encrypted_private_key,
            public_key: keys.public_key,
            v2: None,
        }
    }
}

impl ValidatedAccountKeys {
    /// The keys of a request that may carry either shape. `accountKeys` supersedes the flat `keys`
    /// object when both are sent.
    fn from_request(account_keys: Option<AccountKeysData>, keys: Option<KeysData>) -> ApiResult<Option<Self>> {
        match (account_keys, keys) {
            (Some(account_keys), _) => account_keys.validate().map(Some),
            (None, keys) => Ok(keys.map(Self::from)),
        }
    }

    fn is_v2(&self) -> bool {
        self.v2.is_some()
    }

    /// Writes the parts of the state that live on the user itself. The user still needs saving, and
    /// [`Self::save_signature_key_pair`] still needs calling once it has been.
    ///
    /// Rejects downgrading an account from v2 back to v1.
    pub fn apply(&self, user: &mut User) -> EmptyResult {
        if user.is_v2() && self.v2.is_none() {
            err!("Cannot downgrade an account from v2 to v1 encryption")
        }

        user.private_key = Some(self.private_key.clone());
        user.public_key = Some(self.public_key.clone());

        user.signed_public_key = self.v2.as_ref().map(|v2| v2.signed_public_key.clone());
        user.security_state = self.v2.as_ref().map(|v2| v2.security_state.clone());
        user.security_version = self.v2.as_ref().map(|v2| v2.security_version);

        Ok(())
    }

    /// Persists the signature key pair. Separate from [`Self::apply`] because the row has a foreign
    /// key to the user, so it can only be written once the user exists.
    pub async fn save_signature_key_pair(&self, user_id: &UserId, conn: &DbConn) -> EmptyResult {
        // Skip if the account is v1, since v1 accounts don't have a signature key pair.
        let Some(v2) = &self.v2 else {
            return Ok(());
        };

        let mut key_pair = match UserSignatureKeyPair::find_by_user(user_id, conn).await {
            Some(mut key_pair) => {
                key_pair.signature_algorithm = v2.signature_algorithm as i32;
                key_pair.signing_key.clone_from(&v2.signing_key);
                key_pair.verifying_key.clone_from(&v2.verifying_key);
                key_pair
            }
            None => UserSignatureKeyPair::new(
                user_id.clone(),
                v2.signature_algorithm,
                v2.signing_key.clone(),
                v2.verifying_key.clone(),
            ),
        };
        key_pair.save(conn).await
    }
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
    contained_key_id: Option<KeyId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    #[serde(flatten)]
    compat: RegisterDataCompat,

    keys: Option<KeysData>,
    // Supersedes `keys`, and the only way a v2 account can be initialized here.
    account_keys: Option<AccountKeysData>,

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

    if data.compat.unprocessable(&data.email) {
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

    // Check against the password hint setting and the keys here so if they fail,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;
    let account_keys = ValidatedAccountKeys::from_request(data.account_keys, data.keys)?;

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

    set_kdf_data(&mut user, data.compat.kdf())?;

    user.set_password(&data.compat.hash(), Some(data.compat.key()), true, None, &conn).await?;
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(ref account_keys) = account_keys {
        account_keys.apply(&mut user)?;
        // Like upstream, only a v2 registration records the user key id. A v1 account reports it
        // later, through `user-key-id`.
        if account_keys.is_v2() {
            user.key_id = data.compat.key_id();
        }
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

    if let Some(account_keys) = account_keys {
        account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    }

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

    if user.private_key.is_some() {
        err!("Account already initialized, cannot set password")
    }

    if data.compat.unprocessable(&user.email) {
        err_code!("Unexpected SetPasswordData format", Status::UnprocessableEntity.code);
    }

    // Check against the password hint setting here so if it fails,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    let account_keys = ValidatedAccountKeys::from_request(data.account_keys, data.keys)?;

    set_kdf_data(&mut user, data.compat.kdf())?;

    user.set_password(
        &data.compat.hash(),
        Some(data.compat.key()),
        false,
        Some(vec![String::from("revision_date")]), // We need to allow revision-date to use the old security_timestamp
        &conn,
    )
    .await?;
    user.password_hint = password_hint;

    if let Some(ref account_keys) = account_keys {
        account_keys.apply(&mut user)?;
        // As in `register`, only a v2 account records the user key id here
        if account_keys.is_v2() {
            user.key_id = data.compat.key_id();
        }
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

    if let Some(account_keys) = account_keys {
        account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    }

    Ok(Json(json!({
      "object": "set-password",
      "captchaBypassToken": "",
    })))
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

#[get("/users/<user_id>/keys")]
async fn get_account_public_keys(user_id: UserId, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&user_id, &conn).await {
        Some(user) if user.public_key.is_some() => user,
        Some(_) => err_code!("User has no public_key", Status::NotFound.code),
        None => err_code!("User doesn't exist", Status::NotFound.code),
    };

    Ok(Json(user.public_keys_json(&conn).await))
}

#[get("/accounts/keys")]
async fn get_keys(headers: Headers, conn: DbConn) -> JsonResult {
    let user = headers.user;

    Ok(Json(json!({
        "key": user.akey,
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "accountKeys": user.account_keys_json(&conn).await,
        "object": "keys"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostKeysData {
    #[serde(flatten)]
    keys: Option<KeysData>,
    account_keys: Option<AccountKeysData>,
    // The id of the user key these account keys belong to, only honored for v2 `accountKeys`
    user_key_id: Option<KeyId>,
}

#[post("/accounts/keys", data = "<data>")]
async fn post_keys(data: Json<PostKeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PostKeysData = data.into_inner();

    let mut user = headers.user;

    // This only sets the keys of an account that has none yet. Replacing existing ones is what a key
    // rotation does, with the checks that go with it.
    if user.private_key.is_some() || user.public_key.is_some() {
        err!("User has existing keypair")
    }

    // `accountKeys` supersedes the flat `keys` object when both are sent.
    let account_keys = match (data.account_keys, data.keys) {
        (Some(account_keys), _) => {
            let account_keys = account_keys.validate()?;
            if !account_keys.is_v2() {
                err!("AccountKeys are only supported for V2 encryption.")
            }
            // A client that predates key ids sends none, and reports it later through `user-key-id`
            if data.user_key_id.is_some() {
                user.key_id = data.user_key_id;
            }
            account_keys
        }
        (None, Some(keys)) => keys.into(),
        (None, None) => err!("No account keys provided"),
    };

    account_keys.apply(&mut user)?;
    user.save(&conn).await?;
    account_keys.save_signature_key_pair(&user.uuid, &conn).await?;

    Ok(Json(json!({
        "key": user.akey,
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "accountKeys": user.account_keys_json(&conn).await,
        "object":"keys"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassData {
    master_password_hash: String,
    master_password_hint: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,

    // Outdated values, might still be used by older clients
    new_master_password_hash: Option<String>,
    key: Option<String>,
}

#[post("/accounts/password", data = "<data>")]
async fn post_password(data: Json<ChangePassData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    log_user_event(EventType::UserChangedPassword as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    let (new_master_password_hash, new_key) =
        if let (Some(unlock_data), Some(authentication_data)) = (data.unlock_data, data.authentication_data) {
            if authentication_data.kdf != unlock_data.kdf {
                err!("KDF settings must be equal for authentication and unlock")
            }

            if user.email != authentication_data.salt || user.email != unlock_data.salt {
                err!("Invalid master password salt")
            }

            validate_key_id_unchanged(&user, &unlock_data)?;

            (authentication_data.master_password_authentication_hash, unlock_data.master_key_wrapped_user_key)
        } else if let (Some(new_master_password_hash), Some(new_key)) = (data.new_master_password_hash, data.key) {
            (new_master_password_hash, new_key)
        } else {
            err!("Invalid request!")
        };

    let mut user = user;

    user.password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(user.password_hint.as_ref())?;

    user.set_password(
        &new_master_password_hash,
        Some(new_key),
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
    contained_key_id: Option<KeyId>,
}

/// A password or KDF change re-wraps the same user key, so a key id sent with it has to be the
/// current one. Either may be missing: from a client that predates key ids, or a user whose key id
/// isn't known yet. There is nothing to compare in those cases.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/Models/Data/MasterPasswordUnlockData.cs>
fn validate_key_id_unchanged(user: &User, unlock_data: &UnlockData) -> EmptyResult {
    if let (Some(current), Some(contained)) = (&user.key_id, &unlock_data.contained_key_id)
        && current != contained
    {
        err!("Invalid user key sent in master-password unlock data.")
    }
    Ok(())
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

    validate_key_id_unchanged(&headers.user, &data.unlock_data)?;

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
    // Absent in a v1 -> v2 upgrade, which keeps the key the organization already holds
    reset_password_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyData {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: AccountKeysData,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
    new_user_key_id: Option<KeyId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    master_password_unlock_data: MasterPasswordUnlockData,
    #[serde(flatten)]
    common: CommonUnlockData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlockData {
    #[serde(flatten)]
    kdf: KDFData,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
    contained_key_id: Option<KeyId>,
}

/// The unlock data both rotation endpoints share. Vaultwarden has neither trusted device encryption
/// nor passkey login, so `key-rotation-data` reports none of either and these must arrive empty.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Api/KeyManagement/Models/Requests/CommonUnlockDataRequestModel.cs>
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommonUnlockData {
    emergency_access_unlock_data: Vec<UpdateEmergencyAccessData>,
    organization_account_recovery_unlock_data: Vec<UpdateResetPasswordData>,
    #[serde(default)]
    passkey_unlock_data: Vec<Value>,
    #[serde(default)]
    device_key_unlock_data: Vec<Value>,
    v2_upgrade_token: Option<V2UpgradeTokenData>,
}

/// Lets clients that still hold the v1 user key derive the v2 one after another client upgraded the
/// account, so a v1 -> v2 upgrade doesn't have to log every other session out. Opaque to us.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct V2UpgradeTokenData {
    wrapped_user_key1: String,
    wrapped_user_key2: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<SendData>,
}

/// Body of `rotate-user-keys`, which rotates the keys without touching the master password.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateUserKeysData {
    wrapped_account_cryptographic_state: WrappedAccountCryptographicState,
    unlock_data: CommonUnlockData,
    account_data: RotateAccountData,
    unlock_method_data: UnlockMethodData,
    new_user_key_id: Option<KeyId>,
}

/// The v2-only account cryptographic state, where all three parts are mandatory.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrappedAccountCryptographicState {
    public_key_encryption_key_pair: PublicKeyEncryptionKeyPairData,
    signature_key_pair: SignatureKeyPairData,
    security_state: SecurityStateData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockMethodData {
    unlock_method: i32,
    master_password_unlock_data: Option<RotateMasterPasswordUnlockData>,
    // `keyConnectorKeyWrappedUserKey` is deliberately not read: that unlock method is rejected.
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateMasterPasswordUnlockData {
    kdf: KDFData,
    salt: String,
    master_key_wrapped_user_key: String,
    contained_key_id: Option<KeyId>,
}

/// The user key wrapped in the master password unlock data has to be the new one.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/Models/Data/MasterPasswordUnlockData.cs>
fn validate_contained_key_id(contained_key_id: Option<&KeyId>, new_user_key_id: Option<&KeyId>) -> EmptyResult {
    match (contained_key_id, new_user_key_id) {
        // Neither is sent by clients that predate key ids
        (None, None) => Ok(()),
        (Some(contained), Some(new)) if contained == new => Ok(()),
        _ => err!("Invalid user key sent in master-password unlock data."),
    }
}

/// Ref: <https://github.com/bitwarden/server/blob/main/src/Api/KeyManagement/Enums/UnlockMethod.cs>
#[derive(num_derive::FromPrimitive)]
enum UnlockMethod {
    Tde = 0,
    MasterPassword = 1,
    KeyConnector = 2,
}

/// The rotation-specific checks on the new account keys.
///
/// A rotation re-wraps the existing keys under a new user key; it must not swap the identity the
/// account presents to others. So the public key never changes, and for an account that is already
/// v2 the verifying key doesn't either — only the *wrapped* signing key does. A v1 account may gain
/// a signature key pair, which is the v1 -> v2 upgrade.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/UserKey/Implementations/RotateUserAccountKeysCommand.cs>
async fn validate_rotation_account_keys(keys: &ValidatedAccountKeys, user: &User, conn: &DbConn) -> EmptyResult {
    if user.public_key.as_ref() != Some(&keys.public_key) {
        err!("Changing the asymmetric keypair is not possible during key rotation")
    }

    let Some(v2) = &keys.v2 else {
        if user.is_v2() {
            err!("Cannot downgrade an account from v2 to v1 encryption during key rotation")
        }
        // A v1 rotation: the private key stays wrapped by an AES-CBC-HMAC user key
        if enc_string_type(&keys.private_key) != Some(ENC_TYPE_AES_CBC_256_HMAC_SHA256) {
            err!("The provided account private key was not wrapped with AES-256-CBC-HMAC")
        }
        return Ok(());
    };

    // Both a v2 rotation and the v1 -> v2 upgrade end up with a COSE user key wrapping the private keys
    if enc_string_type(&v2.signing_key) != Some(ENC_TYPE_COSE_ENCRYPT0) {
        err!("The provided signing key data is not wrapped with XChaCha20-Poly1305.")
    }
    if enc_string_type(&keys.private_key) != Some(ENC_TYPE_COSE_ENCRYPT0) {
        err!("The provided private key encryption key is not wrapped with XChaCha20-Poly1305.")
    }
    if v2.verifying_key.is_empty() || v2.signed_public_key.is_empty() || v2.security_state.is_empty() {
        err!("The v2 account keys are missing the verifying key, signed public key or security state")
    }

    if !user.is_v2() {
        // The v1 -> v2 upgrade, which is where the signature key pair comes from
        return Ok(());
    }

    let Some(key_pair) = UserSignatureKeyPair::find_by_user(&user.uuid, conn).await else {
        err!("The account is missing its signature key pair")
    };
    if key_pair.verifying_key != v2.verifying_key {
        err!("Changing the verifying key is not possible during key rotation")
    }

    Ok(())
}

/// `AesCbc256_HmacSha256_B64`, the v1 user key
const ENC_TYPE_AES_CBC_256_HMAC_SHA256: &str = "2";
/// `CoseEncrypt0B64`, the v2 user key
const ENC_TYPE_COSE_ENCRYPT0: &str = "7";

/// The encryption type of an EncString, the number before the first `.`.
fn enc_string_type(enc_string: &str) -> Option<&str> {
    enc_string.split_once('.').map(|(enc_type, _)| enc_type)
}

impl KDFData {
    /// Whether these are the settings the user already has, which a key rotation can't change.
    fn is_unchanged_for(&self, user: &User) -> bool {
        user.client_kdf_type == self.kdf
            && user.client_kdf_iter == self.kdf_iterations
            && user.client_kdf_memory == self.kdf_memory
            && user.client_kdf_parallelism == self.kdf_parallelism
    }
}

/// A rotation re-encrypts everything under the new user key, so anything left out would be
/// unreadable afterwards. Both rotation endpoints require the client to send the complete set.
fn validate_rotation_data(
    data: &RotateData,
    existing_ciphers: &[Cipher],
    existing_folders: &[Folder],
    existing_emergency_access: &[EmergencyAccess],
    existing_memberships: &[Membership],
    existing_sends: &[Send],
) -> EmptyResult {
    let account_data = &data.account_data;

    // Check that we're correctly rotating all the user's ciphers
    let existing_cipher_ids = existing_ciphers.iter().map(|c| &c.uuid).collect::<HashSet<&CipherId>>();
    let provided_cipher_ids = account_data
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
    let provided_folder_ids = account_data.folders.iter().filter_map(|f| f.id.as_ref()).collect::<HashSet<&FolderId>>();
    if !provided_folder_ids.is_superset(&existing_folder_ids) {
        err!("All existing folders must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's emergency access keys
    let existing_emergency_access_ids =
        existing_emergency_access.iter().map(|ea| &ea.uuid).collect::<HashSet<&EmergencyAccessId>>();
    let provided_emergency_access_ids =
        data.unlock_data.emergency_access_unlock_data.iter().map(|ea| &ea.id).collect::<HashSet<&EmergencyAccessId>>();
    if !provided_emergency_access_ids.is_superset(&existing_emergency_access_ids) {
        err!("All existing emergency access keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's reset password keys
    let existing_reset_password_ids =
        existing_memberships.iter().map(|m| &m.org_uuid).collect::<HashSet<&OrganizationId>>();
    let provided_reset_password_ids = data
        .unlock_data
        .organization_account_recovery_unlock_data
        .iter()
        .map(|rp| &rp.organization_id)
        .collect::<HashSet<&OrganizationId>>();
    if !provided_reset_password_ids.is_superset(&existing_reset_password_ids) {
        err!("All existing reset password keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's sends
    let existing_send_ids = existing_sends.iter().map(|s| &s.uuid).collect::<HashSet<&SendId>>();
    let provided_send_ids = account_data.sends.iter().filter_map(|s| s.id.as_ref()).collect::<HashSet<&SendId>>();
    if !provided_send_ids.is_superset(&existing_send_ids) {
        err!("All existing sends must be included in the rotation")
    }

    Ok(())
}

/// The public keys and encrypted keysets that participate in a key rotation, so the client can
/// re-share the new user key without having to piece this together from several endpoints.
///
/// The four collections must always be present, even when empty: the SDK errors out if any of them
/// is missing. `trustedDeviceKeyData` and `passkeyKeyData` are always empty here, since vaultwarden
/// supports neither trusted device encryption nor passkey (PRF) login.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/UserKey/Queries/KeyRotationDataQuery.cs>
#[get("/accounts/key-management/key-rotation-data")]
async fn get_key_rotation_data(headers: Headers, conn: DbConn) -> JsonResult {
    let user_id = &headers.user.uuid;

    let mut organization_data = Vec::new();
    for membership in Membership::find_by_user(user_id, &conn).await {
        // Only memberships actually enrolled in account recovery take part in the rotation.
        if membership.reset_password_key.is_none() {
            continue;
        }
        let Some(org) = Organization::find_by_uuid(&membership.org_uuid, &conn).await else {
            continue;
        };
        let Some(public_key) = org.public_key else {
            continue;
        };
        organization_data.push(json!({
            "organizationId": org.uuid,
            "organizationName": org.name,
            "organizationPublicKey": public_key,
            "object": "organizationPasswordResetKeyData",
        }));
    }

    let mut emergency_access_data = Vec::new();
    for emergency_access in EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await {
        // Without a stored key there is nothing to re-share.
        if emergency_access.key_encrypted.is_none() {
            continue;
        }
        let Some(grantee_id) = emergency_access.grantee_uuid.clone() else {
            continue;
        };
        let Some(grantee) = User::find_by_uuid(&grantee_id, &conn).await else {
            continue;
        };
        let Some(public_key) = grantee.public_key.clone() else {
            continue;
        };
        emergency_access_data.push(json!({
            "id": emergency_access.uuid,
            "granteeId": grantee_id,
            "granteeName": grantee.name,
            "granteeEmail": grantee.email,
            "publicKey": public_key,
            "object": "emergencyAccessKeyData",
        }));
    }

    Ok(Json(json!({
        "organizationPasswordResetKeyData": organization_data,
        "emergencyAccessKeyData": emergency_access_data,
        "trustedDeviceKeyData": [],
        "passkeyKeyData": [],
        "object": "keyRotationData",
    })))
}

/// Everything a rotation replaces, once each endpoint's wrapper has been peeled off.
struct RotateData {
    account_keys: ValidatedAccountKeys,
    account_data: RotateAccountData,
    unlock_data: CommonUnlockData,
    /// Only v2 (COSE) user keys have an id, so this is `None` for a v1 -> v1 rotation.
    new_user_key_id: Option<KeyId>,
    /// The new user key, wrapped by the master key.
    wrapped_user_key: String,
    /// Only for `rotate-user-account-keys`, where the master password changes along with the keys.
    new_password_hash: Option<String>,
}

impl CommonUnlockData {
    /// We advertise no trusted devices or passkeys in `key-rotation-data`, so a client sending
    /// either has produced keys for something that doesn't exist here. Silently dropping them would
    /// leave the client believing an unlock method was rotated when it wasn't.
    fn validate(&self) -> EmptyResult {
        if !self.passkey_unlock_data.is_empty() {
            err!("Passkey unlock is not supported")
        }
        if !self.device_key_unlock_data.is_empty() {
            err!("Trusted device unlock is not supported")
        }
        Ok(())
    }
}

#[post("/accounts/key-management/rotate-user-account-keys", data = "<data>")]
async fn post_rotatekey(data: Json<KeyData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: KeyData = data.into_inner();

    if !headers.user.check_valid_password(&data.old_master_key_authentication_hash) {
        err!("Invalid password")
    }

    let unlock_data = data.account_unlock_data.master_password_unlock_data;
    if !unlock_data.kdf.is_unchanged_for(&headers.user) || unlock_data.email != headers.user.email {
        err!("Changing the kdf variant or email is not supported during key rotation");
    }
    validate_contained_key_id(unlock_data.contained_key_id.as_ref(), data.new_user_key_id.as_ref())?;

    let mut common = data.account_unlock_data.common;
    // This endpoint always logs every session out, so an upgrade token is never kept here. That
    // also clears one left over from an earlier upgrade. Ref: upstream's AccountsKeyManagementController
    common.v2_upgrade_token = None;

    rotate_account(
        RotateData {
            account_keys: data.account_keys.validate()?,
            account_data: data.account_data,
            unlock_data: common,
            new_user_key_id: data.new_user_key_id,
            wrapped_user_key: unlock_data.master_key_encrypted_user_key,
            new_password_hash: Some(unlock_data.master_key_authentication_hash),
        },
        headers,
        conn,
        nt,
    )
    .await
}

/// The body shared by both rotation endpoints: check that the client re-encrypted everything, re-save
/// it, then swap the account keys and the wrapped user key.
async fn rotate_account(data: RotateData, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    // TODO: See if we can wrap everything within a SQL Transaction. If something fails it should revert everything.
    data.unlock_data.validate()?;

    let user_id = &headers.user.uuid;
    let mut existing_ciphers = Cipher::find_owned_by_user(user_id, &conn).await;
    let mut existing_folders = Folder::find_by_user(user_id, &conn).await;
    let mut existing_emergency_access = EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await;
    let mut existing_memberships = Membership::find_by_user(user_id, &conn).await;
    // We only rotate the reset password key if it is set.
    existing_memberships.retain(|m| m.reset_password_key.is_some());
    let mut existing_sends = Send::find_by_user(user_id, &conn).await;

    validate_rotation_data(
        &data,
        &existing_ciphers,
        &existing_folders,
        &existing_emergency_access,
        &existing_memberships,
        &existing_sends,
    )?;

    validate_rotation_account_keys(&data.account_keys, &headers.user, &conn).await?;

    // The upgrade token only means anything for a v1 account moving to v2: it lets sessions still
    // holding the v1 user key pick up the v2 one instead of being forced to re-authenticate. For an
    // account that is already v2 it is meaningless, so it gets discarded and the security stamp is
    // reset, as a rotation otherwise would. That ends the refresh tokens, while the access tokens in
    // use run out on their own, as upstream.
    let is_upgrade = data.unlock_data.v2_upgrade_token.is_some() && !headers.user.is_v2();
    let upgrade_token = match &data.unlock_data.v2_upgrade_token {
        Some(token) if is_upgrade => Some(serde_json::to_string(token)?),
        _ => None,
    };

    // An upgrade can't re-wrap the account recovery keys: that needs the organization's public key
    // to be trusted, and an upgrade shows the user no prompt. So the stored keys are kept, and each
    // organization gets the upgrade token instead, to unwrap the v2 user key with.
    // Ref: upstream's OrganizationUserRotationValidator
    for reset_password_data in &data.unlock_data.organization_account_recovery_unlock_data {
        let has_key = reset_password_data.reset_password_key.as_deref().is_some_and(|k| !k.is_empty());
        if is_upgrade && has_key {
            err!("Account recovery keys cannot be rotated during a V1 to V2 upgrade rotation.")
        }
        if !is_upgrade && !has_key {
            err!("Account recovery keys cannot be null or empty during rotation.")
        }
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.account_data.ciphers)?;

    // TODO: Ideally we'd do everything after this point in a single transaction.

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
    for emergency_access_data in data.unlock_data.emergency_access_unlock_data {
        let Some(saved_emergency_access) =
            existing_emergency_access.iter_mut().find(|ea| ea.uuid == emergency_access_data.id)
        else {
            err!("Emergency access doesn't exist or is not owned by the user")
        };

        saved_emergency_access.key_encrypted = Some(emergency_access_data.key_encrypted);
        saved_emergency_access.save(&conn).await?;
    }

    // Update reset password data
    for reset_password_data in data.unlock_data.organization_account_recovery_unlock_data {
        let Some(membership) =
            existing_memberships.iter_mut().find(|m| m.org_uuid == reset_password_data.organization_id)
        else {
            err!("Reset password doesn't exist")
        };

        if !is_upgrade {
            membership.reset_password_key = reset_password_data.reset_password_key;
        }
        membership.v2_upgrade_token.clone_from(&upgrade_token);
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
            // Other sessions still hold the old user key, so an update to a re-encrypted cipher could cause issues.
            // After the user is saved they are logged out, or on an upgrade, told to sync the new key.
            update_cipher_from_data(saved_cipher, cipher_data, &headers, None, &conn, &nt, UpdateType::None).await?;
        }
    }

    // Update user data
    let mut user = headers.user;
    user.v2_upgrade_token = upgrade_token;

    data.account_keys.apply(&mut user)?;
    // The old id names a key that no longer exists, so it is replaced even when the new key has none.
    user.key_id = data.new_user_key_id;

    user.akey = data.wrapped_user_key;
    if let Some(new_password_hash) = data.new_password_hash {
        user.set_password(&new_password_hash, None, false, None, &conn).await?;
    }
    // An upgrade keeps the sessions alive, see `is_upgrade` above
    if !is_upgrade {
        user.reset_security_stamp_after_key_rotation(&conn).await?;
    }

    // The key pair goes first: if saving the user then fails during an upgrade, the account is still
    // v1 and the key pair unused, instead of a v2 account without one, which no client could unlock.
    // A failure between the two writes of a v2 rotation still needs a transaction to undo.
    data.account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    user.save(&conn).await?;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    // When the sessions were kept alive, the reason lets the other clients sync the new keys (through
    // the upgrade token) instead of logging out, if they have `pm-31050-no-logout-key-upgrade-rotation`.
    let reason = is_upgrade.then_some(LogOutReason::KeyRotation);
    nt.send_logout_with_reason(&user, Some(&headers.device), reason, &conn).await;

    Ok(())
}

/// Rotates the account keys without changing the master password.
///
/// Unlike `rotate-user-account-keys` this carries no proof of the master password: the request is
/// authorized by the session alone, which is how upstream defines it, and the client has to be
/// unlocked to produce the payload in the first place.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Api/KeyManagement/Controllers/AccountsKeyManagementController.cs>
#[post("/accounts/key-management/rotate-user-keys", data = "<data>")]
async fn post_rotate_user_keys(
    data: Json<RotateUserKeysData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data: RotateUserKeysData = data.into_inner();

    let wrapped_user_key = match UnlockMethod::from_i32(data.unlock_method_data.unlock_method) {
        Some(UnlockMethod::MasterPassword) => {
            let Some(unlock_data) = data.unlock_method_data.master_password_unlock_data else {
                err!("Missing master password unlock data")
            };
            if !unlock_data.kdf.is_unchanged_for(&headers.user) {
                err!("Changing the kdf variant is not supported during key rotation")
            }
            if unlock_data.salt != headers.user.email {
                err!("Invalid master password salt")
            }
            validate_contained_key_id(unlock_data.contained_key_id.as_ref(), data.new_user_key_id.as_ref())?;
            unlock_data.master_key_wrapped_user_key
        }
        Some(UnlockMethod::Tde) => err!("Trusted device encryption is not supported"),
        Some(UnlockMethod::KeyConnector) => err!("Key connector is not supported"),
        None => err!("Unrecognized unlock method"),
    };

    rotate_account(
        RotateData {
            account_keys: data.wrapped_account_cryptographic_state.validate()?,
            account_data: data.account_data,
            unlock_data: data.unlock_data,
            new_user_key_id: data.new_user_key_id,
            wrapped_user_key,
            new_password_hash: None,
        },
        headers,
        conn,
        nt,
    )
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdData {
    user_key_id: KeyId,
}

#[post("/accounts/key-management/user-key-id", data = "<data>")]
async fn post_user_key(data: Json<KeyIdData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let mut user = headers.user;
    // Only a backfill for accounts that have none. Afterwards the id changes with the key, in a rotation.
    if user.key_id.is_some() {
        err!("User key id is already set.")
    }

    user.key_id = Some(data.into_inner().user_key_id);
    user.save(&conn).await
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
async fn post_prelogin(data: Json<PreloginData>, ip: ClientIp, conn: DbConn) -> JsonResult {
    prelogin(data, ip, conn).await
}

pub async fn prelogin(data: Json<PreloginData>, ip: ClientIp, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data: PreloginData = data.into_inner();

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&data.email, &conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    };

    Ok(Json(json!({
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
    })))
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
    // Not used for now
    // #[serde(alias = "type")]
    // _type: i32,
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    client_headers: ClientHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    let data = data.into_inner();

    let Some(user) = User::find_by_mail(&data.email, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    // Validate device uuid and type
    let device = match Device::find_by_uuid_and_user(&data.device_identifier, &user.uuid, &conn).await {
        Some(device) if device.atype == client_headers.device_type => device,
        _ => err!("AuthRequest doesn't exist", "Device verification failed"),
    };

    let auth_request = AuthRequest::new(
        user.uuid.clone(),
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

    Ok(Json(json!({
        "id": auth_request.uuid,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": null,
        "masterPasswordHash": null,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": null,
        "requestApproved": false,
        "origin": CONFIG.domain_origin(),
        "object": "auth-request"
    })))
}

#[get("/auth-requests/<auth_request_id>")]
async fn get_auth_request(auth_request_id: AuthRequestId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err!("AuthRequest doesn't exist", "Record not found or user uuid does not match")
    };

    let response_date_utc = auth_request.response_date.map(|response_date| format_date(&response_date));

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        "masterPasswordHash": auth_request.master_password_hash,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
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

    if headers.device.uuid != data.device_identifier {
        err!("AuthRequest doesn't exist", "Device verification failed")
    }

    if auth_request.approved.is_some() {
        err!("An authentication request with the same device already exists")
    }

    let response_date = Utc::now().naive_utc();
    let response_date_utc = format_date(&response_date);

    if data.request_approved {
        auth_request.approved = Some(data.request_approved);
        auth_request.enc_key = Some(data.key);
        auth_request.master_password_hash = data.master_password_hash;
        auth_request.response_device_id = Some(data.device_identifier.clone());
        auth_request.response_date = Some(response_date);
        auth_request.save(&conn).await?;

        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, &headers.device, &conn).await;

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

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        "masterPasswordHash": auth_request.master_password_hash,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
}

#[get("/auth-requests/<auth_request_id>/response?<code>")]
async fn get_auth_request_response(
    auth_request_id: AuthRequestId,
    code: &str,
    client_headers: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    let Some(auth_request) = AuthRequest::find_by_uuid(&auth_request_id, &conn).await else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    if auth_request.device_type != client_headers.device_type
        || auth_request.request_ip != client_headers.ip.ip.to_string()
        || !auth_request.check_access_code(code)
    {
        err!("AuthRequest doesn't exist", "Invalid device, IP or code")
    }

    let response_date_utc = auth_request.response_date.map(|response_date| format_date(&response_date));

    Ok(Json(json!({
        "id": &auth_request_id,
        "publicKey": auth_request.public_key,
        "requestDeviceType": DeviceType::from_i32(auth_request.device_type).to_string(),
        "requestIpAddress": auth_request.request_ip,
        "key": auth_request.enc_key,
        "masterPasswordHash": auth_request.master_password_hash,
        "creationDate": format_date(&auth_request.creation_date),
        "responseDate": response_date_utc,
        "requestApproved": auth_request.approved,
        "origin": CONFIG.domain_origin(),
        "object":"auth-request"
    })))
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
            .filter(|request| request.approved.is_none())
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
