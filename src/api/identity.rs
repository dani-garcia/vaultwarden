use chrono::Utc;
use num_traits::FromPrimitive;
use rocket::{
    Route,
    form::{Form, FromForm},
    http::{Cookie, CookieJar, SameSite},
    response::Redirect,
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult,
        core::{
            accounts::{PreloginData, RegisterData, kdf_upgrade, prelogin, register},
            log_user_event,
            two_factor::{
                authenticator, duo, duo_oidc, email, enforce_2fa_policy, is_twofactor_provider_usable, webauthn,
                yubikey,
            },
        },
        master_password_policy,
        push::register_push_device,
    },
    auth,
    auth::{AuthMethod, ClientHeaders, ClientIp, ClientVersion, Secure, generate_organization_api_key_login_claims},
    crypto,
    db::{
        DbConn,
        models::{
            AuthRequest, AuthRequestId, Device, DeviceId, DeviceType, EventType, Invitation, Membership,
            OIDCCodeResponseError, OrgPolicy, OrgPolicyType, Organization, OrganizationApiKey, OrganizationId, SendId,
            SsoAuth, SsoUser, TwoFactor, TwoFactorIncomplete, TwoFactorType, User, UserId,
        },
    },
    error::MapResult,
    mail, sso,
    sso::{OIDCCode, OIDCCodeChallenge, OIDCCodeVerifier, OIDCState},
    util,
};

pub fn routes() -> Vec<Route> {
    routes![
        login,
        post_prelogin,
        prelogin_password,
        identity_register,
        register_verification_email,
        register_finish,
        prevalidate,
        authorize,
        oidcsignin,
        oidcsignin_error
    ]
}

#[post("/connect/token", data = "<data>")]
async fn login(
    data: Form<ConnectData>,
    client_header: ClientHeaders,
    client_version: Option<ClientVersion>,
    conn: DbConn,
) -> JsonResult {
    let data: ConnectData = data.into_inner();

    let mut user_id: Option<UserId> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            check_is_some(data.refresh_token.as_ref(), "refresh_token cannot be blank")?;
            refresh_login(data, &conn, &client_header.ip).await
        }
        "password" if CONFIG.sso_enabled() && CONFIG.sso_only() => err!("SSO sign-in is required"),
        "password" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.password.as_ref(), "password cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;
            check_is_some(data.username.as_ref(), "username cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            password_login(data, &mut user_id, &conn, &client_header.ip, client_version.as_ref()).await
        }
        "client_credentials" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.client_secret.as_ref(), "client_secret cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            api_key_login(data, &mut user_id, &conn, &client_header.ip).await
        }
        "authorization_code" if CONFIG.sso_enabled() => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.code.as_ref(), "code cannot be blank")?;
            check_is_some(data.code_verifier.as_ref(), "code verifier cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            sso_login(data, &mut user_id, &conn, &client_header.ip, client_version.as_ref()).await
        }
        "authorization_code" => err!("SSO sign-in is not available"),
        "send_access" => {
            crate::ratelimit::check_limit_unauthenticated(&client_header.ip.ip)?;
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.send_id.as_ref(), "send_id cannot be blank")?;

            let tokens = auth::SendTokens::generate_tokens(
                data.send_id.as_ref().unwrap(),
                data.password_hash_b64,
                &client_header.ip,
                &conn,
            )
            .await?;
            Ok(Json(tokens.to_json()))
        }
        t => err!("Invalid type", t),
    };

    if let Some(user_id) = user_id {
        match &login_result {
            Ok(_) => {
                log_user_event(
                    EventType::UserLoggedIn as i32,
                    &user_id,
                    client_header.device_type,
                    &client_header.ip.ip,
                    &conn,
                )
                .await;
            }
            Err(e) => {
                if let Some(ev) = e.get_event() {
                    log_user_event(ev.event as i32, &user_id, client_header.device_type, &client_header.ip.ip, &conn)
                        .await;
                }
            }
        }
    }

    login_result
}

async fn refresh_login(data: ConnectData, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    // When a refresh token is invalid or missing we need to respond with an HTTP BadRequest (400)
    // It also needs to return a json which holds at least a key `error` with the value `invalid_grant`
    // See the link below for details
    // https://github.com/bitwarden/clients/blob/2ee158e720a5e7dbe3641caf80b569e97a1dd91b/libs/common/src/services/api.service.ts#L1786-L1797

    let Some(refresh_token) = data.refresh_token else {
        err_json!(json!({"error": "invalid_grant"}), "Missing refresh_token")
    };

    // ---
    // Disabled this variable, it was used to generate the JWT
    // Because this might get used in the future, and is add by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // let members = Membership::find_confirmed_by_user(&user.uuid, conn).await;
    match auth::refresh_tokens(ip, &refresh_token, data.client_id, conn).await {
        Err(err) => {
            err_json!(
                json!({"error": "invalid_grant"}),
                format!("Unable to refresh login credentials: {}", err.message())
            )
        }
        Ok((mut device, auth_tokens)) => {
            // Save to update `device.updated_at` to track usage and toggle new status
            device.save(true, conn).await?;

            let result = json!({
                "refresh_token": auth_tokens.refresh_token(),
                "access_token": auth_tokens.access_token(),
                "expires_in": auth_tokens.expires_in(),
                "token_type": "Bearer",
                "scope": auth_tokens.scope(),
            });

            Ok(Json(result))
        }
    }
}

// After exchanging the code we need to check first if 2FA is needed before continuing
async fn sso_login(
    data: ConnectData,
    user_id: &mut Option<UserId>,
    conn: &DbConn,
    ip: &ClientIp,
    client_version: Option<&ClientVersion>,
) -> JsonResult {
    AuthMethod::Sso.check_scope(data.scope.as_ref())?;

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    let (code, code_verifier) = match (data.code.as_ref(), data.code_verifier.as_ref()) {
        (None, _) => err!(
            "Got no code in OIDC data",
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        ),
        (_, None) => err!(
            "Got no code verifier in OIDC data",
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        ),
        (Some(code), Some(code_verifier)) => (code, code_verifier.clone()),
    };

    let (sso_auth, user_infos) = sso::exchange_code(code, code_verifier, conn).await?;
    let user_with_sso = match SsoUser::find_by_identifier(&user_infos.identifier, conn).await {
        None => match SsoUser::find_by_mail(&user_infos.email, conn).await {
            None => None,
            Some((user, Some(_))) => {
                error!(
                    "Login failure ({}), existing SSO user ({}) with same email ({})",
                    user_infos.identifier, user.uuid, user.email
                );
                err_silent!(
                    "Existing SSO user with same email",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
            Some((user, None))
                if user.private_key.is_none()
                    && !CONFIG.sso_signups_allowed()
                    && !CONFIG.is_email_domain_allowed(&user.email)
                    && !CONFIG.mail_enabled()
                    && Invitation::find_by_mail(&user.email, conn).await.is_none() =>
            {
                error!(
                    "Login failure ({}), no invitation with email ({}) was found",
                    user_infos.identifier, user.email
                );
                err_silent!(
                    "Missing invitation",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
            Some((user, None)) if user.private_key.is_some() && !CONFIG.sso_signups_match_email() => {
                error!(
                    "Login failure ({}), existing non SSO user ({}) with same email ({}) and association is disabled",
                    user_infos.identifier, user.uuid, user.email
                );
                err_silent!(
                    "Existing non SSO user with same email",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
            Some((user, None)) => match user_infos.email_verified {
                None if !CONFIG.sso_allow_unknown_email_verification() => {
                    error!(
                        "Login failure ({}), existing non SSO user ({}) with same email ({}) and email verification status is unknown",
                        user_infos.identifier, user.uuid, user.email
                    );
                    err_silent!(
                        "Email verification status is unknown",
                        ErrorEvent {
                            event: EventType::UserFailedLogIn
                        }
                    )
                }
                Some(false) => {
                    error!(
                        "Login failure ({}), existing non SSO user ({}) with same email ({}) and email is not verified",
                        user_infos.identifier, user.uuid, user.email
                    );
                    err_silent!(
                        "Email is not verified by the SSO provider",
                        ErrorEvent {
                            event: EventType::UserFailedLogIn
                        }
                    )
                }
                _ => Some((user, None)),
            },
        },
        Some((user, sso_user)) => Some((user, Some(sso_user))),
    };

    let now = Utc::now().naive_utc();
    // Will trigger 2FA flow if needed
    let (user, mut device, twofactor_token, sso_user) = match user_with_sso {
        None => {
            if !CONFIG.is_sso_signup_allowed(&user_infos.email) {
                if CONFIG.signups_domains_whitelist().is_empty() {
                    err!(
                        "Signups are disabled. You will need an invitation",
                        ErrorEvent {
                            event: EventType::UserFailedLogIn
                        }
                    );
                }
                err!(
                    "Email domain not allowed",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                );
            }

            match user_infos.email_verified {
                None if !CONFIG.sso_allow_unknown_email_verification() => err!(
                    "Your provider does not send email verification status.\n\
                    You will need to change the server configuration (check `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`) to log in.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                ),
                Some(false) => err!(
                    "You need to verify your email with your provider before you can log in",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                ),
                _ => (),
            }

            let mut user = User::new(&user_infos.email, user_infos.user_name.clone());
            user.verified_at = Some(now);
            user.save(conn).await?;

            let device = get_device(&data, conn, &user).await?;

            (user, device, None, None)
        }
        Some((user, _)) if !user.enabled => {
            err!(
                "This user has been disabled",
                format!("IP: {}. Username: {}.", ip.ip, user.email),
                ErrorEvent {
                    event: EventType::UserFailedLogIn
                }
            )
        }
        Some((mut user, sso_user)) => {
            let mut device = get_device(&data, conn, &user).await?;

            let twofactor_token = twofactor_auth(&mut user, &data, &mut device, ip, client_version, conn).await?;

            if user.private_key.is_none() {
                // User was invited a stub was created
                user.verified_at = Some(now);
                if let Some(ref user_name) = user_infos.user_name {
                    user.name = user_name.clone();
                }

                user.save(conn).await?;
            }

            if user.email != user_infos.email {
                if CONFIG.mail_enabled() {
                    mail::send_sso_change_email(&user_infos.email).await?;
                }
                info!("User {} email changed in SSO provider from {} to {}", user.uuid, user.email, user_infos.email);
            }

            (user, device, twofactor_token, sso_user)
        }
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_id = Some(user.uuid.clone());

    // We passed 2FA get auth tokens
    let auth_tokens = sso::redeem(&device, &user, data.client_id, sso_user, sso_auth, user_infos, conn).await?;

    authenticated_response(&user, &mut device, auth_tokens, twofactor_token, true, conn, ip).await
}

async fn password_login(
    data: ConnectData,
    user_id: &mut Option<UserId>,
    conn: &DbConn,
    ip: &ClientIp,
    client_version: Option<&ClientVersion>,
) -> JsonResult {
    // Validate scope
    AuthMethod::Password.check_scope(data.scope.as_ref())?;

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Get the user
    let username = data.username.as_ref().unwrap().trim();
    let Some(mut user) = User::find_by_mail(username, conn).await else {
        err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {username}.", ip.ip))
    };

    // Set the user_id here to be passed back used for event logging.
    *user_id = Some(user.uuid.clone());

    // Check if the user is disabled
    if !user.enabled {
        err!(
            "This user has been disabled",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let password = data.password.as_ref().unwrap();

    // If we get an auth request, we don't check the user's password, but the access code of the auth request
    if let Some(ref auth_request_id) = data.auth_request {
        let Some(auth_request) = AuthRequest::find_by_uuid_and_user(auth_request_id, &user.uuid, conn).await else {
            err!(
                "Auth request not found. Try again.",
                format!("IP: {}. Username: {username}.", ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        };

        let expiration_time = auth_request.creation_date + chrono::Duration::minutes(5);
        let request_expired = Utc::now().naive_utc() >= expiration_time;

        if auth_request.user_uuid != user.uuid
            || !auth_request.approved.unwrap_or(false)
            || request_expired
            || ip.ip.to_string() != auth_request.request_ip
            || !auth_request.check_access_code(password)
        {
            err!(
                "Username or access code is incorrect. Try again",
                format!("IP: {}. Username: {username}.", ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        }
    } else if !user.check_valid_password(password) {
        err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn,
            }
        )
    }

    // Change the KDF Iterations (only when not logging in with an auth request)
    if data.auth_request.is_none() {
        kdf_upgrade(&mut user, password, conn).await?;
    }

    let now = Utc::now().naive_utc();

    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.signups_verify() {
        if user.last_verifying_at.is_none()
            || now.signed_duration_since(user.last_verifying_at.unwrap()).num_seconds()
                > CONFIG.signups_verify_resend_time().cast_signed()
        {
            let resend_limit = CONFIG.signups_verify_resend_limit().cast_signed();
            if resend_limit == 0 || user.login_verify_count < resend_limit {
                // We want to send another email verification if we require signups to verify
                // their email address, and we haven't sent them a reminder in a while...
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(conn).await {
                    error!("Error updating user: {e:#?}");
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
                    error!("Error auto-sending email verification email: {e:#?}");
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        err!(
            "Please verify your email before trying again.",
            format!("IP: {}. Username: {username}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let mut device = get_device(&data, conn, &user).await?;

    let twofactor_token = twofactor_auth(&mut user, &data, &mut device, ip, client_version, conn).await?;

    let auth_tokens = auth::AuthTokens::new(&device, &user, AuthMethod::Password, data.client_id);

    authenticated_response(&user, &mut device, auth_tokens, twofactor_token, false, conn, ip).await
}

/// Whether the account creation the clients run when nothing else is on offer can succeed here.
///
/// A client that gets the trusted device options, but neither a master password nor an approval an
/// administrator could give, decides it is looking at a fresh account and walks it through creation:
/// generate the account keys and post them, enrol into the account recovery of the organization behind
/// the SSO login, then trust the device. Every one of those has to be able to go through: if enrolment
/// is refused the keys are already written, and the next login fails at posting them a second time,
/// leaving an account that can never be unlocked at all.
///
/// So the same conditions the enrolment endpoint enforces are checked here, before the client has
/// written anything. Withholding the options instead sends it to setting a master password, which works
/// and leaves the door to trusted devices open for the next login.
async fn account_creation_can_succeed(user: &User, conn: &DbConn) -> bool {
    // `POST /accounts/keys` refuses to replace the keys of an account that has them, and the
    // clients post a freshly generated pair without looking.
    if user.private_key.is_some() || user.public_key.is_some() {
        return false;
    }

    // The organization the client enrols into is the one `GET /organizations/<identifier>/auto-enroll-status`
    // hands it, so ask the same question here.
    let Some(membership) = Membership::find_main_user_org(&user.uuid, conn).await else {
        return false;
    };

    // That lookup only rules out the `Revoked` status itself, which revoking never actually writes: it
    // shifts the status out of the active range instead, so a revoked membership comes back from it like
    // any other. The enrolment endpoint runs behind `OrgMemberHeaders` and turns exactly those away.
    if !membership.is_active() {
        return false;
    }

    // What `check_reset_password_applicable` demands of that organization.
    if !CONFIG.mail_enabled() {
        return false;
    }
    if !OrgPolicy::find_by_org_and_type(&membership.org_uuid, OrgPolicyType::ResetPassword, conn)
        .await
        .is_some_and(|policy| policy.enabled)
    {
        return false;
    }

    // Enrolling wraps the user key for the organization, so it needs its public key.
    Organization::find_by_uuid(&membership.org_uuid, conn)
        .await
        .is_some_and(|org| org.public_key.is_some_and(|key| !key.is_empty()))
}

/// The ways an account could get through the trusted device flow, which is what decides whether
/// offering it leads anywhere.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Four independent facts about one account, not a state that could be an enum"
)]
struct TrustedDeviceWaysIn {
    /// This device already holds the keys, so it unlocks without asking anyone.
    device_is_trusted: bool,
    /// A master password to fall back on.
    has_master_password: bool,
    /// An administrator of an organization who could let a new device in, which they can only do
    /// once the member enrolled into account recovery.
    has_admin_approval: bool,
    /// Nothing set up yet, but the account creation the clients run in that case would go through.
    can_create_account: bool,
}

impl TrustedDeviceWaysIn {
    /// Whether the trusted device options belong in a login response, and in which of their two roles.
    ///
    /// `Some(true)` means they are only there to walk a user without a master password off the feature
    /// after it was switched off; `None` means they are withheld, because nothing the client could do
    /// with them would work. The order mirrors how the clients read them: a trusted device unlocks
    /// straight away, otherwise an administrator to ask or a master password to type is offered, and only
    /// when there is neither does the client try to create a fresh account.
    fn offer(&self, enabled: bool) -> Option<bool> {
        // Once the feature is switched off again, a user without a master password would be locked out
        // of their own vault. Keep telling their still trusted devices about it so their client can walk
        // them through setting one while they can still unlock.
        let offboarding = !enabled && self.offboarding_candidate();
        if !(enabled || offboarding) {
            return None;
        }

        let leads_somewhere =
            self.device_is_trusted || self.has_admin_approval || self.has_master_password || self.can_create_account;
        leads_somewhere.then_some(offboarding)
    }

    /// A user who is still on a trusted device and has no master password to fall back on, and so
    /// has to be told when the feature goes away.
    fn offboarding_candidate(&self) -> bool {
        self.device_is_trusted && !self.has_master_password
    }
}

/// Trusted device encryption ("passwordless SSO"): instead of deriving the user key from a master
/// password, the client keeps a copy of it on the device, wrapped for a key pair that the device
/// generated. Its presence in the response is what makes the clients offer the flow at all.
///
/// Upstream ties this to the SSO configuration of an organization; Vaultwarden configures SSO for the
/// whole server, so `SSO_TRUSTED_DEVICE_ENCRYPTION` decides it here. Either way it stays an SSO feature,
/// a password login never gets these options.
/// https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/UserDecryptionOptionsBuilder.cs
async fn trusted_device_option(user: &User, device: &Device, conn: &DbConn) -> Option<Value> {
    let enabled = CONFIG.sso_trusted_device_encryption();

    let mut ways_in = TrustedDeviceWaysIn {
        device_is_trusted: device.is_trusted(),
        has_master_password: !user.password_hash.is_empty(),
        has_admin_approval: false,
        can_create_account: false,
    };

    // Answered ahead of everything else so a server that does not offer trusted devices, and has no
    // user left on them, does no work for the feature at all.
    if !(enabled || ways_in.offboarding_candidate()) {
        return None;
    }

    let memberships = Membership::find_by_user(&user.uuid, conn).await;

    // An admin can only take over the approval once the member handed them a key to work with, which is
    // what enrolling into account recovery does. The same condition the request itself is created and
    // answered under, so this does not announce a way out that would be refused the moment it is taken.
    ways_in.has_admin_approval = memberships.iter().any(Membership::can_use_admin_approval);

    // Only worth asking when nothing cheaper already lets the client in.
    if !(ways_in.device_is_trusted || ways_in.has_admin_approval || ways_in.has_master_password) {
        ways_in.can_create_account = account_creation_can_succeed(user, conn).await;
    }

    let offboarding = ways_in.offer(enabled)?;

    // Any other device of this user that could show an approval prompt. The user unlocks a new
    // device from one of these, or with the master password if they have one.
    let has_login_approving_device = Device::find_by_user(&user.uuid, conn)
        .await
        .iter()
        .any(|other| other.uuid != device.uuid && DeviceType::from_i32(other.atype).can_approve_login_requests());

    // Whether the user is on the answering side of that. The clients use it to push someone who could
    // approve others, but has no master password themselves, into setting one. Every active membership
    // counts, not only a confirmed one: an administrator provisioned by this very login holds the role
    // before anybody has confirmed them. See `has_manage_reset_password_role_for_tde`.
    let has_manage_reset_password_permission =
        memberships.iter().any(Membership::has_manage_reset_password_role_for_tde);

    Some(json!({
        "HasAdminApproval": ways_in.has_admin_approval,
        "HasLoginApprovingDevice": has_login_approving_device,
        "HasManageResetPasswordPermission": has_manage_reset_password_permission,
        "IsTdeOffboarding": offboarding,
        "EncryptedPrivateKey": device.trusted_private_key(),
        "EncryptedUserKey": device.trusted_user_key(),
        "Object": "trustedDeviceUserDecryptionOption"
    }))
}

async fn authenticated_response(
    user: &User,
    device: &mut Device,
    auth_tokens: auth::AuthTokens,
    twofactor_token: Option<String>,
    sso_login: bool,
    conn: &DbConn,
    ip: &ClientIp,
) -> JsonResult {
    if CONFIG.mail_enabled() && device.is_new() {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, device).await {
            error!("Error sending new device email: {e:#?}");

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    // register push device
    if !device.is_new() {
        register_push_device(device, conn).await?;
    }

    // Save to update `device.updated_at` to track usage and toggle new status
    device.save(true, conn).await?;

    let master_password_policy = master_password_policy(user, conn).await;

    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let account_keys = if user.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        })
    } else {
        Value::Null
    };

    let mut user_decryption_options = json!({
        "HasMasterPassword": has_master_password,
        "MasterPasswordUnlock": master_password_unlock,
        "Object": "userDecryptionOptions"
    });

    if sso_login && let Some(option) = trusted_device_option(user, device, conn).await {
        user_decryption_options["TrustedDeviceOption"] = option;
    }

    let mut result = json!({
        "access_token": auth_tokens.access_token(),
        "expires_in": auth_tokens.expires_in(),
        "token_type": "Bearer",
        "refresh_token": auth_tokens.refresh_token(),
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: Same as above
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": master_password_policy,
        "scope": auth_tokens.scope(),
        "AccountKeys": account_keys,
        "UserDecryptionOptions": user_decryption_options,
    });

    if !user.akey.is_empty() {
        result["Key"] = Value::String(user.akey.clone());
    }

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", user.email, ip.ip);
    Ok(Json(result))
}

async fn api_key_login(data: ConnectData, user_id: &mut Option<UserId>, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Validate scope
    match data.scope.as_ref() {
        Some(scope) if scope == &AuthMethod::UserApiKey.scope() => user_api_key_login(data, user_id, conn, ip).await,
        Some(scope) if scope == &AuthMethod::OrgApiKey.scope() => organization_api_key_login(data, conn, ip).await,
        _ => err!("Scope not supported"),
    }
}

async fn user_api_key_login(
    data: ConnectData,
    user_id: &mut Option<UserId>,
    conn: &DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Get the user via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let Some(client_user_id) = client_id.strip_prefix("user.") else {
        err!("Malformed client_id", format!("IP: {}.", ip.ip))
    };
    let client_user_id: UserId = client_user_id.into();
    let Some(user) = User::find_by_uuid(&client_user_id, conn).await else {
        err!("Invalid client_id", format!("IP: {}.", ip.ip))
    };

    // Set the user_id here to be passed back used for event logging.
    *user_id = Some(user.uuid.clone());

    // Check if the user is disabled
    if !user.enabled {
        err!(
            "This user has been disabled (API key login)",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    // Check API key. Note that API key logins bypass 2FA.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !user.check_valid_api_key(client_secret) {
        err!(
            "Incorrect client_secret",
            format!("IP: {}. Username: {}.", ip.ip, user.email),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let mut device = get_device(&data, conn, &user).await?;

    if CONFIG.mail_enabled() && device.is_new() {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device).await {
            error!("Error sending new device email: {e:#?}");

            if CONFIG.require_device_email() {
                err!(
                    "Could not send login notification email. Please contact your administrator.",
                    ErrorEvent {
                        event: EventType::UserFailedLogIn
                    }
                )
            }
        }
    }

    // ---
    // Disabled this variable, it was used to generate the JWT
    // Because this might get used in the future, and is add by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // let orgs = Membership::find_confirmed_by_user(&user.uuid, conn).await;
    let access_claims = auth::LoginJwtClaims::default(&device, &user, &AuthMethod::UserApiKey, data.client_id);

    // Save to update `device.updated_at` to track usage and toggle new status
    device.save(true, conn).await?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let account_keys = if user.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        })
    } else {
        Value::Null
    };

    // Note: No refresh_token is returned. The CLI just repeats the
    // client_credentials login flow when the existing token expires.
    let result = json!({
        "access_token": access_claims.token(),
        "expires_in": access_claims.expires_in(),
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
        "ForcePasswordReset": false,
        "scope": AuthMethod::UserApiKey.scope(),
        "AccountKeys": account_keys,
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions"
        },
    });

    Ok(Json(result))
}

async fn organization_api_key_login(data: ConnectData, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    // Get the org via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let Some(org_id) = client_id.strip_prefix("organization.") else {
        err!("Malformed client_id", format!("IP: {}.", ip.ip))
    };
    let org_id: OrganizationId = org_id.to_owned().into();
    let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(&org_id, conn).await else {
        err!("Invalid client_id", format!("IP: {}.", ip.ip))
    };

    // Check API key.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !org_api_key.check_valid_api_key(client_secret) {
        err!("Incorrect client_secret", format!("IP: {}. Organization: {}.", ip.ip, org_api_key.org_uuid))
    }

    let claim = generate_organization_api_key_login_claims(org_api_key.uuid, org_api_key.org_uuid);
    let access_token = auth::encode_jwt(&claim);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": AuthMethod::OrgApiKey.scope(),
    })))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
async fn get_device(data: &ConnectData, conn: &DbConn, user: &User) -> ApiResult<Device> {
    // On iOS, device_type sends "iOS", on others it sends a number
    // When unknown or unable to parse, return 14, which is 'Unknown Browser'
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(14);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    // Find device or create new
    if let Some(device) = Device::find_by_uuid_and_user(&device_id, &user.uuid, conn).await {
        Ok(device)
    } else {
        let mut device = Device::new(device_id, user.uuid.clone(), device_name, device_type);
        // save device without updating `device.updated_at`
        device.save(false, conn).await?;
        Ok(device)
    }
}

async fn twofactor_auth(
    user: &mut User,
    data: &ConnectData,
    device: &mut Device,
    ip: &ClientIp,
    client_version: Option<&ClientVersion>,
    conn: &DbConn,
) -> ApiResult<Option<String>> {
    let twofactors = TwoFactor::find_by_user(&user.uuid, conn).await;

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        enforce_2fa_policy(user, &user.uuid, device.atype, &ip.ip, conn).await?;
        return Ok(None);
    }

    TwoFactorIncomplete::mark_incomplete(&user.uuid, &device.uuid, &device.name, device.atype, ip, conn).await?;

    let twofactor_ids: Vec<_> = twofactors
        .iter()
        .filter_map(|tf| {
            let provider_type = TwoFactorType::from_i32(tf.atype)?;
            (tf.enabled && is_twofactor_provider_usable(&provider_type, Some(&tf.data))).then_some(tf.atype)
        })
        .collect();
    if twofactor_ids.is_empty() {
        err!("No enabled and usable two factor providers are available for this account")
    }

    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, assume the first one
    // Ignore Remember and RecoveryCode Types during this check, these are special
    if ![TwoFactorType::Remember as i32, TwoFactorType::RecoveryCode as i32].contains(&selected_id)
        && !twofactor_ids.contains(&selected_id)
    {
        err_json!(
            json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
            "Invalid two factor provider"
        )
    }

    let Some(ref twofactor_code) = data.two_factor_token else {
        err_json!(
            json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
            "2FA token not provided"
        )
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    let selected_data = selected_data(selected_twofactor);

    match TwoFactorType::from_i32(selected_id) {
        Some(TwoFactorType::Authenticator) => {
            authenticator::validate_totp_code_str(&user.uuid, twofactor_code, &selected_data?, ip, conn).await?;
        }
        Some(TwoFactorType::Webauthn) => webauthn::validate_webauthn_login(&user.uuid, twofactor_code, conn).await?,
        Some(TwoFactorType::YubiKey) => yubikey::validate_yubikey_login(twofactor_code, &selected_data?).await?,
        Some(TwoFactorType::Duo) => {
            if CONFIG.duo_use_iframe() {
                // Legacy iframe prompt flow
                duo::validate_duo_login(&user.email, twofactor_code, conn).await?;
            } else {
                // OIDC based flow
                duo_oidc::validate_duo_login(
                    &user.email,
                    twofactor_code,
                    data.client_id.as_ref().unwrap(),
                    data.device_identifier.as_ref().unwrap(),
                    conn,
                )
                .await?;
            }
        }
        Some(TwoFactorType::Email) => {
            email::validate_email_code_str(&user.uuid, twofactor_code, &selected_data?, &ip.ip, conn).await?;
        }
        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                // When a 2FA Remember token is used, check and validate this JWT token, if it is valid, just continue
                // If it is invalid we need to trigger the 2FA Login prompt
                Some(ref token)
                    if !CONFIG.disable_2fa_remember()
                        && (crypto::ct_eq(token, twofactor_code)
                            && auth::decode_2fa_remember(twofactor_code)
                                .is_ok_and(|t| t.sub == device.uuid && t.user_uuid == user.uuid)) => {}
                _ => {
                    // Always delete the current twofactor remember token here if it exists
                    if device.twofactor_remember.is_some() {
                        device.delete_twofactor_remember();
                        // We need to save here, since we send a err_json!() which prevents saving `device` at a later stage
                        device.save(true, conn).await?;
                    }
                    err_json!(
                        json_err_twofactor(&twofactor_ids, &user.uuid, data, client_version, conn).await?,
                        "2FA Remember token not provided or expired"
                    )
                }
            }
        }
        Some(TwoFactorType::RecoveryCode) => {
            // Check if recovery code is correct
            if !user.check_valid_recovery_code(twofactor_code) {
                err!("Recovery code is incorrect. Try again.")
            }

            // Remove all twofactors from the user
            TwoFactor::delete_all_by_user(&user.uuid, conn).await?;
            enforce_2fa_policy(user, &user.uuid, device.atype, &ip.ip, conn).await?;

            log_user_event(EventType::UserRecovered2fa as i32, &user.uuid, device.atype, &ip.ip, conn).await;

            // Remove the recovery code, not needed without twofactors
            user.totp_recover = None;
            user.save(conn).await?;
        }
        _ => err!(
            "Invalid two factor provider",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
    }

    TwoFactorIncomplete::mark_complete(&user.uuid, &device.uuid, conn).await?;

    let remember = data.two_factor_remember.unwrap_or(0);
    let two_factor = if !CONFIG.disable_2fa_remember() && remember == 1 {
        Some(device.refresh_twofactor_remember())
    } else {
        None
    };
    Ok(two_factor)
}

fn selected_data(tf: Option<TwoFactor>) -> ApiResult<String> {
    tf.map(|t| t.data).map_res("Two factor doesn't exist")
}

async fn json_err_twofactor(
    providers: &[i32],
    user_id: &UserId,
    data: &ConnectData,
    client_version: Option<&ClientVersion>,
    conn: &DbConn,
) -> ApiResult<Value> {
    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers.iter().map(ToString::to_string).collect::<Vec<String>>(),
        "TwoFactorProviders2" : {}, // { "0" : null }
        "MasterPasswordPolicy": {
            "Object": "masterPasswordPolicy"
        }
    });

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;

        match TwoFactorType::from_i32(*provider) {
            Some(TwoFactorType::Webauthn) if CONFIG.is_webauthn_2fa_supported() => {
                let request = webauthn::generate_webauthn_login(user_id, conn).await?;
                result["TwoFactorProviders2"][provider.to_string()] = request.0;
            }

            Some(TwoFactorType::Duo) => {
                let email = if let Some(u) = User::find_by_uuid(user_id, conn).await {
                    u.email
                } else {
                    err!("User does not exist")
                };

                if CONFIG.duo_use_iframe() {
                    // Legacy iframe prompt flow
                    let (signature, host) = duo::generate_duo_signature(&email, conn).await?;
                    result["TwoFactorProviders2"][provider.to_string()] = json!({
                        "Host": host,
                        "Signature": signature,
                    });
                } else {
                    // OIDC based flow
                    let auth_url = duo_oidc::get_duo_auth_url(
                        &email,
                        data.client_id.as_ref().unwrap(),
                        data.device_identifier.as_ref().unwrap(),
                        conn,
                    )
                    .await?;

                    result["TwoFactorProviders2"][provider.to_string()] = json!({
                        "AuthUrl": auth_url,
                    });
                }
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, tf_type as i32, conn).await else {
                    err!("No YubiKey devices registered")
                };

                let yubikey_metadata: yubikey::YubikeyMetadata = serde_json::from_str(&twofactor.data)?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Nfc": yubikey_metadata.nfc,
                });
            }

            Some(tf_type @ TwoFactorType::Email) => {
                let Some(twofactor) = TwoFactor::find_by_user_and_type(user_id, tf_type as i32, conn).await else {
                    err!("No twofactor email registered")
                };

                // Starting with version 2025.5.0 the client will call `/api/two-factor/send-email-login`.
                let disabled_send = if let Some(cv) = client_version {
                    let ver_match = semver::VersionReq::parse(">=2025.5.0").unwrap();
                    ver_match.matches(&cv.0)
                } else {
                    false
                };

                // Send email immediately if email is the only 2FA option.
                if providers.len() == 1 && !disabled_send {
                    email::send_token(user_id, conn).await?;
                }

                let email_data = email::EmailTokenData::from_json(&twofactor.data)?;
                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Email": email::obscure_email(&email_data.email),
                });
            }

            None
            | Some(
                TwoFactorType::Authenticator
                | TwoFactorType::EmailVerificationChallenge
                | TwoFactorType::OrganizationDuo
                | TwoFactorType::ProtectedActions
                | TwoFactorType::RecoveryCode
                | TwoFactorType::Remember
                | TwoFactorType::U2f
                | TwoFactorType::U2fLoginChallenge
                | TwoFactorType::U2fRegisterChallenge
                | TwoFactorType::Webauthn
                | TwoFactorType::WebauthnLoginChallenge
                | TwoFactorType::WebauthnRegisterChallenge,
            ) => { /* Nothing special to do for these providers */ }
        }
    }

    Ok(result)
}

#[post("/accounts/prelogin", data = "<data>")]
async fn post_prelogin(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    prelogin(data, conn).await
}

#[post("/accounts/prelogin/password", data = "<data>")]
async fn prelogin_password(data: Json<PreloginData>, conn: DbConn) -> Json<Value> {
    prelogin(data, conn).await
}

#[post("/accounts/register", data = "<data>")]
async fn identity_register(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    register(data, false, conn).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterVerificationData {
    email: String,
    name: Option<String>,
    // receiveMarketingEmails: bool,
}

#[derive(rocket::Responder)]
enum RegisterVerificationResponse {
    #[response(status = 204)]
    NoContent(()),
    Token(Json<String>),
}

#[post("/accounts/register/send-verification-email", data = "<data>")]
async fn register_verification_email(
    data: Json<RegisterVerificationData>,
    ip: ClientIp,
    conn: DbConn,
) -> ApiResult<RegisterVerificationResponse> {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data = data.into_inner();

    // the registration can only continue if signup is allowed or there exists an invitation
    if !(CONFIG.is_signup_allowed(&data.email)
        || (!CONFIG.mail_enabled() && Invitation::find_by_mail(&data.email, &conn).await.is_some()))
    {
        err!("Registration not allowed or user already exists")
    }

    let should_send_mail = CONFIG.mail_enabled() && CONFIG.signups_verify();

    let token_claims = auth::generate_register_verify_claims(data.email.clone(), data.name.clone(), should_send_mail);
    let token = auth::encode_jwt(&token_claims);

    if should_send_mail {
        let user = User::find_by_mail(&data.email, &conn).await;
        if user.as_ref().is_some_and(|u| u.private_key.is_some()) {
            // There is still a timing side channel here in that the code
            // paths that send mail take noticeably longer than ones that don't.
            // Add a randomized sleep to mitigate this somewhat.
            use rand::{RngExt, rngs::SmallRng};
            let mut rng: SmallRng = rand::make_rng();
            let sleep_ms: u64 = rng.random_range(900..=1100);
            tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
        } else {
            mail::send_register_verify_email(&data.email, &token).await?;
        }

        Ok(RegisterVerificationResponse::NoContent(()))
    } else {
        // If email verification is not required, return the token directly
        // the clients will use this token to finish the registration
        Ok(RegisterVerificationResponse::Token(Json(token)))
    }
}

#[post("/accounts/register/finish", data = "<data>")]
async fn register_finish(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    register(data, true, conn).await
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, FromForm)]
struct ConnectData {
    #[field(name = uncased("grant_type"))]
    #[field(name = uncased("granttype"))]
    grant_type: String, // refresh_token, password, client_credentials (API key)

    // Needed for grant_type="refresh_token"
    #[field(name = uncased("refresh_token"))]
    #[field(name = uncased("refreshtoken"))]
    refresh_token: Option<String>,

    // Needed for grant_type = "password" | "client_credentials"
    #[field(name = uncased("client_id"))]
    #[field(name = uncased("clientid"))]
    client_id: Option<String>, // web, cli, desktop, browser, mobile
    #[field(name = uncased("client_secret"))]
    #[field(name = uncased("clientsecret"))]
    client_secret: Option<String>,
    #[field(name = uncased("password"))]
    password: Option<String>,
    #[field(name = uncased("scope"))]
    scope: Option<String>,
    #[field(name = uncased("username"))]
    username: Option<String>,

    #[field(name = uncased("device_identifier"))]
    #[field(name = uncased("deviceidentifier"))]
    device_identifier: Option<DeviceId>,
    #[field(name = uncased("device_name"))]
    #[field(name = uncased("devicename"))]
    device_name: Option<String>,
    #[field(name = uncased("device_type"))]
    #[field(name = uncased("devicetype"))]
    device_type: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("device_push_token"))]
    #[field(name = uncased("devicepushtoken"))]
    _device_push_token: Option<String>, // Unused; mobile device push not yet supported.

    // Needed for two-factor auth
    #[field(name = uncased("two_factor_provider"))]
    #[field(name = uncased("twofactorprovider"))]
    two_factor_provider: Option<i32>,
    #[field(name = uncased("two_factor_token"))]
    #[field(name = uncased("twofactortoken"))]
    two_factor_token: Option<String>,
    #[field(name = uncased("two_factor_remember"))]
    #[field(name = uncased("twofactorremember"))]
    two_factor_remember: Option<i32>,
    #[field(name = uncased("authrequest"))]
    auth_request: Option<AuthRequestId>,

    // Needed for authorization code
    #[field(name = uncased("code"))]
    code: Option<OIDCCode>,
    #[field(name = uncased("code_verifier"))]
    code_verifier: Option<OIDCCodeVerifier>,

    // Needed for send access
    send_id: Option<SendId>,
    password_hash_b64: Option<String>,
}
fn check_is_some<T>(value: Option<&T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

#[get("/sso/prevalidate")]
fn prevalidate() -> JsonResult {
    if CONFIG.sso_enabled() {
        let sso_token = sso::encode_ssotoken_claims();
        Ok(Json(json!({
            "token": sso_token,
        })))
    } else {
        err!("SSO sign-in is not available")
    }
}

const SSO_BINDING_COOKIE: &str = "VW_SSO_BINDING";

#[get("/connect/oidc-signin?<code>&<state>", rank = 1)]
async fn oidcsignin(code: OIDCCode, state: String, cookies: &CookieJar<'_>, mut conn: DbConn) -> ApiResult<Redirect> {
    oidcsignin_redirect(state, code, None, cookies, &mut conn).await
}

// Bitwarden client appear to only care for code and state
// We save the error in the database and set the encoded state as the code to be able to retrieve them later on
// cf: https://github.com/bitwarden/clients/blob/afd36d290ce18fb0048e0575e7d5a8f78b5dbffc/libs/auth/src/angular/sso/sso.component.ts#L156
#[get("/connect/oidc-signin?<state>&<error>&<error_description>", rank = 2)]
async fn oidcsignin_error(
    state: String,
    error: String,
    error_description: Option<String>,
    cookies: &CookieJar<'_>,
    mut conn: DbConn,
) -> ApiResult<Redirect> {
    oidcsignin_redirect(
        state.clone(),
        state.into(),
        Some(OIDCCodeResponseError {
            error,
            error_description,
        }),
        cookies,
        &mut conn,
    )
    .await
}

// The state was encoded using Base64 to ensure no issue with providers.
// iss and scope parameters are needed for redirection to work on IOS.
// We pass the state as the code to get it back later on.
async fn oidcsignin_redirect(
    base64_state: String,
    code: OIDCCode,
    error: Option<OIDCCodeResponseError>,
    cookies: &CookieJar<'_>,
    conn: &mut DbConn,
) -> ApiResult<Redirect> {
    let state = sso::decode_state(&base64_state)?;

    let Some(mut sso_auth) = SsoAuth::find(&state, conn).await else {
        err!(format!("Cannot retrieve sso_auth for {state}"))
    };

    // Browser-binding check
    // The cookie was set on /connect/authorize and must come from the same browser that initiated the flow.
    let cookie_value = cookies.get(SSO_BINDING_COOKIE).map(|c| c.value().to_owned());
    let provided_hash = cookie_value.as_deref().map(|v| crypto::sha256_hex(v.as_bytes()));
    match (sso_auth.binding_hash.as_deref(), provided_hash.as_deref()) {
        (Some(expected), Some(actual)) if crypto::ct_eq(expected, actual) => {}
        _ => err!(format!("SSO session binding mismatch for {state}")),
    }
    cookies
        .remove(Cookie::build(SSO_BINDING_COOKIE).path(format!("{}/identity/connect/", CONFIG.domain_path())).build());

    sso_auth.code_response = Some(code.clone());
    sso_auth.code_response_error = error;
    sso_auth.updated_at = Utc::now().naive_utc();
    sso_auth.save(conn).await?;

    let mut url = match url::Url::parse(&sso_auth.redirect_uri) {
        Ok(url) => url,
        Err(err) => err!(format!("Failed to parse redirect uri ({}): {err}", sso_auth.redirect_uri)),
    };

    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &state)
        .append_pair("scope", &AuthMethod::Sso.scope())
        .append_pair("iss", &CONFIG.domain());

    debug!("Redirection to {url}");

    Ok(Redirect::temporary(String::from(url)))
}

#[derive(Debug, Clone, Default, FromForm)]
struct AuthorizeData {
    #[field(name = uncased("client_id"))]
    #[field(name = uncased("clientid"))]
    client_id: String,
    #[field(name = uncased("redirect_uri"))]
    #[field(name = uncased("redirecturi"))]
    redirect_uri: String,
    #[allow(unused)]
    response_type: Option<String>,
    #[allow(unused)]
    scope: Option<String>,
    state: OIDCState,
    code_challenge: OIDCCodeChallenge,
    code_challenge_method: String,
    #[allow(unused)]
    response_mode: Option<String>,
    #[allow(unused)]
    domain_hint: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("ssoToken"))]
    sso_token: Option<String>,
}

// The `redirect_uri` will change depending of the client (web, android, ios ..)
#[get("/connect/authorize?<data..>")]
async fn authorize(data: AuthorizeData, cookies: &CookieJar<'_>, secure: Secure, conn: DbConn) -> ApiResult<Redirect> {
    let AuthorizeData {
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        ..
    } = data;

    if code_challenge_method != "S256" {
        err!("Unsupported code challenge method");
    }

    // Generate browser-binding token. Stored hashed in DB; raw value handed to the browser as a cookie.
    // Validated on /connect/oidc-signin
    let binding_token = data_encoding::BASE64URL_NOPAD.encode(&crypto::get_random_bytes::<32>());
    let binding_hash = crypto::sha256_hex(binding_token.as_bytes());

    let auth_url =
        sso::authorize_url(state, code_challenge, &client_id, &redirect_uri, Some(binding_hash), conn).await?;

    cookies.add(
        Cookie::build((SSO_BINDING_COOKIE, binding_token))
            .path(format!("{}/identity/connect/", CONFIG.domain_path()))
            .max_age(time::Duration::seconds(sso::SSO_AUTH_EXPIRATION.num_seconds()))
            .same_site(SameSite::Lax) // Lax is needed because the IdP runs on a different FQDN
            .http_only(true)
            .secure(secure.https)
            .build(),
    );

    Ok(Redirect::temporary(String::from(auth_url)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::MembershipStatus;

    /// A `TrustedDeviceWaysIn` plus the server setting, so the cases below read as what they are.
    #[expect(clippy::struct_excessive_bools, reason = "Mirrors the struct under test")]
    struct Account {
        enabled: bool,
        device_is_trusted: bool,
        has_master_password: bool,
        has_admin_approval: bool,
        can_create_account: bool,
    }

    impl Account {
        /// A user of a server that offers trusted devices, on a device it does not know yet, with
        /// nothing set up: the shape everything below varies from.
        fn new() -> Self {
            Self {
                enabled: true,
                device_is_trusted: false,
                has_master_password: false,
                has_admin_approval: false,
                can_create_account: false,
            }
        }

        fn offer(&self) -> Option<bool> {
            TrustedDeviceWaysIn {
                device_is_trusted: self.device_is_trusted,
                has_master_password: self.has_master_password,
                has_admin_approval: self.has_admin_approval,
                can_create_account: self.can_create_account,
            }
            .offer(self.enabled)
        }
    }

    #[test]
    fn a_server_that_does_not_offer_trusted_devices_says_nothing_about_them() {
        for (device_is_trusted, has_master_password) in [(false, false), (false, true), (true, true)] {
            let account = Account {
                enabled: false,
                device_is_trusted,
                has_master_password,
                ..Account::new()
            };
            assert_eq!(account.offer(), None);
        }
    }

    #[test]
    fn a_user_left_on_a_trusted_device_is_walked_off_the_feature() {
        // The feature is gone but this device still unlocks and its owner has no master password.
        // They are told so, so their client can walk them through setting one while they still can.
        let account = Account {
            enabled: false,
            device_is_trusted: true,
            ..Account::new()
        };
        assert_eq!(account.offer(), Some(true), "offboarding");

        // With the feature on, the same device is simply trusted.
        let account = Account {
            device_is_trusted: true,
            ..Account::new()
        };
        assert_eq!(account.offer(), Some(false));

        // With a master password there is nothing to walk them off, they can unlock either way.
        let account = Account {
            enabled: false,
            device_is_trusted: true,
            has_master_password: true,
            ..Account::new()
        };
        assert_eq!(account.offer(), None);
    }

    #[test]
    fn every_way_through_the_flow_is_offered_it_and_nothing_else_is() {
        // Nothing set up, nobody to ask, and account creation would fail at the enrolment: the one
        // combination that would leave the account half built. The client is sent to setting a
        // master password instead.
        assert_eq!(Account::new().offer(), None);

        for account in [
            // A device that can unlock right now.
            Account {
                device_is_trusted: true,
                ..Account::new()
            },
            // An administrator to ask, which needs the member to be enrolled in account recovery.
            Account {
                has_admin_approval: true,
                ..Account::new()
            },
            // A master password to fall back on.
            Account {
                has_master_password: true,
                ..Account::new()
            },
            // A fresh account in an organization that can actually take the enrolment.
            Account {
                can_create_account: true,
                ..Account::new()
            },
        ] {
            assert_eq!(account.offer(), Some(false));
        }
    }

    /// What `trusted_device_option` reads off the memberships of the user logging in.
    fn has_admin_approval(memberships: &[Membership]) -> bool {
        memberships.iter().any(Membership::can_use_admin_approval)
    }

    fn membership(org: &str, status: MembershipStatus, enrolled: bool) -> Membership {
        let mut membership = Membership::new(String::from("user").into(), org.to_owned().into(), None);
        membership.status = status as i32;
        membership.reset_password_key = enrolled.then(|| String::from("2.aXY=|Y2lwaGVy|bWFj"));
        membership
    }

    #[test]
    fn enrolling_into_trusted_devices_leaves_an_administrator_to_ask() {
        // Invited into an organization that unlocks with trusted devices, before enrolling: nobody
        // holds a key to approve with yet.
        let mut memberships = [membership("org", MembershipStatus::Invited, false)];
        assert!(!has_admin_approval(&memberships));

        // Enrolling is what `put_reset_password_enrollment` does for an account without a master
        // password: it writes the key and accepts the invitation in the same step. Confirming the
        // member is an administrator's own, later decision, and until they get round to it the
        // member is stuck here.
        memberships[0].status = MembershipStatus::Accepted as i32;
        memberships[0].reset_password_key = Some(String::from("2.aXY=|Y2lwaGVy|bWFj"));

        assert!(has_admin_approval(&memberships), "the enrolment is what an administrator answers with");

        // Losing the trusted device at that point is the case this covers: no master password, no
        // device that unlocks, and an administrator to ask is the only way back in.
        let account = Account {
            has_admin_approval: has_admin_approval(&memberships),
            ..Account::new()
        };
        assert_eq!(account.offer(), Some(false), "the flow leads somewhere, so it is offered");
    }

    #[test]
    fn one_organization_that_could_approve_is_enough() {
        // A member of several organizations only needs one of them to hold a key for them.
        let memberships = [
            membership("invited", MembershipStatus::Invited, true),
            membership("not-enrolled", MembershipStatus::Confirmed, false),
            membership("enrolled", MembershipStatus::Accepted, true),
        ];
        assert!(has_admin_approval(&memberships));

        // Take that one away and there is nobody left to ask, however many organizations remain.
        let memberships = [
            membership("invited", MembershipStatus::Invited, true),
            membership("not-enrolled", MembershipStatus::Confirmed, false),
            membership("revoked", MembershipStatus::Revoked, true),
        ];
        assert!(!has_admin_approval(&memberships));
    }
}
