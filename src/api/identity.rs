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
use webauthn_rs::prelude::{Base64UrlSafeData, DiscoverableAuthentication, DiscoverableKey, Passkey};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, PublicKeyCredential,
};

use crate::api::core::two_factor::webauthn::WEBAUTHN;
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
            AuthRequest, AuthRequestId, Device, DeviceId, EventType, Invitation, OIDCCodeResponseError,
            OrganizationApiKey, OrganizationId, SsoAuth, SsoUser, TwoFactor, TwoFactorIncomplete, TwoFactorType, User,
            UserId, WebAuthnCredential, WebAuthnLoginChallenge, WebAuthnLoginChallengeId,
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
        oidcsignin_error,
        get_web_authn_assertion_options
    ]
}

/// Deny-by-default SSO gate (mirrors Bitwarden's `SsoRequestValidator`):
/// non-exempt grants are rejected under `SSO_ONLY`.
fn check_sso_only(grant_type: &str) -> EmptyResult {
    if !CONFIG.sso_enabled() || !CONFIG.sso_only() {
        return Ok(());
    }
    match grant_type {
        "authorization_code" | "client_credentials" | "refresh_token" => Ok(()),
        _ => err!("SSO sign-in is required"),
    }
}

#[post("/connect/token", data = "<data>")]
async fn login(
    data: Form<ConnectData>,
    client_header: ClientHeaders,
    client_version: Option<ClientVersion>,
    conn: DbConn,
) -> JsonResult {
    let data: ConnectData = data.into_inner();

    check_sso_only(data.grant_type.as_ref())?;

    let mut user_id: Option<UserId> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            check_is_some(data.refresh_token.as_ref(), "refresh_token cannot be blank")?;
            refresh_login(data, &conn, &client_header.ip).await
        }
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
        "webauthn" => {
            check_is_some(data.client_id.as_ref(), "client_id cannot be blank")?;
            check_is_some(data.scope.as_ref(), "scope cannot be blank")?;

            check_is_some(data.device_identifier.as_ref(), "device_identifier cannot be blank")?;
            check_is_some(data.device_name.as_ref(), "device_name cannot be blank")?;
            check_is_some(data.device_type.as_ref(), "device_type cannot be blank")?;

            check_is_some(data.device_response.as_ref(), "device_response cannot be blank")?;
            check_is_some(data.token.as_ref(), "token cannot be blank")?;

            webauthn_login(data, &mut user_id, &conn, &client_header.ip).await
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
            if !CONFIG.is_email_domain_allowed(&user_infos.email) {
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
                format!("IP: {}. Username: {}.", ip.ip, user.display_name()),
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

    authenticated_response(&user, &mut device, auth_tokens, twofactor_token, conn, ip).await
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

    authenticated_response(&user, &mut device, auth_tokens, twofactor_token, conn, ip).await
}

async fn authenticated_response(
    user: &User,
    device: &mut Device,
    auth_tokens: auth::AuthTokens,
    twofactor_token: Option<String>,
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
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions"
        },
    });

    if !user.akey.is_empty() {
        result["Key"] = Value::String(user.akey.clone());
    }

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", user.display_name(), ip.ip);
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
                | TwoFactorType::WebauthnPasskeyAssertionChallenge
                | TwoFactorType::WebauthnPasskeyRegisterChallenge
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
    conn: DbConn,
) -> ApiResult<RegisterVerificationResponse> {
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

// Copied from webauthn-rs to rename clientDataJSON -> clientDataJson for Bitwarden compatibility
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssertionResponseCopy {
    pub authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
    pub signature: Base64UrlSafeData,
    pub user_handle: Option<Base64UrlSafeData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AssertionResponseCopy,
    pub r#type: String,
    #[allow(dead_code)]
    pub extensions: Option<Value>,
}

impl From<PublicKeyCredentialCopy> for PublicKeyCredential {
    fn from(p: PublicKeyCredentialCopy) -> Self {
        Self {
            id: p.id,
            raw_id: p.raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: p.response.authenticator_data,
                client_data_json: p.response.client_data_json,
                signature: p.response.signature,
                user_handle: p.response.user_handle,
            },
            extensions: AuthenticationExtensionsClientOutputs::default(),
            type_: p.r#type,
        }
    }
}

fn passkey_credential_id(passkey: &Passkey) -> ApiResult<String> {
    serde_json::to_value(passkey.cred_id())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| crate::error::Error::new("Invalid passkey credential", "Could not serialize credential id"))
}

fn passkey_transports(passkey: &Passkey) -> Vec<String> {
    serde_json::to_value(passkey)
        .ok()
        .and_then(|value| {
            value
                .pointer("/cred/transports")
                .and_then(Value::as_array)
                .map(|transports| transports.iter().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>())
        })
        .unwrap_or_default()
}

/// Augments the base login response (from `authenticated_response`) with the credential-
/// specific `WebAuthnPrfOption` field that upstream Bitwarden's `UserDecryptionOptionsBuilder`
/// attaches via `WithWebAuthnLoginCredential` after a successful passkey assertion. Without
/// this attachment the client receives a valid access token but no way to unlock the vault
/// from the PRF secret it just derived — login completes, vault stays locked.
pub(crate) fn build_webauthn_login_response(base: Value, matched_wac: &WebAuthnCredential, passkey: &Passkey) -> Value {
    let mut result = base;
    if let Some(prf_option) = build_webauthn_login_prf_option(matched_wac, passkey) {
        result["UserDecryptionOptions"]["WebAuthnPrfOption"] = prf_option;
    }
    result
}

/// Singular `WebAuthnPrfOption` for the webauthn-login response. The Bitwarden client's
/// immediate post-passkey-login decryption path reads this field to recover the user key from
/// the PRF output the assertion just produced. Gated on `has_prf_keyset()` so we never
/// advertise PRF capability for a credential whose keyset is incomplete.
pub(crate) fn build_webauthn_login_prf_option(matched_wac: &WebAuthnCredential, passkey: &Passkey) -> Option<Value> {
    if !matched_wac.has_prf_keyset() {
        return None;
    }
    let credential_id = passkey_credential_id(passkey).ok()?;
    let transports = passkey_transports(passkey);
    Some(json!({
        "EncryptedPrivateKey": matched_wac.encrypted_private_key,
        "EncryptedUserKey": matched_wac.encrypted_user_key,
        "CredentialId": credential_id,
        "Transports": transports,
    }))
}

/// `WebAuthnPrfOptions` array for `UserDecryptionOptions` (login response) and
/// `userDecryption` (sync response). Only credentials with `prf_status() == Enabled`
/// (supports PRF + complete keyset) appear; corrupted blobs are filter_map'd out
/// so one broken row doesn't suppress the lock-screen option for healthy
/// credentials. Mirrors upstream
/// `SyncResponseModel.UserDecryption.WebAuthnPrfOptions`.
pub(crate) fn build_webauthn_prf_options(credentials: &[WebAuthnCredential]) -> Vec<Value> {
    credentials
        .iter()
        .filter(|wac| wac.has_prf_keyset())
        .filter_map(|wac| {
            let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
            let credential_id = passkey_credential_id(&passkey).ok()?;
            let transports = passkey_transports(&passkey);
            Some(json!({
                "EncryptedPrivateKey": wac.encrypted_private_key,
                "EncryptedUserKey": wac.encrypted_user_key,
                "CredentialId": credential_id,
                "Transports": transports,
            }))
        })
        .collect()
}

#[get("/accounts/webauthn/assertion-options")]
async fn get_web_authn_assertion_options(ip: ClientIp, conn: DbConn) -> JsonResult {
    // Same gate the 2FA WebAuthn entry point uses, applied here so a
    // misconfigured DOMAIN (e.g., IP literal that has no parseable host)
    // returns a clean error instead of panicking inside the `WEBAUTHN`
    // `LazyLock` initializer.
    if !CONFIG.is_webauthn_2fa_supported() {
        err!("Configured `DOMAIN` is not compatible with Webauthn")
    }

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("SSO sign-in is required")
    }

    // This endpoint is unauthenticated; rate-limit it so it cannot be abused to
    // flood the challenge table. Expired rows are removed by a scheduled job.
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // start_discoverable_authentication() requests an empty allow-list
    // (discoverable credentials) and user verification.
    let (response, state) = WEBAUTHN.start_discoverable_authentication()?;

    // Persist the challenge state so it can be verified on the follow-up token
    // request. It is keyed by a random token and consumed exactly once.
    let challenge = WebAuthnLoginChallenge::new(serde_json::to_string(&state)?);
    let token = challenge.id.clone();
    challenge.save(&conn).await?;

    // Only `public_key` is forwarded: the `mediation: Conditional` field that
    // start_discoverable_authentication() sets is intentionally dropped, since
    // Bitwarden's "Log in with passkey" is an explicit-button flow, not autofill.
    let options = serde_json::to_value(response.public_key)?;

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webAuthnLoginAssertionOptions"
    })))
}

async fn webauthn_login(data: ConnectData, user_id: &mut Option<UserId>, conn: &DbConn, ip: &ClientIp) -> JsonResult {
    // A single generic message is returned to the client for every failure so the
    // endpoint cannot be used to probe which accounts exist or have passkeys.
    const AUTH_FAILED: &str = "Passkey authentication failed.";

    // Validate scope and rate-limit the login.
    AuthMethod::WebAuthn.check_scope(data.scope.as_ref())?;
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Recover and consume (single-use) the saved challenge state. Every
    // submission carrying a valid token is spent, regardless of body content
    // or which user the assertion later claims — a caller with a valid token
    // cannot repeatedly replay it with malformed bodies.
    let token = WebAuthnLoginChallengeId::from(data.token.as_ref().unwrap().clone());
    let Some(saved_challenge) = WebAuthnLoginChallenge::take(&token, conn).await else {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Missing or expired passkey login challenge.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    };
    let Ok(state) = serde_json::from_str::<DiscoverableAuthentication>(&saved_challenge.challenge) else {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Corrupt passkey login challenge state.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    };

    // Parse the authenticator assertion. A malformed body must yield the same
    // generic error as any other failure, not a raw deserialization error.
    let Ok(device_response) = serde_json::from_str::<PublicKeyCredentialCopy>(data.device_response.as_ref().unwrap())
    else {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Malformed passkey assertion.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    };
    let credential: PublicKeyCredential = device_response.into();

    // Identify which user the discoverable credential claims to belong to from
    // its user handle. This only parses client-supplied data; user-scoped event
    // logging is delayed until the assertion is cryptographically verified.
    let user_uuid = match WEBAUTHN.identify_discoverable_authentication(&credential) {
        Ok((user_uuid, _)) => UserId::from(user_uuid.to_string()),
        Err(e) => err!(
            AUTH_FAILED,
            format!("IP: {}. Could not identify passkey credential: {e:?}", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        ),
    };

    let Some(user) = User::find_by_uuid(&user_uuid, conn).await else {
        err!(
            AUTH_FAILED,
            format!("IP: {}. No user matches passkey user handle {user_uuid}.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    };

    let username = user.email.clone();

    // Load this user's passkey-login credentials.
    let parsed_credentials: Vec<(WebAuthnCredential, Passkey)> = WebAuthnCredential::find_by_user(&user.uuid, conn)
        .await
        .into_iter()
        .filter_map(|wac| {
            let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
            Some((wac, passkey))
        })
        .collect();

    if parsed_credentials.is_empty() {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Username: {username}. No passkey credentials registered.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let discoverable_keys: Vec<DiscoverableKey> =
        parsed_credentials.iter().map(|(_, passkey)| DiscoverableKey::from(passkey)).collect();

    // Verify the assertion. webauthn-rs checks the signature, challenge, origin,
    // user verification and the signature counter against the registered keys.
    let authentication_result =
        match WEBAUTHN.finish_discoverable_authentication(&credential, state, &discoverable_keys) {
            Ok(result) => result,
            Err(e) => err!(
                AUTH_FAILED,
                format!("IP: {}. Username: {username}. WebAuthn verification failed: {e:?}", ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn
                }
            ),
        };

    // The assertion is now bound to a registered credential for this user. From
    // this point on, failed account-state checks can be attributed to the user
    // without allowing arbitrary user-handle event log pollution.
    *user_id = Some(user.uuid.clone());

    if !user.enabled {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Username: {username}. Account is disabled.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    // Reject an unverified account before doing any server-side persistence.
    // Mirrors the password-login email-verify gate but elides the verification
    // reminder email and the distinguishable error message. Returning the same
    // `AUTH_FAILED` as every other branch prevents using passkey login as an
    // oracle for verification state. The descriptive hint still reaches
    // legitimate users via password login.
    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.signups_verify() {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Username: {username}. Account is not email-verified.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    // Locate the credential that was actually used and persist any counter update.
    let Some((mut matched_wac, mut passkey)) = parsed_credentials
        .into_iter()
        .find(|(_, passkey)| crypto::ct_eq(passkey.cred_id().as_slice(), authentication_result.cred_id().as_slice()))
    else {
        err!(
            AUTH_FAILED,
            format!("IP: {}. Username: {username}. Verified credential is not registered.", ip.ip),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    };

    // Persist any signature-counter advance from this assertion.
    if passkey.update_credential(&authentication_result) == Some(true) {
        matched_wac.credential = serde_json::to_string(&passkey)?;
        matched_wac.update_credential(conn).await?;
    }

    let mut device = get_device(&data, conn, &user).await?;

    // Mirror the 2FA-state gate that password login applies (twofactor_auth):
    // - no providers at all → enforce_2fa_policy (revoke from RequireTwoFactor
    //   orgs the user no longer satisfies) and let the passkey login proceed.
    // - rows exist but every provider is disabled or unusable → reject, same
    //   message the password path returns. The passkey is the auth, so we
    //   don't ask for a 2FA token when usable providers exist.
    let twofactors = TwoFactor::find_by_user(&user.uuid, conn).await;
    if twofactors.is_empty() {
        enforce_2fa_policy(&user, &user.uuid, device.atype, &ip.ip, conn).await?;
    } else if !twofactors.iter().any(|tf| {
        TwoFactorType::from_i32(tf.atype)
            .is_some_and(|t| tf.enabled && is_twofactor_provider_usable(&t, Some(&tf.data)))
    }) {
        err!("No enabled and usable two factor providers are available for this account")
    }

    let auth_tokens = auth::AuthTokens::new(&device, &user, AuthMethod::WebAuthn, data.client_id);

    // Build the common response, then attach the credential-specific `WebAuthnPrfOption`
    // upstream populates via `WithWebAuthnLoginCredential` after a webauthn-grant assertion.
    // The wrapped-key payload lets the client unlock the vault using the PRF secret it just
    // derived; without it, login completes but the vault stays locked.
    let Json(base) = authenticated_response(&user, &mut device, auth_tokens, None, conn, ip).await?;
    Ok(Json(build_webauthn_login_response(base, &matched_wac, &passkey)))
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, FromForm)]
struct ConnectData {
    #[field(name = uncased("grant_type"))]
    #[field(name = uncased("granttype"))]
    grant_type: String, // refresh_token, password, client_credentials (API key), webauthn

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

    // Needed for grant_type = "webauthn"
    #[field(name = uncased("deviceresponse"))]
    device_response: Option<String>,
    // Token identifying the webauthn authentication state
    #[field(name = uncased("token"))]
    token: Option<String>,
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
    use webauthn_rs::prelude::{
        AttestationFormat, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, Credential, ECDSACurve, ParsedAttestation,
    };
    use webauthn_rs_proto::{AuthenticatorTransport, RegisteredExtensions, UserVerificationPolicy};

    fn passkey(transports: Option<Vec<AuthenticatorTransport>>) -> Passkey {
        Credential {
            cred_id: [1, 2, 3, 4].into(),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [1; 32].into(),
                    y: [2; 32].into(),
                }),
            },
            counter: 0,
            transports,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: UserVerificationPolicy::Required,
            extensions: RegisteredExtensions::none(),
            attestation: ParsedAttestation::default(),
            attestation_format: AttestationFormat::None,
        }
        .into()
    }

    #[test]
    fn passkey_credential_id_returns_browser_credential_id() {
        assert_eq!(passkey_credential_id(&passkey(None)).unwrap(), "AQIDBA");
    }

    #[test]
    fn passkey_transports_returns_saved_transport_hints() {
        let passkey = passkey(Some(vec![AuthenticatorTransport::Internal, AuthenticatorTransport::Hybrid]));

        assert_eq!(passkey_transports(&passkey), vec![String::from("internal"), String::from("hybrid")]);
    }

    #[test]
    fn passkey_transports_defaults_to_empty_when_absent() {
        assert!(passkey_transports(&passkey(None)).is_empty());
    }

    fn make_credential(
        supports_prf: bool,
        encrypted_user_key: Option<&str>,
        encrypted_public_key: Option<&str>,
        encrypted_private_key: Option<&str>,
        passkey_json: &str,
    ) -> WebAuthnCredential {
        WebAuthnCredential::new(
            UserId::from(String::from("00000000-0000-0000-0000-000000000000")),
            String::from("test"),
            passkey_json.to_owned(),
            String::from("credential-id-hash"),
            supports_prf,
            encrypted_user_key.map(String::from),
            encrypted_public_key.map(String::from),
            encrypted_private_key.map(String::from),
        )
    }

    #[test]
    fn webauthn_prf_options_skips_credentials_without_full_keyset() {
        let pk = serde_json::to_string(&passkey(None)).unwrap();
        let creds = [
            make_credential(false, Some("u"), Some("p"), Some("k"), &pk), // PRF unsupported
            make_credential(true, None, None, None, &pk),                 // PRF supported, no keyset
            make_credential(true, Some("u"), Some("p"), None, &pk),       // partial keyset
        ];
        assert!(build_webauthn_prf_options(&creds).is_empty());
    }

    #[test]
    fn webauthn_prf_options_emits_entry_per_enabled_credential() {
        let pk = serde_json::to_string(&passkey(Some(vec![AuthenticatorTransport::Internal]))).unwrap();
        let creds = [
            make_credential(true, Some("uk-a"), Some("pk-a"), Some("priv-a"), &pk),
            make_credential(true, Some("uk-b"), Some("pk-b"), Some("priv-b"), &pk),
            make_credential(false, Some("uk-c"), Some("pk-c"), Some("priv-c"), &pk), // skipped
        ];
        let options = build_webauthn_prf_options(&creds);

        assert_eq!(options.len(), 2, "only PRF-enabled credentials should produce entries");
        // Match upstream `WebAuthnPrfDecryptionOption` field names (PascalCase). The Bitwarden
        // client deserialises case-insensitively, but pinning the casing here catches a
        // refactor that accidentally renames a key.
        assert_eq!(options[0]["EncryptedUserKey"], "uk-a");
        assert_eq!(options[0]["EncryptedPrivateKey"], "priv-a");
        assert_eq!(options[0]["CredentialId"], "AQIDBA");
        assert_eq!(options[0]["Transports"], json!(["internal"]));
        assert_eq!(options[1]["EncryptedUserKey"], "uk-b");
        assert_eq!(options[1]["EncryptedPrivateKey"], "priv-b");
    }

    #[test]
    fn webauthn_login_prf_option_emits_for_enabled_credential() {
        // Pins the singular `WebAuthnPrfOption` block emitted by the webauthn-login response.
        // The Bitwarden client's post-passkey-login decryption path reads this specific field
        // (alongside the plural `WebAuthnPrfOptions` array used by the lock screen). Removing
        // it leaves the credential just authenticated with un-usable for immediate vault unlock
        // even though the PRF assertion already produced the output the client would decrypt
        // with.
        let pk = passkey(Some(vec![AuthenticatorTransport::Internal]));
        let pk_blob = serde_json::to_string(&pk).unwrap();
        let wac = make_credential(true, Some("uk"), Some("pk"), Some("priv"), &pk_blob);

        let option = build_webauthn_login_prf_option(&wac, &pk).expect("PRF-enabled credential emits singular option");
        assert_eq!(option["EncryptedPrivateKey"], "priv");
        assert_eq!(option["EncryptedUserKey"], "uk");
        assert_eq!(option["CredentialId"], "AQIDBA");
        assert_eq!(option["Transports"], json!(["internal"]));
    }

    #[test]
    fn webauthn_login_response_attaches_singular_prf_option_for_enabled_credential() {
        // Pins the shape of the `webauthn_login` response augmentation: when a PRF-enabled
        // credential authenticates, `UserDecryptionOptions.WebAuthnPrfOption` (singular) is
        // attached to the response. Matches upstream Bitwarden's `UserDecryptionOptions`
        // contract (singular field, populated only by the webauthn grant via
        // `UserDecryptionOptionsBuilder.WithWebAuthnLoginCredential`).
        let base = json!({
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "Object": "userDecryptionOptions",
            }
        });
        let pk = passkey(Some(vec![AuthenticatorTransport::Internal]));
        let wac = make_credential(true, Some("uk"), Some("pk"), Some("priv"), &serde_json::to_string(&pk).unwrap());

        let response = build_webauthn_login_response(base, &wac, &pk);

        assert_eq!(response["UserDecryptionOptions"]["WebAuthnPrfOption"]["EncryptedPrivateKey"], "priv");
        assert_eq!(response["UserDecryptionOptions"]["WebAuthnPrfOption"]["EncryptedUserKey"], "uk");
        assert_eq!(response["UserDecryptionOptions"]["WebAuthnPrfOption"]["CredentialId"], "AQIDBA");
        assert_eq!(response["UserDecryptionOptions"]["WebAuthnPrfOption"]["Transports"], json!(["internal"]));
        // Pre-existing fields are preserved.
        assert_eq!(response["UserDecryptionOptions"]["HasMasterPassword"], true);
    }

    #[test]
    fn webauthn_login_response_omits_singular_prf_option_when_credential_keyset_incomplete() {
        // PRF-capable but no keyset (Supported, not Enabled) → no field attached, matching
        // upstream's `GetPrfStatus() == Enabled` gate inside `WithWebAuthnLoginCredential`.
        let base = json!({
            "UserDecryptionOptions": { "HasMasterPassword": true, "Object": "userDecryptionOptions" }
        });
        let pk = passkey(None);
        let wac = make_credential(true, None, None, None, &serde_json::to_string(&pk).unwrap());

        let response = build_webauthn_login_response(base, &wac, &pk);

        assert!(response["UserDecryptionOptions"]["WebAuthnPrfOption"].is_null());
        // Untouched otherwise.
        assert_eq!(response["UserDecryptionOptions"]["HasMasterPassword"], true);
    }

    #[test]
    fn webauthn_login_response_is_noop_for_prf_unsupported_credential() {
        // Behavior: a credential whose authenticator doesn't support PRF (`supports_prf=false`)
        // must produce **zero modification** to the response — not a null field, not an empty
        // object, nothing. The function's contract is "only emit for Enabled". We assert by
        // comparing the whole response to the input.
        let base = json!({
            "UserDecryptionOptions": { "HasMasterPassword": true, "Object": "userDecryptionOptions" }
        });
        let pk = passkey(None);
        // supports_prf=false, even with all blobs present, should still not emit the option.
        let wac = make_credential(false, Some("uk"), Some("pk"), Some("priv"), &serde_json::to_string(&pk).unwrap());

        let response = build_webauthn_login_response(base.clone(), &wac, &pk);

        assert_eq!(response, base, "PRF-unsupported credential must produce no modification");
    }

    #[test]
    fn webauthn_login_response_lands_user_in_vault_for_prf_enabled_credential() {
        // End-to-end behaviour: after a passkey login with a PRF-enabled credential the
        // response must carry the wrapped-key payload the client combines with the PRF
        // secret from the just-completed assertion to recover the user key and unlock the
        // vault. Without it, the client authenticates successfully but lands on the lock
        // screen with an MP prompt — which is what triggered the original regression
        // report. Pins the contract upstream populates via `WithWebAuthnLoginCredential`.
        let base = json!({
            "UserDecryptionOptions": { "HasMasterPassword": false, "Object": "userDecryptionOptions" }
        });
        let pk = passkey(Some(vec![AuthenticatorTransport::Internal]));
        let wac = make_credential(true, Some("uk"), Some("pk"), Some("priv"), &serde_json::to_string(&pk).unwrap());

        let response = build_webauthn_login_response(base, &wac, &pk);
        let prf = &response["UserDecryptionOptions"]["WebAuthnPrfOption"];

        // All four fields must be present for the client to perform the unlock.
        assert!(prf.is_object(), "unlock payload must be an object, not null");
        assert!(prf["EncryptedPrivateKey"].as_str().is_some(), "EncryptedPrivateKey required");
        assert!(prf["EncryptedUserKey"].as_str().is_some(), "EncryptedUserKey required");
        assert!(prf["CredentialId"].as_str().is_some(), "CredentialId required");
        assert!(prf["Transports"].is_array(), "Transports required (may be empty)");
    }

    #[test]
    fn webauthn_login_response_is_idempotent_for_enabled_credential() {
        // Behavior: calling the augmentation twice on the same inputs produces an identical
        // response on each call. Pins that the function is pure (no accumulating side effects)
        // and that writing the same key twice doesn't change the structure.
        let base = json!({
            "UserDecryptionOptions": { "HasMasterPassword": true, "Object": "userDecryptionOptions" }
        });
        let pk = passkey(Some(vec![AuthenticatorTransport::Internal]));
        let wac = make_credential(true, Some("uk"), Some("pk"), Some("priv"), &serde_json::to_string(&pk).unwrap());

        let once = build_webauthn_login_response(base, &wac, &pk);
        let twice = build_webauthn_login_response(once.clone(), &wac, &pk);

        assert_eq!(once, twice, "idempotent application of the augmentation");
    }

    #[test]
    fn webauthn_login_prf_option_suppressed_when_credential_lacks_keyset() {
        // PRF-capable but no keyset (Supported status) → no singular emission, matching the
        // `GetPrfStatus() == Enabled` gate the original webauthn-login code already applied.
        let pk = passkey(None);
        let pk_blob = serde_json::to_string(&pk).unwrap();
        let supported_only = make_credential(true, None, None, None, &pk_blob);
        let unsupported = make_credential(false, Some("uk"), Some("pk"), Some("priv"), &pk_blob);
        let partial = make_credential(true, Some("uk"), Some("pk"), None, &pk_blob);

        assert!(build_webauthn_login_prf_option(&supported_only, &pk).is_none());
        assert!(build_webauthn_login_prf_option(&unsupported, &pk).is_none());
        assert!(build_webauthn_login_prf_option(&partial, &pk).is_none());
    }

    #[test]
    fn webauthn_prf_options_skips_corrupted_credential_blob() {
        // A row whose `credential` column was somehow corrupted should be silently dropped
        // rather than aborting the whole response — the lock screen should still surface the
        // healthy credentials.
        let pk = serde_json::to_string(&passkey(None)).unwrap();
        let creds = [
            make_credential(true, Some("uk-a"), Some("pk-a"), Some("priv-a"), "not-json"),
            make_credential(true, Some("uk-b"), Some("pk-b"), Some("priv-b"), &pk),
        ];
        let options = build_webauthn_prf_options(&creds);

        assert_eq!(options.len(), 1);
        assert_eq!(options[0]["EncryptedUserKey"], "uk-b");
    }
}
