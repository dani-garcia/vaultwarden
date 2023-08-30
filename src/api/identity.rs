use chrono::Utc;
use jsonwebtoken::DecodingKey;
use num_traits::FromPrimitive;
use rocket::serde::json::Json;
use rocket::{
    form::{Form, FromForm},
    http::CookieJar,
    Route,
};
use serde_json::Value;

use crate::{
    api::{
        core::accounts::{PreloginData, RegisterData, _prelogin, _register},
        core::log_user_event,
        core::two_factor::{duo, email, email::EmailTokenData, yubikey},
        ApiResult, EmptyResult, JsonResult, JsonUpcase,
    },
    auth::{encode_jwt, generate_organization_api_key_login_claims, generate_ssotoken_claims, ClientHeaders, ClientIp},
    db::{models::*, DbConn},
    error::MapResult,
    mail, util,
    util::{CookieManager, CustomRedirect},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![login, prelogin, identity_register, prevalidate, authorize, oidcsignin]
}

#[post("/connect/token", data = "<data>")]
async fn login(data: Form<ConnectData>, client_header: ClientHeaders, mut conn: DbConn) -> JsonResult {
    let data: ConnectData = data.into_inner();

    let mut user_uuid: Option<String> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            _check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            _refresh_login(data, &mut conn).await
        }
        "password" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.password, "password cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;
            _check_is_some(&data.username, "username cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _password_login(data, &mut user_uuid, &mut conn, &client_header.ip).await
        }
        "client_credentials" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.client_secret, "client_secret cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _api_key_login(data, &mut user_uuid, &mut conn, &client_header.ip).await
        }
        "authorization_code" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.code, "code cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;
            _authorization_login(data, &mut user_uuid, &mut conn, &client_header.ip).await
        }
        t => err!("Invalid type", t),
    };

    if let Some(user_uuid) = user_uuid {
        match &login_result {
            Ok(_) => {
                log_user_event(
                    EventType::UserLoggedIn as i32,
                    &user_uuid,
                    client_header.device_type,
                    &client_header.ip.ip,
                    &mut conn,
                )
                .await;
            }
            Err(e) => {
                if let Some(ev) = e.get_event() {
                    log_user_event(
                        ev.event as i32,
                        &user_uuid,
                        client_header.device_type,
                        &client_header.ip.ip,
                        &mut conn,
                    )
                    .await
                }
            }
        }
    }

    login_result
}

async fn _refresh_login(data: ConnectData, conn: &mut DbConn) -> JsonResult {
    // Extract token
    let token = data.refresh_token.unwrap();

    // Get device by refresh token
    let mut device = Device::find_by_refresh_token(&token, conn).await.map_res("Invalid refresh token")?;

    let scope = "api offline_access";
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Common
    let user = User::find_by_uuid(&device.user_uuid, conn).await.unwrap();
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    let result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
        "scope": scope,
        "unofficialServer": true,
    });

    Ok(Json(result))
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenPayload {
    exp: i64,
    email: Option<String>,
    nonce: String,
}

async fn _authorization_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    let scope = match data.scope.as_ref() {
        None => err!("Got no scope in OIDC data"),
        Some(scope) => scope,
    };
    if scope != "api offline_access" {
        err!("Scope not supported")
    }

    let scope_vec = vec!["api".into(), "offline_access".into()];
    let code = match data.code.as_ref() {
        None => err!("Got no code in OIDC data"),
        Some(code) => code,
    };

    let (refresh_token, id_token, user_info) = match get_auth_code_access_token(code).await {
        Ok((refresh_token, id_token, user_info)) => (refresh_token, id_token, user_info),
        Err(_err) => err!("Could not retrieve access token"),
    };

    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let token =
        match jsonwebtoken::decode::<TokenPayload>(id_token.as_str(), &DecodingKey::from_secret(&[]), &validation) {
            Err(_err) => err!("Could not decode id token"),
            Ok(payload) => payload.claims,
        };

    // let expiry = token.exp;
    let nonce = token.nonce;
    let mut new_user = false;

    match SsoNonce::find(&nonce, conn).await {
        Some(sso_nonce) => {
            match sso_nonce.delete(conn).await {
                Ok(_) => {
                    let user_email = match token.email {
                        Some(email) => email,
                        None => match user_info.email() {
                            None => err!("Neither id token nor userinfo contained an email"),
                            Some(email) => email.to_owned().to_string(),
                        },
                    };
                    let now = Utc::now().naive_utc();

                    let mut user = match User::find_by_mail(&user_email, conn).await {
                        Some(user) => user,
                        None => {
                            new_user = true;
                            User::new(user_email.clone())
                        }
                    };

                    if new_user {
                        user.verified_at = Some(Utc::now().naive_utc());
                        user.save(conn).await?;
                    }

                    // Set the user_uuid here to be passed back used for event logging.
                    *user_uuid = Some(user.uuid.clone());

                    let (mut device, new_device) = get_device(&data, conn, &user).await;

                    let twofactor_token = twofactor_auth(&user.uuid, &data, &mut device, ip, true, conn).await?;

                    if CONFIG.mail_enabled() && new_device {
                        if let Err(e) =
                            mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await
                        {
                            error!("Error sending new device email: {:#?}", e);

                            if CONFIG.require_device_email() {
                                err!("Could not send login notification email. Please contact your administrator.")
                            }
                        }
                    }

                    if CONFIG.sso_acceptall_invites() {
                        for user_org in UserOrganization::find_invited_by_user(&user.uuid, conn).await.iter_mut() {
                            user_org.status = UserOrgStatus::Accepted as i32;
                            user_org.save(conn).await?;
                        }
                    }

                    device.refresh_token = refresh_token.clone();
                    device.save(conn).await?;

                    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
                    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
                    device.save(conn).await?;

                    let mut result = json!({
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "refresh_token": device.refresh_token,
                        "expires_in": expires_in,
                        "Key": user.akey,
                        "PrivateKey": user.private_key,
                        "Kdf": user.client_kdf_type,
                        "KdfIterations": user.client_kdf_iter,
                        "KdfMemory": user.client_kdf_memory,
                        "KdfParallelism": user.client_kdf_parallelism,
                        "ResetMasterPassword": user.password_hash.is_empty(),
                        "scope": scope,
                        "unofficialServer": true,
                    });

                    if let Some(token) = twofactor_token {
                        result["TwoFactorToken"] = Value::String(token);
                    }

                    info!("User {} logged in successfully. IP: {}", user.email, ip.ip);
                    Ok(Json(result))
                }
                Err(_) => err!("Failed to delete nonce"),
            }
        }
        None => {
            err!("Invalid nonce")
        }
    }
}

async fn _password_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    if CONFIG.sso_enabled() && CONFIG.sso_only() {
        err!("SSO sign-in is required");
    }

    // Get the user
    let username = data.username.as_ref().unwrap().trim();
    let mut user = match User::find_by_mail(username, conn).await {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

    // Check password
    let password = data.password.as_ref().unwrap();
    if let Some(auth_request_uuid) = data.auth_request.clone() {
        if let Some(auth_request) = AuthRequest::find_by_uuid(auth_request_uuid.as_str(), conn).await {
            if !auth_request.check_access_code(password) {
                err!(
                    "Username or access code is incorrect. Try again",
                    format!("IP: {}. Username: {}.", ip.ip, username),
                    ErrorEvent {
                        event: EventType::UserFailedLogIn,
                    }
                )
            }
        } else {
            err!(
                "Auth request not found. Try again.",
                format!("IP: {}. Username: {}.", ip.ip, username),
                ErrorEvent {
                    event: EventType::UserFailedLogIn,
                }
            )
        }
    } else if !user.check_valid_password(password) {
        err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn,
            }
        )
    }

    // Change the KDF Iterations
    if user.password_iterations != CONFIG.password_iterations() {
        user.password_iterations = CONFIG.password_iterations();
        user.set_password(password, None, false, None);

        if let Err(e) = user.save(conn).await {
            error!("Error updating user: {:#?}", e);
        }
    }

    // Check if the user is disabled
    if !user.enabled {
        err!(
            "This user has been disabled",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let now = Utc::now().naive_utc();

    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.signups_verify() {
        if user.last_verifying_at.is_none()
            || now.signed_duration_since(user.last_verifying_at.unwrap()).num_seconds()
                > CONFIG.signups_verify_resend_time() as i64
        {
            let resend_limit = CONFIG.signups_verify_resend_limit() as i32;
            if resend_limit == 0 || user.login_verify_count < resend_limit {
                // We want to send another email verification if we require signups to verify
                // their email address, and we haven't sent them a reminder in a while...
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(conn).await {
                    error!("Error updating user: {:#?}", e);
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
                    error!("Error auto-sending email verification email: {:#?}", e);
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        err!(
            "Please verify your email before trying again.",
            format!("IP: {}. Username: {}.", ip.ip, username),
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    let (mut device, new_device) = get_device(&data, conn, &user).await;

    let twofactor_token = twofactor_auth(&user.uuid, &data, &mut device, ip, false, conn).await?;

    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

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

    // Common
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    let mut result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.akey,
        "PrivateKey": user.private_key,
        //"TwoFactorToken": "11122233333444555666777888999"

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false,// TODO: Same as above
        "scope": scope,
        "unofficialServer": true,
    });

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", username, ip.ip);
    Ok(Json(result))
}

async fn _api_key_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Validate scope
    match data.scope.as_ref().unwrap().as_ref() {
        "api" => _user_api_key_login(data, user_uuid, conn, ip).await,
        "api.organization" => _organization_api_key_login(data, conn, ip).await,
        _ => err!("Scope not supported"),
    }
}

async fn _user_api_key_login(
    data: ConnectData,
    user_uuid: &mut Option<String>,
    conn: &mut DbConn,
    ip: &ClientIp,
) -> JsonResult {
    // Get the user via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let client_user_uuid = match client_id.strip_prefix("user.") {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let user = match User::find_by_uuid(client_user_uuid, conn).await {
        Some(user) => user,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

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

    let (mut device, new_device) = get_device(&data, conn, &user).await;

    if CONFIG.mail_enabled() && new_device {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

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

    // Common
    let scope_vec = vec!["api".into()];
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    // Note: No refresh_token is returned. The CLI just repeats the
    // client_credentials login flow when the existing token expires.
    let result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false, // TODO: Same as above
        "scope": "api",
        "unofficialServer": true,
    });

    Ok(Json(result))
}

async fn _organization_api_key_login(data: ConnectData, conn: &mut DbConn, ip: &ClientIp) -> JsonResult {
    // Get the org via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let org_uuid = match client_id.strip_prefix("organization.") {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let org_api_key = match OrganizationApiKey::find_by_org_uuid(org_uuid, conn).await {
        Some(org_api_key) => org_api_key,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Check API key.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !org_api_key.check_valid_api_key(client_secret) {
        err!("Incorrect client_secret", format!("IP: {}. Organization: {}.", ip.ip, org_api_key.org_uuid))
    }

    let claim = generate_organization_api_key_login_claims(org_api_key.uuid, org_api_key.org_uuid);
    let access_token = crate::auth::encode_jwt(&claim);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "api.organization",
        "unofficialServer": true,
    })))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
async fn get_device(data: &ConnectData, conn: &mut DbConn, user: &User) -> (Device, bool) {
    // On iOS, device_type sends "iOS", on others it sends a number
    // When unknown or unable to parse, return 14, which is 'Unknown Browser'
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(14);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    let mut new_device = false;
    // Find device or create new
    let device = match Device::find_by_uuid_and_user(&device_id, &user.uuid, conn).await {
        Some(device) => device,
        None => {
            new_device = true;
            Device::new(device_id, user.uuid.clone(), device_name, device_type)
        }
    };

    (device, new_device)
}

async fn twofactor_auth(
    user_uuid: &str,
    data: &ConnectData,
    device: &mut Device,
    ip: &ClientIp,
    is_sso: bool,
    conn: &mut DbConn,
) -> ApiResult<Option<String>> {
    let twofactors = TwoFactor::find_by_user(user_uuid, conn).await;

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        return Ok(None);
    }

    TwoFactorIncomplete::mark_incomplete(user_uuid, &device.uuid, &device.name, ip, conn).await?;

    let twofactor_ids: Vec<_> = twofactors.iter().map(|tf| tf.atype).collect();
    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, asume the first one

    let twofactor_code = match data.two_factor_token {
        Some(ref code) => code,
        None => {
            if is_sso {
                if CONFIG.sso_only() {
                    err!("2FA not supported with SSO login, contact your administrator");
                } else {
                    err!("2FA not supported with SSO login, log in directly using email and master password");
                }
            } else {
                err_json!(_json_err_twofactor(&twofactor_ids, user_uuid, conn).await?, "2FA token not provided");
            }
        }
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    use crate::api::core::two_factor as _tf;
    use crate::crypto::ct_eq;

    let selected_data = _selected_data(selected_twofactor);
    let mut remember = data.two_factor_remember.unwrap_or(0);

    match TwoFactorType::from_i32(selected_id) {
        Some(TwoFactorType::Authenticator) => {
            _tf::authenticator::validate_totp_code_str(user_uuid, twofactor_code, &selected_data?, ip, conn).await?
        }
        Some(TwoFactorType::Webauthn) => {
            _tf::webauthn::validate_webauthn_login(user_uuid, twofactor_code, conn).await?
        }
        Some(TwoFactorType::YubiKey) => _tf::yubikey::validate_yubikey_login(twofactor_code, &selected_data?).await?,
        Some(TwoFactorType::Duo) => {
            _tf::duo::validate_duo_login(data.username.as_ref().unwrap().trim(), twofactor_code, conn).await?
        }
        Some(TwoFactorType::Email) => {
            _tf::email::validate_email_code_str(user_uuid, twofactor_code, &selected_data?, conn).await?
        }

        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                Some(ref code) if !CONFIG.disable_2fa_remember() && ct_eq(code, twofactor_code) => {
                    remember = 1; // Make sure we also return the token here, otherwise it will only remember the first time
                }
                _ => {
                    err_json!(
                        _json_err_twofactor(&twofactor_ids, user_uuid, conn).await?,
                        "2FA Remember token not provided"
                    )
                }
            }
        }
        _ => err!(
            "Invalid two factor provider",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        ),
    }

    TwoFactorIncomplete::mark_complete(user_uuid, &device.uuid, conn).await?;

    if !CONFIG.disable_2fa_remember() && remember == 1 {
        Ok(Some(device.refresh_twofactor_remember()))
    } else {
        device.delete_twofactor_remember();
        Ok(None)
    }
}

fn _selected_data(tf: Option<TwoFactor>) -> ApiResult<String> {
    tf.map(|t| t.data).map_res("Two factor doesn't exist")
}

async fn _json_err_twofactor(providers: &[i32], user_uuid: &str, conn: &mut DbConn) -> ApiResult<Value> {
    use crate::api::core::two_factor;

    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers,
        "TwoFactorProviders2" : {} // { "0" : null }
    });

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;

        match TwoFactorType::from_i32(*provider) {
            Some(TwoFactorType::Authenticator) => { /* Nothing to do for TOTP */ }

            Some(TwoFactorType::Webauthn) if CONFIG.domain_set() => {
                let request = two_factor::webauthn::generate_webauthn_login(user_uuid, conn).await?;
                result["TwoFactorProviders2"][provider.to_string()] = request.0;
            }

            Some(TwoFactorType::Duo) => {
                let email = match User::find_by_uuid(user_uuid, conn).await {
                    Some(u) => u.email,
                    None => err!("User does not exist"),
                };

                let (signature, host) = duo::generate_duo_signature(&email, conn).await?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Host": host,
                    "Signature": signature,
                });
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn).await {
                    Some(tf) => tf,
                    None => err!("No YubiKey devices registered"),
                };

                let yubikey_metadata: yubikey::YubikeyMetadata = serde_json::from_str(&twofactor.data)?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Nfc": yubikey_metadata.Nfc,
                })
            }

            Some(tf_type @ TwoFactorType::Email) => {
                use crate::api::core::two_factor as _tf;

                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn).await {
                    Some(tf) => tf,
                    None => err!("No twofactor email registered"),
                };

                // Send email immediately if email is the only 2FA option
                if providers.len() == 1 {
                    _tf::email::send_token(user_uuid, conn).await?
                }

                let email_data = EmailTokenData::from_json(&twofactor.data)?;
                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Email": email::obscure_email(&email_data.email),
                })
            }

            _ => {}
        }
    }

    Ok(result)
}

#[post("/accounts/prelogin", data = "<data>")]
async fn prelogin(data: JsonUpcase<PreloginData>, conn: DbConn) -> Json<Value> {
    _prelogin(data, conn).await
}

#[post("/accounts/register", data = "<data>")]
async fn identity_register(data: JsonUpcase<RegisterData>, conn: DbConn) -> JsonResult {
    _register(data, conn).await
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, FromForm)]
#[allow(non_snake_case)]
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
    device_identifier: Option<String>,
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
    auth_request: Option<String>,
    // Needed for authorization code
    #[form(field = uncased("code"))]
    code: Option<String>,
}
fn _check_is_some<T>(value: &Option<T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

#[get("/account/prevalidate")]
#[allow(non_snake_case)]
fn prevalidate() -> JsonResult {
    let claims = generate_ssotoken_claims();
    let ssotoken = encode_jwt(&claims);
    Ok(Json(json!({
        "token": ssotoken,
    })))
}

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    RedirectUrl, Scope,
};

async fn get_client_from_sso_config() -> ApiResult<CoreClient> {
    let redirect = CONFIG.sso_callback_path();
    let client_id = ClientId::new(CONFIG.sso_client_id());
    let client_secret = ClientSecret::new(CONFIG.sso_client_secret());
    let issuer_url = match IssuerUrl::new(CONFIG.sso_authority()) {
        Ok(issuer) => issuer,
        Err(_err) => err!("invalid issuer URL"),
    };

    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
        Ok(metadata) => metadata,
        Err(_err) => {
            err!("Failed to discover OpenID provider")
        }
    };

    let redirect_uri = match RedirectUrl::new(redirect) {
        Ok(uri) => uri,
        Err(err) => err!("Invalid redirection url: {}", err.to_string()),
    };
    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(redirect_uri);

    Ok(client)
}

#[get("/connect/oidc-signin?<code>")]
fn oidcsignin(code: String, jar: &CookieJar<'_>, _conn: DbConn) -> ApiResult<CustomRedirect> {
    let cookiemanager = CookieManager::new(jar);

    let redirect_uri = match cookiemanager.get_cookie("redirect_uri".to_string()) {
        None => err!("No redirect_uri in cookie"),
        Some(uri) => uri,
    };
    let orig_state = match cookiemanager.get_cookie("state".to_string()) {
        None => err!("No state in cookie"),
        Some(state) => state,
    };

    cookiemanager.delete_cookie("redirect_uri".to_string());
    cookiemanager.delete_cookie("state".to_string());

    let redirect = CustomRedirect {
        url: format!("{redirect_uri}?code={code}&state={orig_state}"),
        headers: vec![],
    };

    Ok(redirect)
}

#[derive(FromForm)]
#[allow(non_snake_case)]
struct AuthorizeData {
    #[allow(unused)]
    #[field(name = uncased("client_id"))]
    #[field(name = uncased("clientid"))]
    client_id: Option<String>,
    #[field(name = uncased("redirect_uri"))]
    #[field(name = uncased("redirecturi"))]
    redirect_uri: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("response_type"))]
    #[field(name = uncased("responsetype"))]
    response_type: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("scope"))]
    scope: Option<String>,
    #[field(name = uncased("state"))]
    state: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("code_challenge"))]
    code_challenge: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("code_challenge_method"))]
    code_challenge_method: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("response_mode"))]
    response_mode: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("domain_hint"))]
    domain_hint: Option<String>,
    #[allow(unused)]
    #[field(name = uncased("ssoToken"))]
    ssoToken: Option<String>,
}

#[get("/connect/authorize?<data..>")]
async fn authorize(data: AuthorizeData, jar: &CookieJar<'_>, mut conn: DbConn) -> ApiResult<CustomRedirect> {
    let cookiemanager = CookieManager::new(jar);
    match get_client_from_sso_config().await {
        Ok(client) => {
            let (auth_url, _csrf_state, nonce) = client
                .authorize_url(
                    AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .url();

            let sso_nonce = SsoNonce::new(nonce.secret().to_string());
            sso_nonce.save(&mut conn).await?;

            let redirect_uri = match data.redirect_uri {
                None => err!("No redirect_uri in data"),
                Some(uri) => uri,
            };
            cookiemanager.set_cookie("redirect_uri".to_string(), redirect_uri);
            let state = match data.state {
                None => err!("No state in data"),
                Some(state) => state,
            };
            cookiemanager.set_cookie("state".to_string(), state);

            let redirect = CustomRedirect {
                url: format!("{}", auth_url),
                headers: vec![],
            };

            Ok(redirect)
        }
        Err(_err) => err!("Unable to find client from identifier"),
    }
}

async fn get_auth_code_access_token(code: &str) -> ApiResult<(String, String, CoreUserInfoClaims)> {
    let oidc_code = AuthorizationCode::new(String::from(code));
    match get_client_from_sso_config().await {
        Ok(client) => match client.exchange_code(oidc_code).request_async(async_http_client).await {
            Ok(token_response) => {
                let refresh_token = match token_response.refresh_token() {
                    Some(token) => token.secret().to_string(),
                    None => String::new(),
                };
                let id_token = match token_response.extra_fields().id_token() {
                    None => err!("Token response did not contain an id_token"),
                    Some(token) => token.to_string(),
                };

                let user_info: CoreUserInfoClaims =
                    match client.user_info(token_response.access_token().to_owned(), None) {
                        Err(_err) => err!("Token response did not contain user_info"),
                        Ok(info) => match info.request_async(async_http_client).await {
                            Err(_err) => err!("Request to user_info endpoint failed"),
                            Ok(claim) => claim,
                        },
                    };

                Ok((refresh_token, id_token, user_info))
            }
            Err(err) => err!("Failed to contact token endpoint: {}", err.to_string()),
        },
        Err(_err) => err!("Unable to find client"),
    }
}
