use chrono::Utc;
use num_traits::FromPrimitive;
use rocket::{
    request::{Form, FormItems, FromForm},
    Route,
};
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{
    api::{
        core::two_factor::{duo, email, email::EmailTokenData, yubikey},
        ApiResult, EmptyResult, JsonResult,
    },
    auth::ClientIp,
    db::{models::*, DbConn},
    error::MapResult,
    mail, util, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![login]
}

#[post("/connect/token", data = "<data>")]
fn login(data: Form<ConnectData>, conn: DbConn, ip: ClientIp) -> JsonResult {
    let data: ConnectData = data.into_inner();

    match data.grant_type.as_ref() {
        "refresh_token" => {
            _check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            _refresh_login(data, conn)
        }
        "password" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.password, "password cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;
            _check_is_some(&data.username, "username cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _password_login(data, conn, &ip)
        }
        "client_credentials" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.client_secret, "client_secret cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;

            _api_key_login(data, conn, &ip)
        }
        t => err!("Invalid type", t),
    }
}

fn _refresh_login(data: ConnectData, conn: DbConn) -> JsonResult {
    // Extract token
    let token = data.refresh_token.unwrap();

    // Get device by refresh token
    let mut device = Device::find_by_refresh_token(&token, &conn).map_res("Invalid refresh token")?;

    let scope = "api offline_access";
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Common
    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn);
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn)?;

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
        "scope": scope,
        "unofficialServer": true,
    })))
}

fn _password_login(data: ConnectData, conn: DbConn, ip: &ClientIp) -> JsonResult {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Get the user
    let username = data.username.as_ref().unwrap();
    let user = match User::find_by_mail(username, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username)),
    };

    // Check password
    let password = data.password.as_ref().unwrap();
    if !user.check_valid_password(password) {
        err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    // Check if the user is disabled
    if !user.enabled {
        err!("This user has been disabled", format!("IP: {}. Username: {}.", ip.ip, username))
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
                let mut user = user;
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(&conn) {
                    error!("Error updating user: {:#?}", e);
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid) {
                    error!("Error auto-sending email verification email: {:#?}", e);
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        err!("Please verify your email before trying again.", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    let (mut device, new_device) = get_device(&data, &conn, &user);

    let twofactor_token = twofactor_auth(&user.uuid, &data, &mut device, ip, &conn)?;

    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name) {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn);
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn)?;

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

fn _api_key_login(data: ConnectData, conn: DbConn, ip: &ClientIp) -> JsonResult {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api" {
        err!("Scope not supported")
    }
    let scope_vec = vec!["api".into()];

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Get the user via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let user_uuid = match client_id.strip_prefix("user.") {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let user = match User::find_by_uuid(user_uuid, &conn) {
        Some(user) => user,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Check if the user is disabled
    if !user.enabled {
        err!("This user has been disabled (API key login)", format!("IP: {}. Username: {}.", ip.ip, user.email))
    }

    // Check API key. Note that API key logins bypass 2FA.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !user.check_valid_api_key(client_secret) {
        err!("Incorrect client_secret", format!("IP: {}. Username: {}.", ip.ip, user.email))
    }

    let (mut device, new_device) = get_device(&data, &conn, &user);

    if CONFIG.mail_enabled() && new_device {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name) {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn);
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn)?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    // Note: No refresh_token is returned. The CLI just repeats the
    // client_credentials login flow when the existing token expires.
    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "Key": user.akey,
        "PrivateKey": user.private_key,

        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "ResetMasterPassword": false, // TODO: Same as above
        "scope": scope,
        "unofficialServer": true,
    })))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
fn get_device(data: &ConnectData, conn: &DbConn, user: &User) -> (Device, bool) {
    // On iOS, device_type sends "iOS", on others it sends a number
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(0);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    let mut new_device = false;
    // Find device or create new
    let device = match Device::find_by_uuid(&device_id, conn) {
        Some(device) => {
            // Check if owned device, and recreate if not
            if device.user_uuid != user.uuid {
                info!("Device exists but is owned by another user. The old device will be discarded");
                new_device = true;
                Device::new(device_id, user.uuid.clone(), device_name, device_type)
            } else {
                device
            }
        }
        None => {
            new_device = true;
            Device::new(device_id, user.uuid.clone(), device_name, device_type)
        }
    };

    (device, new_device)
}

fn twofactor_auth(
    user_uuid: &str,
    data: &ConnectData,
    device: &mut Device,
    ip: &ClientIp,
    conn: &DbConn,
) -> ApiResult<Option<String>> {
    let twofactors = TwoFactor::find_by_user(user_uuid, conn);

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        return Ok(None);
    }

    TwoFactorIncomplete::mark_incomplete(user_uuid, &device.uuid, &device.name, ip, conn)?;

    let twofactor_ids: Vec<_> = twofactors.iter().map(|tf| tf.atype).collect();
    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, asume the first one

    let twofactor_code = match data.two_factor_token {
        Some(ref code) => code,
        None => err_json!(_json_err_twofactor(&twofactor_ids, user_uuid, conn)?, "2FA token not provided"),
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    use crate::api::core::two_factor as _tf;
    use crate::crypto::ct_eq;

    let selected_data = _selected_data(selected_twofactor);
    let mut remember = data.two_factor_remember.unwrap_or(0);

    match TwoFactorType::from_i32(selected_id) {
        Some(TwoFactorType::Authenticator) => {
            _tf::authenticator::validate_totp_code_str(user_uuid, twofactor_code, &selected_data?, ip, conn)?
        }
        Some(TwoFactorType::U2f) => _tf::u2f::validate_u2f_login(user_uuid, twofactor_code, conn)?,
        Some(TwoFactorType::Webauthn) => _tf::webauthn::validate_webauthn_login(user_uuid, twofactor_code, conn)?,
        Some(TwoFactorType::YubiKey) => _tf::yubikey::validate_yubikey_login(twofactor_code, &selected_data?)?,
        Some(TwoFactorType::Duo) => {
            _tf::duo::validate_duo_login(data.username.as_ref().unwrap(), twofactor_code, conn)?
        }
        Some(TwoFactorType::Email) => {
            _tf::email::validate_email_code_str(user_uuid, twofactor_code, &selected_data?, conn)?
        }

        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                Some(ref code) if !CONFIG.disable_2fa_remember() && ct_eq(code, twofactor_code) => {
                    remember = 1; // Make sure we also return the token here, otherwise it will only remember the first time
                }
                _ => {
                    err_json!(_json_err_twofactor(&twofactor_ids, user_uuid, conn)?, "2FA Remember token not provided")
                }
            }
        }
        _ => err!("Invalid two factor provider"),
    }

    TwoFactorIncomplete::mark_complete(user_uuid, &device.uuid, conn)?;

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

fn _json_err_twofactor(providers: &[i32], user_uuid: &str, conn: &DbConn) -> ApiResult<Value> {
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

            Some(TwoFactorType::U2f) if CONFIG.domain_set() => {
                let request = two_factor::u2f::generate_u2f_login(user_uuid, conn)?;
                let mut challenge_list = Vec::new();

                for key in request.registered_keys {
                    challenge_list.push(json!({
                        "appId": request.app_id,
                        "challenge": request.challenge,
                        "version": key.version,
                        "keyHandle": key.key_handle,
                    }));
                }

                let challenge_list_str = serde_json::to_string(&challenge_list).unwrap();

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Challenges": challenge_list_str,
                });
            }

            Some(TwoFactorType::Webauthn) if CONFIG.domain_set() => {
                let request = two_factor::webauthn::generate_webauthn_login(user_uuid, conn)?;
                result["TwoFactorProviders2"][provider.to_string()] = request.0;
            }

            Some(TwoFactorType::Duo) => {
                let email = match User::find_by_uuid(user_uuid, conn) {
                    Some(u) => u.email,
                    None => err!("User does not exist"),
                };

                let (signature, host) = duo::generate_duo_signature(&email, conn)?;

                result["TwoFactorProviders2"][provider.to_string()] = json!({
                    "Host": host,
                    "Signature": signature,
                });
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn) {
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

                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, conn) {
                    Some(tf) => tf,
                    None => err!("No twofactor email registered"),
                };

                // Send email immediately if email is the only 2FA option
                if providers.len() == 1 {
                    _tf::email::send_token(user_uuid, conn)?
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

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default)]
#[allow(non_snake_case)]
struct ConnectData {
    // refresh_token, password, client_credentials (API key)
    grant_type: String,

    // Needed for grant_type="refresh_token"
    refresh_token: Option<String>,

    // Needed for grant_type = "password" | "client_credentials"
    client_id: Option<String>,     // web, cli, desktop, browser, mobile
    client_secret: Option<String>, // API key login (cli only)
    password: Option<String>,
    scope: Option<String>,
    username: Option<String>,

    device_identifier: Option<String>,
    device_name: Option<String>,
    device_type: Option<String>,
    device_push_token: Option<String>, // Unused; mobile device push not yet supported.

    // Needed for two-factor auth
    two_factor_provider: Option<i32>,
    two_factor_token: Option<String>,
    two_factor_remember: Option<i32>,
}

impl<'f> FromForm<'f> for ConnectData {
    type Error = String;

    fn from_form(items: &mut FormItems<'f>, _strict: bool) -> Result<Self, Self::Error> {
        let mut form = Self::default();
        for item in items {
            let (key, value) = item.key_value_decoded();
            let mut normalized_key = key.to_lowercase();
            normalized_key.retain(|c| c != '_'); // Remove '_'

            match normalized_key.as_ref() {
                "granttype" => form.grant_type = value,
                "refreshtoken" => form.refresh_token = Some(value),
                "clientid" => form.client_id = Some(value),
                "clientsecret" => form.client_secret = Some(value),
                "password" => form.password = Some(value),
                "scope" => form.scope = Some(value),
                "username" => form.username = Some(value),
                "deviceidentifier" => form.device_identifier = Some(value),
                "devicename" => form.device_name = Some(value),
                "devicetype" => form.device_type = Some(value),
                "devicepushtoken" => form.device_push_token = Some(value),
                "twofactorprovider" => form.two_factor_provider = value.parse().ok(),
                "twofactortoken" => form.two_factor_token = Some(value),
                "twofactorremember" => form.two_factor_remember = value.parse().ok(),
                key => warn!("Detected unexpected parameter during login: {}", key),
            }
        }

        Ok(form)
    }
}

fn _check_is_some<T>(value: &Option<T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}
