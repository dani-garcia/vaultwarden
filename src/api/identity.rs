use chrono::Utc;
use jsonwebtoken::DecodingKey;
use num_traits::FromPrimitive;
use rocket::serde::json::Json;
use rocket::{
    form::{Form, FromForm},
    http::Status,
    response::Redirect,
    Route,
};
use serde_json::Value;
use std::iter::FromIterator;

use crate::{
    api::{
        core::accounts::{PreloginData, _prelogin},
        core::two_factor::{duo, email, email::EmailTokenData, yubikey},
        ApiResult, EmptyResult, JsonResult, JsonUpcase,
    },
    auth::ClientIp,
    db::{models::*, DbConn},
    error::MapResult,
    mail, util, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![login, prelogin, prevalidate, authorize]
}

#[post("/connect/token", data = "<data>")]
async fn login(data: Form<ConnectData>, conn: DbConn, ip: ClientIp) -> JsonResult {
    let data: ConnectData = data.into_inner();

    match data.grant_type.as_ref() {
        "refresh_token" => {
            _check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            _refresh_login(data, conn).await
        }
        "password" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.password, "password cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;
            _check_is_some(&data.username, "username cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _password_login(data, conn, &ip).await
        }
        "client_credentials" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.client_secret, "client_secret cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;

            _api_key_login(data, conn, &ip).await
        }
        "authorization_code" => {
            _check_is_some(&data.code, "code cannot be blank")?;
            _check_is_some(&data.org_identifier, "org_identifier cannot be blank")?;
            _check_is_some(&data.device_identifier, "device identifier cannot be blank")?;

            _authorization_login(data, conn, &ip).await
        }
        t => err!("Invalid type", t),
    }
}

async fn _refresh_login(data: ConnectData, conn: DbConn) -> JsonResult {
    // Extract token
    let token = data.refresh_token.unwrap();

    // Get device by refresh token
    let mut device = Device::find_by_refresh_token(&token, &conn).await.map_res("Invalid refresh token")?;

    let scope = "api offline_access";
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Common
    let user = User::find_by_uuid(&device.user_uuid, &conn).await.unwrap();
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn).await?;

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

#[derive(Debug, Serialize, Deserialize)]
struct TokenPayload {
    exp: i64,
    email: String,
    nonce: String,
}

async fn _authorization_login(data: ConnectData, conn: DbConn, ip: &ClientIp) -> JsonResult {
    let org_identifier = data.org_identifier.as_ref().unwrap();
    let code = data.code.as_ref().unwrap();

    let organization = Organization::find_by_identifier(org_identifier, &conn).await.unwrap();
    let sso_config = SsoConfig::find_by_org(&organization.uuid, &conn).await.unwrap();

    let (_access_token, refresh_token, id_token) = match get_auth_code_access_token(code, &sso_config).await {
        Ok((_access_token, refresh_token, id_token)) => (_access_token, refresh_token, id_token),
        Err(err) => err!(err),
    };

    // https://github.com/Keats/jsonwebtoken/issues/236#issuecomment-1093039195
    // let token = jsonwebtoken::decode::<TokenPayload>(access_token.as_str()).unwrap().claims;
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();

    let token = jsonwebtoken::decode::<TokenPayload>(id_token.as_str(), &DecodingKey::from_secret(&[]), &validation)
        .unwrap()
        .claims;

    // let expiry = token.exp;
    let nonce = token.nonce;

    match SsoNonce::find_by_org_and_nonce(&organization.uuid, &nonce, &conn).await {
        Some(sso_nonce) => {
            match sso_nonce.delete(&conn).await {
                Ok(_) => {
                    // let expiry = token.exp;
                    let user_email = token.email;
                    let now = Utc::now().naive_utc();

                    // COMMON
                    // TODO handle missing users, currently this will panic if the user does not exist!
                    let user = User::find_by_mail(&user_email, &conn).await.unwrap();

                    let (mut device, new_device) = get_device(&data, &conn, &user).await;

                    let twofactor_token = twofactor_auth(&user.uuid, &data, &mut device, ip, &conn).await?;

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

                    device.refresh_token = refresh_token.clone();
                    device.save(&conn).await?;

                    let scope_vec = vec!["api".into(), "offline_access".into()];
                    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn).await;
                    let (access_token_new, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
                    device.save(&conn).await?;

                    let mut result = json!({
                        "access_token": access_token_new,
                        "expires_in": expires_in,
                        "token_type": "Bearer",
                        "refresh_token": refresh_token,
                        "Key": user.akey,
                        "PrivateKey": user.private_key,

                        "Kdf": user.client_kdf_type,
                        "KdfIterations": user.client_kdf_iter,
                        "ResetMasterPassword": false, // TODO: according to official server seems something like: user.password_hash.is_empty(), but would need testing
                        "scope": "api offline_access",
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

async fn _password_login(data: ConnectData, conn: DbConn, ip: &ClientIp) -> JsonResult {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Get the user
    let username = data.username.as_ref().unwrap().trim();
    let user = match User::find_by_mail(username, &conn).await {
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

    // Check if org policy prevents password login
    let user_orgs = UserOrganization::find_by_user_and_policy(&user.uuid, OrgPolicyType::RequireSso, &conn).await;
    if !user_orgs.is_empty() && user_orgs[0].atype != UserOrgType::Owner && user_orgs[0].atype != UserOrgType::Admin {
        // if requires SSO is active, user is in exactly one org by policy rules
        // policy only applies to "non-owner/non-admin" members

        err!("Organization policy requires SSO sign in");
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

                if let Err(e) = user.save(&conn).await {
                    error!("Error updating user: {:#?}", e);
                }

                if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
                    error!("Error auto-sending email verification email: {:#?}", e);
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        err!("Please verify your email before trying again.", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    let (mut device, new_device) = get_device(&data, &conn, &user).await;

    let twofactor_token = twofactor_auth(&user.uuid, &data, &mut device, ip, &conn).await?;

    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn).await?;

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

async fn _api_key_login(data: ConnectData, conn: DbConn, ip: &ClientIp) -> JsonResult {
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
    let user = match User::find_by_uuid(user_uuid, &conn).await {
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

    let (mut device, new_device) = get_device(&data, &conn, &user).await;

    if CONFIG.mail_enabled() && new_device {
        let now = Utc::now().naive_utc();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, &ip.ip.to_string(), &now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.require_device_email() {
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let orgs = UserOrganization::find_confirmed_by_user(&user.uuid, &conn).await;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(&conn).await?;

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
async fn get_device(data: &ConnectData, conn: &DbConn, user: &User) -> (Device, bool) {
    // On iOS, device_type sends "iOS", on others it sends a number
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(0);
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
    conn: &DbConn,
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
        None => err_json!(_json_err_twofactor(&twofactor_ids, user_uuid, conn).await?, "2FA token not provided"),
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
        Some(TwoFactorType::YubiKey) => _tf::yubikey::validate_yubikey_login(twofactor_code, &selected_data?)?,
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
        _ => err!("Invalid two factor provider"),
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

async fn _json_err_twofactor(providers: &[i32], user_uuid: &str, conn: &DbConn) -> ApiResult<Value> {
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

    // Needed for authorization code
    code: Option<String>,
    org_identifier: Option<String>,
}

// TODO Might need to migrate this: https://github.com/SergioBenitez/Rocket/pull/1489#issuecomment-1114750006

fn _check_is_some<T>(value: &Option<T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

#[get("/account/prevalidate?<domainHint>")]
#[allow(non_snake_case)]
// The compiler warns about unreachable code here. But I've tested it, and it seems to work
// as expected. All errors appear to be reachable, as is the Ok response.
#[allow(unreachable_code)]
async fn prevalidate(domainHint: String, conn: DbConn) -> JsonResult {
    let empty_result = json!({});

    // TODO: fix panic on failig to retrive (no unwrap on null)
    let organization = Organization::find_by_identifier(&domainHint, &conn).await.unwrap();

    let sso_config = SsoConfig::find_by_org(&organization.uuid, &conn);
    match sso_config.await {
        Some(sso_config) => {
            if !sso_config.use_sso {
                return err_code!("SSO Not allowed for organization", Status::BadRequest.code);
            }
            if sso_config.authority.is_none() || sso_config.client_id.is_none() || sso_config.client_secret.is_none() {
                return err_code!("Organization is incorrectly configured for SSO", Status::BadRequest.code);
            }
        }
        None => {
            return err_code!("Unable to find sso config", Status::BadRequest.code);
        }
    }

    if domainHint.is_empty() {
        return err_code!("No Organization Identifier Provided", Status::BadRequest.code);
    }

    Ok(Json(empty_result))
}

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    RedirectUrl, Scope,
};

async fn get_client_from_sso_config(sso_config: &SsoConfig) -> Result<CoreClient, &'static str> {
    let redirect = sso_config.callback_path.clone();
    let client_id = ClientId::new(sso_config.client_id.as_ref().unwrap().to_string());
    let client_secret = ClientSecret::new(sso_config.client_secret.as_ref().unwrap().to_string());
    let issuer_url =
        IssuerUrl::new(sso_config.authority.as_ref().unwrap().to_string()).or(Err("invalid issuer URL"))?;

    // TODO: This comparison will fail if one URI has a trailing slash and the other one does not.
    // Should we remove trailing slashes when saving? Or when checking?
    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
        Ok(metadata) => metadata,
        Err(_err) => {
            return Err("Failed to discover OpenID provider");
        }
    };

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(RedirectUrl::new(redirect).or(Err("Invalid redirect URL"))?);

    Ok(client)
}

#[get("/connect/authorize?<domain_hint>&<state>")]
async fn authorize(domain_hint: String, state: String, conn: DbConn) -> ApiResult<Redirect> {
    let organization = Organization::find_by_identifier(&domain_hint, &conn).await.unwrap();
    let sso_config = SsoConfig::find_by_org(&organization.uuid, &conn).await.unwrap();

    match get_client_from_sso_config(&sso_config).await {
        Ok(client) => {
            let (mut authorize_url, _csrf_state, nonce) = client
                .authorize_url(
                    AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .url();

            let sso_nonce = SsoNonce::new(organization.uuid, nonce.secret().to_string());
            sso_nonce.save(&conn).await?;

            // it seems impossible to set the state going in dynamically (requires static lifetime string)
            // so I change it after the fact
            let old_pairs = authorize_url.query_pairs();
            let new_pairs = old_pairs.map(|pair| {
                let (key, value) = pair;
                if key == "state" {
                    return format!("{}={}", key, state);
                }
                format!("{}={}", key, value)
            });
            let full_query = Vec::from_iter(new_pairs).join("&");
            authorize_url.set_query(Some(full_query.as_str()));

            Ok(Redirect::to(authorize_url.to_string()))
        }
        Err(err) => err!("Unable to find client from identifier {}", err),
    }
}

async fn get_auth_code_access_token(
    code: &str,
    sso_config: &SsoConfig,
) -> Result<(String, String, String), &'static str> {
    let oidc_code = AuthorizationCode::new(String::from(code));
    match get_client_from_sso_config(sso_config).await {
        Ok(client) => match client.exchange_code(oidc_code).request_async(async_http_client).await {
            Ok(token_response) => {
                let access_token = token_response.access_token().secret().to_string();
                let refresh_token = token_response.refresh_token().unwrap().secret().to_string();
                let id_token = token_response.extra_fields().id_token().unwrap().to_string();
                Ok((access_token, refresh_token, id_token))
            }
            Err(_err) => Err("Failed to contact token endpoint"),
        },
        Err(_err) => Err("unable to find client"),
    }
}
