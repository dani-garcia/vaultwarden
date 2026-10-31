use chrono::{DateTime, TimeDelta, Utc};
use rocket::{Route, serde::json::Json};

use crate::{
    CONFIG,
    api::{
        EmptyResult, JsonResult, PasswordOrOtpData,
        core::{
            log_user_event,
            two_factor::{VerificationTokenData, generate_recover_code},
        },
    },
    auth::{ClientHeaders, Headers, two_factor},
    crypto,
    db::{
        DbConn,
        models::{
            AuthRequest, AuthRequestId, DeviceId, EventType, TwoFactor, TwoFactorIncomplete, TwoFactorType, User,
            UserId,
        },
    },
    error::{Error, MapResult},
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![get_email, send_email_login, send_email, email, disable_email]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailLoginData {
    #[serde(alias = "DeviceIdentifier")]
    device_identifier: Option<DeviceId>,
    #[serde(alias = "Email")]
    email: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    auth_request_id: Option<AuthRequestId>,
    auth_request_access_code: Option<String>,
}

/// User is trying to login and wants to use email 2FA.
/// Does not require Bearer token
#[post("/two-factor/send-email-login", data = "<data>")] // JsonResult
async fn send_email_login(data: Json<SendEmailLoginData>, client_headers: ClientHeaders, conn: DbConn) -> EmptyResult {
    let data: SendEmailLoginData = data.into_inner();

    if !CONFIG._enable_email_2fa() {
        err!(crate::i18n::two_factor_email_disabled(&client_headers.locale))
    }

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&client_headers.ip.ip)?;

    // Get the user
    let email = match &data.email {
        Some(email) if !email.is_empty() => Some(email),
        _ => None,
    };
    let master_password_hash = match &data.master_password_hash {
        Some(password_hash) if !password_hash.is_empty() => Some(password_hash),
        _ => None,
    };
    let auth_request_id = match &data.auth_request_id {
        Some(auth_request_id) if !auth_request_id.is_empty() => Some(auth_request_id),
        _ => None,
    };

    let user = if let Some(email) = email {
        let Some(user) = User::find_by_mail(email, &conn).await else {
            err!(
                "Username or password is incorrect. Try again",
                format!("IP: {}. Username: {}.", client_headers.ip.ip, email.escape_debug())
            )
        };

        if let Some(master_password_hash) = master_password_hash {
            // Check password
            if !user.check_valid_password(master_password_hash) {
                err!(
                    "Username or password is incorrect. Try again",
                    format!("IP: {}. Username: {}.", client_headers.ip.ip, email.escape_debug())
                )
            }
        } else if let Some(auth_request_id) = auth_request_id {
            let Some(auth_request) = AuthRequest::find_by_uuid(auth_request_id, &conn).await else {
                err!(
                    crate::i18n::two_factor_auth_request_not_found(&client_headers.locale),
                    crate::i18n::two_factor_user_not_found(&client_headers.locale)
                )
            };
            let Some(code) = &data.auth_request_access_code else {
                err!(crate::i18n::two_factor_no_auth_request_access_code(&client_headers.locale))
            };

            if auth_request.device_type != client_headers.device_type
                || auth_request.request_ip != client_headers.ip.ip.to_string()
                || !auth_request.check_access_code(code)
            {
                err!(
                    crate::i18n::two_factor_auth_request_not_found(&client_headers.locale),
                    crate::i18n::two_factor_invalid_device_ip_or_code(&client_headers.locale)
                )
            }
        } else if let Some(device_identifier) = &data.device_identifier {
            // iOS/Android SSO logins send the email and device id but no password hash,
            // so accept a device that has a pending 2FA login for this user
            if TwoFactorIncomplete::find_by_user_and_device(&user.uuid, device_identifier, &conn).await.is_none() {
                err!(
                    "Username or password is incorrect. Try again",
                    format!("IP: {}. Username: {}.", client_headers.ip.ip, email.escape_debug())
                )
            }
            debug!(
                "Email 2FA fallback: pending login. Username: {}. Device: {}.",
                user.email,
                device_identifier.to_string().escape_debug()
            );
        } else {
            err!(crate::i18n::two_factor_no_password_hash_submitted(&client_headers.locale))
        }

        user
    } else {
        let Some(device_identifier) = &data.device_identifier else {
            err!(crate::i18n::two_factor_no_device_identifier_submitted(&client_headers.locale))
        };
        // SSO login only sends device id, so we get the user by the most recently used device
        let Some(user) = User::find_by_device_for_email2fa(device_identifier, &conn).await else {
            err!(
                "Username or password is incorrect. Try again",
                format!("IP: {}. Device: {}.", client_headers.ip.ip, device_identifier.to_string().escape_debug())
            )
        };

        user
    };

    send_token(&user.uuid, &conn, Some(&client_headers.locale)).await
}

/// Generate the token, save the data for later verification and send email to user
pub async fn send_token(user_id: &UserId, conn: &DbConn, locale: Option<&str>) -> EmptyResult {
    let default_locale = CONFIG.default_locale();
    let locale = locale.unwrap_or(default_locale.as_str());
    let mut twofactor = TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Email, conn)
        .await
        .map_res(crate::i18n::two_factor_not_found(locale))?;

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());

    let mut twofactor_data = EmailTokenData::from_json(&twofactor.data)?;
    twofactor_data.set_token(generated_token);
    twofactor.data = twofactor_data.to_json();
    twofactor.save(conn).await?;

    mail::send_token_for_locale(
        &twofactor_data.email,
        &twofactor_data.last_token.map_res(crate::i18n::two_factor_token_empty(locale))?,
        Some(locale),
    )
    .await?;

    Ok(())
}

/// When user clicks on Manage email 2FA show the user the related information
#[post("/two-factor/get-email", data = "<data>")]
async fn get_email(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let (enabled, mfa_email) =
        if let Some(x) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email, &conn).await {
            let twofactor_data = EmailTokenData::from_json(&x.data)?;
            (true, Some(twofactor_data.email))
        } else {
            (false, None)
        };

    Ok(Json(rocket::serde::json::json!({
        "email": rocket::serde::json::json!({
            "enabled": enabled,
            "email": mfa_email,
        }),
        "userVerificationToken": two_factor::email_token(user.uuid, mfa_email, enabled),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailData {
    /// Email where 2FA codes will be sent to, can be different than user email account.
    email: String,
    user_verification_token: String,
}

/// Send a verification email to the specified email address to check whether it exists/belongs to user.
#[post("/two-factor/send-email", data = "<data>")]
async fn send_email(data: Json<SendEmailData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SendEmailData = data.into_inner();
    let user = headers.user;

    two_factor::validate_email(&data.user_verification_token, &user.uuid, data.email.clone(), false)?;

    if !CONFIG._enable_email_2fa() {
        err!(crate::i18n::two_factor_email_disabled(&headers.locale))
    }

    if let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email, &conn).await {
        tf.delete(&conn).await?;
    }

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());
    let twofactor_data = EmailTokenData::new(data.email, Some(generated_token));

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor =
        TwoFactor::new(user.uuid.clone(), TwoFactorType::EmailVerificationChallenge, twofactor_data.to_json());
    twofactor.save(&conn).await?;

    mail::send_token_for_locale(
        &twofactor_data.email,
        &twofactor_data.last_token.map_res(crate::i18n::two_factor_token_empty(&headers.locale))?,
        Some(&headers.locale),
    )
    .await?;

    Ok(Json(json!({})))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailData {
    email: String,
    token: String,
    user_verification_token: String,
}

/// Verify email belongs to user and can be used for 2FA email codes.
#[put("/two-factor/email", data = "<data>")]
async fn email(data: Json<EmailData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EmailData = data.into_inner();
    let mut user = headers.user;

    two_factor::validate_email(&data.user_verification_token, &user.uuid, data.email, false)?;

    let mut twofactor = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::EmailVerificationChallenge, &conn)
        .await
        .map_res(crate::i18n::two_factor_not_found(&headers.locale))?;

    let mut email_data = EmailTokenData::from_json(&twofactor.data)?;

    let Some(issued_token) = &email_data.last_token else {
        err!(crate::i18n::two_factor_no_token_available(&headers.locale))
    };

    if !crypto::ct_eq(issued_token, data.token) {
        err!(crate::i18n::two_factor_token_invalid(&headers.locale))
    }

    email_data.reset_token();
    twofactor.atype = TwoFactorType::Email as i32;
    twofactor.data = email_data.to_json();
    twofactor.save(&conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    Ok(Json(json!({})))
}

#[delete("/two-factor/email", data = "<data>")]
async fn disable_email(data: Json<VerificationTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let user = headers.user;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email, &conn).await {
        let twofactor_data = EmailTokenData::from_json(&twofactor.data)?;
        two_factor::validate_email(&data.user_verification_token, &user.uuid, twofactor_data.email, true)?;

        twofactor.delete(&conn).await?;
        log_user_event(EventType::UserDisabled2fa, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;
    }

    super::check_2fa_state(&user, headers.device.atype, &headers.ip.ip, &conn).await?;

    Ok(())
}

/// Validate the email code when used as TwoFactor token mechanism
pub async fn validate_email_code_str(
    user_id: &UserId,
    token: &str,
    data: &str,
    ip: &std::net::IpAddr,
    conn: &DbConn,
) -> EmptyResult {
    let mut email_data = EmailTokenData::from_json(data)?;
    let locale = CONFIG.default_locale();
    let mut twofactor = TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Email, conn)
        .await
        .map_res(crate::i18n::two_factor_not_found(&locale))?;
    let Some(issued_token) = &email_data.last_token else {
        err!(
            format!("No token available! IP: {ip}"),
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };

    if !crypto::ct_eq(issued_token, token) {
        email_data.add_attempt();
        if email_data.attempts >= u64::from(CONFIG.email_attempts_limit()) {
            email_data.reset_token();
        }
        twofactor.data = email_data.to_json();
        twofactor.save(conn).await?;

        err!(
            format!("Token is invalid! IP: {ip}"),
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    email_data.reset_token();
    twofactor.data = email_data.to_json();
    twofactor.save(conn).await?;

    let dt = DateTime::from_timestamp(email_data.token_sent, 0).expect("Email token timestamp invalid.").naive_utc();
    let max_time = i64::from(CONFIG.email_expiration_time());
    if dt + TimeDelta::try_seconds(max_time).unwrap() < Utc::now().naive_utc() {
        err!(
            "Token has expired",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    Ok(())
}

/// Data stored in the TwoFactor table in the db
#[derive(Serialize, Deserialize)]
pub struct EmailTokenData {
    /// Email address where the token will be sent to. Can be different from account email.
    pub email: String,
    /// Some(token): last valid token issued that has not been entered.
    /// None: valid token was used and removed.
    pub last_token: Option<String>,
    /// UNIX timestamp of token issue.
    pub token_sent: i64,
    /// Amount of token entry attempts for last_token.
    pub attempts: u64,
}

impl EmailTokenData {
    pub fn new(email: String, token: Option<String>) -> EmailTokenData {
        EmailTokenData {
            email,
            last_token: token,
            token_sent: Utc::now().timestamp(),
            attempts: 0,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = Utc::now().timestamp();
    }

    pub fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }

    pub fn add_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn from_json(string: &str) -> Result<EmailTokenData, Error> {
        let res: Result<EmailTokenData, serde_json::Error> = serde_json::from_str(string);
        if let Ok(x) = res {
            Ok(x)
        } else {
            err!(crate::i18n::two_factor_decode_email_token_data_failed(&CONFIG.default_locale()))
        }
    }
}

pub async fn activate_email_2fa(user: &User, conn: &DbConn) -> EmptyResult {
    if user.verified_at.is_none() {
        err!(crate::i18n::two_factor_auto_enable_email_requires_verified(&CONFIG.default_locale()));
    }
    // The token is set when the first code is sent
    let twofactor_data = EmailTokenData::new(user.email.clone(), None);
    let twofactor = TwoFactor::new(user.uuid.clone(), TwoFactorType::Email, twofactor_data.to_json());
    twofactor.save(conn).await
}

/// Takes an email address and obscures it by replacing it with asterisks except two characters.
pub fn obscure_email(email: &str) -> String {
    let split: Vec<&str> = email.rsplitn(2, '@').collect();

    let mut name = split[1].to_owned();
    let domain = &split[0];

    let name_size = name.chars().count();

    let new_name = if let 1..=3 = name_size {
        "*".repeat(name_size)
    } else {
        let stars = "*".repeat(name_size - 2);
        name.truncate(2);
        format!("{name}{stars}")
    };

    format!("{new_name}@{domain}")
}

pub async fn find_and_activate_email_2fa(user_id: &UserId, conn: &DbConn) -> EmptyResult {
    if let Some(user) = User::find_by_uuid(user_id, conn).await {
        activate_email_2fa(&user, conn).await
    } else {
        err!(crate::i18n::two_factor_user_not_found_exclam(&CONFIG.default_locale()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obscure_email_long() {
        let email = "bytes@example.ext";

        let result = obscure_email(email);

        // Only first two characters should be visible.
        assert_eq!(result, "by***@example.ext");
    }

    #[test]
    fn test_obscure_email_short() {
        let email = "byt@example.ext";

        let result = obscure_email(email);

        // If it's smaller than 3 characters it should only show asterisks.
        assert_eq!(result, "***@example.ext");
    }
}
