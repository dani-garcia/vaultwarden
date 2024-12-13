use chrono::{DateTime, TimeDelta, Utc};
use rocket::serde::json::Json;
use rocket::Route;

use crate::{
    api::{
        core::{log_user_event, two_factor::_generate_recover_code},
        EmptyResult, JsonResult, PasswordOrOtpData,
    },
    auth::Headers,
    crypto,
    db::{
        models::{EventType, TwoFactor, TwoFactorType, User},
        DbConn,
    },
    error::{Error, MapResult},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![get_email, send_email_login, send_email, email,]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailLoginData {
    // DeviceIdentifier: String, // Currently not used
    #[serde(alias = "Email")]
    email: String,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: String,
}

/// User is trying to login and wants to use email 2FA.
/// Does not require Bearer token
#[post("/two-factor/send-email-login", data = "<data>")] // JsonResult
async fn send_email_login(data: Json<SendEmailLoginData>, mut conn: DbConn) -> EmptyResult {
    let data: SendEmailLoginData = data.into_inner();

    use crate::db::models::User;

    // Get the user
    let Some(user) = User::find_by_mail(&data.email, &mut conn).await else {
        err!("Username or password is incorrect. Try again.")
    };

    // Check password
    if !user.check_valid_password(&data.master_password_hash) {
        err!("Username or password is incorrect. Try again.")
    }

    if !CONFIG._enable_email_2fa() {
        err!("Email 2FA is disabled")
    }

    send_token(&user.uuid, &mut conn).await?;

    Ok(())
}

/// Generate the token, save the data for later verification and send email to user
pub async fn send_token(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
    let type_ = TwoFactorType::Email as i32;
    let mut twofactor =
        TwoFactor::find_by_user_and_type(user_uuid, type_, conn).await.map_res("Two factor not found")?;

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());

    let mut twofactor_data = EmailTokenData::from_json(&twofactor.data)?;
    twofactor_data.set_token(generated_token);
    twofactor.data = twofactor_data.to_json();
    twofactor.save(conn).await?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token.map_res("Token is empty")?).await?;

    Ok(())
}

/// When user clicks on Manage email 2FA show the user the related information
#[post("/two-factor/get-email", data = "<data>")]
async fn get_email(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &mut conn).await?;

    let (enabled, mfa_email) =
        match TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email as i32, &mut conn).await {
            Some(x) => {
                let twofactor_data = EmailTokenData::from_json(&x.data)?;
                (true, json!(twofactor_data.email))
            }
            _ => (false, serde_json::value::Value::Null),
        };

    Ok(Json(json!({
        "email": mfa_email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendEmailData {
    /// Email where 2FA codes will be sent to, can be different than user email account.
    email: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

/// Send a verification email to the specified email address to check whether it exists/belongs to user.
#[post("/two-factor/send-email", data = "<data>")]
async fn send_email(data: Json<SendEmailData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    let data: SendEmailData = data.into_inner();
    let user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, false, &mut conn)
    .await?;

    if !CONFIG._enable_email_2fa() {
        err!("Email 2FA is disabled")
    }

    let type_ = TwoFactorType::Email as i32;

    if let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &mut conn).await {
        tf.delete(&mut conn).await?;
    }

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());
    let twofactor_data = EmailTokenData::new(data.email, generated_token);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::EmailVerificationChallenge, twofactor_data.to_json());
    twofactor.save(&mut conn).await?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token.map_res("Token is empty")?).await?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailData {
    email: String,
    token: String,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

/// Verify email belongs to user and can be used for 2FA email codes.
#[put("/two-factor/email", data = "<data>")]
async fn email(data: Json<EmailData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: EmailData = data.into_inner();
    let mut user = headers.user;

    // This is the last step in the verification process, delete the otp directly afterwards
    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &mut conn)
    .await?;

    let type_ = TwoFactorType::EmailVerificationChallenge as i32;
    let mut twofactor =
        TwoFactor::find_by_user_and_type(&user.uuid, type_, &mut conn).await.map_res("Two factor not found")?;

    let mut email_data = EmailTokenData::from_json(&twofactor.data)?;

    let Some(issued_token) = &email_data.last_token else {
        err!("No token available")
    };

    if !crypto::ct_eq(issued_token, data.token) {
        err!("Token is invalid")
    }

    email_data.reset_token();
    twofactor.atype = TwoFactorType::Email as i32;
    twofactor.data = email_data.to_json();
    twofactor.save(&mut conn).await?;

    _generate_recover_code(&mut user, &mut conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    Ok(Json(json!({
        "email": email_data.email,
        "enabled": "true",
        "object": "twoFactorEmail"
    })))
}

/// Validate the email code when used as TwoFactor token mechanism
pub async fn validate_email_code_str(user_uuid: &str, token: &str, data: &str, conn: &mut DbConn) -> EmptyResult {
    let mut email_data = EmailTokenData::from_json(data)?;
    let mut twofactor = TwoFactor::find_by_user_and_type(user_uuid, TwoFactorType::Email as i32, conn)
        .await
        .map_res("Two factor not found")?;
    let Some(issued_token) = &email_data.last_token else {
        err!(
            "No token available",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    };

    if !crypto::ct_eq(issued_token, token) {
        email_data.add_attempt();
        if email_data.attempts >= CONFIG.email_attempts_limit() {
            email_data.reset_token();
        }
        twofactor.data = email_data.to_json();
        twofactor.save(conn).await?;

        err!(
            "Token is invalid",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    email_data.reset_token();
    twofactor.data = email_data.to_json();
    twofactor.save(conn).await?;

    let date = DateTime::from_timestamp(email_data.token_sent, 0).expect("Email token timestamp invalid.").naive_utc();
    let max_time = CONFIG.email_expiration_time() as i64;
    if date + TimeDelta::try_seconds(max_time).unwrap() < Utc::now().naive_utc() {
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
    pub fn new(email: String, token: String) -> EmailTokenData {
        EmailTokenData {
            email,
            last_token: Some(token),
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
        self.attempts += 1;
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn from_json(string: &str) -> Result<EmailTokenData, Error> {
        let res: Result<EmailTokenData, serde_json::Error> = serde_json::from_str(string);
        match res {
            Ok(x) => Ok(x),
            Err(_) => err!("Could not decode EmailTokenData from string"),
        }
    }
}

pub async fn activate_email_2fa(user: &User, conn: &mut DbConn) -> EmptyResult {
    if user.verified_at.is_none() {
        err!("Auto-enabling of email 2FA failed because the users email address has not been verified!");
    }
    let twofactor_data = EmailTokenData::new(user.email.clone(), String::new());
    let twofactor = TwoFactor::new(user.uuid.clone(), TwoFactorType::Email, twofactor_data.to_json());
    twofactor.save(conn).await
}

/// Takes an email address and obscures it by replacing it with asterisks except two characters.
pub fn obscure_email(email: &str) -> String {
    let split: Vec<&str> = email.rsplitn(2, '@').collect();

    let mut name = split[1].to_string();
    let domain = &split[0];

    let name_size = name.chars().count();

    let new_name = match name_size {
        1..=3 => "*".repeat(name_size),
        _ => {
            let stars = "*".repeat(name_size - 2);
            name.truncate(2);
            format!("{name}{stars}")
        }
    };

    format!("{}@{}", new_name, &domain)
}

pub async fn find_and_activate_email_2fa(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
    if let Some(user) = User::find_by_uuid(user_uuid, conn).await {
        activate_email_2fa(&user, conn).await
    } else {
        err!("User not found!");
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
