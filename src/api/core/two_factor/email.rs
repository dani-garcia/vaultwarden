use rocket::Route;
use rocket_contrib::json::Json;
use serde_json;

use crate::api::{EmptyResult, JsonResult, JsonUpcase, PasswordData};
use crate::auth::Headers;
use crate::db::{
    models::{TwoFactor, TwoFactorType},
    DbConn,
};
use crate::error::Error;
use crate::mail;
use crate::crypto;

use chrono::{Duration, NaiveDateTime, Utc};
use std::char;
use std::ops::Add;

const MAX_TIME_DIFFERENCE: i64 = 600;
const TOKEN_LEN: usize = 6;

pub fn routes() -> Vec<Route> {
    routes![
        get_email,
        send_email_login,
        send_email,
        email,
    ]
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SendEmailLoginData {
    Email: String,
    MasterPasswordHash: String,
}

/// User is trying to login and wants to use email 2FA.
/// Does not require Bearer token
#[post("/two-factor/send-email-login", data = "<data>")] // JsonResult
fn send_email_login(data: JsonUpcase<SendEmailLoginData>, conn: DbConn) -> EmptyResult {
    let data: SendEmailLoginData = data.into_inner().data;

    use crate::db::models::User;

    // Get the user
    let user = match User::find_by_mail(&data.Email, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    let type_ = TwoFactorType::Email as i32;
    let mut twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn)?;

    let generated_token = generate_token();
    let mut twofactor_data = EmailTokenData::from_json(&twofactor.data)?;
    twofactor_data.set_token(generated_token);
    twofactor.data = twofactor_data.to_json();
    twofactor.save(&conn)?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token?)?;

    Ok(())
}

#[post("/two-factor/get-email", data = "<data>")]
fn get_email(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Email as i32;
    let enabled = match TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn) {
        Some(x) => x.enabled,
        _ => false,
    };

    Ok(Json(json!({
        "Email": user.email,
        "Enabled": enabled,
        "Object": "twoFactorEmail"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SendEmailData {
    /// Email where 2FA codes will be sent to, can be different than user email account.
    Email: String,
    MasterPasswordHash: String,
}

fn generate_token() -> String {
    crypto::get_random(vec![0; TOKEN_LEN])
        .iter()
        .map(|byte| { (byte % 10)})
        .map(|num| {
            dbg!(num);
            char::from_digit(num as u32, 10).unwrap()
        })
        .collect()
}

/// Send a verification email to the specified email address to check whether it exists/belongs to user.
#[post("/two-factor/send-email", data = "<data>")]
fn send_email(data: JsonUpcase<SendEmailData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: SendEmailData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Email as i32;

    if let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn) {
        tf.delete(&conn)?;
    }

    let generated_token = generate_token();
    let twofactor_data = EmailTokenData::new(data.Email, generated_token);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(
        user.uuid,
        TwoFactorType::EmailVerificationChallenge,
        twofactor_data.to_json(),
    );
    twofactor.save(&conn)?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token?)?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct EmailData {
    Email: String,
    MasterPasswordHash: String,
    Token: String,
}

/// Verify email belongs to user and can be used for 2FA email codes.
#[put("/two-factor/email", data = "<data>")]
fn email(data: JsonUpcase<EmailData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EmailData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::EmailVerificationChallenge as i32;
    let mut twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn)?;

    let mut email_data = EmailTokenData::from_json(&twofactor.data)?;

    let issued_token = match &email_data.last_token {
        Some(t) => t,
        _ => err!("No token available"),
    };

    if issued_token != &data.Token {
        err!("Email token does not match")
    }

    email_data.reset_token();
    twofactor.atype = TwoFactorType::Email as i32;
    twofactor.data = email_data.to_json();
    twofactor.save(&conn)?;

    Ok(Json(json!({
        "Email": email_data.email,
        "Enabled": "true",
        "Object": "twoFactorEmail"
    })))
}

/// Validate the email code when used as TwoFactor token mechanism
pub fn validate_email_code_str(user_uuid: &str, token: &str, data: &str, conn: &DbConn) -> EmptyResult {
    let mut email_data = EmailTokenData::from_json(&data)?;
    let mut twofactor = TwoFactor::find_by_user_and_type(&user_uuid, TwoFactorType::Email as i32, &conn)?;
    let issued_token = match &email_data.last_token {
        Some(t) => t,
        _ => err!("No token available"),
    };

    if issued_token != &*token {
        err!("Email token does not match")
    }

    email_data.reset_token();
    twofactor.data = email_data.to_json();
    twofactor.save(&conn)?;

    let date = NaiveDateTime::from_timestamp(email_data.token_sent, 0);
    if date.add(Duration::seconds(MAX_TIME_DIFFERENCE)) < Utc::now().naive_utc() {
        err!("Email token too old")
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct EmailTokenData {
    pub email: String,
    pub last_token: Option<String>,
    pub token_sent: i64,
}

impl EmailTokenData {
    pub fn new(email: String, token: String) -> EmailTokenData {
        EmailTokenData {
            email,
            last_token: Some(token),
            token_sent: Utc::now().naive_utc().timestamp(),
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = Utc::now().naive_utc().timestamp();
    }

    pub fn reset_token(&mut self) {
        self.last_token = None;
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn from_json(string: &str) -> Result<EmailTokenData, Error> {
        let res: Result<EmailTokenData, crate::serde_json::Error> = serde_json::from_str(&string);
        match res {
            Ok(x) => Ok(x),
            Err(_) => err!("Could not decode EmailTokenData from string"),
        }
    }
}

/// Takes an email address and obscures it by replacing it with asterisks except two characters.
pub fn obscure_email(email: &str) -> String {
    let split: Vec<&str> = email.split("@").collect();

    let mut name = split[0].to_string();
    let domain = &split[1];

    let name_size = name.chars().count();

    let new_name = match name_size {
        1..=3 => "*".repeat(name_size),
        _ => {
            let stars = "*".repeat(name_size - 2);
            name.truncate(2);
            format!("{}{}", name, stars)
        }
    };

    format!("{}@{}", new_name, &domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obscure_email_long() {
        let email = "bytes@example.ext";

        let result = obscure_email(&email);

        // Only first two characters should be visible.
        assert_eq!(result, "by***@example.ext");
    }

    #[test]
    fn test_obscure_email_short() {
        let email = "byt@example.ext";

        let result = obscure_email(&email);

        // If it's smaller than 3 characters it should only show asterisks.
        assert_eq!(result, "***@example.ext");
    }

    #[test]
    fn test_token() {
        let result = generate_token();

        assert_eq!(result.chars().count(), 6);
    }
}
