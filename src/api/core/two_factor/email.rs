use data_encoding::{BASE32};
use oath::{totp_raw_now, HashType};
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json;

use crate::api::core::two_factor::totp;
use crate::api::{EmptyResult, JsonResult, JsonUpcase, PasswordData};
use crate::auth::Headers;
use crate::db::{
    models::{TwoFactor, TwoFactorType},
    DbConn,
};
use crate::error::{Error};
use crate::{crypto, mail};

const TOTP_TIME_STEP: u64 = 120;

pub fn routes() -> Vec<Route> {
    routes![get_email, send_email_login, send_email, email,]
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SendEmailLoginData {
    Email: String,
    MasterPasswordHash: String,
}

// Does not require Bearer token
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
    let twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn)?;

    let twofactor_data = EmailTokenData::from_json(&twofactor.data)?;

    let decoded_key = totp::validate_decode_key(&twofactor_data.totp_secret)?;

    let generated_token = totp_raw_now(&decoded_key, 6, 0, TOTP_TIME_STEP, &HashType::SHA1);
    let token_string = generated_token.to_string();

    mail::send_token(&twofactor_data.email, &token_string)?;

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

    Ok(Json(json!({// TODO check! FIX!
        "Email": user.email,
        "Enabled": enabled,
        "Object": "twoFactorEmail"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SendEmailData {
    Email: String,
    // Email where 2FA codes will be sent to, can be different than user email account.
    MasterPasswordHash: String,
}

// Send a verification email to the specified email address to check whether it exists/belongs to user.
#[post("/two-factor/send-email", data = "<data>")]
fn send_email(data: JsonUpcase<SendEmailData>, headers: Headers, conn: DbConn) -> EmptyResult {
    use oath::{totp_raw_now, HashType};

    let data: SendEmailData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Email as i32;

    // TODO: Delete previous email thing.
    match TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn) {
        Some(tf) => tf.delete(&conn),
        _ => Ok(()),
    };

    let secret = crypto::get_random(vec![0u8; 20]);
    let base32_secret = BASE32.encode(&secret);

    let twofactor_data = EmailTokenData::new(data.Email, base32_secret);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(
        user.uuid,
        TwoFactorType::EmailVerificationChallenge,
        twofactor_data.to_json(),
    );
    twofactor.save(&conn)?;

    let generated_token = totp_raw_now(&secret, 6, 0, TOTP_TIME_STEP, &HashType::SHA1);
    let token_string = generated_token.to_string();

    mail::send_token(&twofactor_data.email, &token_string)?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct EmailData {
    Email: String,
    MasterPasswordHash: String,
    Token: String,
}

// Verify email used for 2FA email codes.
#[put("/two-factor/email", data = "<data>")]
fn email(data: JsonUpcase<EmailData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EmailData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let token_u64 = match data.Token.parse::<u64>() {
        Ok(token) => token,
        _ => err!("Could not parse token"),
    };

    let type_ = TwoFactorType::EmailVerificationChallenge as i32;
    let mut twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn)?;

    let email_data = EmailTokenData::from_json(&twofactor.data)?;

    totp::validate_totp_code_with_time_step(token_u64, &email_data.totp_secret, TOTP_TIME_STEP)?;

    twofactor.atype = TwoFactorType::Email as i32;
    twofactor.save(&conn)?;

    Ok(Json(json!({
        "Email": email_data.email,
        "Enabled": "true",
        "Object": "twoFactorEmail"
    })))
}

pub fn validate_email_code_str(code: &str, data: &str) -> EmptyResult {
    let totp_code: u64 = match code.parse() {
        Ok(code) => code,
        _ => err!("Email code is not a number"),
    };

    validate_email_code(totp_code, data)
}

pub fn validate_email_code(code: u64, data: &str) -> EmptyResult {
    let email_data = EmailTokenData::from_json(&data)?;

    let decoded_secret = match BASE32.decode(email_data.totp_secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid email secret"),
    };

    let generated = totp_raw_now(&decoded_secret, 6, 0, TOTP_TIME_STEP, &HashType::SHA1);
    if generated != code {
        err!("Invalid email code");
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct EmailTokenData {
    pub email: String,
    pub totp_secret: String,
}

impl EmailTokenData {
    pub fn new(email: String, totp_secret: String) -> EmailTokenData {
        EmailTokenData {
            email,
            totp_secret,
        }
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
            let stars = "*".repeat(name_size-2);
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
}
