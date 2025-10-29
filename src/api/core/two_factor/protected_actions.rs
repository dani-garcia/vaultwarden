use chrono::{naive::serde::ts_seconds, NaiveDateTime, TimeDelta, Utc};
use rocket::{serde::json::Json, Route};

use crate::{
    api::EmptyResult,
    auth::Headers,
    crypto,
    db::{
        models::{TwoFactor, TwoFactorType, UserId},
        DbConn,
    },
    error::{Error, MapResult},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![request_otp, verify_otp]
}

/// Data stored in the TwoFactor table in the db
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectedActionData {
    /// Token issued to validate the protected action
    pub token: String,
    /// UNIX timestamp of token issue.
    #[serde(with = "ts_seconds")]
    pub token_sent: NaiveDateTime,
    // The total amount of attempts
    pub attempts: u64,
}

impl ProtectedActionData {
    pub fn new(token: String) -> Self {
        Self {
            token,
            token_sent: Utc::now().naive_utc(),
            attempts: 0,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn from_json(string: &str) -> Result<Self, Error> {
        let res: Result<Self, serde_json::Error> = serde_json::from_str(string);
        match res {
            Ok(x) => Ok(x),
            Err(_) => err!("Could not decode ProtectedActionData from string"),
        }
    }

    pub fn add_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn time_since_sent(&self) -> TimeDelta {
        Utc::now().naive_utc() - self.token_sent
    }
}

#[post("/accounts/request-otp")]
async fn request_otp(headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Email is disabled for this server. Either enable email or login using your master password instead of login via device.");
    }

    let user = headers.user;

    // Only one Protected Action per user is allowed to take place, delete the previous one
    if let Some(pa) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::ProtectedActions as i32, &conn).await
    {
        let pa_data = ProtectedActionData::from_json(&pa.data)?;
        let elapsed = pa_data.time_since_sent().num_seconds();
        let delay = 30;
        if elapsed < delay {
            err!(format!("Please wait {} seconds before requesting another code.", (delay - elapsed)));
        }

        pa.delete(&conn).await?;
    }

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());
    let pa_data = ProtectedActionData::new(generated_token);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::ProtectedActions, pa_data.to_json());
    twofactor.save(&conn).await?;

    mail::send_protected_action_token(&user.email, &pa_data.token).await?;

    Ok(())
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ProtectedActionVerify {
    #[serde(rename = "OTP", alias = "otp")]
    otp: String,
}

#[post("/accounts/verify-otp", data = "<data>")]
async fn verify_otp(data: Json<ProtectedActionVerify>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Email is disabled for this server. Either enable email or login using your master password instead of login via device.");
    }

    let user = headers.user;
    let data: ProtectedActionVerify = data.into_inner();

    // Delete the token after one validation attempt
    // This endpoint only gets called for the vault export, and doesn't need a second attempt
    validate_protected_action_otp(&data.otp, &user.uuid, true, &conn).await
}

pub async fn validate_protected_action_otp(
    otp: &str,
    user_id: &UserId,
    delete_if_valid: bool,
    conn: &DbConn,
) -> EmptyResult {
    let mut pa = TwoFactor::find_by_user_and_type(user_id, TwoFactorType::ProtectedActions as i32, conn)
        .await
        .map_res("Protected action token not found, try sending the code again or restart the process")?;
    let mut pa_data = ProtectedActionData::from_json(&pa.data)?;
    pa_data.add_attempt();
    pa.data = pa_data.to_json();

    // Fail after x attempts if the token has been used too many times.
    // Don't delete it, as we use it to keep track of attempts.
    if pa_data.attempts >= CONFIG.email_attempts_limit() {
        err!("Token has expired")
    }

    // Check if the token has expired (Using the email 2fa expiration time)
    let max_time = CONFIG.email_expiration_time() as i64;
    if pa_data.time_since_sent().num_seconds() > max_time {
        pa.delete(conn).await?;
        err!("Token has expired")
    }

    if !crypto::ct_eq(&pa_data.token, otp) {
        pa.save(conn).await?;
        err!("Token is invalid")
    }

    if delete_if_valid {
        pa.delete(conn).await?;
    }

    Ok(())
}
