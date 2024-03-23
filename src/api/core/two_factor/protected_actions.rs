use chrono::{DateTime, TimeDelta, Utc};
use rocket::{serde::json::Json, Route};

use crate::{
    api::EmptyResult,
    auth::Headers,
    crypto,
    db::{
        models::{TwoFactor, TwoFactorType},
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
    pub token_sent: i64,
    // The total amount of attempts
    pub attempts: u8,
}

impl ProtectedActionData {
    pub fn new(token: String) -> Self {
        Self {
            token,
            token_sent: Utc::now().timestamp(),
            attempts: 0,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub fn from_json(string: &str) -> Result<Self, Error> {
        let res: Result<Self, crate::serde_json::Error> = serde_json::from_str(string);
        match res {
            Ok(x) => Ok(x),
            Err(_) => err!("Could not decode ProtectedActionData from string"),
        }
    }

    pub fn add_attempt(&mut self) {
        self.attempts += 1;
    }
}

#[post("/accounts/request-otp")]
async fn request_otp(headers: Headers, mut conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Email is disabled for this server. Either enable email or login using your master password instead of login via device.");
    }

    let user = headers.user;

    // Only one Protected Action per user is allowed to take place, delete the previous one
    if let Some(pa) =
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::ProtectedActions as i32, &mut conn).await
    {
        pa.delete(&mut conn).await?;
    }

    let generated_token = crypto::generate_email_token(CONFIG.email_token_size());
    let pa_data = ProtectedActionData::new(generated_token);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::ProtectedActions, pa_data.to_json());
    twofactor.save(&mut conn).await?;

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
async fn verify_otp(data: Json<ProtectedActionVerify>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Email is disabled for this server. Either enable email or login using your master password instead of login via device.");
    }

    let user = headers.user;
    let data: ProtectedActionVerify = data.into_inner();

    // Delete the token after one validation attempt
    // This endpoint only gets called for the vault export, and doesn't need a second attempt
    validate_protected_action_otp(&data.otp, &user.uuid, true, &mut conn).await
}

pub async fn validate_protected_action_otp(
    otp: &str,
    user_uuid: &str,
    delete_if_valid: bool,
    conn: &mut DbConn,
) -> EmptyResult {
    let pa = TwoFactor::find_by_user_and_type(user_uuid, TwoFactorType::ProtectedActions as i32, conn)
        .await
        .map_res("Protected action token not found, try sending the code again or restart the process")?;
    let mut pa_data = ProtectedActionData::from_json(&pa.data)?;

    pa_data.add_attempt();
    // Delete the token after x attempts if it has been used too many times
    // We use the 6, which should be more then enough for invalid attempts and multiple valid checks
    if pa_data.attempts > 6 {
        pa.delete(conn).await?;
        err!("Token has expired")
    }

    // Check if the token has expired (Using the email 2fa expiration time)
    let date =
        DateTime::from_timestamp(pa_data.token_sent, 0).expect("Protected Action token timestamp invalid.").naive_utc();
    let max_time = CONFIG.email_expiration_time() as i64;
    if date + TimeDelta::try_seconds(max_time).unwrap() < Utc::now().naive_utc() {
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
