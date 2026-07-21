use data_encoding::BASE32;
use rocket::{Route, serde::json::Json};

use crate::{
    api::{EmptyResult, JsonResult, PasswordOrOtpData, core::log_user_event, core::two_factor::generate_recover_code},
    auth::{ClientIp, Headers},
    crypto,
    db::{
        DbConn,
        models::{EventType, TwoFactor, TwoFactorType, UserId},
    },
    util::NumberOrString,
};

pub use crate::config::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![generate_authenticator, activate_authenticator, activate_authenticator_put, disable_authenticator]
}

#[post("/two-factor/get-authenticator", data = "<data>")]
async fn generate_authenticator(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let type_ = TwoFactorType::Authenticator as i32;
    let twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await;

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data),
        _ => (false, crypto::encode_random_bytes::<20>(&BASE32)),
    };

    // Upstream seems to also return `userVerificationToken`, but doesn't seem to be used at all.
    // It should help prevent TOTP disclosure if someone keeps their vault unlocked.
    // Since it doesn't seem to be used, and also does not cause any issues, lets leave it out of the response.
    // See: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Auth/Controllers/TwoFactorController.cs#L94
    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnableAuthenticatorData {
    key: String,
    token: NumberOrString,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[post("/two-factor/authenticator", data = "<data>")]
async fn activate_authenticator(data: Json<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner();
    let key = data.key;
    let token = data.token.into_string();

    let mut user = headers.user;

    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &conn)
    .await?;

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = if let Ok(decoded) = BASE32.decode(key.as_bytes()) {
        decoded
    } else {
        err!("Invalid totp secret")
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    // Validate the token provided with the key, and save new twofactor
    validate_totp_code(&user.uuid, &token, &key.to_uppercase(), &headers.ip, &conn).await?;

    generate_recover_code(&mut user, &conn).await;

    log_user_event(EventType::UserUpdated2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[put("/two-factor/authenticator", data = "<data>")]
async fn activate_authenticator_put(data: Json<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_authenticator(data, headers, conn).await
}

pub async fn validate_totp_code_str(
    user_id: &UserId,
    totp_code: &str,
    secret: &str,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    if !totp_code.chars().all(char::is_numeric) {
        err!("TOTP code is not a number");
    }

    validate_totp_code(user_id, totp_code, secret, ip, conn).await
}

/// The outcome of checking a TOTP `code` against the allowed time window.
pub(crate) enum TotpValidation {
    /// The code is valid. Contains the accepted time step, which must be stored as the
    /// new "last used" value so the same code cannot be reused.
    Accepted(i64),
    /// The code matched a time step that has already been used (replay protection).
    Reused,
    /// The code did not match any step within the allowed window.
    Rejected,
}

/// Verifies a 6-digit TOTP `code` against the already base32-decoded `secret`, allowing
/// `steps` (>= 0) time steps of ±30 seconds drift in either direction and rejecting any
/// time step that is not newer than `last_used`. The comparison is constant-time.
/// Shared by the user 2FA flow and the admin-page 2FA.
pub(crate) fn verify_totp(secret: &[u8], code: &str, timestamp: i64, last_used: i64, steps: i64) -> TotpValidation {
    use totp_lite::{Sha1, totp_custom};

    for step in -steps..=steps {
        let time_step = timestamp / 30i64 + step;
        // The generator needs the time as an u64; we only ever deal with times >= 0.
        let time: u64 = (timestamp + step * 30i64).cast_unsigned();
        let generated = totp_custom::<Sha1>(30, 6, secret, time);

        if crypto::ct_eq(&generated, code) {
            return if time_step > last_used {
                TotpValidation::Accepted(time_step)
            } else {
                TotpValidation::Reused
            };
        }
    }
    TotpValidation::Rejected
}

pub async fn validate_totp_code(
    user_id: &UserId,
    totp_code: &str,
    secret: &str,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    let Ok(decoded_secret) = BASE32.decode(secret.as_bytes()) else {
        err!("Invalid TOTP secret")
    };

    let mut twofactor = match TwoFactor::find_by_user_and_type(user_id, TwoFactorType::Authenticator as i32, conn).await
    {
        Some(tf) => tf,
        _ => TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, secret.to_owned()),
    };

    // The amount of steps back and forward in time
    // Also check if we need to disable time drifted TOTP codes.
    // If that is the case, we set the steps to 0 so only the current TOTP is valid.
    let steps = i64::from(!CONFIG.authenticator_disable_time_drift());

    // Get the current system time in UNIX Epoch (UTC)
    let current_time = chrono::Utc::now();
    let current_timestamp = current_time.timestamp();

    match verify_totp(&decoded_secret, totp_code, current_timestamp, twofactor.last_used, steps) {
        TotpValidation::Accepted(time_step) => {
            // If the accepted step is not the current one the time is drifted either server or client side.
            let step = time_step - current_timestamp / 30i64;
            if step != 0 {
                warn!("TOTP Time drift detected. The step offset is {step}");
            }

            // Save the last used time step so only totp time steps higher then this one are allowed.
            // This will also save a newly created twofactor if the code is correct.
            twofactor.last_used = time_step;
            twofactor.save(conn).await?;
            Ok(())
        }
        TotpValidation::Reused => {
            warn!("This TOTP or a TOTP code within {steps} steps back or forward has already been used!");
            err!(
                format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            )
        }
        // Else no valid code received, deny access
        TotpValidation::Rejected => {
            err!(
                format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            )
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableAuthenticatorData {
    key: String,
    master_password_hash: String,
    r#type: NumberOrString,
}

#[delete("/two-factor/authenticator", data = "<data>")]
async fn disable_authenticator(data: Json<DisableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let user = headers.user;
    let type_ = data.r#type.into_i32()?;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await {
        if twofactor.data == data.key {
            twofactor.delete(&conn).await?;
            log_user_event(EventType::UserDisabled2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
                .await;
        } else {
            err!(format!("TOTP key for user {} does not match recorded value, cannot deactivate", &user.email));
        }
    }

    if TwoFactor::find_by_user(&user.uuid, &conn).await.is_empty() {
        super::enforce_2fa_policy(&user, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await?;
    }

    Ok(Json(json!({
        "enabled": false,
        "keys": type_,
        "object": "twoFactorProvider"
    })))
}

#[cfg(test)]
mod tests {
    use super::{TotpValidation, verify_totp};
    use data_encoding::BASE32;
    use totp_lite::{Sha1, totp_custom};

    fn code_at(secret: &[u8], timestamp: i64) -> String {
        totp_custom::<Sha1>(30, 6, secret, timestamp.cast_unsigned())
    }

    #[test]
    fn totp_accepts_rejects_and_detects_reuse() {
        let secret = BASE32.decode(b"JBSWY3DPEHPK3PXP").unwrap();
        let ts = 1_700_000_000i64;
        let step = ts / 30;
        let current = code_at(&secret, ts);

        // A fresh current code is accepted and reports the current time step.
        assert!(matches!(verify_totp(&secret, &current, ts, 0, 1), TotpValidation::Accepted(s) if s == step));
        // The same code is rejected as reused once its step has been recorded.
        assert!(matches!(verify_totp(&secret, &current, ts, step, 1), TotpValidation::Reused));
        // A wrong code is rejected.
        assert!(matches!(verify_totp(&secret, "000000", ts, 0, 1), TotpValidation::Rejected));

        // The previous 30s window is accepted with one step of drift...
        let previous = code_at(&secret, ts - 30);
        assert!(matches!(verify_totp(&secret, &previous, ts, 0, 1), TotpValidation::Accepted(_)));
        // ...but rejected when drift is disabled (steps = 0).
        assert!(matches!(verify_totp(&secret, &previous, ts, 0, 0), TotpValidation::Rejected));
    }
}
