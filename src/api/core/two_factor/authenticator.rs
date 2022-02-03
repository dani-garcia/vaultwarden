use data_encoding::BASE32;
use rocket::Route;
use rocket_contrib::json::Json;

use crate::{
    api::{
        core::two_factor::_generate_recover_code, EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData,
    },
    auth::{ClientIp, Headers},
    crypto,
    db::{
        models::{TwoFactor, TwoFactorType},
        DbConn,
    },
};

pub use crate::config::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![generate_authenticator, activate_authenticator, activate_authenticator_put,]
}

#[post("/two-factor/get-authenticator", data = "<data>")]
fn generate_authenticator(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::Authenticator as i32;
    let twofactor = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn);

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data),
        _ => (false, BASE32.encode(&crypto::get_random(vec![0u8; 20]))),
    };

    Ok(Json(json!({
        "Enabled": enabled,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EnableAuthenticatorData {
    MasterPasswordHash: String,
    Key: String,
    Token: NumberOrString,
}

#[post("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator(
    data: JsonUpcase<EnableAuthenticatorData>,
    headers: Headers,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let key = data.Key;
    let token = data.Token.into_string();

    let mut user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = match BASE32.decode(key.as_bytes()) {
        Ok(decoded) => decoded,
        _ => err!("Invalid totp secret"),
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    // Validate the token provided with the key, and save new twofactor
    validate_totp_code(&user.uuid, &token, &key.to_uppercase(), &ip, &conn)?;

    _generate_recover_code(&mut user, &conn);

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[put("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator_put(
    data: JsonUpcase<EnableAuthenticatorData>,
    headers: Headers,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    activate_authenticator(data, headers, ip, conn)
}

pub fn validate_totp_code_str(
    user_uuid: &str,
    totp_code: &str,
    secret: &str,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    if !totp_code.chars().all(char::is_numeric) {
        err!("TOTP code is not a number");
    }

    validate_totp_code(user_uuid, totp_code, secret, ip, conn)
}

pub fn validate_totp_code(user_uuid: &str, totp_code: &str, secret: &str, ip: &ClientIp, conn: &DbConn) -> EmptyResult {
    use totp_lite::{totp_custom, Sha1};

    let decoded_secret = match BASE32.decode(secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid TOTP secret"),
    };

    let mut twofactor = match TwoFactor::find_by_user_and_type(user_uuid, TwoFactorType::Authenticator as i32, conn) {
        Some(tf) => tf,
        _ => TwoFactor::new(user_uuid.to_string(), TwoFactorType::Authenticator, secret.to_string()),
    };

    // The amount of steps back and forward in time
    // Also check if we need to disable time drifted TOTP codes.
    // If that is the case, we set the steps to 0 so only the current TOTP is valid.
    let steps = !CONFIG.authenticator_disable_time_drift() as i64;

    // Get the current system time in UNIX Epoch (UTC)
    let current_time = chrono::Utc::now();
    let current_timestamp = current_time.timestamp();

    for step in -steps..=steps {
        let time_step = current_timestamp / 30i64 + step;

        // We need to calculate the time offsite and cast it as an u64.
        // Since we only have times into the future and the totp generator needs an u64 instead of the default i64.
        let time = (current_timestamp + step * 30i64) as u64;
        let generated = totp_custom::<Sha1>(30, 6, &decoded_secret, time);

        // Check the the given code equals the generated and if the time_step is larger then the one last used.
        if generated == totp_code && time_step > twofactor.last_used as i64 {
            // If the step does not equals 0 the time is drifted either server or client side.
            if step != 0 {
                warn!("TOTP Time drift detected. The step offset is {}", step);
            }

            // Save the last used time step so only totp time steps higher then this one are allowed.
            // This will also save a newly created twofactor if the code is correct.
            twofactor.last_used = time_step as i32;
            twofactor.save(conn)?;
            return Ok(());
        } else if generated == totp_code && time_step <= twofactor.last_used as i64 {
            warn!("This TOTP or a TOTP code within {} steps back or forward has already been used!", steps);
            err!(format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip));
        }
    }

    // Else no valide code received, deny access
    err!(format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip.ip));
}
