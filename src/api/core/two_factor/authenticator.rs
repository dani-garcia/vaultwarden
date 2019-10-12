use data_encoding::BASE32;
use rocket::Route;
use rocket_contrib::json::Json;

use crate::api::core::two_factor::_generate_recover_code;
use crate::api::{EmptyResult, JsonResult, JsonUpcase, NumberOrString, PasswordData};
use crate::auth::Headers;
use crate::crypto;
use crate::db::{
    models::{TwoFactor, TwoFactorType},
    DbConn,
};

pub fn routes() -> Vec<Route> {
    routes![
        generate_authenticator,
        activate_authenticator,
        activate_authenticator_put,
    ]
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
fn activate_authenticator(data: JsonUpcase<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableAuthenticatorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let key = data.Key;
    let token = data.Token.into_i32()? as u64;

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

    let type_ = TwoFactorType::Authenticator;
    let twofactor = TwoFactor::new(user.uuid.clone(), type_, key.to_uppercase());

    // Validate the token provided with the key
    validate_totp_code(&user.uuid, token, &twofactor.data, &conn)?;

    _generate_recover_code(&mut user, &conn);
    twofactor.save(&conn)?;

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[put("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator_put(data: JsonUpcase<EnableAuthenticatorData>, headers: Headers, conn: DbConn) -> JsonResult {
    activate_authenticator(data, headers, conn)
}

pub fn validate_totp_code_str(user_uuid: &str, totp_code: &str, secret: &str, conn: &DbConn) -> EmptyResult {
    let totp_code: u64 = match totp_code.parse() {
        Ok(code) => code,
        _ => err!("TOTP code is not a number"),
    };

    validate_totp_code(user_uuid, totp_code, secret, &conn)
}

pub fn validate_totp_code(user_uuid: &str, totp_code: u64, secret: &str, conn: &DbConn) -> EmptyResult {
    use oath::{totp_raw_custom_time, HashType};
    use std::time::{UNIX_EPOCH, SystemTime};

    let decoded_secret = match BASE32.decode(secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid TOTP secret"),
    };

    let mut twofactor = TwoFactor::find_by_user_and_type(&user_uuid, TwoFactorType::Authenticator as i32, &conn)?;

    // Get the current system time in UNIX Epoch (UTC)
    let current_time: u64 = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("Earlier than 1970-01-01 00:00:00 UTC").as_secs();

    // The amount of steps back and forward in time
    let steps = 1;
    for step in -steps..=steps {

        let time_step = (current_time / 30) as i32 + step;
        // We need to calculate the time offsite and cast it as an i128.
        // Else we can't do math with it on a default u64 variable.
        let time_offset: i128 = (step * 30).into();
        let generated = totp_raw_custom_time(&decoded_secret, 6, 0, 30, (current_time as i128 + time_offset) as u64, &HashType::SHA1);

        // Check the the given code equals the generated and if the time_step is larger then the one last used.
        if generated == totp_code && time_step > twofactor.last_used {

            // If the step does not equals 0 the time is drifted either server or client side.
            if step != 0 {
                info!("TOTP Time drift detected. The step offset is {}", step);
            }

            // Save the last used time step so only totp time steps higher then this one are allowed.
            twofactor.last_used = time_step;
            twofactor.save(&conn)?;
            return Ok(());
        } else if generated == totp_code && time_step <= twofactor.last_used {
            warn!("This or a TOTP code within {} steps back and forward has already been used!", steps);
            err!("Invalid TOTP Code!");
        }
    }

    // Else no valide code received, deny access
    err!("Invalid TOTP code!");
}
