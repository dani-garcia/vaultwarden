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
    validate_totp_code(token, &twofactor.data)?;

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

pub fn validate_totp_code_str(totp_code: &str, secret: &str) -> EmptyResult {
    let totp_code: u64 = match totp_code.parse() {
        Ok(code) => code,
        _ => err!("TOTP code is not a number"),
    };

    validate_totp_code(totp_code, secret)
}

pub fn validate_totp_code(totp_code: u64, secret: &str) -> EmptyResult {
    use oath::{totp_raw_now, HashType};

    let decoded_secret = match BASE32.decode(secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid TOTP secret"),
    };

    let generated = totp_raw_now(&decoded_secret, 6, 0, 30, &HashType::SHA1);
    if generated != totp_code {
        err!("Invalid TOTP code");
    }

    Ok(())
}
