use rocket_contrib::{Json, Value};

use data_encoding::BASE32;

use db::DbConn;

use crypto;

use api::{PasswordData, JsonResult, NumberOrString};
use auth::Headers;

#[get("/two-factor")]
fn get_twofactor(headers: Headers) -> JsonResult {
    let data = if headers.user.totp_secret.is_none() {
        Value::Null
    } else {
        json!([{
            "Enabled": true,
            "Type": 0,
            "Object": "twoFactorProvider"
        }])
    };

    Ok(Json(json!({
        "Data": data,
        "Object": "list"
    })))
}

#[post("/two-factor/get-recover", data = "<data>")]
fn get_recover(data: Json<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner();

    if !headers.user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": headers.user.totp_recover,
        "Object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RecoverTwoFactor {
    masterPasswordHash: String,
    email: String,
    recoveryCode: String,
}

#[post("/two-factor/recover", data = "<data>")]
fn recover(data: Json<RecoverTwoFactor>, conn: DbConn) -> JsonResult {
    let data: RecoverTwoFactor = data.into_inner();

    use db::models::User;

    // Get the user
    let mut user = match User::find_by_mail(&data.email, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again.")
    };

    // Check password
    if !user.check_valid_password(&data.masterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.recoveryCode) {
        err!("Recovery code is incorrect. Try again.")
    }

    user.totp_secret = None;
    user.totp_recover = None;
    user.save(&conn);

    Ok(Json(json!({})))
}

#[post("/two-factor/get-authenticator", data = "<data>")]
fn generate_authenticator(data: Json<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner();

    if !headers.user.check_valid_password(&data.masterPasswordHash) {
        err!("Invalid password");
    }

    let (enabled, key) = match headers.user.totp_secret {
        Some(secret) => (true, secret),
        _ => (false, BASE32.encode(&crypto::get_random(vec![0u8; 20])))
    };

    Ok(Json(json!({
        "Enabled": enabled,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EnableTwoFactorData {
    masterPasswordHash: String,
    key: String,
    token: NumberOrString,
}

#[post("/two-factor/authenticator", data = "<data>")]
fn activate_authenticator(data: Json<EnableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: EnableTwoFactorData = data.into_inner();
    let password_hash = data.masterPasswordHash;
    let key = data.key;
    let token = match data.token.to_i32() {
        Some(n) => n as u64,
        None => err!("Malformed token")
    };

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = match BASE32.decode(key.as_bytes()) {
        Ok(decoded) => decoded,
        _ => err!("Invalid totp secret")
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    // Set key in user.totp_secret
    let mut user = headers.user;
    user.totp_secret = Some(key.to_uppercase());

    // Validate the token provided with the key
    if !user.check_totp_code(Some(token)) {
        err!("Invalid totp code")
    }

    // Generate totp_recover
    let totp_recover = BASE32.encode(&crypto::get_random(vec![0u8; 20]));
    user.totp_recover = Some(totp_recover);

    user.save(&conn);

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DisableTwoFactorData {
    masterPasswordHash: String,
    #[serde(rename = "type")]
    _type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
fn disable_authenticator(data: Json<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner();
    let password_hash = data.masterPasswordHash;

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let mut user = headers.user;
    user.totp_secret = None;
    user.totp_recover = None;

    user.save(&conn);

    Ok(Json(json!({
        "Enabled": false,
        "Type": 0,
        "Object": "twoFactorProvider"
    })))
}
