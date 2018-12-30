use rocket::request::{Form, FormItems, FromForm};
use rocket::Route;

use rocket_contrib::json::Json;
use serde_json::Value;

use num_traits::FromPrimitive;

use crate::db::models::*;
use crate::db::DbConn;

use crate::util::{self, JsonMap};

use crate::api::{ApiResult, EmptyResult, JsonResult};

use crate::auth::ClientIp;

use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![login]
}

#[post("/connect/token", data = "<data>")]
fn login(data: Form<ConnectData>, conn: DbConn, ip: ClientIp) -> JsonResult {
    let data: ConnectData = data.into_inner();

    match data.grant_type.as_ref() {
        "refresh_token" => {
            _check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            _refresh_login(data, conn)
        }
        "password" => {
            _check_is_some(&data.client_id, "client_id cannot be blank")?;
            _check_is_some(&data.password, "password cannot be blank")?;
            _check_is_some(&data.scope, "scope cannot be blank")?;
            _check_is_some(&data.username, "username cannot be blank")?;

            _check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            _check_is_some(&data.device_name, "device_name cannot be blank")?;
            _check_is_some(&data.device_type, "device_type cannot be blank")?;

            _password_login(data, conn, ip)
        }
        t => err!("Invalid type", t),
    }
}

fn _refresh_login(data: ConnectData, conn: DbConn) -> JsonResult {
    // Extract token
    let token = data.refresh_token.unwrap();

    // Get device by refresh token
    let mut device = match Device::find_by_refresh_token(&token, &conn) {
        Some(device) => device,
        None => err!("Invalid refresh token"),
    };

    // COMMON
    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let orgs = UserOrganization::find_by_user(&user.uuid, &conn);

    let (access_token, expires_in) = device.refresh_tokens(&user, orgs);

    device.save(&conn)?;
    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.key,
        "PrivateKey": user.private_key,
    })))
}

fn _password_login(data: ConnectData, conn: DbConn, ip: ClientIp) -> JsonResult {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }

    // Get the user
    let username = data.username.as_ref().unwrap();
    let user = match User::find_by_mail(username, &conn) {
        Some(user) => user,
        None => err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {}.", ip.ip, username)
        ),
    };

    // Check password
    let password = data.password.as_ref().unwrap();
    if !user.check_valid_password(password) {
        err!(
            "Username or password is incorrect. Try again",
            format!("IP: {}. Username: {}.", ip.ip, username)
        )
    }

    // On iOS, device_type sends "iOS", on others it sends a number
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(0);
    let device_id = data.device_identifier.clone().expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    // Find device or create new
    let mut device = match Device::find_by_uuid(&device_id, &conn) {
        Some(device) => {
            // Check if owned device, and recreate if not
            if device.user_uuid != user.uuid {
                info!("Device exists but is owned by another user. The old device will be discarded");
                Device::new(device_id, user.uuid.clone(), device_name, device_type)
            } else {
                device
            }
        }
        None => Device::new(device_id, user.uuid.clone(), device_name, device_type),
    };

    let twofactor_token = twofactor_auth(&user.uuid, &data.clone(), &mut device, &conn)?;

    // Common
    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let orgs = UserOrganization::find_by_user(&user.uuid, &conn);

    let (access_token, expires_in) = device.refresh_tokens(&user, orgs);
    device.save(&conn)?;

    let mut result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.key,
        "PrivateKey": user.private_key,
        //"TwoFactorToken": "11122233333444555666777888999"
    });

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", username, ip.ip);
    Ok(Json(result))
}

fn twofactor_auth(
    user_uuid: &str,
    data: &ConnectData,
    device: &mut Device,
    conn: &DbConn,
) -> ApiResult<Option<String>> {
    let twofactors_raw = TwoFactor::find_by_user(user_uuid, conn);
    // Remove u2f challenge twofactors (impl detail)
    let twofactors: Vec<_> = twofactors_raw.iter().filter(|tf| tf.type_ < 1000).collect();

    let providers: Vec<_> = twofactors.iter().map(|tf| tf.type_).collect();

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        return Ok(None);
    }

    let provider = data.two_factor_provider.unwrap_or(providers[0]); // If we aren't given a two factor provider, asume the first one

    let twofactor_code = match data.two_factor_token {
        Some(ref code) => code,
        None => err_json!(_json_err_twofactor(&providers, user_uuid, conn)?),
    };

    let twofactor = twofactors.iter().filter(|tf| tf.type_ == provider).nth(0);

    match TwoFactorType::from_i32(provider) {
        Some(TwoFactorType::Remember) => {
            match device.twofactor_remember {
                Some(ref remember) if remember == twofactor_code => return Ok(None), // No twofactor token needed here
                _ => err_json!(_json_err_twofactor(&providers, user_uuid, conn)?),
            }
        }

        Some(TwoFactorType::Authenticator) => {
            let twofactor = match twofactor {
                Some(tf) => tf,
                None => err!("TOTP not enabled"),
            };

            let totp_code: u64 = match twofactor_code.parse() {
                Ok(code) => code,
                _ => err!("Invalid TOTP code"),
            };

            if !twofactor.check_totp_code(totp_code) {
                err_json!(_json_err_twofactor(&providers, user_uuid, conn)?)
            }
        }

        Some(TwoFactorType::U2f) => {
            use crate::api::core::two_factor;

            two_factor::validate_u2f_login(user_uuid, &twofactor_code, conn)?;
        }

        Some(TwoFactorType::YubiKey) => {
            use crate::api::core::two_factor;

            two_factor::validate_yubikey_login(user_uuid, twofactor_code, conn)?;
        }

        _ => err!("Invalid two factor provider"),
    }

    if data.two_factor_remember.unwrap_or(0) == 1 {
        Ok(Some(device.refresh_twofactor_remember()))
    } else {
        device.delete_twofactor_remember();
        Ok(None)
    }
}

fn _json_err_twofactor(providers: &[i32], user_uuid: &str, conn: &DbConn) -> ApiResult<Value> {
    use crate::api::core::two_factor;

    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers,
        "TwoFactorProviders2" : {} // { "0" : null }
    });

    for provider in providers {
        result["TwoFactorProviders2"][provider.to_string()] = Value::Null;

        match TwoFactorType::from_i32(*provider) {
            Some(TwoFactorType::Authenticator) => { /* Nothing to do for TOTP */ }

            Some(TwoFactorType::U2f) if CONFIG.domain_set => {
                let request = two_factor::generate_u2f_login(user_uuid, conn)?;
                let mut challenge_list = Vec::new();

                for key in request.registered_keys {
                    let mut challenge_map = JsonMap::new();

                    challenge_map.insert("appId".into(), Value::String(request.app_id.clone()));
                    challenge_map.insert("challenge".into(), Value::String(request.challenge.clone()));
                    challenge_map.insert("version".into(), Value::String(key.version));
                    challenge_map.insert("keyHandle".into(), Value::String(key.key_handle.unwrap_or_default()));

                    challenge_list.push(Value::Object(challenge_map));
                }

                let mut map = JsonMap::new();
                use serde_json;
                let challenge_list_str = serde_json::to_string(&challenge_list).unwrap();

                map.insert("Challenges".into(), Value::String(challenge_list_str));
                result["TwoFactorProviders2"][provider.to_string()] = Value::Object(map);
            }

            Some(tf_type @ TwoFactorType::YubiKey) => {
                let twofactor = match TwoFactor::find_by_user_and_type(user_uuid, tf_type as i32, &conn) {
                    Some(tf) => tf,
                    None => err!("No YubiKey devices registered"),
                };

                let yubikey_metadata: two_factor::YubikeyMetadata =
                    serde_json::from_str(&twofactor.data).expect("Can't parse Yubikey Metadata");

                let mut map = JsonMap::new();
                map.insert("Nfc".into(), Value::Bool(yubikey_metadata.Nfc));
                result["TwoFactorProviders2"][provider.to_string()] = Value::Object(map);
            }

            _ => {}
        }
    }

    Ok(result)
}

#[derive(Debug, Clone, Default)]
#[allow(non_snake_case)]
struct ConnectData {
    grant_type: String, // refresh_token, password

    // Needed for grant_type="refresh_token"
    refresh_token: Option<String>,

    // Needed for grant_type="password"
    client_id: Option<String>, // web, cli, desktop, browser, mobile
    password: Option<String>,
    scope: Option<String>,
    username: Option<String>,

    device_identifier: Option<String>,
    device_name: Option<String>,
    device_type: Option<String>,

    // Needed for two-factor auth
    two_factor_provider: Option<i32>,
    two_factor_token: Option<String>,
    two_factor_remember: Option<i32>,
}

impl<'f> FromForm<'f> for ConnectData {
    type Error = String;

    fn from_form(items: &mut FormItems<'f>, _strict: bool) -> Result<Self, Self::Error> {
        let mut form = Self::default();
        for item in items {
            let (key, value) = item.key_value_decoded();
            let mut normalized_key = key.to_lowercase();
            normalized_key.retain(|c| c != '_'); // Remove '_'

            match normalized_key.as_ref() {
                "granttype" => form.grant_type = value,
                "refreshtoken" => form.refresh_token = Some(value),
                "clientid" => form.client_id = Some(value),
                "password" => form.password = Some(value),
                "scope" => form.scope = Some(value),
                "username" => form.username = Some(value),
                "deviceidentifier" => form.device_identifier = Some(value),
                "devicename" => form.device_name = Some(value),
                "devicetype" => form.device_type = Some(value),
                "twofactorprovider" => form.two_factor_provider = value.parse().ok(),
                "twofactortoken" => form.two_factor_token = Some(value),
                "twofactorremember" => form.two_factor_remember = value.parse().ok(),
                key => warn!("Detected unexpected parameter during login: {}", key),
            }
        }

        Ok(form)
    }
}

fn _check_is_some<T>(value: &Option<T>, msg: &str) -> EmptyResult {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}
