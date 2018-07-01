use std::collections::HashMap;

use rocket::{Route, Outcome};
use rocket::request::{self, Request, FromRequest, Form, FormItems, FromForm};

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use util;

use api::JsonResult;

pub fn routes() -> Vec<Route> {
    routes![ login]
}

#[post("/connect/token", data = "<connect_data>")]
fn login(connect_data: Form<ConnectData>, device_type: DeviceType, conn: DbConn) -> JsonResult {
    let data = connect_data.get();

    match data.grant_type {
        GrantType::RefreshToken =>_refresh_login(data, device_type, conn),
        GrantType::Password => _password_login(data, device_type, conn)
    }
}

fn _refresh_login(data: &ConnectData, _device_type: DeviceType, conn: DbConn) -> JsonResult {
    // Extract token
    let token = data.get("refresh_token");

    // Get device by refresh token
    let mut device = match Device::find_by_refresh_token(token, &conn) {
        Some(device) => device,
        None => err!("Invalid refresh token")
    };

    // COMMON
    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let orgs = UserOrganization::find_by_user(&user.uuid, &conn);

    let (access_token, expires_in) = device.refresh_tokens(&user, orgs);
    device.save(&conn);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.key,
        "PrivateKey": user.private_key,
    })))
}

fn _password_login(data: &ConnectData, device_type: DeviceType, conn: DbConn) -> JsonResult {
    // Validate scope
    let scope = data.get("scope");
    if scope != "api offline_access" {
        err!("Scope not supported")
    }

    // Get the user
    let username = data.get("username");
    let user = match User::find_by_mail(username, &conn) {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again.")
    };

    // Check password
    let password = data.get("password");
    if !user.check_valid_password(password) {
        err!("Username or password is incorrect. Try again.")
    }
    
    // Let's only use the header and ignore the 'devicetype' parameter
    let device_type_num = device_type.0;

    let (device_id, device_name) = if data.is_device {
        (
            data.get("deviceidentifier").clone(),
            data.get("devicename").clone(),
        )
    } else {
        (format!("web-{}", user.uuid), String::from("web"))
    };

    // Find device or create new
    let mut device = match Device::find_by_uuid(&device_id, &conn) {
        Some(device) => {
            // Check if valid device
            if device.user_uuid != user.uuid {
                device.delete(&conn);
                err!("Device is not owned by user")
            }

            device
        }
        None => {
            // Create new device
            Device::new(device_id, user.uuid.clone(), device_name, device_type_num)
        }
    };

    let twofactor_token = if user.requires_twofactor() {
        let twofactor_provider = util::parse_option_string(data.get_opt("twoFactorProvider")).unwrap_or(0);
        let twofactor_code = match data.get_opt("twoFactorToken") {
            Some(code) => code,
            None => err_json!(_json_err_twofactor())
        };

       match twofactor_provider {
            0 /* TOTP */ => { 
                let totp_code: u64 = match twofactor_code.parse() {
                    Ok(code) => code,
                    Err(_) => err!("Invalid Totp code")
                };

                if !user.check_totp_code(totp_code) {
                    err_json!(_json_err_twofactor())
                }

                if util::parse_option_string(data.get_opt("twoFactorRemember")).unwrap_or(0) == 1 {
                    device.refresh_twofactor_remember();
                    device.twofactor_remember.clone()
                } else {
                    device.delete_twofactor_remember();
                    None
                }
            },
            5 /* Remember */ => {
                match device.twofactor_remember {
                    Some(ref remember) if remember == twofactor_code => (),
                    _ => err_json!(_json_err_twofactor())
                };
                None // No twofactor token needed here
            },
            _ => err!("Invalid two factor provider"),
        }
    } else { None };  // No twofactor token if twofactor is disabled

    // Common
    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let orgs = UserOrganization::find_by_user(&user.uuid, &conn);

    let (access_token, expires_in) = device.refresh_tokens(&user, orgs);
    device.save(&conn);

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

    Ok(Json(result))
}

fn _json_err_twofactor() -> Value {
    json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : [ 0 ],
        "TwoFactorProviders2" : { "0" : null }
    })
}

#[derive(Clone, Copy)]
struct DeviceType(i32);

impl<'a, 'r> FromRequest<'a, 'r> for DeviceType {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let headers = request.headers();
        let type_opt = headers.get_one("Device-Type");
        let type_num = util::parse_option_string(type_opt).unwrap_or(0);

        Outcome::Success(DeviceType(type_num))
    }
}


#[derive(Debug)]
struct ConnectData {
    grant_type: GrantType,
    is_device: bool,
    data: HashMap<String, String>,
}

#[derive(Debug, Copy, Clone)]
enum GrantType { RefreshToken, Password }

impl ConnectData {
    fn get(&self, key: &str) -> &String {
        &self.data[&key.to_lowercase()]
    }

    fn get_opt(&self, key: &str) -> Option<&String> {
        self.data.get(&key.to_lowercase())
    }
}

const VALUES_REFRESH: [&str; 1] = ["refresh_token"];
const VALUES_PASSWORD: [&str; 5] = ["client_id", "grant_type", "password", "scope", "username"];
const VALUES_DEVICE: [&str; 3] = ["deviceidentifier", "devicename", "devicetype"];

impl<'f> FromForm<'f> for ConnectData {
    type Error = String;

    fn from_form(items: &mut FormItems<'f>, _strict: bool) -> Result<Self, Self::Error> {
        let mut data = HashMap::new();

        // Insert data into map
        for (key, value) in items {
            match (key.url_decode(), value.url_decode()) {
                (Ok(key), Ok(value)) => data.insert(key.to_lowercase(), value),
                _ => return Err("Error decoding key or value".to_string()),
            };
        }

        // Validate needed values
        let (grant_type, is_device) =
            match data.get("grant_type").map(String::as_ref) {
                Some("refresh_token") => {
                    check_values(&data, &VALUES_REFRESH)?;
                    (GrantType::RefreshToken, false) // Device doesn't matter here
                }
                Some("password") => {
                    check_values(&data, &VALUES_PASSWORD)?;

                    let is_device = match data["client_id"].as_ref() {
                        "browser" | "mobile" => check_values(&data, &VALUES_DEVICE)?,
                        _ => false
                    };
                    (GrantType::Password, is_device)
                }
                _ => return Err("Grant type not supported".to_string())
            };

        Ok(ConnectData { grant_type, is_device, data })
    }
}

fn check_values(map: &HashMap<String, String>, values: &[&str]) -> Result<bool, String> {
    for value in values {
        if !map.contains_key(*value) {
            return Err(format!("{} cannot be blank", value));
        }
    }
    Ok(true)
}
