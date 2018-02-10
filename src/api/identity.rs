use std::collections::HashMap;

use rocket::Route;
use rocket::request::{Form, FormItems, FromForm};
use rocket::response::status::BadRequest;

use rocket_contrib::Json;

use db::DbConn;
use db::models::*;
use util;

pub fn routes() -> Vec<Route> {
    routes![ login]
}

#[post("/connect/token", data = "<connect_data>")]
fn login(connect_data: Form<ConnectData>, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let data = connect_data.get();
    println!("{:#?}", data);

    let mut device = match data.grant_type {
        GrantType::RefreshToken => {
            // Extract token
            let token = data.get("refresh_token").unwrap();

            // Get device by refresh token
            match Device::find_by_refresh_token(token, &conn) {
                Some(device) => device,
                None => err!("Invalid refresh token")
            }
        }
        GrantType::Password => {
            // Validate scope
            let scope = data.get("scope").unwrap();
            if scope != "api offline_access" {
                err!("Scope not supported")
            }

            // Get the user
            let username = data.get("username").unwrap();
            let user = match User::find_by_mail(username, &conn) {
                Some(user) => user,
                None => err!("Invalid username or password")
            };

            // Check password
            let password = data.get("password").unwrap();
            if !user.check_valid_password(password) {
                err!("Invalid username or password")
            }

            /*
            //TODO: When invalid username or password, return this with a 400 BadRequest:
            {
              "error": "invalid_grant",
              "error_description": "invalid_username_or_password",
              "ErrorModel": {
                "Message": "Username or password is incorrect. Try again.",
                "ValidationErrors": null,
                "ExceptionMessage": null,
                "ExceptionStackTrace": null,
                "InnerExceptionMessage": null,
                "Object": "error"
              }
            }
            */

            // Check if totp code is required and the value is correct
            let totp_code = util::parse_option_string(data.get("twoFactorToken").map(String::as_ref));

            if !user.check_totp_code(totp_code) {
                // Return error 400
                return err_json!(json!({
                        "error" : "invalid_grant",
                        "error_description" : "Two factor required.",
                        "TwoFactorProviders" : [ 0 ],
                        "TwoFactorProviders2" : { "0" : null }
                    }));
            }

            // Let's only use the header and ignore the 'devicetype' parameter
            // TODO Get header Device-Type
            let device_type_num = 0;// headers.device_type;

            let (device_id, device_name) = match data.get("client_id").unwrap().as_ref() {
                "web" => { (format!("web-{}", user.uuid), String::from("web")) }
                "browser" | "mobile" => {
                    (
                        data.get("deviceidentifier").unwrap().clone(),
                        data.get("devicename").unwrap().clone(),
                    )
                }
                _ => err!("Invalid client id")
            };

            // Find device or create new
            let device = match Device::find_by_uuid(&device_id, &conn) {
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
                    Device::new(device_id, user.uuid, device_name, device_type_num)
                }
            };


            device
        }
    };

    let user = User::find_by_uuid(&device.user_uuid, &conn).unwrap();
    let (access_token, expires_in) = device.refresh_tokens(&user);
    device.save(&conn);

    // TODO: when to include :privateKey and :TwoFactorToken?
    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.key,
        "PrivateKey": user.private_key
    })))
}

#[derive(Debug)]
struct ConnectData {
    grant_type: GrantType,
    data: HashMap<String, String>,
}

impl ConnectData {
    fn get(&self, key: &str) -> Option<&String> {
        self.data.get(&key.to_lowercase())
    }
}

#[derive(Debug, Copy, Clone)]
enum GrantType { RefreshToken, Password }


const VALUES_REFRESH: [&str; 1] = ["refresh_token"];

const VALUES_PASSWORD: [&str; 5] = ["client_id",
    "grant_type", "password", "scope", "username"];

const VALUES_DEVICE: [&str; 3] = ["deviceidentifier",
    "devicename", "devicetype"];


impl<'f> FromForm<'f> for ConnectData {
    type Error = String;

    fn from_form(items: &mut FormItems<'f>, strict: bool) -> Result<Self, Self::Error> {
        let mut data = HashMap::new();

        // Insert data into map
        for (key, value) in items {
            let decoded_key: String = match key.url_decode() {
                Ok(decoded) => decoded,
                Err(e) => return Err(format!("Error decoding key: {}", value)),
            };

            let decoded_value: String = match value.url_decode() {
                Ok(decoded) => decoded,
                Err(e) => return Err(format!("Error decoding value: {}", value)),
            };

            data.insert(decoded_key.to_lowercase(), decoded_value);
        }

        // Validate needed values
        let grant_type =
            match data.get("grant_type").map(|s| &s[..]) {
                Some("refresh_token") => {
                    // Check if refresh token is proviced
                    if let Err(msg) = check_values(&data, &VALUES_REFRESH) {
                        return Err(msg);
                    }

                    GrantType::RefreshToken
                }
                Some("password") => {
                    // Check if basic values are provided
                    if let Err(msg) = check_values(&data, &VALUES_PASSWORD) {
                        return Err(msg);
                    }

                    // Check that device values are present on device
                    match data.get("client_id").unwrap().as_ref() {
                        "browser" | "mobile" => {
                            if let Err(msg) = check_values(&data, &VALUES_DEVICE) {
                                return Err(msg);
                            }
                        }
                        _ => {}
                    }

                    GrantType::Password
                }

                _ => return Err(format!("Grant type not supported"))
            };

        Ok(ConnectData { grant_type, data })
    }
}

fn check_values(map: &HashMap<String, String>, values: &[&str]) -> Result<(), String> {
    for value in values {
        if !map.contains_key(*value) {
            return Err(format!("{} cannot be blank", value));
        }
    }

    Ok(())
}