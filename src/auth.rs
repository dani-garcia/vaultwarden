///
/// JWT Handling
///

use util::read_file;
use time::Duration;

use jwt;
use serde::ser::Serialize;

use CONFIG;

const JWT_ALGORITHM: jwt::Algorithm = jwt::Algorithm::RS256;
pub const JWT_ISSUER: &'static str = "localhost:8000/identity";

lazy_static! {
    pub static ref DEFAULT_VALIDITY: Duration = Duration::hours(2);
    static ref JWT_HEADER: jwt::Header = jwt::Header::new(JWT_ALGORITHM);

    static ref PRIVATE_RSA_KEY: Vec<u8> = match read_file(&CONFIG.private_rsa_key) {
        Ok(key) => key,
        Err(e) => panic!("Error loading private RSA Key from {}\n Error: {}", CONFIG.private_rsa_key, e)
    };

    static ref PUBLIC_RSA_KEY: Vec<u8> = match read_file(&CONFIG.public_rsa_key) {
        Ok(key) => key,
        Err(e) => panic!("Error loading public RSA Key from {}\n Error: {}", CONFIG.public_rsa_key, e)
    };
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jwt::encode(&JWT_HEADER, claims, &PRIVATE_RSA_KEY) {
        Ok(token) => return token,
        Err(e) => panic!("Error encoding jwt {}", e)
    };
}

pub fn decode_jwt(token: &str) -> Result<JWTClaims, String> {
    let validation = jwt::Validation {
        leeway: 30, // 30 seconds
        validate_exp: true,
        validate_iat: true,
        validate_nbf: true,
        aud: None,
        iss: Some(JWT_ISSUER.into()),
        sub: None,
        algorithms: vec![JWT_ALGORITHM],
    };

    match jwt::decode(token, &PUBLIC_RSA_KEY, &validation) {
        Ok(decoded) => Ok(decoded.claims),
        Err(msg) => {
            println!("Error validating jwt - {:#?}", msg);
            Err(msg.to_string())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JWTClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,

    // user security_stamp
    pub sstamp: String,
    // device uuid
    pub device: String,
    // [ "api", "offline_access" ]
    pub scope: Vec<String>,
    // [ "Application" ]
    pub amr: Vec<String>,
}

///
/// Bearer token authentication
///

use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};

use db::DbConn;
use db::models::{User, Device};

pub struct Headers {
    pub host: String,
    pub device: Device,
    pub user: User,
}

impl<'a, 'r> FromRequest<'a, 'r> for Headers {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get host
        let host = match headers.get_one("Host") {
            Some(host) => format!("http://{}", host), // TODO: Check if HTTPS
            _ => String::new()
        };

        // Get access_token
        let access_token: &str = match request.headers().get_one("Authorization") {
            Some(a) => {
                match a.rsplit("Bearer ").next() {
                    Some(split) => split,
                    None => err_handler!("No access token provided")
                }
            }
            None => err_handler!("No access token provided")
        };

        // Check JWT token is valid and get device and user from it
        let claims: JWTClaims = match decode_jwt(access_token) {
            Ok(claims) => claims,
            Err(_) => err_handler!("Invalid claim")
        };

        let device_uuid = claims.device;
        let user_uuid = claims.sub;

        let conn = match request.guard::<DbConn>() {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB")
        };

        let device = match Device::find_by_uuid(&device_uuid, &conn) {
            Some(device) => device,
            None => err_handler!("Invalid device id")
        };

        let user = match User::find_by_uuid(&user_uuid, &conn) {
            Some(user) => user,
            None => err_handler!("Device has no user associated")
        };

        if user.security_stamp != claims.sstamp {
            err_handler!("Invalid security stamp")
        }

        Outcome::Success(Headers { host, device, user })
    }
}