//
// JWT Handling
//
use crate::util::read_file;
use chrono::Duration;

use jsonwebtoken::{self, Algorithm, Header};
use serde::ser::Serialize;

use crate::error::{Error, MapResult};
use crate::CONFIG;

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

lazy_static! {
    pub static ref DEFAULT_VALIDITY: Duration = Duration::hours(2);
    pub static ref JWT_ISSUER: String = CONFIG.domain.clone();
    static ref JWT_HEADER: Header = Header::new(JWT_ALGORITHM);
    static ref PRIVATE_RSA_KEY: Vec<u8> = match read_file(&CONFIG.private_rsa_key) {
        Ok(key) => key,
        Err(e) => panic!(
            "Error loading private RSA Key from {}\n Error: {}",
            CONFIG.private_rsa_key, e
        ),
    };
    static ref PUBLIC_RSA_KEY: Vec<u8> = match read_file(&CONFIG.public_rsa_key) {
        Ok(key) => key,
        Err(e) => panic!(
            "Error loading public RSA Key from {}\n Error: {}",
            CONFIG.public_rsa_key, e
        ),
    };
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jsonwebtoken::encode(&JWT_HEADER, claims, &PRIVATE_RSA_KEY) {
        Ok(token) => token,
        Err(e) => panic!("Error encoding jwt {}", e),
    }
}

pub fn decode_jwt(token: &str) -> Result<JWTClaims, Error> {
    let validation = jsonwebtoken::Validation {
        leeway: 30, // 30 seconds
        validate_exp: true,
        validate_iat: false, // IssuedAt is the same as NotBefore
        validate_nbf: true,
        aud: None,
        iss: Some(JWT_ISSUER.clone()),
        sub: None,
        algorithms: vec![JWT_ALGORITHM],
    };

    jsonwebtoken::decode(token, &PUBLIC_RSA_KEY, &validation)
        .map(|d| d.claims)
        .map_res("Error decoding login JWT")
}

pub fn decode_invite_jwt(token: &str) -> Result<InviteJWTClaims, Error> {
    let validation = jsonwebtoken::Validation {
        leeway: 30, // 30 seconds
        validate_exp: true,
        validate_iat: false, // IssuedAt is the same as NotBefore
        validate_nbf: true,
        aud: None,
        iss: Some(JWT_ISSUER.clone()),
        sub: None,
        algorithms: vec![JWT_ALGORITHM],
    };

    jsonwebtoken::decode(token, &PUBLIC_RSA_KEY, &validation)
        .map(|d| d.claims)
        .map_res("Error decoding invite JWT")
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

    pub orgowner: Vec<String>,
    pub orgadmin: Vec<String>,
    pub orguser: Vec<String>,
    pub orgmanager: Vec<String>,

    // user security_stamp
    pub sstamp: String,
    // device uuid
    pub device: String,
    // [ "api", "offline_access" ]
    pub scope: Vec<String>,
    // [ "Application" ]
    pub amr: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteJWTClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub email: String,
    pub org_id: String,
    pub user_org_id: Option<String>,
}

//
// Bearer token authentication
//
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;

use crate::db::models::{Device, User, UserOrgStatus, UserOrgType, UserOrganization};
use crate::db::DbConn;

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
        let host = if CONFIG.domain_set {
            CONFIG.domain.clone()
        } else if let Some(referer) = headers.get_one("Referer") {
            referer.to_string()
        } else {
            // Try to guess from the headers
            use std::env;

            let protocol = if let Some(proto) = headers.get_one("X-Forwarded-Proto") {
                proto
            } else if env::var("ROCKET_TLS").is_ok() {
                "https"
            } else {
                "http"
            };

            let host = if let Some(host) = headers.get_one("X-Forwarded-Host") {
                host
            } else if let Some(host) = headers.get_one("Host") {
                host
            } else {
                ""
            };

            format!("{}://{}", protocol, host)
        };

        // Get access_token
        let access_token: &str = match headers.get_one("Authorization") {
            Some(a) => match a.rsplit("Bearer ").next() {
                Some(split) => split,
                None => err_handler!("No access token provided"),
            },
            None => err_handler!("No access token provided"),
        };

        // Check JWT token is valid and get device and user from it
        let claims: JWTClaims = match decode_jwt(access_token) {
            Ok(claims) => claims,
            Err(_) => err_handler!("Invalid claim"),
        };

        let device_uuid = claims.device;
        let user_uuid = claims.sub;

        let conn = match request.guard::<DbConn>() {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB"),
        };

        let device = match Device::find_by_uuid(&device_uuid, &conn) {
            Some(device) => device,
            None => err_handler!("Invalid device id"),
        };

        let user = match User::find_by_uuid(&user_uuid, &conn) {
            Some(user) => user,
            None => err_handler!("Device has no user associated"),
        };

        if user.security_stamp != claims.sstamp {
            err_handler!("Invalid security stamp")
        }

        Outcome::Success(Headers { host, device, user })
    }
}

pub struct OrgHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
}

impl<'a, 'r> FromRequest<'a, 'r> for OrgHeaders {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match request.guard::<Headers>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                // org_id is expected to be the second param ("/organizations/<org_id>")
                match request.get_param::<String>(1) {
                    Some(Ok(org_id)) => {
                        let conn = match request.guard::<DbConn>() {
                            Outcome::Success(conn) => conn,
                            _ => err_handler!("Error getting DB"),
                        };

                        let user = headers.user;
                        let org_user = match UserOrganization::find_by_user_and_org(&user.uuid, &org_id, &conn) {
                            Some(user) => {
                                if user.status == UserOrgStatus::Confirmed as i32 {
                                    user
                                } else {
                                    err_handler!("The current user isn't confirmed member of the organization")
                                }
                            }
                            None => err_handler!("The current user isn't member of the organization"),
                        };

                        Outcome::Success(Self {
                            host: headers.host,
                            device: headers.device,
                            user,
                            org_user_type: {
                                if let Some(org_usr_type) = UserOrgType::from_i32(org_user.type_) {
                                    org_usr_type
                                } else {
                                    // This should only happen if the DB is corrupted
                                    err_handler!("Unknown user type in the database")
                                }
                            },
                        })
                    }
                    _ => err_handler!("Error getting the organization id"),
                }
            }
        }
    }
}

pub struct AdminHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
}

impl<'a, 'r> FromRequest<'a, 'r> for AdminHeaders {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match request.guard::<OrgHeaders>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                if headers.org_user_type >= UserOrgType::Admin {
                    Outcome::Success(Self {
                        host: headers.host,
                        device: headers.device,
                        user: headers.user,
                        org_user_type: headers.org_user_type,
                    })
                } else {
                    err_handler!("You need to be Admin or Owner to call this endpoint")
                }
            }
        }
    }
}

pub struct OwnerHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
}

impl<'a, 'r> FromRequest<'a, 'r> for OwnerHeaders {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match request.guard::<OrgHeaders>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                if headers.org_user_type == UserOrgType::Owner {
                    Outcome::Success(Self {
                        host: headers.host,
                        device: headers.device,
                        user: headers.user,
                    })
                } else {
                    err_handler!("You need to be Owner to call this endpoint")
                }
            }
        }
    }
}

//
// Client IP address detection
//
use std::net::IpAddr;

pub struct ClientIp {
    pub ip: IpAddr,
}

impl<'a, 'r> FromRequest<'a, 'r> for ClientIp {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let ip = match request.client_ip() {
            Some(addr) => addr,
            None => "0.0.0.0".parse().unwrap(),
        };

        Outcome::Success(ClientIp { ip })
    }
}
