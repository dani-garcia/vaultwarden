//
// JWT Handling
//
use chrono::{Duration, Utc};
use num_traits::FromPrimitive;
use once_cell::sync::Lazy;

use jsonwebtoken::{self, Algorithm, DecodingKey, EncodingKey, Header};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use crate::{
    error::{Error, MapResult},
    util::read_file,
    CONFIG,
};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

pub static DEFAULT_VALIDITY: Lazy<Duration> = Lazy::new(|| Duration::hours(2));
static JWT_HEADER: Lazy<Header> = Lazy::new(|| Header::new(JWT_ALGORITHM));

pub static JWT_LOGIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|login", CONFIG.domain_origin()));
static JWT_INVITE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|invite", CONFIG.domain_origin()));
static JWT_EMERGENCY_ACCESS_INVITE_ISSUER: Lazy<String> =
    Lazy::new(|| format!("{}|emergencyaccessinvite", CONFIG.domain_origin()));
static JWT_DELETE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|delete", CONFIG.domain_origin()));
static JWT_VERIFYEMAIL_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|verifyemail", CONFIG.domain_origin()));
static JWT_ADMIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|admin", CONFIG.domain_origin()));
static JWT_SEND_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|send", CONFIG.domain_origin()));

static PRIVATE_RSA_KEY_VEC: Lazy<Vec<u8>> = Lazy::new(|| {
    read_file(&CONFIG.private_rsa_key()).unwrap_or_else(|e| panic!("Error loading private RSA Key.\n{}", e))
});
static PRIVATE_RSA_KEY: Lazy<EncodingKey> = Lazy::new(|| {
    EncodingKey::from_rsa_pem(&PRIVATE_RSA_KEY_VEC).unwrap_or_else(|e| panic!("Error decoding private RSA Key.\n{}", e))
});
static PUBLIC_RSA_KEY_VEC: Lazy<Vec<u8>> = Lazy::new(|| {
    read_file(&CONFIG.public_rsa_key()).unwrap_or_else(|e| panic!("Error loading public RSA Key.\n{}", e))
});
static PUBLIC_RSA_KEY: Lazy<DecodingKey> = Lazy::new(|| {
    DecodingKey::from_rsa_pem(&PUBLIC_RSA_KEY_VEC).unwrap_or_else(|e| panic!("Error decoding public RSA Key.\n{}", e))
});

pub fn load_keys() {
    Lazy::force(&PRIVATE_RSA_KEY);
    Lazy::force(&PUBLIC_RSA_KEY);
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jsonwebtoken::encode(&JWT_HEADER, claims, &PRIVATE_RSA_KEY) {
        Ok(token) => token,
        Err(e) => panic!("Error encoding jwt {}", e),
    }
}

fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: String) -> Result<T, Error> {
    let validation = jsonwebtoken::Validation {
        leeway: 30, // 30 seconds
        validate_exp: true,
        validate_nbf: true,
        aud: None,
        iss: Some(issuer),
        sub: None,
        algorithms: vec![JWT_ALGORITHM],
    };

    let token = token.replace(char::is_whitespace, "");
    jsonwebtoken::decode(&token, &PUBLIC_RSA_KEY, &validation).map(|d| d.claims).map_res("Error decoding JWT")
}

pub fn decode_login(token: &str) -> Result<LoginJwtClaims, Error> {
    decode_jwt(token, JWT_LOGIN_ISSUER.to_string())
}

pub fn decode_invite(token: &str) -> Result<InviteJwtClaims, Error> {
    decode_jwt(token, JWT_INVITE_ISSUER.to_string())
}

pub fn decode_emergency_access_invite(token: &str) -> Result<EmergencyAccessInviteJwtClaims, Error> {
    decode_jwt(token, JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string())
}

pub fn decode_delete(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_DELETE_ISSUER.to_string())
}

pub fn decode_verify_email(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_VERIFYEMAIL_ISSUER.to_string())
}

pub fn decode_admin(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_ADMIN_ISSUER.to_string())
}

pub fn decode_send(token: &str) -> Result<BasicJwtClaims, Error> {
    decode_jwt(token, JWT_SEND_ISSUER.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginJwtClaims {
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
pub struct InviteJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub email: String,
    pub org_id: Option<String>,
    pub user_org_id: Option<String>,
    pub invited_by_email: Option<String>,
}

pub fn generate_invite_claims(
    uuid: String,
    email: String,
    org_id: Option<String>,
    user_org_id: Option<String>,
    invited_by_email: Option<String>,
) -> InviteJwtClaims {
    let time_now = Utc::now().naive_utc();
    InviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::days(5)).timestamp(),
        iss: JWT_INVITE_ISSUER.to_string(),
        sub: uuid,
        email,
        org_id,
        user_org_id,
        invited_by_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyAccessInviteJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub email: String,
    pub emer_id: Option<String>,
    pub grantor_name: Option<String>,
    pub grantor_email: Option<String>,
}

pub fn generate_emergency_access_invite_claims(
    uuid: String,
    email: String,
    emer_id: Option<String>,
    grantor_name: Option<String>,
    grantor_email: Option<String>,
) -> EmergencyAccessInviteJwtClaims {
    let time_now = Utc::now().naive_utc();
    EmergencyAccessInviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::days(5)).timestamp(),
        iss: JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string(),
        sub: uuid,
        email,
        emer_id,
        grantor_name,
        grantor_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn generate_delete_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now().naive_utc();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::days(5)).timestamp(),
        iss: JWT_DELETE_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_verify_email_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now().naive_utc();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::days(5)).timestamp(),
        iss: JWT_VERIFYEMAIL_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_admin_claims() -> BasicJwtClaims {
    let time_now = Utc::now().naive_utc();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::minutes(20)).timestamp(),
        iss: JWT_ADMIN_ISSUER.to_string(),
        sub: "admin_panel".to_string(),
    }
}

pub fn generate_send_claims(send_id: &str, file_id: &str) -> BasicJwtClaims {
    let time_now = Utc::now().naive_utc();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::minutes(2)).timestamp(),
        iss: JWT_SEND_ISSUER.to_string(),
        sub: format!("{}/{}", send_id, file_id),
    }
}

//
// Bearer token authentication
//
use rocket::request::{FromRequest, Outcome, Request};

use crate::db::{
    models::{CollectionUser, Device, User, UserOrgStatus, UserOrgType, UserOrganization, UserStampException},
    DbConn,
};

pub struct Host {
    pub host: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for Host {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get host
        let host = if CONFIG.domain_set() {
            CONFIG.domain()
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

        Outcome::Success(Host {
            host,
        })
    }
}

pub struct Headers {
    pub host: String,
    pub device: Device,
    pub user: User,
}

impl<'a, 'r> FromRequest<'a, 'r> for Headers {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let host = match Host::from_request(request) {
            Outcome::Forward(_) => return Outcome::Forward(()),
            Outcome::Failure(f) => return Outcome::Failure(f),
            Outcome::Success(host) => host.host,
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
        let claims = match decode_login(access_token) {
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
            if let Some(stamp_exception) =
                user.stamp_exception.as_deref().and_then(|s| serde_json::from_str::<UserStampException>(s).ok())
            {
                let current_route = match request.route().and_then(|r| r.name) {
                    Some(name) => name,
                    _ => err_handler!("Error getting current route for stamp exception"),
                };

                // Check if the stamp exception has expired first.
                // Then, check if the current route matches any of the allowed routes.
                // After that check the stamp in exception matches the one in the claims.
                if Utc::now().naive_utc().timestamp() > stamp_exception.expire {
                    // If the stamp exception has been expired remove it from the database.
                    // This prevents checking this stamp exception for new requests.
                    let mut user = user;
                    user.reset_stamp_exception();
                    if let Err(e) = user.save(&conn) {
                        error!("Error updating user: {:#?}", e);
                    }
                    err_handler!("Stamp exception is expired")
                } else if !stamp_exception.routes.contains(&current_route.to_string()) {
                    err_handler!("Invalid security stamp: Current route and exception route do not match")
                } else if stamp_exception.security_stamp != claims.sstamp {
                    err_handler!("Invalid security stamp for matched stamp exception")
                }
            } else {
                err_handler!("Invalid security stamp")
            }
        }

        Outcome::Success(Headers {
            host,
            device,
            user,
        })
    }
}

pub struct OrgHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub org_user: UserOrganization,
    pub org_id: String,
}

// org_id is usually the second path param ("/organizations/<org_id>"),
// but there are cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
fn get_org_id(request: &Request) -> Option<String> {
    if let Some(Ok(org_id)) = request.get_param::<String>(1) {
        if uuid::Uuid::parse_str(&org_id).is_ok() {
            return Some(org_id);
        }
    }

    if let Some(Ok(org_id)) = request.get_query_value::<String>("organizationId") {
        if uuid::Uuid::parse_str(&org_id).is_ok() {
            return Some(org_id);
        }
    }

    None
}

impl<'a, 'r> FromRequest<'a, 'r> for OrgHeaders {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        match request.guard::<Headers>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                match get_org_id(request) {
                    Some(org_id) => {
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
                                if let Some(org_usr_type) = UserOrgType::from_i32(org_user.atype) {
                                    org_usr_type
                                } else {
                                    // This should only happen if the DB is corrupted
                                    err_handler!("Unknown user type in the database")
                                }
                            },
                            org_user,
                            org_id,
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

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
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

impl From<AdminHeaders> for Headers {
    fn from(h: AdminHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
        }
    }
}

// col_id is usually the fourth path param ("/organizations/<org_id>/collections/<col_id>"),
// but there could be cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
fn get_col_id(request: &Request) -> Option<String> {
    if let Some(Ok(col_id)) = request.get_param::<String>(3) {
        if uuid::Uuid::parse_str(&col_id).is_ok() {
            return Some(col_id);
        }
    }

    if let Some(Ok(col_id)) = request.get_query_value::<String>("collectionId") {
        if uuid::Uuid::parse_str(&col_id).is_ok() {
            return Some(col_id);
        }
    }

    None
}

/// The ManagerHeaders are used to check if you are at least a Manager
/// and have access to the specific collection provided via the <col_id>/collections/collectionId.
/// This does strict checking on the collection_id, ManagerHeadersLoose does not.
pub struct ManagerHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
}

impl<'a, 'r> FromRequest<'a, 'r> for ManagerHeaders {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        match request.guard::<OrgHeaders>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                if headers.org_user_type >= UserOrgType::Manager {
                    match get_col_id(request) {
                        Some(col_id) => {
                            let conn = match request.guard::<DbConn>() {
                                Outcome::Success(conn) => conn,
                                _ => err_handler!("Error getting DB"),
                            };

                            if !headers.org_user.has_full_access() {
                                match CollectionUser::find_by_collection_and_user(
                                    &col_id,
                                    &headers.org_user.user_uuid,
                                    &conn,
                                ) {
                                    Some(_) => (),
                                    None => err_handler!("The current user isn't a manager for this collection"),
                                }
                            }
                        }
                        _ => err_handler!("Error getting the collection id"),
                    }

                    Outcome::Success(Self {
                        host: headers.host,
                        device: headers.device,
                        user: headers.user,
                        org_user_type: headers.org_user_type,
                    })
                } else {
                    err_handler!("You need to be a Manager, Admin or Owner to call this endpoint")
                }
            }
        }
    }
}

impl From<ManagerHeaders> for Headers {
    fn from(h: ManagerHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
        }
    }
}

/// The ManagerHeadersLoose is used when you at least need to be a Manager,
/// but there is no collection_id sent with the request (either in the path or as form data).
pub struct ManagerHeadersLoose {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
}

impl<'a, 'r> FromRequest<'a, 'r> for ManagerHeadersLoose {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        match request.guard::<OrgHeaders>() {
            Outcome::Forward(_) => Outcome::Forward(()),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Success(headers) => {
                if headers.org_user_type >= UserOrgType::Manager {
                    Outcome::Success(Self {
                        host: headers.host,
                        device: headers.device,
                        user: headers.user,
                        org_user_type: headers.org_user_type,
                    })
                } else {
                    err_handler!("You need to be a Manager, Admin or Owner to call this endpoint")
                }
            }
        }
    }
}

impl From<ManagerHeadersLoose> for Headers {
    fn from(h: ManagerHeadersLoose) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
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

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
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

    fn from_request(req: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let ip = if CONFIG._ip_header_enabled() {
            req.headers().get_one(&CONFIG.ip_header()).and_then(|ip| {
                match ip.find(',') {
                    Some(idx) => &ip[..idx],
                    None => ip,
                }
                .parse()
                .map_err(|_| warn!("'{}' header is malformed: {}", CONFIG.ip_header(), ip))
                .ok()
            })
        } else {
            None
        };

        let ip = ip.or_else(|| req.remote().map(|r| r.ip())).unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        Outcome::Success(ClientIp {
            ip,
        })
    }
}
