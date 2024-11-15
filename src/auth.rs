// JWT Handling
//
use chrono::{TimeDelta, Utc};
use jsonwebtoken::{errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header};
use num_traits::FromPrimitive;
use once_cell::sync::{Lazy, OnceCell};
use openssl::rsa::Rsa;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::{
    env,
    fs::File,
    io::{Read, Write},
    net::IpAddr,
};

use crate::{error::Error, CONFIG};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

pub static DEFAULT_VALIDITY: Lazy<TimeDelta> = Lazy::new(|| TimeDelta::try_hours(2).unwrap());
static JWT_HEADER: Lazy<Header> = Lazy::new(|| Header::new(JWT_ALGORITHM));

pub static JWT_LOGIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|login", CONFIG.domain_origin()));
static JWT_INVITE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|invite", CONFIG.domain_origin()));
static JWT_EMERGENCY_ACCESS_INVITE_ISSUER: Lazy<String> =
    Lazy::new(|| format!("{}|emergencyaccessinvite", CONFIG.domain_origin()));
static JWT_DELETE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|delete", CONFIG.domain_origin()));
static JWT_VERIFYEMAIL_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|verifyemail", CONFIG.domain_origin()));
static JWT_ADMIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|admin", CONFIG.domain_origin()));
static JWT_SEND_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|send", CONFIG.domain_origin()));
static JWT_ORG_API_KEY_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|api.organization", CONFIG.domain_origin()));
static JWT_FILE_DOWNLOAD_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|file_download", CONFIG.domain_origin()));

static PRIVATE_RSA_KEY: OnceCell<EncodingKey> = OnceCell::new();
static PUBLIC_RSA_KEY: OnceCell<DecodingKey> = OnceCell::new();

pub fn initialize_keys() -> Result<(), Error> {
    fn read_key(create_if_missing: bool) -> Result<(Rsa<openssl::pkey::Private>, Vec<u8>), Error> {
        let mut priv_key_buffer = Vec::with_capacity(2048);

        let mut priv_key_file = File::options()
            .create(create_if_missing)
            .truncate(false)
            .read(true)
            .write(create_if_missing)
            .open(CONFIG.private_rsa_key())?;

        #[allow(clippy::verbose_file_reads)]
        let bytes_read = priv_key_file.read_to_end(&mut priv_key_buffer)?;

        let rsa_key = if bytes_read > 0 {
            Rsa::private_key_from_pem(&priv_key_buffer[..bytes_read])?
        } else if create_if_missing {
            // Only create the key if the file doesn't exist or is empty
            let rsa_key = Rsa::generate(2048)?;
            priv_key_buffer = rsa_key.private_key_to_pem()?;
            priv_key_file.write_all(&priv_key_buffer)?;
            info!("Private key '{}' created correctly", CONFIG.private_rsa_key());
            rsa_key
        } else {
            err!("Private key does not exist or invalid format", CONFIG.private_rsa_key());
        };

        Ok((rsa_key, priv_key_buffer))
    }

    let (priv_key, priv_key_buffer) = read_key(true).or_else(|_| read_key(false))?;
    let pub_key_buffer = priv_key.public_key_to_pem()?;

    let enc = EncodingKey::from_rsa_pem(&priv_key_buffer)?;
    let dec: DecodingKey = DecodingKey::from_rsa_pem(&pub_key_buffer)?;
    if PRIVATE_RSA_KEY.set(enc).is_err() {
        err!("PRIVATE_RSA_KEY must only be initialized once")
    }
    if PUBLIC_RSA_KEY.set(dec).is_err() {
        err!("PUBLIC_RSA_KEY must only be initialized once")
    }
    Ok(())
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jsonwebtoken::encode(&JWT_HEADER, claims, PRIVATE_RSA_KEY.wait()) {
        Ok(token) => token,
        Err(e) => panic!("Error encoding jwt {e}"),
    }
}

fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: String) -> Result<T, Error> {
    let mut validation = jsonwebtoken::Validation::new(JWT_ALGORITHM);
    validation.leeway = 30; // 30 seconds
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer]);

    let token = token.replace(char::is_whitespace, "");
    match jsonwebtoken::decode(&token, PUBLIC_RSA_KEY.wait(), &validation) {
        Ok(d) => Ok(d.claims),
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => err!("Token is invalid"),
            ErrorKind::InvalidIssuer => err!("Issuer is invalid"),
            ErrorKind::ExpiredSignature => err!("Token has expired"),
            _ => err!("Error decoding JWT"),
        },
    }
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

pub fn decode_api_org(token: &str) -> Result<OrgApiKeyLoginJwtClaims, Error> {
    decode_jwt(token, JWT_ORG_API_KEY_ISSUER.to_string())
}

pub fn decode_file_download(token: &str) -> Result<FileDownloadClaims, Error> {
    decode_jwt(token, JWT_FILE_DOWNLOAD_ISSUER.to_string())
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

    // ---
    // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
    // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
    // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
    // See: https://github.com/dani-garcia/vaultwarden/issues/4156
    // ---
    // pub orgowner: Vec<String>,
    // pub orgadmin: Vec<String>,
    // pub orguser: Vec<String>,
    // pub orgmanager: Vec<String>,

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
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    InviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
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
    pub emer_id: String,
    pub grantor_name: String,
    pub grantor_email: String,
}

pub fn generate_emergency_access_invite_claims(
    uuid: String,
    email: String,
    emer_id: String,
    grantor_name: String,
    grantor_email: String,
) -> EmergencyAccessInviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    EmergencyAccessInviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string(),
        sub: uuid,
        email,
        emer_id,
        grantor_name,
        grantor_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgApiKeyLoginJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub client_id: String,
    pub client_sub: String,
    pub scope: Vec<String>,
}

pub fn generate_organization_api_key_login_claims(uuid: String, org_id: String) -> OrgApiKeyLoginJwtClaims {
    let time_now = Utc::now();
    OrgApiKeyLoginJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(1).unwrap()).timestamp(),
        iss: JWT_ORG_API_KEY_ISSUER.to_string(),
        sub: uuid,
        client_id: format!("organization.{org_id}"),
        client_sub: org_id,
        scope: vec!["api.organization".into()],
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDownloadClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub file_id: String,
}

pub fn generate_file_download_claims(uuid: String, file_id: String) -> FileDownloadClaims {
    let time_now = Utc::now();
    FileDownloadClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: JWT_FILE_DOWNLOAD_ISSUER.to_string(),
        sub: uuid,
        file_id,
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
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_DELETE_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_verify_email_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_VERIFYEMAIL_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_admin_claims() -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(CONFIG.admin_session_lifetime()).unwrap()).timestamp(),
        iss: JWT_ADMIN_ISSUER.to_string(),
        sub: "admin_panel".to_string(),
    }
}

pub fn generate_send_claims(send_id: &str, file_id: &str) -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: JWT_SEND_ISSUER.to_string(),
        sub: format!("{send_id}/{file_id}"),
    }
}

//
// Bearer token authentication
//
use rocket::{
    outcome::try_outcome,
    request::{FromRequest, Outcome, Request},
};

use crate::db::{
    models::{Collection, Device, User, UserOrgStatus, UserOrgType, UserOrganization, UserStampException},
    DbConn,
};

pub struct Host {
    pub host: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get host
        let host = if CONFIG.domain_set() {
            CONFIG.domain()
        } else if let Some(referer) = headers.get_one("Referer") {
            referer.to_string()
        } else {
            // Try to guess from the headers
            let protocol = if let Some(proto) = headers.get_one("X-Forwarded-Proto") {
                proto
            } else if env::var("ROCKET_TLS").is_ok() {
                "https"
            } else {
                "http"
            };

            let host = if let Some(host) = headers.get_one("X-Forwarded-Host") {
                host
            } else {
                headers.get_one("Host").unwrap_or_default()
            };

            format!("{protocol}://{host}")
        };

        Outcome::Success(Host {
            host,
        })
    }
}

pub struct ClientHeaders {
    pub device_type: i32,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(ip) => ip,
            _ => err_handler!("Error getting Client IP"),
        };
        // When unknown or unable to parse, return 14, which is 'Unknown Browser'
        let device_type: i32 =
            request.headers().get_one("device-type").map(|d| d.parse().unwrap_or(14)).unwrap_or_else(|| 14);

        Outcome::Success(ClientHeaders {
            device_type,
            ip,
        })
    }
}

pub struct Headers {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Headers {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let host = try_outcome!(Host::from_request(request).await).host;
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(ip) => ip,
            _ => err_handler!("Error getting Client IP"),
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

        let mut conn = match DbConn::from_request(request).await {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB"),
        };

        let device = match Device::find_by_uuid_and_user(&device_uuid, &user_uuid, &mut conn).await {
            Some(device) => device,
            None => err_handler!("Invalid device id"),
        };

        let user = match User::find_by_uuid(&user_uuid, &mut conn).await {
            Some(user) => user,
            None => err_handler!("Device has no user associated"),
        };

        if user.security_stamp != claims.sstamp {
            if let Some(stamp_exception) =
                user.stamp_exception.as_deref().and_then(|s| serde_json::from_str::<UserStampException>(s).ok())
            {
                let current_route = match request.route().and_then(|r| r.name.as_deref()) {
                    Some(name) => name,
                    _ => err_handler!("Error getting current route for stamp exception"),
                };

                // Check if the stamp exception has expired first.
                // Then, check if the current route matches any of the allowed routes.
                // After that check the stamp in exception matches the one in the claims.
                if Utc::now().timestamp() > stamp_exception.expire {
                    // If the stamp exception has been expired remove it from the database.
                    // This prevents checking this stamp exception for new requests.
                    let mut user = user;
                    user.reset_stamp_exception();
                    if let Err(e) = user.save(&mut conn).await {
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
            ip,
        })
    }
}

pub struct OrgHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub org_user: UserOrganization,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OrgHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(Headers::from_request(request).await);

        // org_id is usually the second path param ("/organizations/<org_id>"),
        // but there are cases where it is a query value.
        // First check the path, if this is not a valid uuid, try the query values.
        let url_org_id: Option<&str> = {
            let mut url_org_id = None;
            if let Some(Ok(org_id)) = request.param::<&str>(1) {
                if uuid::Uuid::parse_str(org_id).is_ok() {
                    url_org_id = Some(org_id);
                }
            }

            if let Some(Ok(org_id)) = request.query_value::<&str>("organizationId") {
                if uuid::Uuid::parse_str(org_id).is_ok() {
                    url_org_id = Some(org_id);
                }
            }

            url_org_id
        };

        match url_org_id {
            Some(org_id) => {
                let mut conn = match DbConn::from_request(request).await {
                    Outcome::Success(conn) => conn,
                    _ => err_handler!("Error getting DB"),
                };

                let user = headers.user;
                let org_user = match UserOrganization::find_by_user_and_org(&user.uuid, org_id, &mut conn).await {
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
                    ip: headers.ip,
                })
            }
            _ => err_handler!("Error getting the organization id"),
        }
    }
}

pub struct AdminHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.org_user_type >= UserOrgType::Admin {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                org_user_type: headers.org_user_type,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be Admin or Owner to call this endpoint")
        }
    }
}

impl From<AdminHeaders> for Headers {
    fn from(h: AdminHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

// col_id is usually the fourth path param ("/organizations/<org_id>/collections/<col_id>"),
// but there could be cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
fn get_col_id(request: &Request<'_>) -> Option<String> {
    if let Some(Ok(col_id)) = request.param::<String>(3) {
        if uuid::Uuid::parse_str(&col_id).is_ok() {
            return Some(col_id);
        }
    }

    if let Some(Ok(col_id)) = request.query_value::<String>("collectionId") {
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
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ManagerHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.org_user_type >= UserOrgType::Manager {
            match get_col_id(request) {
                Some(col_id) => {
                    let mut conn = match DbConn::from_request(request).await {
                        Outcome::Success(conn) => conn,
                        _ => err_handler!("Error getting DB"),
                    };

                    if !Collection::can_access_collection(&headers.org_user, &col_id, &mut conn).await {
                        err_handler!("The current user isn't a manager for this collection")
                    }
                }
                _ => err_handler!("Error getting the collection id"),
            }

            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be a Manager, Admin or Owner to call this endpoint")
        }
    }
}

impl From<ManagerHeaders> for Headers {
    fn from(h: ManagerHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

/// The ManagerHeadersLoose is used when you at least need to be a Manager,
/// but there is no collection_id sent with the request (either in the path or as form data).
pub struct ManagerHeadersLoose {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub org_user: UserOrganization,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ManagerHeadersLoose {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.org_user_type >= UserOrgType::Manager {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                org_user: headers.org_user,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be a Manager, Admin or Owner to call this endpoint")
        }
    }
}

impl From<ManagerHeadersLoose> for Headers {
    fn from(h: ManagerHeadersLoose) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

impl ManagerHeaders {
    pub async fn from_loose(
        h: ManagerHeadersLoose,
        collections: &Vec<String>,
        conn: &mut DbConn,
    ) -> Result<ManagerHeaders, Error> {
        for col_id in collections {
            if uuid::Uuid::parse_str(col_id).is_err() {
                err!("Collection Id is malformed!");
            }
            if !Collection::can_access_collection(&h.org_user, col_id, conn).await {
                err!("You don't have access to all collections!");
            }
        }

        Ok(ManagerHeaders {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        })
    }
}

pub struct OwnerHeaders {
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OwnerHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.org_user_type == UserOrgType::Owner {
            Outcome::Success(Self {
                device: headers.device,
                user: headers.user,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be Owner to call this endpoint")
        }
    }
}

//
// Client IP address detection
//

pub struct ClientIp {
    pub ip: IpAddr,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
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

pub struct Secure {
    pub https: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Secure {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Try to guess from the headers
        let protocol = match headers.get_one("X-Forwarded-Proto") {
            Some(proto) => proto,
            None => {
                if env::var("ROCKET_TLS").is_ok() {
                    "https"
                } else {
                    "http"
                }
            }
        };

        Outcome::Success(Secure {
            https: protocol == "https",
        })
    }
}

pub struct WsAccessTokenHeader {
    pub access_token: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for WsAccessTokenHeader {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get access_token
        let access_token = match headers.get_one("Authorization") {
            Some(a) => a.rsplit("Bearer ").next().map(String::from),
            None => None,
        };

        Outcome::Success(Self {
            access_token,
        })
    }
}

pub struct ClientVersion(pub semver::Version);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientVersion {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        let Some(version) = headers.get_one("Bitwarden-Client-Version") else {
            err_handler!("No Bitwarden-Client-Version header provided")
        };

        let Ok(version) = semver::Version::parse(version) else {
            err_handler!("Invalid Bitwarden-Client-Version header provided")
        };

        Outcome::Success(ClientVersion(version))
    }
}
