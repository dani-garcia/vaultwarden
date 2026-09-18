#[path = "auth/send.rs"]
pub mod send;
pub type SendTokens = send::SendTokens;
pub type SendHeaders = send::SendHeaders;

use std::{
    env,
    net::IpAddr,
    sync::{LazyLock, OnceLock},
};

use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, errors::ErrorKind};
use num_traits::FromPrimitive;
use openssl::rsa::Rsa;
use serde::{de::DeserializeOwned, ser::Serialize};

use rocket::{
    outcome::try_outcome,
    request::{FromRequest, Outcome, Request},
};

use crate::{
    CONFIG,
    api::{ApiResult, core::log_event},
    config::PathType,
    db::{
        DbConn,
        models::{
            AttachmentId, CipherId, Collection, CollectionId, Device, DeviceId, DeviceType, EmergencyAccessId,
            EventType, Membership, MembershipId, MembershipStatus, MembershipType, OrgApiKeyId, OrganizationId,
            SendFileId, SendId, User, UserId, UserStampException,
        },
    },
    error::Error,
    sso,
};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

// Limit when BitWarden consider the token as expired
pub static BW_EXPIRATION: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_minutes(5).unwrap());

pub static DEFAULT_REFRESH_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_days(30).unwrap());
pub static MOBILE_REFRESH_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_days(90).unwrap());
pub static DEFAULT_ACCESS_VALIDITY: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::try_hours(2).unwrap());
static JWT_HEADER: LazyLock<Header> = LazyLock::new(|| Header::new(JWT_ALGORITHM));

pub static JWT_LOGIN_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|login", CONFIG.domain_origin()));
static JWT_INVITE_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|invite", CONFIG.domain_origin()));
static JWT_EMERGENCY_ACCESS_INVITE_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|emergencyaccessinvite", CONFIG.domain_origin()));
static JWT_DELETE_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|delete", CONFIG.domain_origin()));
static JWT_VERIFYEMAIL_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|verifyemail", CONFIG.domain_origin()));
static JWT_ADMIN_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|admin", CONFIG.domain_origin()));
static JWT_SEND_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|send", CONFIG.domain_origin()));
static JWT_ORG_API_KEY_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|api.organization", CONFIG.domain_origin()));
static JWT_FILE_DOWNLOAD_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|file_download", CONFIG.domain_origin()));
static JWT_REGISTER_VERIFY_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|register_verify", CONFIG.domain_origin()));
static JWT_2FA_REMEMBER_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|2faremember", CONFIG.domain_origin()));

static PRIVATE_RSA_KEY: OnceLock<EncodingKey> = OnceLock::new();
static PUBLIC_RSA_KEY: OnceLock<DecodingKey> = OnceLock::new();

pub async fn initialize_keys() -> Result<(), Error> {
    use std::io::Error as IoError;

    let rsa_key_filename = crate::storage::file_name(&CONFIG.private_rsa_key())
        .ok_or_else(|| IoError::other("Private RSA key path missing filename"))?;

    let operator = CONFIG.opendal_operator_for_path_type(&PathType::RsaKey).map_err(IoError::other)?;

    let priv_key_buffer = match operator.read(&rsa_key_filename).await {
        Ok(buffer) => Some(buffer),
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    let (priv_key, priv_key_buffer) = if let Some(priv_key_buffer) = priv_key_buffer {
        (Rsa::private_key_from_pem(priv_key_buffer.to_vec().as_slice())?, priv_key_buffer.to_vec())
    } else {
        let rsa_key = Rsa::generate(2048)?;
        let priv_key_buffer = rsa_key.private_key_to_pem()?;
        operator.write(&rsa_key_filename, priv_key_buffer.clone()).await?;
        info!("Private key '{}' created correctly", CONFIG.private_rsa_key());
        (rsa_key, priv_key_buffer)
    };
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

pub fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: String) -> Result<T, Error> {
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
            _ => err!(format!("Error decoding JWT: {:?}", err)),
        },
    }
}

pub fn decode_refresh(token: &str) -> Result<RefreshJwtClaims, Error> {
    decode_jwt(token, JWT_LOGIN_ISSUER.to_string())
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

pub fn decode_register_verify(token: &str) -> Result<RegisterVerifyClaims, Error> {
    decode_jwt(token, JWT_REGISTER_VERIFY_ISSUER.to_string())
}

pub fn decode_2fa_remember(token: &str) -> Result<TwoFactorRememberClaims, Error> {
    decode_jwt(token, JWT_2FA_REMEMBER_ISSUER.to_string())
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
    pub sub: UserId,

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
    pub device: DeviceId,
    // what kind of device, like FirefoxBrowser or Android derived from DeviceType
    pub devicetype: String,
    // the type of client_id, like web, cli, desktop, browser or mobile
    pub client_id: String,

    // [ "api", "offline_access" ]
    pub scope: Vec<String>,
    // [ "Application" ]
    pub amr: Vec<String>,
}

impl LoginJwtClaims {
    pub fn new(
        device: &Device,
        user: &User,
        nbf: i64,
        exp: i64,
        scope: Vec<String>,
        client_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        // ---
        // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
        // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
        // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
        // ---
        // fn arg: orgs: Vec<super::UserOrganization>,
        // ---
        // let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == 0).map(|o| o.org_uuid.clone()).collect();
        // let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == 1).map(|o| o.org_uuid.clone()).collect();
        // let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == 2).map(|o| o.org_uuid.clone()).collect();
        // let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == 3).map(|o| o.org_uuid.clone()).collect();

        if exp <= (now + *BW_EXPIRATION).timestamp() {
            warn!("Raise access_token lifetime to more than 5min.");
        }

        // Create the JWT claims struct, to send to the client
        Self {
            nbf,
            exp,
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid.clone(),
            premium: true,
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: !CONFIG.mail_enabled() || user.verified_at.is_some(),

            // ---
            // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
            // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
            // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
            // See: https://github.com/dani-garcia/vaultwarden/issues/4156
            // ---
            // orgowner,
            // orgadmin,
            // orguser,
            // orgmanager,
            sstamp: user.security_stamp.clone(),
            device: device.uuid.clone(),
            devicetype: DeviceType::from_i32(device.atype).to_string(),
            client_id: client_id.unwrap_or("undefined".to_owned()),
            scope,
            amr: vec!["Application".into()],
        }
    }

    pub fn default(device: &Device, user: &User, auth_method: &AuthMethod, client_id: Option<String>) -> Self {
        let time_now = Utc::now();
        Self::new(
            device,
            user,
            time_now.timestamp(),
            (time_now + *DEFAULT_ACCESS_VALIDITY).timestamp(),
            auth_method.scope_vec(),
            client_id,
            time_now,
        )
    }

    pub fn token(&self) -> String {
        encode_jwt(&self)
    }

    pub fn expires_in(&self) -> i64 {
        self.exp - Utc::now().timestamp()
    }
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
    pub sub: UserId,

    pub email: String,
    pub org_id: OrganizationId,
    pub member_id: MembershipId,
    pub invited_by_email: Option<String>,
}

pub fn generate_invite_claims(
    user_id: UserId,
    email: String,
    org_id: OrganizationId,
    member_id: MembershipId,
    invited_by_email: Option<String>,
) -> InviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    InviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_INVITE_ISSUER.to_string(),
        sub: user_id,
        email,
        org_id,
        member_id,
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
    pub sub: UserId,

    pub email: String,
    pub emer_id: EmergencyAccessId,
    pub grantor_name: String,
    pub grantor_email: String,
}

pub fn generate_emergency_access_invite_claims(
    user_id: UserId,
    email: String,
    emer_id: EmergencyAccessId,
    grantor_name: String,
    grantor_email: String,
) -> EmergencyAccessInviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    EmergencyAccessInviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string(),
        sub: user_id,
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
    pub sub: OrgApiKeyId,

    pub client_id: String,
    pub client_sub: OrganizationId,
    pub scope: Vec<String>,
}

pub fn generate_organization_api_key_login_claims(
    org_api_key_uuid: OrgApiKeyId,
    org_id: OrganizationId,
) -> OrgApiKeyLoginJwtClaims {
    let time_now = Utc::now();
    OrgApiKeyLoginJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(1).unwrap()).timestamp(),
        iss: JWT_ORG_API_KEY_ISSUER.to_string(),
        sub: org_api_key_uuid,
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
    pub sub: CipherId,

    pub file_id: AttachmentId,
}

pub fn generate_file_download_claims(cipher_id: CipherId, file_id: AttachmentId) -> FileDownloadClaims {
    let time_now = Utc::now();
    FileDownloadClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: JWT_FILE_DOWNLOAD_ISSUER.to_string(),
        sub: cipher_id,
        file_id,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub name: Option<String>,
    pub verified: bool,
}

pub fn generate_register_verify_claims(email: String, name: Option<String>, verified: bool) -> RegisterVerifyClaims {
    let time_now = Utc::now();
    RegisterVerifyClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(30).unwrap()).timestamp(),
        iss: JWT_REGISTER_VERIFY_ISSUER.to_string(),
        sub: email,
        name,
        verified,
    }
}

#[derive(Serialize, Deserialize)]
pub struct TwoFactorRememberClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: DeviceId,
    // UserId
    pub user_uuid: UserId,
}

pub fn generate_2fa_remember_claims(device_uuid: DeviceId, user_uuid: UserId) -> TwoFactorRememberClaims {
    let time_now = Utc::now();
    TwoFactorRememberClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_days(30).unwrap()).timestamp(),
        iss: JWT_2FA_REMEMBER_ISSUER.to_string(),
        sub: device_uuid,
        user_uuid,
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

impl BasicJwtClaims {
    pub fn expires_in(&self) -> i64 {
        self.exp - Utc::now().timestamp()
    }

    pub fn token(&self) -> String {
        encode_jwt(&self)
    }
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

pub fn generate_verify_email_claims(user_id: &UserId) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.invitation_expiration_hours());
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_hours(expire_hours).unwrap()).timestamp(),
        iss: JWT_VERIFYEMAIL_ISSUER.to_string(),
        sub: user_id.to_string(),
    }
}

pub fn generate_admin_claims() -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(CONFIG.admin_session_lifetime()).unwrap()).timestamp(),
        iss: JWT_ADMIN_ISSUER.to_string(),
        sub: "admin_panel".to_owned(),
    }
}

pub fn generate_send_claims(send_id: &SendId, file_id: &SendFileId) -> BasicJwtClaims {
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
            referer.to_owned()
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
        let Outcome::Success(ip) = ClientIp::from_request(request).await else {
            err_handler!("Error getting Client IP")
        };
        // When unknown or unable to parse, return 'UnknownBrowser'
        let device_type: i32 = request
            .headers()
            .get_one("device-type")
            .and_then(|d| d.parse().ok())
            .unwrap_or(DeviceType::UnknownBrowser as i32);

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
        let Outcome::Success(ip) = ClientIp::from_request(request).await else {
            err_handler!("Error getting Client IP")
        };

        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };

        // Check JWT token is valid and get device and user from it
        let Ok(claims) = decode_login(access_token) else {
            err_handler!("Invalid claim")
        };

        let device_id = claims.device;
        let user_id = claims.sub;

        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };

        let Some(device) = Device::find_by_uuid_and_user(&device_id, &user_id, &conn).await else {
            err_handler!("Invalid device id")
        };

        let Some(user) = User::find_by_uuid(&user_id, &conn).await else {
            err_handler!("Device has no user associated")
        };

        if user.security_stamp != claims.sstamp {
            if let Some(stamp_exception) =
                user.stamp_exception.as_deref().and_then(|s| serde_json::from_str::<UserStampException>(s).ok())
            {
                let Some(current_route) = request.route().and_then(|r| r.name.as_deref()) else {
                    err_handler!("Error getting current route for stamp exception")
                };

                // Check if the stamp exception has expired first.
                // Then, check if the current route matches any of the allowed routes.
                // After that check the stamp in exception matches the one in the claims.
                if Utc::now().timestamp() > stamp_exception.expire {
                    // If the stamp exception has been expired remove it from the database.
                    // This prevents checking this stamp exception for new requests.
                    let mut user = user;
                    user.reset_stamp_exception();
                    if let Err(e) = user.save(&conn).await {
                        error!("Error updating user: {e:#?}");
                    }
                    err_handler!("Stamp exception is expired")
                } else if !stamp_exception.routes.contains(&current_route.to_owned()) {
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
    #[allow(dead_code)]
    pub membership_type: MembershipType,
    pub membership_status: MembershipStatus,
    pub membership: Membership,
    pub ip: ClientIp,
}

impl OrgHeaders {
    fn is_member(&self) -> bool {
        // Only allow not revoked members, we can not use the Confirmed status here
        // as some endpoints can be triggered by invited users during joining
        self.membership_status != MembershipStatus::Revoked && self.membership_type >= MembershipType::User
    }
    fn is_confirmed_and_admin(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed && self.membership_type >= MembershipType::Admin
    }
    // "Manager-level or above": a confirmed Custom, Admin or Owner member. (The legacy Manager role
    // has been folded into Custom, which shares the same authorization rank.)
    fn is_confirmed_and_manager(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed && self.membership_type >= MembershipType::Custom
    }
    fn is_confirmed_and_owner(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed && self.membership_type == MembershipType::Owner
    }
    fn is_confirmed(&self) -> bool {
        self.membership_status == MembershipStatus::Confirmed
    }
    // Custom-role permission checks. Admins and Owners implicitly hold every
    // permission; a Custom member holds a permission only if the matching flag
    // is set on their Membership. The has_* helpers gate the flags on the
    // Custom type, so stale flags on other types can never grant anything.
    fn can_manage_users(&self) -> bool {
        may_manage_users(&self.membership)
    }
    fn can_manage_groups(&self) -> bool {
        may_manage_groups(&self.membership)
    }
    fn can_manage_users_or_groups(&self) -> bool {
        may_manage_users_or_groups(&self.membership)
    }
    fn can_manage_policies(&self) -> bool {
        may_manage_policies(&self.membership)
    }
    fn can_access_event_logs(&self) -> bool {
        self.is_confirmed()
            && (self.membership_type >= MembershipType::Admin || self.membership.has_access_event_logs())
    }
    fn can_access_import_export(&self) -> bool {
        self.is_confirmed()
            && (self.membership_type >= MembershipType::Admin || self.membership.has_access_import_export())
    }
    // NOTE: no `can_access_reports` helper on purpose. Vaultwarden has no server-side report endpoints --
    // clients compute reports from the organization cipher list -- so `accessReports` is enforced where
    // that list is served (`get_org_details`). A guard here would invite gating an endpoint on "may call
    // reports" instead of "may read these ciphers".
}

/// Upstream's `BasePermissionRequirement`: a confirmed Owner or Admin, or a Custom member holding the
/// permission itself. An unparsable stored role satisfies neither comparison and so fails closed.
fn has_org_permission(membership: &Membership, permission: impl FnOnce(&Membership) -> bool) -> bool {
    membership.has_status(MembershipStatus::Confirmed)
        && (membership.atype >= MembershipType::Admin || permission(membership))
}

/// Upstream's `ManageUsersRequirement`.
fn may_manage_users(membership: &Membership) -> bool {
    has_org_permission(membership, Membership::has_manage_users)
}

/// Upstream's `ManageGroupsRequirement`, which guards `GET /organizations/<org_id>/groups/<id>/details`
/// as well as creating, updating and deleting groups.
fn may_manage_groups(membership: &Membership) -> bool {
    has_org_permission(membership, Membership::has_manage_groups)
}

/// Upstream's `ManageUsersOrGroupsRequirement`, which guards the group *details list* only.
fn may_manage_users_or_groups(membership: &Membership) -> bool {
    has_org_permission(membership, |m| m.has_manage_users() || m.has_manage_groups())
}

/// Upstream's `ManagePoliciesRequirement`. Note that holding it does not make a member exempt from any
/// policy; only Owners and Admins are excluded from policy enforcement.
fn may_manage_policies(membership: &Membership) -> bool {
    has_org_permission(membership, Membership::has_manage_policies)
}

// org_id is usually the second path param ("/organizations/<org_id>"),
// but there are cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
fn get_org_id(request: &Request<'_>) -> Option<OrganizationId> {
    if let Some(Ok(org_id)) = request.param::<OrganizationId>(1) {
        Some(org_id)
    } else if let Some(Ok(org_id)) = request.query_value::<OrganizationId>("organizationId") {
        Some(org_id)
    } else {
        None
    }
}

// Special Guard to ensure that there is an organization id present
// If there is no org id trigger the Outcome::Forward.
// This is useful for endpoints which work for both organization and personal vaults, like purge.
pub struct OrgIdGuard;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OrgIdGuard {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match get_org_id(request) {
            Some(_) => Outcome::Success(OrgIdGuard),
            None => Outcome::Forward(rocket::http::Status::NotFound),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OrgHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(Headers::from_request(request).await);

        // Extract the org_id from the request
        let url_org_id = get_org_id(request);

        match url_org_id {
            Some(org_id) if uuid::Uuid::parse_str(&org_id).is_ok() => {
                let Outcome::Success(conn) = DbConn::from_request(request).await else {
                    err_handler!("Error getting DB")
                };

                let user = headers.user;
                let Some(membership) = Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await else {
                    err_handler!("The current user isn't member of the organization");
                };

                Outcome::Success(Self {
                    host: headers.host,
                    device: headers.device,
                    user,
                    membership_type: {
                        if let Some(member_type) = MembershipType::from_i32(membership.atype) {
                            member_type
                        } else {
                            // This should only happen if the DB is corrupted
                            err_handler!("Unknown user type in the database")
                        }
                    },
                    membership_status: {
                        if let Some(member_status) = MembershipStatus::from_i32(membership.status) {
                            // NOTE: add additional check for revoked if from_i32 is ever changed
                            // to return Revoked status.
                            member_status
                        } else {
                            err_handler!("User status is either revoked or invalid.")
                        }
                    },
                    membership,
                    ip: headers.ip,
                })
            }
            _ => err_handler!("Error getting the organization id"),
        }
    }
}

pub struct AdminHeaders {
    // Kept for parity with the other org header guards (and possible future use); the org export
    // endpoint that used to read this now goes through `AccessImportExportHeaders` instead.
    #[allow(dead_code)]
    pub host: String,
    pub device: Device,
    pub user: User,
    pub membership_type: MembershipType,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

impl AdminHeaders {
    pub async fn log_event(&self, event_type: EventType, source_uuid: &str, org_id: &OrganizationId, conn: &DbConn) {
        log_event(event_type, source_uuid, org_id, &self.user.uuid, self.device.atype, &self.ip.ip, conn).await;
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.is_confirmed_and_admin() {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                membership_type: headers.membership_type,
                ip: headers.ip,
                org_id: headers.membership.org_uuid,
            })
        } else {
            err_handler!("You need to be Admin or Owner to call this endpoint")
        }
    }
}

// Macro to generate a request guard that permits a confirmed Admin/Owner, or a
// confirmed Custom member holding the given permission. The generated struct
// mirrors AdminHeaders so it can be used as a drop-in replacement on endpoints.
macro_rules! generate_manage_headers {
    ($name:ident, $check:ident, $err:literal) => {
        #[allow(dead_code)]
        pub struct $name {
            pub host: String,
            pub device: Device,
            pub user: User,
            pub membership_type: MembershipType,
            // The caller's membership record. Holding the permission that opens an endpoint says
            // nothing about *which* data the caller may reach, so handlers need the membership to
            // apply the regular full-access/per-collection checks on top of the guard.
            pub membership: Membership,
            pub ip: ClientIp,
            pub org_id: OrganizationId,
        }

        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for $name {
            type Error = &'static str;

            async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
                let headers = try_outcome!(OrgHeaders::from_request(request).await);
                if headers.$check() {
                    Outcome::Success(Self {
                        host: headers.host,
                        device: headers.device,
                        user: headers.user,
                        membership_type: headers.membership_type,
                        ip: headers.ip,
                        org_id: headers.membership.org_uuid.clone(),
                        membership: headers.membership,
                    })
                } else {
                    err_handler!($err)
                }
            }
        }

        impl From<$name> for Headers {
            fn from(h: $name) -> Headers {
                Headers {
                    host: h.host,
                    device: h.device,
                    user: h.user,
                    ip: h.ip,
                }
            }
        }
    };
}

generate_manage_headers!(
    ManageUsersHeaders,
    can_manage_users,
    "You need the 'Manage Users' permission, or to be an Admin or Owner, to call this endpoint"
);
generate_manage_headers!(
    ManageGroupsHeaders,
    can_manage_groups,
    "You need the 'Manage Groups' permission, or to be an Admin or Owner, to call this endpoint"
);
generate_manage_headers!(
    ManagePoliciesHeaders,
    can_manage_policies,
    "You need the 'Manage Policies' permission, or to be an Admin or Owner, to call this endpoint"
);
// Upstream's `ManageUsersOrGroupsRequirement`, which guards only the group *details list*
// (`GET /organizations/<org_id>/groups/details`). The single-group view is narrower
// (`ManageGroupsRequirement`) and therefore keeps `ManageGroupsHeaders`.
generate_manage_headers!(
    ManageUsersOrGroupsHeaders,
    can_manage_users_or_groups,
    "You need the 'Manage Users' or 'Manage Groups' permission, or to be an Admin or Owner, to call this endpoint"
);
generate_manage_headers!(
    AccessEventLogsHeaders,
    can_access_event_logs,
    "You need the 'Access Event Logs' permission, or to be an Admin or Owner, to call this endpoint"
);
generate_manage_headers!(
    AccessImportExportHeaders,
    can_access_import_export,
    "You need the 'Access Import/Export' permission, or to be an Admin or Owner, to call this endpoint"
);
// NOTE: no `AccessReportsHeaders`. See the note next to `can_access_import_export` above:
// `accessReports` guards data (the organization cipher list), not a dedicated endpoint.

// col_id is usually the fourth path param ("/organizations/<org_id>/collections/<col_id>"),
// but there could be cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
fn get_col_id(request: &Request<'_>) -> Option<CollectionId> {
    if let Some(Ok(col_id)) = request.param::<String>(3)
        && uuid::Uuid::parse_str(&col_id).is_ok()
    {
        return Some(col_id.into());
    }

    if let Some(Ok(col_id)) = request.query_value::<String>("collectionId")
        && uuid::Uuid::parse_str(&col_id).is_ok()
    {
        return Some(col_id.into());
    }

    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectionManageAccess {
    Any,
    ExplicitManage,
    Denied,
}

fn collection_access_by_role(membership: &Membership, custom_has_any_access: bool) -> CollectionManageAccess {
    if !membership.has_status(MembershipStatus::Confirmed) {
        return CollectionManageAccess::Denied;
    }

    match MembershipType::from_i32(membership.atype) {
        Some(MembershipType::Owner | MembershipType::Admin) => CollectionManageAccess::Any,
        Some(MembershipType::Custom) if custom_has_any_access => CollectionManageAccess::Any,
        // A member must prove an actual users_collections.manage / collections_groups.manage
        // assignment. Neither membership nor group `access_all` is ever counted as one.
        Some(MembershipType::Custom | MembershipType::User) => CollectionManageAccess::ExplicitManage,
        None => CollectionManageAccess::Denied,
    }
}

fn collection_edit_access(membership: &Membership) -> CollectionManageAccess {
    collection_access_by_role(membership, membership.has_edit_any_collection())
}

fn collection_read_access(membership: &Membership) -> CollectionManageAccess {
    collection_access_by_role(
        membership,
        membership.has_edit_any_collection() || membership.has_delete_any_collection(),
    )
}

/// Upstream's `BulkCollectionOperations.ReadWithAccess`, which guards the *single* collection
/// `/details` endpoint: Owner/Admin, `Edit any collection`, `Delete any collection` and `Manage users`
/// reach every collection, everyone else needs a real per-collection Manage grant.
///
/// Deliberately not the same question as [`collection_read_access`], which models upstream's
/// `ReadAccess` (`GET /collections/<col_id>/users`) and does *not* accept `Manage users`. The two
/// upstream operations differ, so these two predicates differ as well — widening
/// `CollectionReadHeaders` instead would have silently changed the `/users` endpoint too.
///
/// `Manage groups` is absent on purpose: upstream grants it `ReadAllWithAccess` (the collection
/// *list*, see `may_read_all_collections_with_access`) but not `ReadWithAccess`.
fn collection_read_with_access(membership: &Membership) -> CollectionManageAccess {
    collection_access_by_role(
        membership,
        membership.has_edit_any_collection() || membership.has_delete_any_collection() || membership.has_manage_users(),
    )
}

/// Upstream authorizes `POST /collections/bulk-access` against **both**
/// `BulkCollectionOperations.ModifyUserAccess` and `BulkCollectionOperations.ModifyGroupAccess`, and
/// its authorization service only succeeds when every requirement passes. With Vaultwarden's
/// effective `allowAdminAccessToAllCollectionItems = true`, upstream resolves them as
///
/// * `ModifyUserAccess`  = `Manage users`  OR the regular collection-update authorization
/// * `ModifyGroupAccess` = `Manage groups` OR the regular collection-update authorization
///
/// Requiring both therefore reduces to: a caller who may update the collection anyway (Owner/Admin,
/// `Edit any collection`, or a per-collection Manage grant), or one holding *both* org-wide
/// permissions. Only `Manage users` or only `Manage groups` is not enough, because the other
/// requirement then still falls back to the update check — which is the point of an endpoint that
/// rewrites a collection's user *and* group assignments in the same request.
fn collection_modify_access(membership: &Membership) -> CollectionManageAccess {
    if membership.has_status(MembershipStatus::Confirmed)
        && membership.has_manage_users()
        && membership.has_manage_groups()
    {
        return CollectionManageAccess::Any;
    }

    collection_edit_access(membership)
}

/// Collection deletion never falls back to a per-collection Manage grant.
///
/// Vaultwarden serializes `limitCollectionDeletion = true` unconditionally, and upstream gates
/// manage-based deletion on that setting being *off*: with the limit active only Owners, Admins and
/// holders of `Delete any collection` may delete. Accepting a stored `manage` grant here would break that
/// promise and make a per-collection Manage ACL double as a collection-deletion permission.
/// A Manage grant keeps its full meaning for editing (`collection_edit_access`).
fn collection_delete_access(membership: &Membership) -> CollectionManageAccess {
    if !membership.has_status(MembershipStatus::Confirmed) {
        return CollectionManageAccess::Denied;
    }

    match MembershipType::from_i32(membership.atype) {
        Some(MembershipType::Owner | MembershipType::Admin) => CollectionManageAccess::Any,
        Some(MembershipType::Custom) if membership.has_delete_any_collection() => CollectionManageAccess::Any,
        Some(MembershipType::Custom | MembershipType::User) | None => CollectionManageAccess::Denied,
    }
}

async fn can_manage_collection(
    access: CollectionManageAccess,
    membership: &Membership,
    collection_uuid: &CollectionId,
    conn: &DbConn,
) -> bool {
    match access {
        CollectionManageAccess::Any => true,
        CollectionManageAccess::ExplicitManage => {
            membership.has_explicit_collection_manage_access(collection_uuid, conn).await
        }
        CollectionManageAccess::Denied => false,
    }
}

/// Whether `membership` may edit (rewrite the access of) `collection_uuid`, on exactly the same rules as
/// the path-based `ManagerHeaders` guard: Edit-any (or Admin/Owner) reaches every collection, otherwise
/// only those carrying a real per-collection Manage grant. Group `access_all` deliberately does not
/// qualify. Body-param endpoints cannot use `ManagerHeaders`, so they run this per collection instead.
pub(crate) async fn can_edit_collection(
    membership: &Membership,
    collection_uuid: &CollectionId,
    conn: &DbConn,
) -> bool {
    can_manage_collection(collection_edit_access(membership), membership, collection_uuid, conn).await
}

/// Whether `membership` may read a collection's user/group access mappings.
///
/// The same rule as `CollectionReadHeaders`: Admin/Owner, Edit-any/Delete-any, or a real
/// per-collection Manage assignment. Ordinary read access and group `access_all` do not qualify.
pub(crate) async fn can_read_collection_access(
    membership: &Membership,
    collection_uuid: &CollectionId,
    conn: &DbConn,
) -> bool {
    can_manage_collection(collection_read_access(membership), membership, collection_uuid, conn).await
}

/// Whether `membership` may read `collection_uuid` *together with* its user/group assignments —
/// upstream's `ReadWithAccess`, which guards `GET /organizations/<org_id>/collections/<col_id>/details`.
/// See [`collection_read_with_access`] for why this is not [`can_read_collection_access`].
pub(crate) async fn can_read_collection_with_access(
    membership: &Membership,
    collection_uuid: &CollectionId,
    conn: &DbConn,
) -> bool {
    can_manage_collection(collection_read_with_access(membership), membership, collection_uuid, conn).await
}

/// Whether `membership` may rewrite both the user *and* the group assignments of `collection_uuid`,
/// as `POST /organizations/<org_id>/collections/bulk-access` does. See [`collection_modify_access`].
pub(crate) async fn can_modify_collection_access(
    membership: &Membership,
    collection_uuid: &CollectionId,
    conn: &DbConn,
) -> bool {
    can_manage_collection(collection_modify_access(membership), membership, collection_uuid, conn).await
}

/// ManagerHeaders authorizes collection updates. A Custom member with Edit any collection can
/// update every collection; otherwise the caller must hold a per-collection Manage permission.
/// Read and delete use separate guards so Edit cannot accidentally imply Delete.
pub struct ManagerHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ManagerHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.membership.has_status(MembershipStatus::Confirmed) {
            if let Some(col_id) = get_col_id(request) {
                let access = collection_edit_access(&headers.membership);
                if access != CollectionManageAccess::Any {
                    let Outcome::Success(conn) = DbConn::from_request(request).await else {
                        err_handler!("Error getting DB")
                    };

                    if !can_manage_collection(access, &headers.membership, &col_id, &conn).await {
                        err_handler!("The current user isn't a manager for this collection")
                    }
                }
            } else {
                err_handler!("Error getting the collection id")
            }

            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                ip: headers.ip,
                org_id: headers.membership.org_uuid,
            })
        } else {
            err_handler!("You need to be a Manager, Admin or Owner to call this endpoint")
        }
    }
}

/// Read access to a collection's access mappings — upstream's `BulkCollectionOperations.ReadAccess`.
/// Delete any collection needs this visibility to render the standard collection view, but it does not
/// grant edit or cipher access, and — unlike `ReadWithAccess`, see [`collection_read_with_access`] —
/// `Manage users` alone does not open it.
pub struct CollectionReadHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CollectionReadHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if !headers.membership.has_status(MembershipStatus::Confirmed) {
            err_handler!("You need collection read permission to call this endpoint")
        }

        let Some(col_id) = get_col_id(request) else {
            err_handler!("Error getting the collection id")
        };

        let access = collection_read_access(&headers.membership);

        if access != CollectionManageAccess::Any {
            let Outcome::Success(conn) = DbConn::from_request(request).await else {
                err_handler!("Error getting DB")
            };

            if !can_manage_collection(access, &headers.membership, &col_id, &conn).await {
                err_handler!("The current user isn't a manager for this collection")
            }
        }

        Outcome::Success(Self {
            host: headers.host,
            device: headers.device,
            user: headers.user,
            ip: headers.ip,
            org_id: headers.membership.org_uuid,
        })
    }
}

impl From<CollectionReadHeaders> for Headers {
    fn from(h: CollectionReadHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

/// Delete is fully independent from the other two collection permissions. Vaultwarden advertises
/// `limitCollectionDeletion = true`, so deleting a collection requires Admin/Owner or the explicit
/// Delete any collection permission — see `collection_delete_access` for why a per-collection Manage
/// grant deliberately does not qualify.
pub struct CollectionDeleteHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CollectionDeleteHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if !headers.is_confirmed_and_manager() {
            err_handler!("You need collection delete permission to call this endpoint")
        }

        // Only used to keep this guard bound to routes that actually carry a collection id.
        if get_col_id(request).is_none() {
            err_handler!("Error getting the collection id")
        }

        match collection_delete_access(&headers.membership) {
            CollectionManageAccess::Any => {}
            // Custom is a distinct, fail-closed role: neither Edit any collection nor a stored
            // per-collection Manage grant substitutes for Delete any collection.
            CollectionManageAccess::ExplicitManage | CollectionManageAccess::Denied => {
                err_handler!("You need the 'Delete any collection' permission to call this endpoint")
            }
        }

        Outcome::Success(Self {
            host: headers.host,
            device: headers.device,
            user: headers.user,
            ip: headers.ip,
            org_id: headers.membership.org_uuid,
        })
    }
}

impl From<CollectionDeleteHeaders> for Headers {
    fn from(h: CollectionDeleteHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
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

/// The ManagerHeadersLoose is used for organization endpoints whose exact permission depends on
/// request data or whose response is filtered by the caller's collection-management authority.
pub struct ManagerHeadersLoose {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub membership: Membership,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ManagerHeadersLoose {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.membership.has_status(MembershipStatus::Confirmed) {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                membership: headers.membership,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be a confirmed organization member to call this endpoint")
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

impl CollectionDeleteHeaders {
    pub async fn from_loose(
        h: ManagerHeadersLoose,
        collections: &Vec<CollectionId>,
        conn: &DbConn,
    ) -> Result<CollectionDeleteHeaders, Error> {
        // Bulk delete answers to the same rule as the single-collection route: blanket authority or
        // nothing. A per-collection Manage grant is not a delete permission.
        if collection_delete_access(&h.membership) != CollectionManageAccess::Any {
            err!("You need the 'Delete any collection' permission to call this endpoint")
        }

        for col_id in collections {
            if uuid::Uuid::parse_str(col_id.as_ref()).is_err() {
                err!("Collection Id is malformed!");
            }
            if Collection::find_by_uuid_and_org(col_id, &h.membership.org_uuid, conn).await.is_none() {
                err!("Collection not found", "Collection does not exist or does not belong to this organization")
            }
        }

        Ok(CollectionDeleteHeaders {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
            org_id: h.membership.org_uuid,
        })
    }
}

pub struct OwnerHeaders {
    pub device: Device,
    pub user: User,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OwnerHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.is_confirmed_and_owner() {
            Outcome::Success(Self {
                device: headers.device,
                user: headers.user,
                ip: headers.ip,
                org_id: headers.membership.org_uuid,
            })
        } else {
            err_handler!("You need to be Owner to call this endpoint")
        }
    }
}

pub struct OrgMemberHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub membership: Membership,
    pub ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OrgMemberHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if headers.is_member() {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                membership: headers.membership,
                ip: headers.ip,
            })
        } else {
            err_handler!("You need to be a Member of the Organization to call this endpoint")
        }
    }
}

impl From<OrgMemberHeaders> for Headers {
    fn from(h: OrgMemberHeaders) -> Headers {
        Headers {
            host: h.host,
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

//
// Client IP address detection
//
#[derive(Copy, Clone)]
pub struct ClientIp {
    pub ip: IpAddr,
}

/// Parses a single entry of `ip_header_trusted_proxies`, which can be a CIDR range or a plain IP.
pub fn parse_trusted_proxy(entry: &str) -> Option<IpNet> {
    let entry = entry.trim();
    match entry.parse::<IpNet>() {
        Ok(net) => Some(net),
        // Without a prefix length it is a single address, which is a valid way to write this.
        Err(_) => entry.parse::<IpAddr>().ok().map(IpNet::from),
    }
}

/// The client IP header can be set by anyone able to reach us, so only accept it from a proxy we trust.
fn ip_header_is_trusted(remote: Option<IpAddr>) -> bool {
    let trusted = CONFIG.ip_header_trusted_proxies();
    let trusted = trusted.trim();
    if trusted.eq_ignore_ascii_case("all") {
        return true;
    }

    let Some(remote) = remote else {
        return false;
    };
    // A dual stack listener reports IPv4 clients as IPv4-mapped IPv6, which `is_global()` reports as
    // non global. That is what we want when blocking outgoing requests, but here it would trust them.
    let remote = remote.to_canonical();
    if trusted.eq_ignore_ascii_case("local") {
        return !crate::util::is_global(remote);
    }
    trusted.split(',').filter_map(parse_trusted_proxy).any(|net| net.contains(&remote))
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let remote = req.remote().map(|r| r.ip());

        let ip = if CONFIG._ip_header_enabled() && ip_header_is_trusted(remote) {
            req.headers().get_one(&CONFIG.ip_header()).and_then(|ip| {
                match ip.find(',') {
                    Some(idx) => &ip[..idx],
                    None => ip,
                }
                .parse()
                .map_err(|_| warn!("'{}' header is malformed: {ip}", CONFIG.ip_header()))
                .ok()
            })
        } else {
            if CONFIG._ip_header_enabled() && req.headers().get_one(&CONFIG.ip_header()).is_some() {
                // Log the canonical IP, which is what the user filter will need to match against
                let remote = remote.map(|ip| ip.to_canonical());
                debug!("Ignoring the '{}' header, {remote:?} is not a trusted proxy", CONFIG.ip_header());
            }
            None
        };

        let ip = ip.or(remote).unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        Outcome::Success(ClientIp {
            ip,
        })
    }
}

#[derive(Copy, Clone)]
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

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    OrgApiKey,
    Password,
    Sso,
    UserApiKey,
}

impl AuthMethod {
    pub fn scope(&self) -> String {
        match self {
            AuthMethod::OrgApiKey => "api.organization".to_owned(),
            AuthMethod::UserApiKey => "api".to_owned(),
            AuthMethod::Password | AuthMethod::Sso => "api offline_access".to_owned(),
        }
    }

    pub fn scope_vec(&self) -> Vec<String> {
        self.scope().split_whitespace().map(str::to_owned).collect()
    }

    pub fn check_scope(&self, scope: Option<&String>) -> ApiResult<String> {
        let method_scope = self.scope();
        match scope {
            None => err!("Missing scope"),
            Some(scope) if scope == &method_scope => Ok(method_scope),
            Some(scope) => err!(format!("Scope ({scope}) not supported")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenWrapper {
    Access(String),
    Refresh(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: AuthMethod,

    pub device_token: String,

    pub token: Option<TokenWrapper>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthTokens {
    pub refresh_claims: RefreshJwtClaims,
    pub access_claims: LoginJwtClaims,
}

impl AuthTokens {
    pub fn refresh_token(&self) -> String {
        encode_jwt(&self.refresh_claims)
    }

    pub fn access_token(&self) -> String {
        self.access_claims.token()
    }

    pub fn expires_in(&self) -> i64 {
        self.access_claims.expires_in()
    }

    pub fn scope(&self) -> String {
        self.refresh_claims.sub.scope()
    }

    // Create refresh_token and access_token with default validity
    pub fn new(device: &Device, user: &User, sub: AuthMethod, client_id: Option<String>) -> Self {
        let time_now = Utc::now();

        let access_claims = LoginJwtClaims::default(device, user, &sub, client_id);

        let validity = if device.is_mobile() {
            *MOBILE_REFRESH_VALIDITY
        } else {
            *DEFAULT_REFRESH_VALIDITY
        };

        let refresh_claims = RefreshJwtClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + validity).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub,
            device_token: device.refresh_token.clone(),
            token: None,
        };

        Self {
            refresh_claims,
            access_claims,
        }
    }
}

pub async fn refresh_tokens(
    ip: &ClientIp,
    refresh_token: &str,
    client_id: Option<String>,
    conn: &DbConn,
) -> ApiResult<(Device, AuthTokens)> {
    let refresh_claims = match decode_refresh(refresh_token) {
        Err(err) => {
            error!("Failed to decode refresh_token from {}: {err:?}", ip.ip);
            err_silent!("Invalid refresh token")
        }
        Ok(claims) => claims,
    };

    // Get device by refresh token
    let Some(mut device) = Device::find_by_refresh_token(&refresh_claims.device_token, conn).await else {
        err!("Invalid refresh token")
    };

    // Save to update `updated_at`.
    device.save(true, conn).await?;

    let Some(user) = User::find_by_uuid(&device.user_uuid, conn).await else {
        err!("Impossible to find user")
    };

    let auth_tokens = match refresh_claims.sub {
        AuthMethod::Sso if CONFIG.sso_enabled() && CONFIG.sso_auth_only_not_session() => {
            AuthTokens::new(&device, &user, refresh_claims.sub, client_id)
        }
        AuthMethod::Sso if CONFIG.sso_enabled() => {
            sso::exchange_refresh_token(&device, &user, client_id, refresh_claims).await?
        }
        AuthMethod::Sso => err!("SSO is now disabled, Login again using email and master password"),
        AuthMethod::Password if CONFIG.sso_enabled() && CONFIG.sso_only() => err!("SSO is now required, Login again"),
        AuthMethod::Password => AuthTokens::new(&device, &user, refresh_claims.sub, client_id),
        _ => err!("Invalid auth method, cannot refresh token"),
    };

    Ok((device, auth_tokens))
}

#[cfg(test)]
mod tests {
    use super::{
        CollectionManageAccess, collection_delete_access, collection_edit_access, collection_modify_access,
        collection_read_access, collection_read_with_access, may_manage_groups, may_manage_policies, may_manage_users,
        may_manage_users_or_groups,
    };
    use crate::db::models::{Membership, MembershipStatus as Status, MembershipType, OrganizationId, UserId};

    const OWNER: i32 = MembershipType::Owner as i32;
    const ADMIN: i32 = MembershipType::Admin as i32;
    const USER: i32 = MembershipType::User as i32;
    const CUSTOM: i32 = MembershipType::Custom as i32;
    /// An `atype` this build cannot interpret: a future build, a partial rollback or a hand-edited row.
    const UNKNOWN: i32 = 99;

    /// The permission columns are set regardless of the role on purpose, so a flag left behind by a
    /// role change can be covered too.
    fn member(atype: i32, status: Status, set: impl FnOnce(&mut Membership)) -> Membership {
        let mut membership = Membership::new(
            UserId::from(String::from("test-user")),
            OrganizationId::from(String::from("test-org")),
            None,
        );
        membership.atype = atype;
        membership.status = status as i32;
        set(&mut membership);
        membership
    }

    fn confirmed(atype: i32, set: impl FnOnce(&mut Membership)) -> Membership {
        member(atype, Status::Confirmed, set)
    }

    fn nothing(_: &mut Membership) {}

    /// Every permission this file's guards read, so a row can show that none of them help.
    fn all_permissions(m: &mut Membership) {
        m.edit_any_collection = true;
        m.delete_any_collection = true;
        m.manage_users = true;
        m.manage_groups = true;
        m.manage_policies = true;
    }

    /// Who may edit, read, read-with-access, rewrite the access of, and delete a collection.
    ///
    /// These five predicates model five *different* upstream operations and are deliberately not the
    /// same rule; the differences between the columns are the point of this table. A change that makes
    /// any two of them agree where they must not is what this test exists to catch.
    ///
    /// `Any` reaches every collection of the organization, `ExplicitManage` only those carrying a real
    /// `users_collections.manage` / `collections_groups.manage` grant, `Denied` none at all.
    #[test]
    fn collection_operation_access_matrix() {
        use CollectionManageAccess::{Any, Denied, ExplicitManage as Explicit};

        let owner = confirmed(OWNER, nothing);
        let admin = confirmed(ADMIN, nothing);
        let edit_any = confirmed(CUSTOM, |m| m.edit_any_collection = true);
        let delete_any = confirmed(CUSTOM, |m| m.delete_any_collection = true);
        let manage_users = confirmed(CUSTOM, |m| m.manage_users = true);
        let manage_groups = confirmed(CUSTOM, |m| m.manage_groups = true);
        let manage_both = confirmed(CUSTOM, |m| {
            m.manage_users = true;
            m.manage_groups = true;
        });
        let bare_custom = confirmed(CUSTOM, nothing);
        let user = confirmed(USER, nothing);
        let stale_user = confirmed(USER, all_permissions);
        let revoked = member(CUSTOM, Status::Revoked, all_permissions);
        let unknown = member(UNKNOWN, Status::Confirmed, all_permissions);

        // (case, membership, edit, read, read-with-access, modify access, delete)
        let cases = [
            ("Owner", &owner, Any, Any, Any, Any, Any),
            ("Admin", &admin, Any, Any, Any, Any, Any),
            // Edit-any reaches every collection for editing and may read the access lists, but
            // deletion never follows from it: Vaultwarden always serializes
            // `limitCollectionDeletion = true`.
            ("Custom + editAnyCollection", &edit_any, Any, Any, Any, Any, Denied),
            // Delete-any is the mirror image: it deletes and reads, but does not edit.
            ("Custom + deleteAnyCollection", &delete_any, Explicit, Any, Any, Explicit, Any),
            // Manage-users reaches the single collection *details* view (upstream's `ReadWithAccess`)
            // but not the `/users` access list (`ReadAccess`), which is a narrower operation.
            ("Custom + manageUsers", &manage_users, Explicit, Explicit, Any, Explicit, Denied),
            // Manage-groups reaches neither: upstream grants it the collection *list*, not the single
            // collection with its access.
            ("Custom + manageGroups", &manage_groups, Explicit, Explicit, Explicit, Explicit, Denied),
            // `bulk-access` rewrites user *and* group assignments in one request, so upstream requires
            // both permissions. Either alone still falls back to the regular update authorization.
            ("Custom + manageUsers + manageGroups", &manage_both, Explicit, Explicit, Any, Any, Denied),
            // Without an org-wide permission a Custom member is exactly a User: only real
            // per-collection Manage grants count, and deleting is out of reach entirely.
            ("Custom without permissions", &bare_custom, Explicit, Explicit, Explicit, Explicit, Denied),
            ("User", &user, Explicit, Explicit, Explicit, Explicit, Denied),
            // Flags a role change left behind, an unconfirmed membership and a role this build cannot
            // interpret all fail closed.
            ("User with stale permission flags", &stale_user, Explicit, Explicit, Explicit, Explicit, Denied),
            ("revoked Custom holding everything", &revoked, Denied, Denied, Denied, Denied, Denied),
            ("unknown role holding everything", &unknown, Denied, Denied, Denied, Denied, Denied),
        ];

        for (case, m, edit, read, read_with_access, modify, delete) in cases {
            assert_eq!(collection_edit_access(m), edit, "{case}: edit");
            assert_eq!(collection_read_access(m), read, "{case}: read access lists");
            assert_eq!(collection_read_with_access(m), read_with_access, "{case}: read with access");
            assert_eq!(collection_modify_access(m), modify, "{case}: modify user and group access");
            assert_eq!(collection_delete_access(m), delete, "{case}: delete");
        }
    }

    /// The organization-wide permission guards behind `ManageUsersHeaders` and friends: a confirmed
    /// Owner/Admin, or a Custom member holding *that* permission.
    ///
    /// Catches a guard wired to the wrong flag, a lost status gate, and an unknown stored role
    /// slipping through any of them.
    #[test]
    fn org_permission_guards_require_a_confirmed_role_or_the_matching_flag() {
        let owner = confirmed(OWNER, nothing);
        let admin = confirmed(ADMIN, nothing);
        let invited_owner = member(OWNER, Status::Invited, nothing);
        let users = confirmed(CUSTOM, |m| m.manage_users = true);
        let groups = confirmed(CUSTOM, |m| m.manage_groups = true);
        let policies = confirmed(CUSTOM, |m| m.manage_policies = true);
        let bare_custom = confirmed(CUSTOM, nothing);
        let user = confirmed(USER, nothing);
        let stale_user = confirmed(USER, all_permissions);
        let revoked = member(CUSTOM, Status::Revoked, all_permissions);
        let unknown = member(UNKNOWN, Status::Confirmed, all_permissions);

        // (case, membership, manage users, manage groups, either, manage policies)
        let cases = [
            ("Owner", &owner, true, true, true, true),
            ("Admin", &admin, true, true, true, true),
            // Admins and Owners hold every permission by role, but only once confirmed.
            ("invited Owner", &invited_owner, false, false, false, false),
            ("Custom + manageUsers", &users, true, false, true, false),
            ("Custom + manageGroups", &groups, false, true, true, false),
            ("Custom + managePolicies", &policies, false, false, false, true),
            ("Custom without permissions", &bare_custom, false, false, false, false),
            ("User", &user, false, false, false, false),
            // Stale flags, an unconfirmed membership and an unknown role all fail closed.
            ("User with stale permission flags", &stale_user, false, false, false, false),
            ("revoked Custom holding everything", &revoked, false, false, false, false),
            ("unknown role holding everything", &unknown, false, false, false, false),
        ];

        for (case, m, users, groups, users_or_groups, policies) in cases {
            assert_eq!(may_manage_users(m), users, "{case}: manage users");
            assert_eq!(may_manage_groups(m), groups, "{case}: manage groups");
            assert_eq!(may_manage_users_or_groups(m), users_or_groups, "{case}: manage users or groups");
            assert_eq!(may_manage_policies(m), policies, "{case}: manage policies");
        }
    }
}
