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
    api::ApiResult,
    config::PathType,
    db::{
        DbConn,
        models::{
            AttachmentId, CipherId, Collection, CollectionId, Device, DeviceId, DeviceType, EmergencyAccessId,
            Membership, MembershipId, MembershipStatus, MembershipType, OrgApiKeyId, OrganizationId, SendFileId,
            SendId, User, UserId, UserStampException,
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
        self.is_confirmed() && (self.membership_type >= MembershipType::Admin || self.membership.has_manage_users())
    }
    fn can_manage_groups(&self) -> bool {
        self.is_confirmed() && (self.membership_type >= MembershipType::Admin || self.membership.has_manage_groups())
    }
    fn can_manage_policies(&self) -> bool {
        self.is_confirmed() && (self.membership_type >= MembershipType::Admin || self.membership.has_manage_policies())
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
// NOTE: no `ManageUsersOrGroupsHeaders`. Reading group *details* is not a single-permission question
// -- organization-wide collection reach grants it too -- so both routes take `ManagerHeadersLoose`
// and ask `can_read_group_details`. The full *member* list is, and keeps `ManageUsersHeaders`.
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
        // A Custom member must prove an actual users_collections.manage / collections_groups.manage
        // assignment. Neither membership nor group `access_all` is ever counted as one.
        Some(MembershipType::Custom) => CollectionManageAccess::ExplicitManage,
        Some(MembershipType::User) | None => CollectionManageAccess::Denied,
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

/// Collection deletion never falls back to a per-collection Manage grant.
///
/// Vaultwarden serializes `limitCollectionDeletion = true` unconditionally, and upstream gates
/// manage-based deletion on that setting being *off*: with the limit active only Owners, Admins and
/// holders of `Delete any collection` may delete. Accepting a stored `manage` grant here would break
/// that promise and make the three collection permissions depend on each other — `Create new
/// collections` alone receives an automatic `manage` row for the collection it just created, and
/// could then delete it. A Manage grant keeps its full meaning for editing (`collection_edit_access`);
/// it just is not a delete permission.
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

/// Whether `membership` may edit (rewrite the access of) `collection_uuid`, on exactly the same rules
/// as the path-based `ManagerHeaders` guard: Edit-any (or Admin/Owner) reaches every collection,
/// otherwise only those carrying a real per-collection Manage grant. Group `access_all` deliberately
/// does not qualify.
///
/// Body-param endpoints take collection ids in the request body and so cannot use `ManagerHeaders`;
/// they run this per collection instead, so the two cannot diverge.
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

/// ManagerHeaders authorizes collection updates. A Custom member with Edit any collection can
/// update every collection; otherwise the caller must be a Custom member (or above) holding the
/// per-collection Manage permission. Read and delete use separate guards so Edit cannot
/// accidentally imply Delete.
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
        if headers.is_confirmed_and_manager() {
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

/// Read access to collection metadata and assignment details. Delete any collection needs this
/// visibility to render the standard collection view, but it does not grant edit or cipher access.
pub struct CollectionReadHeaders {
    pub host: String,
    pub device: Device,
    pub user: User,
    pub membership: Membership,
    pub ip: ClientIp,
    pub org_id: OrganizationId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CollectionReadHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = try_outcome!(OrgHeaders::from_request(request).await);
        if !headers.is_confirmed_and_manager() {
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
            org_id: headers.membership.org_uuid.clone(),
            membership: headers.membership,
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

/// The ManagerHeadersLoose is used when you at least need to be a Manager,
/// but there is no collection_id sent with the request (either in the path or as form data).
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
        if headers.is_confirmed_and_manager() {
            Outcome::Success(Self {
                host: headers.host,
                device: headers.device,
                user: headers.user,
                membership: headers.membership,
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
    use super::{CollectionManageAccess, collection_delete_access, collection_edit_access, collection_read_access};
    use crate::db::models::{Membership, MembershipStatus, MembershipType};

    fn membership(member_type: MembershipType) -> Membership {
        let mut membership = Membership::new("test-user".to_owned().into(), "test-org".to_owned().into(), None);
        membership.atype = member_type as i32;
        membership.status = MembershipStatus::Confirmed as i32;
        membership
    }

    #[test]
    fn flagless_custom_requires_explicit_manage_for_edit_and_read_and_cannot_delete() {
        // A flagless Custom member gets no blanket collection authority from its role. Edit and read are
        // answered per collection by `has_explicit_collection_manage_access`, which accepts a real manage
        // grant and nothing else -- a group's `access_all` is not one. Delete has no per-collection fallback
        // at all, hence Denied rather than ExplicitManage; see `collection_delete_access`.
        let custom = membership(MembershipType::Custom);
        assert_eq!(collection_edit_access(&custom), CollectionManageAccess::ExplicitManage);
        assert_eq!(collection_read_access(&custom), CollectionManageAccess::ExplicitManage);
        assert_eq!(collection_delete_access(&custom), CollectionManageAccess::Denied);
    }

    #[test]
    fn custom_any_permissions_remain_independent() {
        let mut edit_any = membership(MembershipType::Custom);
        edit_any.edit_any_collection = true;
        assert_eq!(collection_edit_access(&edit_any), CollectionManageAccess::Any);
        assert_eq!(collection_read_access(&edit_any), CollectionManageAccess::Any);
        // Edit any collection is never a delete permission, not even for a collection the member
        // holds an explicit Manage grant on.
        assert_eq!(collection_delete_access(&edit_any), CollectionManageAccess::Denied);

        let mut delete_any = membership(MembershipType::Custom);
        delete_any.delete_any_collection = true;
        assert_eq!(collection_edit_access(&delete_any), CollectionManageAccess::ExplicitManage);
        assert_eq!(collection_read_access(&delete_any), CollectionManageAccess::Any);
        assert_eq!(collection_delete_access(&delete_any), CollectionManageAccess::Any);

        // Create new collections yields the automatic users_collections.manage row on the created
        // collection. That row must not become a delete permission either.
        let mut create_only = membership(MembershipType::Custom);
        create_only.create_new_collections = true;
        assert_eq!(collection_edit_access(&create_only), CollectionManageAccess::ExplicitManage);
        assert_eq!(collection_delete_access(&create_only), CollectionManageAccess::Denied);
    }

    /// A stored `atype` that is not one of the four known roles must never be treated as one, in
    /// either direction. 3 is the retired Manager discriminant, and a negative value is what a
    /// corrupt row or a hand-written UPDATE could leave behind -- it would satisfy a numeric
    /// `atype <= Admin` SQL predicate, which is why the queries enumerate the two admin values
    /// instead (`ORG_ADMIN_ATYPES`).
    #[test]
    fn unknown_stored_role_values_fail_closed() {
        for atype in [-1, 3, 5, i32::MAX, i32::MIN] {
            let mut unknown = membership(MembershipType::Custom);
            unknown.atype = atype;
            // Even with every permission set, an unrecognized role grants nothing.
            unknown.edit_any_collection = true;
            unknown.delete_any_collection = true;
            unknown.create_new_collections = true;

            assert_eq!(collection_edit_access(&unknown), CollectionManageAccess::Denied, "atype {atype}");
            assert_eq!(collection_read_access(&unknown), CollectionManageAccess::Denied, "atype {atype}");
            assert_eq!(collection_delete_access(&unknown), CollectionManageAccess::Denied, "atype {atype}");
        }
    }

    #[test]
    fn admin_and_user_collection_access_roles() {
        let admin = membership(MembershipType::Admin);
        assert_eq!(collection_edit_access(&admin), CollectionManageAccess::Any);
        assert_eq!(collection_read_access(&admin), CollectionManageAccess::Any);
        assert_eq!(collection_delete_access(&admin), CollectionManageAccess::Any);

        let user = membership(MembershipType::User);
        assert_eq!(collection_edit_access(&user), CollectionManageAccess::Denied);
        assert_eq!(collection_read_access(&user), CollectionManageAccess::Denied);
        assert_eq!(collection_delete_access(&user), CollectionManageAccess::Denied);
    }

    #[test]
    fn a_migrated_legacy_manager_carries_its_authority_in_the_permission_columns() {
        // A legacy Manager who managed every collection through a group with access_all is not
        // recognized by its shape at runtime -- that shape is indistinguishable from a newly created
        // flagless Custom member. The repair migration writes the authority into the permission
        // columns instead, so the guard sees an ordinary Edit/Delete any collection holder.
        let mut migrated_group_manager = membership(MembershipType::Custom);
        migrated_group_manager.edit_any_collection = true;
        migrated_group_manager.delete_any_collection = true;
        assert_eq!(collection_edit_access(&migrated_group_manager), CollectionManageAccess::Any);
        assert_eq!(collection_delete_access(&migrated_group_manager), CollectionManageAccess::Any);

        // Without those columns nothing is derived, no matter which groups the member belongs to.
        let flagless = membership(MembershipType::Custom);
        assert_eq!(collection_edit_access(&flagless), CollectionManageAccess::ExplicitManage);
        assert_eq!(collection_delete_access(&flagless), CollectionManageAccess::Denied);

        let mut unconfirmed = membership(MembershipType::Custom);
        unconfirmed.status = MembershipStatus::Accepted as i32;
        unconfirmed.edit_any_collection = true;
        unconfirmed.delete_any_collection = true;
        assert_eq!(collection_edit_access(&unconfirmed), CollectionManageAccess::Denied);
        assert_eq!(collection_delete_access(&unconfirmed), CollectionManageAccess::Denied);
    }
}
