use chrono::{NaiveDateTime, Utc};

use crate::db::schema::devices;
use crate::{crypto, CONFIG};
use core::fmt;

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = devices)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid, user_uuid))]
pub struct Device {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: String,

    pub name: String,
    pub atype: i32, // https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<String>,
    pub push_token: Option<String>,

    pub refresh_token: String,

    pub twofactor_remember: Option<String>,
}

/// Local methods
impl Device {
    pub fn new(uuid: String, user_uuid: String, name: String, atype: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_uuid: None,
            push_token: None,
            refresh_token: String::new(),
            twofactor_remember: None,
        }
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use data_encoding::BASE64;
        let twofactor_remember = crypto::encode_random_bytes::<180>(BASE64);
        self.twofactor_remember = Some(twofactor_remember.clone());

        twofactor_remember
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    pub fn refresh_tokens(
        &mut self,
        user: &super::User,
        orgs: Vec<super::UserOrganization>,
        scope: Vec<String>,
    ) -> (String, i64) {
        // If there is no refresh token, we create one
        if self.refresh_token.is_empty() {
            use data_encoding::BASE64URL;
            self.refresh_token = crypto::encode_random_bytes::<64>(BASE64URL);
        }

        // Update the expiration of the device and the last update date
        let time_now = Utc::now().naive_utc();
        self.updated_at = time_now;

        let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == 0).map(|o| o.org_uuid.clone()).collect();
        let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == 1).map(|o| o.org_uuid.clone()).collect();
        let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == 2).map(|o| o.org_uuid.clone()).collect();
        let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == 3).map(|o| o.org_uuid.clone()).collect();

        // Create the JWT claims struct, to send to the client
        use crate::auth::{encode_jwt, LoginJwtClaims, DEFAULT_VALIDITY, JWT_LOGIN_ISSUER};
        let claims = LoginJwtClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + *DEFAULT_VALIDITY).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid.clone(),

            premium: true,
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: !CONFIG.mail_enabled() || user.verified_at.is_some(),

            orgowner,
            orgadmin,
            orguser,
            orgmanager,

            sstamp: user.security_stamp.clone(),
            device: self.uuid.clone(),
            scope,
            amr: vec!["Application".into()],
        };

        (encode_jwt(&claims), DEFAULT_VALIDITY.num_seconds())
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Device {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                crate::util::retry(
                    || diesel::replace_into(devices::table).values(&*self).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql {
                crate::util::retry(
                    || diesel::insert_into(devices::table).values(&*self).on_conflict((devices::uuid, devices::user_uuid)).do_update().set(&*self).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading devices")
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn clear_push_token_by_uuid(uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(devices::table)
                .filter(devices::uuid.eq(uuid))
                .set(devices::push_token.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing push token")
        }}
    }
    pub async fn find_by_refresh_token(refresh_token: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::refresh_token.eq(refresh_token))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_latest_active_by_user(user_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        }}
    }
    pub async fn find_push_devices_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<Self>(conn)
                .expect("Error loading push devices")
        }}
    }

    pub async fn check_user_has_push_device(user_uuid: &str, conn: &DbConn) -> bool {
        db_run! { conn: {
            devices::table
            .filter(devices::user_uuid.eq(user_uuid))
            .filter(devices::push_token.is_not_null())
            .count()
            .first::<i64>(conn)
            .ok()
            .unwrap_or(0) != 0
        }}
    }
}

pub enum DeviceType {
    Android = 0,
    Ios = 1,
    ChromeExtension = 2,
    FirefoxExtension = 3,
    OperaExtension = 4,
    EdgeExtension = 5,
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
    ChromeBrowser = 9,
    FirefoxBrowser = 10,
    OperaBrowser = 11,
    EdgeBrowser = 12,
    IEBrowser = 13,
    UnknownBrowser = 14,
    AndroidAmazon = 15,
    Uwp = 16,
    SafariBrowser = 17,
    VivaldiBrowser = 18,
    VivaldiExtension = 19,
    SafariExtension = 20,
    Sdk = 21,
    Server = 22,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceType::Android => write!(f, "Android"),
            DeviceType::Ios => write!(f, "iOS"),
            DeviceType::ChromeExtension => write!(f, "Chrome Extension"),
            DeviceType::FirefoxExtension => write!(f, "Firefox Extension"),
            DeviceType::OperaExtension => write!(f, "Opera Extension"),
            DeviceType::EdgeExtension => write!(f, "Edge Extension"),
            DeviceType::WindowsDesktop => write!(f, "Windows Desktop"),
            DeviceType::MacOsDesktop => write!(f, "MacOS Desktop"),
            DeviceType::LinuxDesktop => write!(f, "Linux Desktop"),
            DeviceType::ChromeBrowser => write!(f, "Chrome Browser"),
            DeviceType::FirefoxBrowser => write!(f, "Firefox Browser"),
            DeviceType::OperaBrowser => write!(f, "Opera Browser"),
            DeviceType::EdgeBrowser => write!(f, "Edge Browser"),
            DeviceType::IEBrowser => write!(f, "Internet Explorer"),
            DeviceType::UnknownBrowser => write!(f, "Unknown Browser"),
            DeviceType::AndroidAmazon => write!(f, "Android Amazon"),
            DeviceType::Uwp => write!(f, "UWP"),
            DeviceType::SafariBrowser => write!(f, "Safari Browser"),
            DeviceType::VivaldiBrowser => write!(f, "Vivaldi Browser"),
            DeviceType::VivaldiExtension => write!(f, "Vivaldi Extension"),
            DeviceType::SafariExtension => write!(f, "Safari Extension"),
            DeviceType::Sdk => write!(f, "SDK"),
            DeviceType::Server => write!(f, "Server"),
        }
    }
}

impl DeviceType {
    pub fn from_i32(value: i32) -> DeviceType {
        match value {
            0 => DeviceType::Android,
            1 => DeviceType::Ios,
            2 => DeviceType::ChromeExtension,
            3 => DeviceType::FirefoxExtension,
            4 => DeviceType::OperaExtension,
            5 => DeviceType::EdgeExtension,
            6 => DeviceType::WindowsDesktop,
            7 => DeviceType::MacOsDesktop,
            8 => DeviceType::LinuxDesktop,
            9 => DeviceType::ChromeBrowser,
            10 => DeviceType::FirefoxBrowser,
            11 => DeviceType::OperaBrowser,
            12 => DeviceType::EdgeBrowser,
            13 => DeviceType::IEBrowser,
            14 => DeviceType::UnknownBrowser,
            15 => DeviceType::AndroidAmazon,
            16 => DeviceType::Uwp,
            17 => DeviceType::SafariBrowser,
            18 => DeviceType::VivaldiBrowser,
            19 => DeviceType::VivaldiExtension,
            20 => DeviceType::SafariExtension,
            21 => DeviceType::Sdk,
            22 => DeviceType::Server,
            _ => DeviceType::UnknownBrowser,
        }
    }
}
