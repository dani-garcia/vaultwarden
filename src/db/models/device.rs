use chrono::{NaiveDateTime, Utc};
use data_encoding::{BASE64, BASE64URL};

use crate::crypto;
use core::fmt;

db_object! {
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
        pub atype: i32,         // https://github.com/bitwarden/server/blob/dcc199bcce4aa2d5621f6fab80f1b49d8b143418/src/Core/Enums/DeviceType.cs
        pub push_uuid: Option<String>,
        pub push_token: Option<String>,

        pub refresh_token: String,

        pub twofactor_remember: Option<String>,
    }
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
            refresh_token: crypto::encode_random_bytes::<64>(BASE64URL),
            twofactor_remember: None,
        }
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        let twofactor_remember = crypto::encode_random_bytes::<180>(BASE64);
        self.twofactor_remember = Some(twofactor_remember.clone());

        twofactor_remember
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    pub fn is_push_device(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }

    pub fn is_registered(&self) -> bool {
        self.push_uuid.is_some()
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Device {
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                crate::util::retry(
                    || diesel::replace_into(devices::table).values(DeviceDb::to_db(self)).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql {
                let value = DeviceDb::to_db(self);
                crate::util::retry(
                    || diesel::insert_into(devices::table).values(&value).on_conflict((devices::uuid, devices::user_uuid)).do_update().set(&value).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .load::<DeviceDb>(conn)
                .expect("Error loading devices")
                .from_db()
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn clear_push_token_by_uuid(uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(devices::table)
                .filter(devices::uuid.eq(uuid))
                .set(devices::push_token.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing push token")
        }}
    }
    pub async fn find_by_refresh_token(refresh_token: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::refresh_token.eq(refresh_token))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_latest_active_by_user(user_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_push_devices_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<DeviceDb>(conn)
                .expect("Error loading push devices")
                .from_db()
        }}
    }

    pub async fn check_user_has_push_device(user_uuid: &str, conn: &mut DbConn) -> bool {
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
    WindowsCLI = 23,
    MacOsCLI = 24,
    LinuxCLI = 25,
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
            DeviceType::WindowsDesktop => write!(f, "Windows"),
            DeviceType::MacOsDesktop => write!(f, "macOS"),
            DeviceType::LinuxDesktop => write!(f, "Linux"),
            DeviceType::ChromeBrowser => write!(f, "Chrome"),
            DeviceType::FirefoxBrowser => write!(f, "Firefox"),
            DeviceType::OperaBrowser => write!(f, "Opera"),
            DeviceType::EdgeBrowser => write!(f, "Edge"),
            DeviceType::IEBrowser => write!(f, "Internet Explorer"),
            DeviceType::UnknownBrowser => write!(f, "Unknown Browser"),
            DeviceType::AndroidAmazon => write!(f, "Android"),
            DeviceType::Uwp => write!(f, "UWP"),
            DeviceType::SafariBrowser => write!(f, "Safari"),
            DeviceType::VivaldiBrowser => write!(f, "Vivaldi"),
            DeviceType::VivaldiExtension => write!(f, "Vivaldi Extension"),
            DeviceType::SafariExtension => write!(f, "Safari Extension"),
            DeviceType::Sdk => write!(f, "SDK"),
            DeviceType::Server => write!(f, "Server"),
            DeviceType::WindowsCLI => write!(f, "Windows CLI"),
            DeviceType::MacOsCLI => write!(f, "macOS CLI"),
            DeviceType::LinuxCLI => write!(f, "Linux CLI"),
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
            23 => DeviceType::WindowsCLI,
            24 => DeviceType::MacOsCLI,
            25 => DeviceType::LinuxCLI,
            _ => DeviceType::UnknownBrowser,
        }
    }
}
