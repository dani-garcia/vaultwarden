use chrono::{NaiveDateTime, Utc};
use derive_more::{Display, From};
use serde_json::Value;

use super::{AuthRequest, UserId};
use crate::{crypto, util::format_date, CONFIG};
use macros::IdFromParam;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = devices)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid, user_uuid))]
    pub struct Device {
        pub uuid: DeviceId,
        pub created_at: NaiveDateTime,
        pub updated_at: NaiveDateTime,

        pub user_uuid: UserId,

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
    pub fn new(uuid: DeviceId, user_uuid: UserId, name: String, atype: i32) -> Self {
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

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.push_uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": false,
            "object":"device"
        })
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

    pub fn refresh_tokens(&mut self, user: &super::User, scope: Vec<String>) -> (String, i64) {
        // If there is no refresh token, we create one
        if self.refresh_token.is_empty() {
            use data_encoding::BASE64URL;
            self.refresh_token = crypto::encode_random_bytes::<64>(BASE64URL);
        }

        // Update the expiration of the device and the last update date
        let time_now = Utc::now();
        self.updated_at = time_now.naive_utc();

        // ---
        // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
        // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
        // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
        // ---
        // fn arg: members: Vec<super::Membership>,
        // ---
        // let orgowner: Vec<_> = members.iter().filter(|m| m.atype == 0).map(|o| o.org_uuid.clone()).collect();
        // let orgadmin: Vec<_> = members.iter().filter(|m| m.atype == 1).map(|o| o.org_uuid.clone()).collect();
        // let orguser: Vec<_> = members.iter().filter(|m| m.atype == 2).map(|o| o.org_uuid.clone()).collect();
        // let orgmanager: Vec<_> = members.iter().filter(|m| m.atype == 3).map(|o| o.org_uuid.clone()).collect();

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

            // ---
            // Disabled these keys to be added to the JWT since they could cause the JWT to get too large
            // Also These key/value pairs are not used anywhere by either Vaultwarden or Bitwarden Clients
            // Because these might get used in the future, and they are added by the Bitwarden Server, lets keep it, but then commented out
            // See: https://github.com/vaultwarden/vaultwarden/issues/4156
            // ---
            // orgowner,
            // orgadmin,
            // orguser,
            // orgmanager,
            sstamp: user.security_stamp.clone(),
            device: self.uuid.clone(),
            scope,
            amr: vec!["Application".into()],
        };

        (encode_jwt(&claims), DEFAULT_VALIDITY.num_seconds())
    }

    pub fn is_push_device(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }

    pub fn is_registered(&self) -> bool {
        self.push_uuid.is_some()
    }
}

pub struct DeviceWithAuthRequest {
    pub device: Device,
    pub pending_auth_request: Option<AuthRequest>,
}

impl DeviceWithAuthRequest {
    pub fn to_json(&self) -> Value {
        let auth_request = match &self.pending_auth_request {
            Some(auth_request) => auth_request.to_json_for_pending_device(),
            None => Value::Null,
        };
        json!({
            "id": self.device.uuid,
            "name": self.device.name,
            "type": self.device.atype,
            "identifier": self.device.push_uuid,
            "creationDate": format_date(&self.device.created_at),
            "devicePendingAuthRequest": auth_request,
            "isTrusted": false,
            "object": "device",
        })
    }

    pub fn from(c: Device, a: Option<AuthRequest>) -> Self {
        Self {
            device: c,
            pending_auth_request: a,
        }
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

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &DeviceId, user_uuid: &UserId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_with_auth_request_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<DeviceWithAuthRequest> {
        let devices = Self::find_by_user(user_uuid, conn).await;
        let mut result = Vec::new();
        for device in devices {
            let auth_request = AuthRequest::find_by_user_and_requested_device(user_uuid, &device.uuid, conn).await;
            result.push(DeviceWithAuthRequest::from(device, auth_request));
        }
        result
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .load::<DeviceDb>(conn)
                .expect("Error loading devices")
                .from_db()
        }}
    }

    pub async fn find_by_uuid(uuid: &DeviceId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn clear_push_token_by_uuid(uuid: &DeviceId, conn: &mut DbConn) -> EmptyResult {
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

    pub async fn find_latest_active_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_push_devices_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<DeviceDb>(conn)
                .expect("Error loading push devices")
                .from_db()
        }}
    }

    pub async fn check_user_has_push_device(user_uuid: &UserId, conn: &mut DbConn) -> bool {
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

#[derive(Display)]
pub enum DeviceType {
    #[display("Android")]
    Android = 0,
    #[display("iOS")]
    Ios = 1,
    #[display("Chrome Extension")]
    ChromeExtension = 2,
    #[display("Firefox Extension")]
    FirefoxExtension = 3,
    #[display("Opera Extension")]
    OperaExtension = 4,
    #[display("Edge Extension")]
    EdgeExtension = 5,
    #[display("Windows")]
    WindowsDesktop = 6,
    #[display("macOS")]
    MacOsDesktop = 7,
    #[display("Linux")]
    LinuxDesktop = 8,
    #[display("Chrome")]
    ChromeBrowser = 9,
    #[display("Firefox")]
    FirefoxBrowser = 10,
    #[display("Opera")]
    OperaBrowser = 11,
    #[display("Edge")]
    EdgeBrowser = 12,
    #[display("Internet Explorer")]
    IEBrowser = 13,
    #[display("Unknown Browser")]
    UnknownBrowser = 14,
    #[display("Android")]
    AndroidAmazon = 15,
    #[display("UWP")]
    Uwp = 16,
    #[display("Safari")]
    SafariBrowser = 17,
    #[display("Vivaldi")]
    VivaldiBrowser = 18,
    #[display("Vivaldi Extension")]
    VivaldiExtension = 19,
    #[display("Safari Extension")]
    SafariExtension = 20,
    #[display("SDK")]
    Sdk = 21,
    #[display("Server")]
    Server = 22,
    #[display("Windows CLI")]
    WindowsCLI = 23,
    #[display("macOS CLI")]
    MacOsCLI = 24,
    #[display("Linux CLI")]
    LinuxCLI = 25,
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

#[derive(
    Clone, Debug, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct DeviceId(String);
