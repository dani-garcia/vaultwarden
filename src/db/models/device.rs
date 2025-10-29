use chrono::{NaiveDateTime, Utc};

use data_encoding::{BASE64, BASE64URL};
use derive_more::{Display, From};
use serde_json::Value;

use super::{AuthRequest, UserId};
use crate::db::schema::devices;
use crate::{
    crypto,
    util::{format_date, get_uuid},
};
use diesel::prelude::*;
use macros::{IdFromParam, UuidFromParam};

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
    pub atype: i32, // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<PushId>,
    pub push_token: Option<String>,

    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
}

/// Local methods
impl Device {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": false,
            "object":"device"
        })
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        let twofactor_remember = crypto::encode_random_bytes::<180>(BASE64);
        self.twofactor_remember = Some(twofactor_remember.clone());

        twofactor_remember
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    // This rely on the fact we only update the device after a successful login
    pub fn is_new(&self) -> bool {
        self.created_at == self.updated_at
    }

    pub fn is_push_device(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }

    pub fn is_cli(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::WindowsCLI | DeviceType::MacOsCLI | DeviceType::LinuxCLI)
    }

    pub fn is_mobile(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
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
            "identifier": self.device.uuid,
            "creationDate": format_date(&self.device.created_at),
            "devicePendingAuthRequest": auth_request,
            "isTrusted": false,
            "encryptedPublicKey": null,
            "encryptedUserKey": null,
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

use crate::api::{ApiResult, EmptyResult};
use crate::error::MapResult;

/// Database methods
impl Device {
    pub async fn new(uuid: DeviceId, user_uuid: UserId, name: String, atype: i32, conn: &DbConn) -> ApiResult<Device> {
        let now = Utc::now().naive_utc();

        let device = Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_uuid: Some(PushId(get_uuid())),
            push_token: None,
            refresh_token: crypto::encode_random_bytes::<64>(BASE64URL),
            twofactor_remember: None,
        };

        device.inner_save(conn).await.map(|()| device)
    }

    async fn inner_save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                crate::util::retry(||
                    diesel::replace_into(devices::table)
                        .values(self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(self)
                        .on_conflict((devices::uuid, devices::user_uuid))
                        .do_update()
                        .set(self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    // Should only be called after user has passed authentication
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();
        self.inner_save(conn).await
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &DeviceId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_with_auth_request_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<DeviceWithAuthRequest> {
        let devices = Self::find_by_user(user_uuid, conn).await;
        let mut result = Vec::new();
        for device in devices {
            let auth_request = AuthRequest::find_by_user_and_requested_device(user_uuid, &device.uuid, conn).await;
            result.push(DeviceWithAuthRequest::from(device, auth_request));
        }
        result
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading devices")
        }}
    }

    pub async fn find_by_uuid(uuid: &DeviceId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn clear_push_token_by_uuid(uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
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

    pub async fn find_latest_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_push_devices_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<Self>(conn)
                .expect("Error loading push devices")
        }}
    }

    pub async fn check_user_has_push_device(user_uuid: &UserId, conn: &DbConn) -> bool {
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

#[derive(Clone, Debug, DieselNewType, Display, From, FromForm, Serialize, Deserialize, UuidFromParam)]
pub struct PushId(pub String);
