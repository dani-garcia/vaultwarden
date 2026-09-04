use chrono::{NaiveDateTime, Utc};
use data_encoding::BASE64URL;
use derive_more::{Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    crypto,
    db::{DbConn, schema::devices},
    error::MapResult,
    util::{format_date, get_uuid},
};
use macros::{IdFromParam, UuidFromParam};

use super::{AuthRequest, UserId};

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
    pub atype: i32, // https://github.com/bitwarden/server/blob/8d547dcc280babab70dd4a3c94ced6a34b12dfbf/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<PushId>,
    pub push_token: Option<String>,

    pub refresh_token: String,
    pub twofactor_remember: Option<String>,

    // Trusted device encryption. The client generates a key pair per device plus a device key
    // that never leaves the device, and stores the three resulting blobs here:
    /// The user key, encrypted with `encrypted_public_key`. This is the copy of the user key that
    /// lets the device unlock the vault without a master password.
    pub encrypted_user_key: Option<String>,
    /// The device public key, encrypted with the user key.
    pub encrypted_public_key: Option<String>,
    /// The device private key, encrypted with the device key. The server never sees the device key.
    pub encrypted_private_key: Option<String>,
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

            push_uuid: Some(PushId(get_uuid())),
            push_token: None,
            refresh_token: Device::generate_refresh_token(),
            twofactor_remember: None,

            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
        }
    }

    #[inline(always)]
    pub fn generate_refresh_token() -> String {
        crypto::encode_random_bytes::<64>(&BASE64URL)
    }

    /// A stored key is only usable when it is actually there and non-empty.
    fn present(key: Option<&String>) -> Option<&String> {
        key.filter(|key| !key.is_empty())
    }

    fn key_json(key: Option<&String>) -> Value {
        match Self::present(key) {
            Some(key) => Value::String(key.clone()),
            None => Value::Null,
        }
    }

    /// Whether this device holds everything needed to unlock the vault on its own.
    ///
    /// A client can drop its device key without telling us, so this only says that the server side
    /// of the trust is complete. See `DeviceExtensions.IsTrusted` upstream.
    pub fn is_trusted(&self) -> bool {
        Self::present(self.encrypted_user_key.as_ref()).is_some()
            && Self::present(self.encrypted_public_key.as_ref()).is_some()
            && Self::present(self.encrypted_private_key.as_ref()).is_some()
    }

    /// The wrapped user key, but only while the whole trust is intact. Handing out one half of an
    /// incomplete set would just make the client fail later in the unlock.
    pub fn trusted_user_key(&self) -> Option<&String> {
        self.is_trusted().then_some(self.encrypted_user_key.as_ref()).flatten()
    }

    pub fn trusted_private_key(&self) -> Option<&String> {
        self.is_trusted().then_some(self.encrypted_private_key.as_ref()).flatten()
    }

    /// Whether the device still holds the private key of its own key pair.
    ///
    /// That key is wrapped with the device key, which a user key rotation does not touch, so it outlives
    /// one. It decides whether a device can be handed a freshly wrapped user key and be trusted again.
    pub fn holds_private_key(&self) -> bool {
        Self::present(self.encrypted_private_key.as_ref()).is_some()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": self.is_trusted(),
            "encryptedUserKey": Self::key_json(self.encrypted_user_key.as_ref()),
            "encryptedPublicKey": Self::key_json(self.encrypted_public_key.as_ref()),
            "object":"device"
        })
    }

    /// Response of `POST /devices/<identifier>/retrieve-keys`, used by the clients to re-wrap the
    /// user key for every trusted device during a key rotation.
    pub fn to_protected_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "encryptedUserKey": Self::key_json(self.encrypted_user_key.as_ref()),
            "encryptedPublicKey": Self::key_json(self.encrypted_public_key.as_ref()),
            "object": "protectedDevice"
        })
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use crate::auth::{encode_jwt, generate_2fa_remember_claims};

        let two_factor_remember_claim = generate_2fa_remember_claims(self.uuid.clone(), self.user_uuid.clone());
        let two_factor_remember_string = encode_jwt(&two_factor_remember_claim);
        self.twofactor_remember = Some(two_factor_remember_string.clone());

        two_factor_remember_string
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
            "isTrusted": self.device.is_trusted(),
            "encryptedPublicKey": Device::key_json(self.device.encrypted_public_key.as_ref()),
            "encryptedUserKey": Device::key_json(self.device.encrypted_user_key.as_ref()),
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

/// Database methods
impl Device {
    pub async fn save(&mut self, update_time: bool, conn: &DbConn) -> EmptyResult {
        if update_time {
            self.updated_at = Utc::now().naive_utc();
        }

        db_run! { conn:
            sqlite, mysql {
                crate::util::retry(||
                    diesel::replace_into(devices::table)
                        .values(&*self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(&*self)
                        .on_conflict((devices::uuid, devices::user_uuid))
                        .do_update()
                        .set(&*self)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        })
        .await
    }

    /// Invalidates every copy of the user key that is wrapped for one of the user's devices.
    ///
    /// Called when the user key is replaced and the client did not say what to put in their place, so
    /// those copies point at a key that no longer unlocks anything. No device counts as trusted
    /// afterwards, so a client that stops here gets an extra login rather than a broken unlock. The
    /// device key pairs are left alone: wrapped with the untouched device key, so
    /// `POST /devices/update-trust` can hand every device the new user key and restore its trust,
    /// dropping whatever it does not list. One statement, so there is no half applied state.
    pub async fn invalidate_wrapped_user_keys(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .set((
                    devices::encrypted_user_key.eq::<Option<String>>(None),
                    devices::encrypted_public_key.eq::<Option<String>>(None),
                ))
                .execute(conn)
                .map_res("Error invalidating the wrapped user keys of the devices")
        })
        .await
    }

    /// Drops every stored key of the named devices, in one statement so it cannot half apply.
    ///
    /// The caller has already checked that each id belongs to this user.
    pub async fn untrust_many(user_uuid: &UserId, device_ids: Vec<DeviceId>, conn: &DbConn) -> EmptyResult {
        if device_ids.is_empty() {
            return Ok(());
        }

        conn.run(move |conn| {
            diesel::update(
                devices::table.filter(devices::user_uuid.eq(user_uuid)).filter(devices::uuid.eq_any(device_ids)),
            )
            .set((
                devices::encrypted_user_key.eq::<Option<String>>(None),
                devices::encrypted_public_key.eq::<Option<String>>(None),
                devices::encrypted_private_key.eq::<Option<String>>(None),
            ))
            .execute(conn)
            .map_res("Error untrusting the devices")
        })
        .await
    }

    /// Replaces the trust of every device of the user in one go: the listed ones are re-wrapped for the
    /// current user key, everything else loses whatever it still holds.
    ///
    /// This is what both a key rotation and `POST /devices/update-trust` come down to; the caller has
    /// already validated the ids, so this only writes. One transaction, so the devices cannot be left
    /// split between the old and the new user key, a state no client can tell apart from a working one.
    pub async fn replace_trust(
        user_uuid: &UserId,
        updates: Vec<(DeviceId, String, String)>,
        conn: &DbConn,
    ) -> EmptyResult {
        conn.run(move |conn| {
            conn.transaction(|conn| -> EmptyResult {
                let keep: Vec<DeviceId> = updates.iter().map(|(device_id, ..)| device_id.clone()).collect();

                // Whatever the untouched devices hold wraps the previous user key, or is one half of
                // a trust that was never finished. Either way it unlocks nothing and must not stay.
                let cleared = (
                    devices::encrypted_user_key.eq::<Option<String>>(None),
                    devices::encrypted_public_key.eq::<Option<String>>(None),
                    devices::encrypted_private_key.eq::<Option<String>>(None),
                );
                let outdated = devices::table.filter(devices::user_uuid.eq(&user_uuid));
                let _: () = if keep.is_empty() {
                    diesel::update(outdated).set(cleared).execute(conn)
                } else {
                    diesel::update(outdated.filter(devices::uuid.ne_all(keep))).set(cleared).execute(conn)
                }
                .map_res("Error untrusting the devices left out of the rotation")?;

                // The device key pair is deliberately not touched here: it is wrapped with the
                // device key, which the server never sees and a rotation never changes.
                for (device_id, encrypted_user_key, encrypted_public_key) in updates {
                    let _: () = diesel::update(
                        devices::table.filter(devices::uuid.eq(device_id)).filter(devices::user_uuid.eq(&user_uuid)),
                    )
                    .set((
                        devices::encrypted_user_key.eq(Some(encrypted_user_key)),
                        devices::encrypted_public_key.eq(Some(encrypted_public_key)),
                    ))
                    .execute(conn)
                    .map_res("Error rotating the wrapped user key of a device")?;
                }

                Ok(())
            })
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &DeviceId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
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
        conn.run(move |conn| {
            devices::table.filter(devices::user_uuid.eq(user_uuid)).load::<Self>(conn).expect("Error loading devices")
        })
        .await
    }

    pub async fn find_by_uuid(uuid: &DeviceId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn clear_push_token_by_uuid(uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table)
                .filter(devices::uuid.eq(uuid))
                .set(devices::push_token.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing push token")
        })
        .await
    }
    pub async fn find_by_refresh_token(refresh_token: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::refresh_token.eq(refresh_token)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_latest_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_push_devices_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<Self>(conn)
                .expect("Error loading push devices")
        })
        .await
    }

    pub async fn check_user_has_push_device(user_uuid: &UserId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    pub async fn rotate_refresh_tokens_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        // Generate a new token per device.
        // We cannot do a single UPDATE with one value because each device needs a unique token.
        let devices = Self::find_by_user(user_uuid, conn).await;
        for mut device in devices {
            device.refresh_token = Device::generate_refresh_token();
            device.save(false, conn).await?;
        }
        Ok(())
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
    #[display("DuckDuckGo")]
    DuckDuckGoBrowser = 26,
}

impl DeviceType {
    #[expect(clippy::match_same_arms, reason = "Specifically define 14 and have a fallback for new types")]
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
            26 => DeviceType::DuckDuckGoBrowser,
            _ => DeviceType::UnknownBrowser,
        }
    }

    /// Whether a device of this type can answer a login request from another device.
    ///
    /// The SDK, the server and the CLIs have no interactive prompt to show the request in, so they are
    /// the ones left out. Matches `LoginApprovingClientTypes` upstream (desktop, mobile, web, browser).
    pub fn can_approve_login_requests(&self) -> bool {
        !matches!(
            self,
            DeviceType::Sdk | DeviceType::Server | DeviceType::WindowsCLI | DeviceType::MacOsCLI | DeviceType::LinuxCLI
        )
    }
}

#[derive(
    Clone, Debug, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct DeviceId(String);

#[derive(Clone, Debug, DieselNewType, Display, From, FromForm, Serialize, Deserialize, UuidFromParam)]
pub struct PushId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_device() -> Device {
        let mut device = Device::new(String::from("device").into(), String::from("user").into(), String::new(), 9);
        device.encrypted_user_key = Some(String::from("2.user"));
        device.encrypted_public_key = Some(String::from("2.public"));
        device.encrypted_private_key = Some(String::from("2.private"));
        device
    }

    #[test]
    fn a_device_is_only_trusted_with_all_three_keys() {
        assert!(trusted_device().is_trusted());

        let keys: [fn(&mut Device) -> &mut Option<String>; 3] = [
            |device| &mut device.encrypted_user_key,
            |device| &mut device.encrypted_public_key,
            |device| &mut device.encrypted_private_key,
        ];

        for key in keys {
            let mut device = trusted_device();
            *key(&mut device) = None;
            assert!(!device.is_trusted());

            let mut device = trusted_device();
            *key(&mut device) = Some(String::new());
            assert!(!device.is_trusted(), "an empty key is as good as a missing one");
        }
    }

    #[test]
    fn an_incomplete_device_hands_out_no_keys_at_all() {
        let mut device = trusted_device();
        assert_eq!(device.trusted_user_key(), Some(&String::from("2.user")));
        assert_eq!(device.trusted_private_key(), Some(&String::from("2.private")));

        // The public key is not part of the login response, but without it the other two are
        // useless to the client, so it must not get them either.
        device.encrypted_public_key = None;
        assert_eq!(device.trusted_user_key(), None);
        assert_eq!(device.trusted_private_key(), None);
    }

    #[test]
    fn a_rotation_leaves_the_device_key_pair_in_place() {
        // What `invalidate_wrapped_user_keys` does: the wrapped user key and the public key go,
        // the private key stays, because the device key that wraps it is untouched by a rotation.
        let mut device = trusted_device();
        device.encrypted_user_key = None;
        device.encrypted_public_key = None;

        assert!(!device.is_trusted(), "nothing may unlock until the client re-wraps");
        assert!(device.holds_private_key(), "but the device can still be handed a new user key");
    }

    #[test]
    fn a_device_that_never_had_a_trust_holds_nothing() {
        let device = Device::new(String::from("device").into(), String::from("user").into(), String::new(), 9);
        assert!(!device.holds_private_key());

        let mut device = trusted_device();
        device.encrypted_private_key = Some(String::new());
        assert!(!device.holds_private_key(), "an empty key is as good as a missing one");
    }

    #[test]
    fn only_interactive_clients_can_approve_a_login_request() {
        for atype in 0..=26 {
            let device_type = DeviceType::from_i32(atype);
            let expected = !matches!(atype, 21..=25);
            assert_eq!(device_type.can_approve_login_requests(), expected, "device type {atype} ({device_type})");
        }
    }
}
