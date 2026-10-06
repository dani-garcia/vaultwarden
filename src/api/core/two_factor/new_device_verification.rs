//! New device verification, the Bitwarden "New device login protection" feature: a password login
//! from an unknown device first has to be confirmed with a code mailed to the account address.
//!
//! Reference: <https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs>

use chrono::{NaiveDateTime, TimeDelta, Utc, naive::serde::ts_seconds};
use rocket::{
    Route,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, PasswordOrOtpData},
    auth::{ClientIp, Headers},
    crypto,
    db::{
        DbConn,
        models::{Device, DeviceId, EventType, TwoFactor, TwoFactorType, User},
    },
    error::{Error, ErrorEvent},
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![resend_new_device_otp, put_verify_devices, post_verify_devices]
}

/// Accounts younger than this are exempt upstream.
const NEW_ACCOUNT_EXEMPTION_HOURS: i64 = 24;

/// Preserve the pending device identifier for resend requests from older mobile clients.
const PENDING_DEVICE_SECONDS: i64 = 15 * 60;

/// Data stored in the `twofactor` table under [`TwoFactorType::NewDeviceVerification`]. Only read
/// and written here, so a code issued for a new device can never authorize anything else.
#[derive(Debug, Serialize, Deserialize)]
pub struct NewDeviceVerificationData {
    pub token: String,
    #[serde(with = "ts_seconds")]
    pub token_sent: NaiveDateTime,
    pub device_identifier: DeviceId,
    pub security_stamp: String,
}

impl NewDeviceVerificationData {
    fn new(token: String, device_identifier: DeviceId, security_stamp: String) -> Self {
        Self {
            token,
            token_sent: Utc::now().naive_utc(),
            device_identifier,
            security_stamp,
        }
    }

    fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn from_json(string: &str) -> Result<Self, Error> {
        if let Ok(data) = serde_json::from_str(string) {
            Ok(data)
        } else {
            err!("Could not decode NewDeviceVerificationData from string")
        }
    }

    fn time_since_sent(&self) -> TimeDelta {
        Utc::now().naive_utc() - self.token_sent
    }

    fn is_expired(&self, max_age_seconds: i64) -> bool {
        self.time_since_sent().num_seconds() > max_age_seconds
    }

    fn matches_device_and_stamp(&self, device_id: &DeviceId, security_stamp: &str) -> bool {
        &self.device_identifier == device_id && self.security_stamp == security_stamp
    }
}

#[expect(clippy::struct_excessive_bools, reason = "Every condition upstream checks, kept separate to stay testable")]
#[derive(Clone, Copy)]
pub struct NewDeviceState<'a> {
    pub enforced: bool,
    pub verify_devices: bool,
    /// The account is younger than the Bitwarden exemption period.
    pub recently_created: bool,
    pub has_two_factor: bool,
    pub known_device: bool,
    pub has_devices: bool,
    pub new_device_otp: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewDeviceAction {
    Skip,
    Verify,
    Challenge,
}

/// Mirrors `DeviceValidator.HandleNewDeviceVerificationAsync` of the Bitwarden server.
pub fn new_device_action(state: NewDeviceState<'_>) -> NewDeviceAction {
    // A non-empty code implies an unknown device, upstream skips the lookup for it.
    if state.new_device_otp.is_none_or(str::is_empty) && state.known_device {
        return NewDeviceAction::Skip;
    }

    // Upstream skips device verification for 2FA users entirely, they keep their existing flow.
    if !state.enforced || !state.verify_devices || state.recently_created || state.has_two_factor {
        return NewDeviceAction::Skip;
    }

    // An empty code counts as a wrong code upstream.
    if state.new_device_otp.is_some() {
        return NewDeviceAction::Verify;
    }

    // A user without any device is a freshly registered user.
    if !state.has_devices {
        return NewDeviceAction::Skip;
    }

    NewDeviceAction::Challenge
}

/// The clients match `ErrorModel.Message` literally to switch to their new device verification
/// screen and show `error_description`. See `api.service.ts` and
/// `new-device-verification.component.ts` in `bitwarden/clients`.
fn device_error(description: &str, message: &str) -> Error {
    let body = json!({
        "error": "device_error",
        "error_description": description,
        "ErrorModel": {
            "Message": message,
            "Object": "error"
        }
    });
    Error::from((description, body)).with_event(ErrorEvent {
        event: EventType::UserFailedLogIn,
    })
}

fn verification_required_error() -> Error {
    device_error("New device verification required", "new device verification required")
}

fn invalid_otp_error() -> Error {
    device_error("Invalid New Device OTP", "invalid new device otp")
}

/// Has to run before the device is stored. Errors are the exact responses the Bitwarden clients expect.
pub async fn validate_new_device_login(
    user: &mut User,
    device_id: &DeviceId,
    device_type: i32,
    new_device_otp: Option<&str>,
    is_auth_request: bool,
    ip: &ClientIp,
    conn: &DbConn,
) -> EmptyResult {
    // Login with device re-uses the password grant but is only ever approved from a known device.
    let enforced = CONFIG.new_device_verification() && CONFIG.mail_enabled() && !is_auth_request;

    let recently_created = Utc::now().naive_utc() - user.created_at < TimeDelta::hours(NEW_ACCOUNT_EXEMPTION_HOURS);

    // Avoids the queries below, `new_device_action` would return `Skip` for each of these too.
    if !enforced || !user.verify_devices || recently_created {
        return Ok(());
    }

    let known_device = Device::find_by_uuid_and_user(device_id, &user.uuid, conn).await.is_some();
    let has_devices = known_device || Device::has_any_by_user(&user.uuid, conn).await;
    let state = NewDeviceState {
        enforced,
        verify_devices: user.verify_devices,
        recently_created,
        has_two_factor: !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty(),
        known_device,
        has_devices,
        new_device_otp,
    };

    match new_device_action(state) {
        NewDeviceAction::Skip => Ok(()),
        NewDeviceAction::Verify => {
            validate_otp(new_device_otp.unwrap_or_default(), user, device_id, conn).await?;

            // The user proved access to their mailbox, so upstream marks the address as verified.
            if user.verified_at.is_none() {
                user.verified_at = Some(Utc::now().naive_utc());
                user.save(conn).await?;
            }
            Ok(())
        }
        NewDeviceAction::Challenge => {
            send_otp(user, device_id, device_type, ip, conn).await?;
            Err(verification_required_error())
        }
    }
}

async fn send_otp(user: &User, device_id: &DeviceId, device_type: i32, ip: &ClientIp, conn: &DbConn) -> EmptyResult {
    // Bitwarden replaces the pending code on each new challenge or resend.
    let data = NewDeviceVerificationData::new(
        crypto::generate_email_token(CONFIG.email_token_size()),
        device_id.clone(),
        user.security_stamp.clone(),
    );
    let twofactor = TwoFactor::new(user.uuid.clone(), TwoFactorType::NewDeviceVerification, data.to_json());
    twofactor.save(conn).await?;

    if let Err(e) =
        mail::send_new_device_verification(&user.email, &data.token, &ip.ip.to_string(), &data.token_sent, device_type)
            .await
    {
        error!("Error sending new device verification email: {e:#?}");
        // Only remove our own unsent code; a concurrent resend may already have replaced it.
        if let Err(e) = twofactor.delete(conn).await {
            error!("Error removing the unsent new device verification code: {e:#?}");
        }
        err!(
            "Could not send the new device verification email. Please contact your administrator.",
            ErrorEvent {
                event: EventType::UserFailedLogIn
            }
        )
    }

    Ok(())
}

/// Validate and atomically consume the code only if no newer code has replaced it.
async fn validate_otp(otp: &str, user: &User, device_id: &DeviceId, conn: &DbConn) -> EmptyResult {
    let type_ = TwoFactorType::NewDeviceVerification;
    let tf = TwoFactor::find_by_user_and_type(&user.uuid, type_, conn).await.ok_or_else(invalid_otp_error)?;
    let data = NewDeviceVerificationData::from_json(&tf.data)?;

    if !data.matches_device_and_stamp(device_id, &user.security_stamp)
        || data.is_expired(CONFIG.email_expiration_time().cast_signed())
        || !crypto::ct_eq(&data.token, otp)
    {
        // Keep the expired record briefly for mobile clients that resend without a device header.
        return Err(invalid_otp_error());
    }

    let expected_data = tf.data.clone();
    if !tf.delete_if_data_matches(&expected_data, conn).await? {
        return Err(invalid_otp_error());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResendNewDeviceOtpData {
    #[serde(alias = "Email")]
    email: String,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(alias = "OTP", alias = "Otp")]
    otp: Option<String>,
}

/// Current web clients identify the device via this header. Older mobile clients omit it.
struct ResendDeviceIdentifier(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ResendDeviceIdentifier {
    type Error = &'static str;

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Self(request.headers().get_one("Device-Identifier").map(str::to_owned)))
    }
}

/// Mirrors the upstream resend endpoint, including its silent success for invalid secrets.
#[post("/accounts/resend-new-device-otp", data = "<data>")]
async fn resend_new_device_otp(
    data: Json<ResendNewDeviceOtpData>,
    device_identifier: ResendDeviceIdentifier,
    ip: ClientIp,
    conn: DbConn,
) -> EmptyResult {
    crate::ratelimit::check_limit_login(&ip.ip)?;

    let ResendDeviceIdentifier(request_device_id) = device_identifier;
    // Reject malformed identifiers before looking up the user, just like Bitwarden.
    if request_device_id.as_ref().is_some_and(|id| id.len() > 50) {
        err!("Invalid device identifier");
    }

    let data: ResendNewDeviceOtpData = data.into_inner();
    if !CONFIG.new_device_verification() || !CONFIG.mail_enabled() {
        return Ok(());
    }

    let Some(user) = User::find_by_mail(data.email.trim(), &conn).await else {
        return Ok(());
    };

    if !user.enabled || !user.verify_devices {
        return Ok(());
    }

    let secret = PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    };
    if secret.validate(&user, true, &conn).await.is_err() {
        return Ok(());
    }

    // Old Android/iOS clients do not send the Device-Identifier header. Reuse the
    // pending device for up to 15 minutes, independently of the OTP's validity.
    let device_id = if let Some(id) = request_device_id.filter(|id| !id.trim().is_empty()) {
        DeviceId::from(id)
    } else {
        let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::NewDeviceVerification, &conn).await
        else {
            return Ok(());
        };
        let pending = NewDeviceVerificationData::from_json(&tf.data)?;
        if pending.security_stamp != user.security_stamp || pending.is_expired(PENDING_DEVICE_SECONDS) {
            return Ok(());
        }
        pending.device_identifier
    };

    if let Err(e) = send_otp(&user, &device_id, 14, &ip, &conn).await {
        error!("Error resending new device verification code: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetVerifyDevicesData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    #[serde(alias = "VerifyDevices")]
    verify_devices: bool,
}

/// Current clients use `POST`, older ones and the API docs use `PUT`.
#[post("/accounts/verify-devices", data = "<data>")]
async fn post_verify_devices(data: Json<SetVerifyDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: SetVerifyDevicesData = data.into_inner();
    let mut user = headers.user;

    // Same user verification upstream requires for this setting.
    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &conn)
    .await?;

    user.verify_devices = data.verify_devices;
    user.save(&conn).await
}

#[put("/accounts/verify-devices", data = "<data>")]
async fn put_verify_devices(data: Json<SetVerifyDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    post_verify_devices(data, headers, conn).await
}

/// Only the pre-2023 web vault reads this. Its section stays disabled because the setter it needs was
/// never part of Vaultwarden, so showing it would only produce a broken toggle.
pub fn device_verification_settings(user: &User) -> Value {
    let enabled = CONFIG.new_device_verification() && CONFIG.mail_enabled() && user.verify_devices;

    json!({
        "isDeviceVerificationSectionEnabled": false,
        "unknownDeviceVerificationEnabled": enabled,
        "object": "deviceVerificationSettings"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenged() -> NewDeviceState<'static> {
        NewDeviceState {
            enforced: true,
            verify_devices: true,
            recently_created: false,
            has_two_factor: false,
            known_device: false,
            has_devices: true,
            new_device_otp: None,
        }
    }

    type Case = (&'static str, Option<&'static str>, fn(&mut NewDeviceState<'static>), NewDeviceAction);

    #[test]
    fn decision_matches_upstream() {
        use NewDeviceAction::{Challenge, Skip, Verify};

        let cases: [Case; 13] = [
            ("unknown device without 2fa", None, |_| (), Challenge),
            ("feature disabled", None, |s| s.enforced = false, Skip),
            ("user opted out", None, |s| s.verify_devices = false, Skip),
            ("account within the exemption period", None, |s| s.recently_created = true, Skip),
            ("2fa configured", None, |s| s.has_two_factor = true, Skip),
            ("2fa configured and a code sent", Some("123456"), |s| s.has_two_factor = true, Skip),
            ("known device", None, |s| s.known_device = true, Skip),
            ("account without any device", None, |s| s.has_devices = false, Skip),
            ("code sent", Some("123456"), |_| (), Verify),
            ("code sent from a known device", Some("123456"), |s| s.known_device = true, Verify),
            ("code sent without any device", Some("123456"), |s| s.has_devices = false, Verify),
            // An empty code counts as wrong, but unlike a real one it does not skip the known device lookup.
            ("empty code sent", Some(""), |_| (), Verify),
            ("empty code sent from a known device", Some(""), |s| s.known_device = true, Skip),
        ];

        for (case, new_device_otp, setup, expected) in cases {
            let mut state = challenged();
            state.new_device_otp = new_device_otp;
            setup(&mut state);
            assert_eq!(new_device_action(state), expected, "{case}");
        }
    }

    /// Guards the early return in `validate_new_device_login`.
    #[test]
    fn shortcut_only_skips_what_the_decision_skips() {
        for enforced in [false, true] {
            for verify_devices in [false, true] {
                for recently_created in [false, true] {
                    if enforced && verify_devices && !recently_created {
                        continue;
                    }
                    let state = NewDeviceState {
                        enforced,
                        verify_devices,
                        recently_created,
                        ..challenged()
                    };
                    assert_eq!(new_device_action(state), NewDeviceAction::Skip);
                }
            }
        }
    }

    /// The clients compare these strings literally, changing them breaks the flow silently.
    #[test]
    fn client_matched_response_fields_are_stable() {
        for (error, description, message) in [
            (verification_required_error(), "New device verification required", "new device verification required"),
            (invalid_otp_error(), "Invalid New Device OTP", "invalid new device otp"),
        ] {
            let expected = json!({
                "error": "device_error",
                "error_description": description,
                "ErrorModel": { "Message": message, "Object": "error" }
            });
            // An exact match also keeps out `TwoFactorProviders2`, which the clients check first.
            assert_eq!(serde_json::from_str::<Value>(&error.to_string()).unwrap(), expected);
        }
    }

    #[test]
    fn stored_code_is_device_and_security_stamp_bound() {
        let device_id = DeviceId::from("device-1".to_owned());
        let mut sent = NewDeviceVerificationData::new("123456".into(), device_id.clone(), "security-stamp-1".into());
        let mut data = NewDeviceVerificationData::from_json(&sent.to_json()).expect("stored data must round trip");
        assert_eq!(data.token, "123456");
        assert!(data.matches_device_and_stamp(&device_id, "security-stamp-1"));
        assert!(!data.matches_device_and_stamp(&DeviceId::from("device-2".to_owned()), "security-stamp-1"));
        assert!(!data.matches_device_and_stamp(&device_id, "security-stamp-2"));
        assert!(!data.is_expired(600));

        sent.token_sent -= TimeDelta::seconds(601);
        data = NewDeviceVerificationData::from_json(&sent.to_json()).unwrap();
        assert!(data.is_expired(600));
        assert!(!data.is_expired(PENDING_DEVICE_SECONDS));
    }

    #[test]
    fn resend_accepts_bitwarden_client_field_names() {
        for raw in [
            r#"{"Email":"user@example.com","MasterPasswordHash":"hash"}"#,
            r#"{"email":"user@example.com","masterPasswordHash":"hash"}"#,
            r#"{"Email":"user@example.com","MasterPasswordHash":null,"OTP":"654321"}"#,
        ] {
            let data: ResendNewDeviceOtpData = serde_json::from_str(raw).expect("client request must deserialize");
            assert_eq!(data.email, "user@example.com");
            assert!(data.master_password_hash.is_some() || data.otp.is_some());
        }
    }
}
