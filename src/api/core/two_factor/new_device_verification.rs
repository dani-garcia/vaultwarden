//! New device verification, the Bitwarden "New device login protection" feature: a password login
//! from an unknown device first has to be confirmed with a code mailed to the account address.
//!
//! Reference: <https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/RequestValidators/DeviceValidator.cs>

use chrono::{NaiveDateTime, TimeDelta, Utc, naive::serde::ts_seconds};
use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, PasswordOrOtpData},
    auth::{ClientIp, Headers},
    crypto,
    db::{
        DbConn,
        models::{Device, DeviceId, EventType, TwoFactor, TwoFactorType, User, UserId},
    },
    error::{Error, ErrorEvent},
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![resend_new_device_otp, put_verify_devices, post_verify_devices]
}

/// Accounts younger than this are exempt upstream.
const NEW_ACCOUNT_EXEMPTION_HOURS: i64 = 24;

/// Minimum time between two verification mails, so repeated logins cannot flood a mailbox.
const RESEND_DELAY_SECONDS: i64 = 30;

/// Data stored in the `twofactor` table under [`TwoFactorType::NewDeviceVerification`]. Only read
/// and written here, so a code issued for a new device can never authorize anything else.
#[derive(Debug, Serialize, Deserialize)]
pub struct NewDeviceVerificationData {
    pub token: String,
    #[serde(with = "ts_seconds")]
    pub token_sent: NaiveDateTime,
    pub attempts: u64,
}

impl NewDeviceVerificationData {
    fn new(token: String) -> Self {
        Self {
            token,
            token_sent: Utc::now().naive_utc(),
            attempts: 0,
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

    fn add_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    fn time_since_sent(&self) -> TimeDelta {
        Utc::now().naive_utc() - self.token_sent
    }

    fn is_expired(&self, max_age_seconds: i64) -> bool {
        self.time_since_sent().num_seconds() > max_age_seconds
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

    let devices = Device::find_by_user(&user.uuid, conn).await;
    let state = NewDeviceState {
        enforced,
        verify_devices: user.verify_devices,
        recently_created,
        has_two_factor: !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty(),
        known_device: devices.iter().any(|d| &d.uuid == device_id),
        has_devices: !devices.is_empty(),
        new_device_otp,
    };

    match new_device_action(state) {
        NewDeviceAction::Skip => Ok(()),
        NewDeviceAction::Verify => {
            validate_otp(new_device_otp.unwrap_or_default(), &user.uuid, conn).await?;

            // The user proved access to their mailbox, so upstream marks the address as verified.
            if user.verified_at.is_none() {
                user.verified_at = Some(Utc::now().naive_utc());
                user.save(conn).await?;
            }
            Ok(())
        }
        NewDeviceAction::Challenge => {
            send_otp(user, device_type, ip, conn).await?;
            Err(verification_required_error())
        }
    }
}

async fn send_otp(user: &User, device_type: i32, ip: &ClientIp, conn: &DbConn) -> EmptyResult {
    let type_ = TwoFactorType::NewDeviceVerification as i32;

    if let Some(ref tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, conn).await {
        let data = NewDeviceVerificationData::from_json(&tf.data)?;
        if !data.is_expired(CONFIG.email_expiration_time().cast_signed())
            && data.time_since_sent().num_seconds() < RESEND_DELAY_SECONDS
        {
            // Keep the code the user just received valid instead of mailing another one.
            return Ok(());
        }
    }

    // Saving replaces any previous code, only the most recent one stays valid.
    let data = NewDeviceVerificationData::new(crypto::generate_email_token(CONFIG.email_token_size()));
    let twofactor = TwoFactor::new(user.uuid.clone(), TwoFactorType::NewDeviceVerification, data.to_json());
    twofactor.save(conn).await?;

    if let Err(e) =
        mail::send_new_device_verification(&user.email, &data.token, &ip.ip.to_string(), &data.token_sent, device_type)
            .await
    {
        error!("Error sending new device verification email: {e:#?}");
        // Drop the unsent code, else the resend delay would ask the next login for a code that never arrived.
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

/// Validates a `NewDeviceOtp` and consumes it when it is correct.
async fn validate_otp(otp: &str, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    let type_ = TwoFactorType::NewDeviceVerification as i32;
    let mut tf = TwoFactor::find_by_user_and_type(user_id, type_, conn).await.ok_or_else(invalid_otp_error)?;

    let mut data = NewDeviceVerificationData::from_json(&tf.data)?;

    if data.is_expired(CONFIG.email_expiration_time().cast_signed()) {
        tf.delete(conn).await?;
        return Err(invalid_otp_error());
    }

    if !crypto::ct_eq(&data.token, otp) {
        data.add_attempt();
        if data.attempts >= CONFIG.email_attempts_limit() {
            // Force a new code to be requested instead of allowing endless guesses.
            tf.delete(conn).await?;
        } else {
            tf.data = data.to_json();
            tf.save(conn).await?;
        }
        return Err(invalid_otp_error());
    }

    tf.delete(conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResendNewDeviceOtpData {
    email: String,
    master_password_hash: String,
}

/// Mirrors `POST /accounts/resend-new-device-otp` upstream, which answers successfully whatever
/// happens so it cannot be used to probe for accounts.
#[post("/accounts/resend-new-device-otp", data = "<data>")]
async fn resend_new_device_otp(data: Json<ResendNewDeviceOtpData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_login(&ip.ip)?;

    let data: ResendNewDeviceOtpData = data.into_inner();

    if !CONFIG.new_device_verification() || !CONFIG.mail_enabled() {
        return Ok(());
    }

    let Some(user) = User::find_by_mail(data.email.trim(), &conn).await else {
        return Ok(());
    };

    if !user.enabled || !user.verify_devices || !user.check_valid_password(&data.master_password_hash) {
        return Ok(());
    }

    // The device type is not part of this request, `Unknown Browser` matches upstream.
    if let Err(e) = send_otp(&user, 14, &ip, &conn).await {
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
    fn stored_code_survives_json_and_expires() {
        let mut sent = NewDeviceVerificationData::new("123456".into());
        sent.add_attempt();
        let mut data = NewDeviceVerificationData::from_json(&sent.to_json()).expect("stored data must round trip");
        assert_eq!(data.token, "123456");
        assert_eq!(data.attempts, 1);
        assert!(!data.is_expired(600));

        data.token_sent -= TimeDelta::seconds(601);
        assert!(data.is_expired(600));
        assert!(!data.is_expired(3600));
    }
}
