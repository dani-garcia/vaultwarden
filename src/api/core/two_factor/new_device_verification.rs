//! New device verification, the Bitwarden "New device login protection" feature.
//!
//! A password login from a device that is not known yet first has to be confirmed with a code that
//! is mailed to the account address. The device is only stored once that code was accepted, so a
//! correct master password on its own never turns an unknown device into a known one.
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
/// Matches the protected actions resend delay.
const RESEND_DELAY_SECONDS: i64 = 30;

/// Data stored in the `twofactor` table under [`TwoFactorType::NewDeviceVerification`]. Only read
/// and written here, so a code issued for a new device can never authorize anything else.
#[derive(Debug, Serialize, Deserialize)]
pub struct NewDeviceVerificationData {
    /// Code the user has to send back as `NewDeviceOtp`.
    pub token: String,
    #[serde(with = "ts_seconds")]
    pub token_sent: NaiveDateTime,
    /// Failed validation attempts for the current token.
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

/// Everything the decision in [`new_device_action`] depends on.
#[expect(clippy::struct_excessive_bools, reason = "Every condition upstream checks, kept separate to stay testable")]
#[derive(Clone, Copy)]
pub struct NewDeviceState {
    pub enforced: bool,
    pub verify_devices: bool,
    /// The account is younger than the Bitwarden exemption period.
    pub recently_created: bool,
    pub has_two_factor: bool,
    pub known_device: bool,
    pub has_devices: bool,
    /// A `NewDeviceOtp` field was sent, an empty one included.
    pub otp_supplied: bool,
    pub otp_not_empty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewDeviceAction {
    /// Continue the login unchanged.
    Skip,
    /// Validate the supplied `NewDeviceOtp` before continuing.
    Verify,
    /// Mail a code and reject this login attempt.
    Challenge,
}

/// Mirrors `DeviceValidator.HandleNewDeviceVerificationAsync` of the Bitwarden server.
pub fn new_device_action(state: NewDeviceState) -> NewDeviceAction {
    // A code implies an unknown device, upstream skips the lookup for it.
    if !state.otp_not_empty && state.known_device {
        return NewDeviceAction::Skip;
    }

    // Upstream skips device verification for 2FA users entirely, they keep their existing flow.
    if !state.enforced || !state.verify_devices || state.recently_created || state.has_two_factor {
        return NewDeviceAction::Skip;
    }

    // An empty code counts as a wrong code upstream.
    if state.otp_supplied {
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
fn verification_required_error() -> Error {
    let body = json!({
        "error": "device_error",
        "error_description": "New device verification required",
        "ErrorModel": {
            "Message": "new device verification required",
            "Object": "error"
        }
    });
    Error::from(("New device verification required", body)).with_event(ErrorEvent {
        event: EventType::UserFailedLogIn,
    })
}

fn invalid_otp_error() -> Error {
    let body = json!({
        "error": "device_error",
        "error_description": "Invalid New Device OTP",
        "ErrorModel": {
            "Message": "invalid new device otp",
            "Object": "error"
        }
    });
    Error::from(("Invalid new device OTP", body)).with_event(ErrorEvent {
        event: EventType::UserFailedLogIn,
    })
}

/// Runs new device verification for a password login, before the device is stored. `Ok(())` means
/// the login may continue, an error carries the response the Bitwarden clients expect.
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

    // Skip the extra queries when the feature cannot apply anyway. Every condition here also
    // makes `new_device_action` return `Skip`.
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
        otp_supplied: new_device_otp.is_some(),
        otp_not_empty: new_device_otp.is_some_and(|otp| !otp.is_empty()),
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

/// Generates and mails a new code, unless a still valid one was sent very recently.
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
        // Drop the code that never went out, the resend delay would otherwise suppress the next
        // attempt and ask the user for a code they cannot have.
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
    let Some(mut tf) = TwoFactor::find_by_user_and_type(user_id, type_, conn).await else {
        return Err(invalid_otp_error());
    };

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

    // Consume the code so it cannot be replayed.
    tf.delete(conn).await?;
    Ok(())
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

/// Changes the account setting that controls whether new devices need to be verified.
/// Current clients use `POST`, older ones and the API docs use `PUT`.
#[put("/accounts/verify-devices", data = "<data>")]
async fn put_verify_devices(data: Json<SetVerifyDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    set_verify_devices(data, headers, conn).await
}

#[post("/accounts/verify-devices", data = "<data>")]
async fn post_verify_devices(data: Json<SetVerifyDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    set_verify_devices(data, headers, conn).await
}

async fn set_verify_devices(data: Json<SetVerifyDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
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

/// Reports the state of this feature to the pre-2023 web vault, the only client that used it.
/// The section stays disabled because its setter was never part of Vaultwarden, so showing it
/// would only produce a broken toggle.
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

    /// A state in which a login gets challenged, so single fields can be flipped per case.
    fn challenged() -> NewDeviceState {
        NewDeviceState {
            enforced: true,
            verify_devices: true,
            recently_created: false,
            has_two_factor: false,
            known_device: false,
            has_devices: true,
            otp_supplied: false,
            otp_not_empty: false,
        }
    }

    /// Case name, whether a code was sent along, what else differs from a challenged login, outcome.
    type Case = (&'static str, bool, fn(&mut NewDeviceState), NewDeviceAction);

    #[test]
    fn decision_matches_upstream() {
        use NewDeviceAction::{Challenge, Skip, Verify};

        let cases: [Case; 11] = [
            ("unknown device without 2fa", false, |_| (), Challenge),
            ("feature disabled", false, |s| s.enforced = false, Skip),
            ("user opted out", false, |s| s.verify_devices = false, Skip),
            ("account within the exemption period", false, |s| s.recently_created = true, Skip),
            ("2fa configured", false, |s| s.has_two_factor = true, Skip),
            ("2fa configured and a code sent", true, |s| s.has_two_factor = true, Skip),
            ("known device", false, |s| s.known_device = true, Skip),
            ("account without any device", false, |s| s.has_devices = false, Skip),
            ("code sent", true, |_| (), Verify),
            ("code sent from a known device", true, |s| s.known_device = true, Verify),
            ("code sent without any device", true, |s| s.has_devices = false, Verify),
        ];

        for (case, sends_code, setup, expected) in cases {
            let mut state = challenged();
            state.otp_supplied = sends_code;
            state.otp_not_empty = sends_code;
            setup(&mut state);
            assert_eq!(new_device_action(state), expected, "{case}");
        }
    }

    /// Upstream only skips the known device lookup for a non-empty code, but still treats an empty
    /// one as a wrong code.
    #[test]
    fn empty_code_is_treated_as_a_wrong_code() {
        let sent_empty = NewDeviceState {
            otp_supplied: true,
            ..challenged()
        };
        assert_eq!(new_device_action(sent_empty), NewDeviceAction::Verify);

        let known_device = NewDeviceState {
            known_device: true,
            ..sent_empty
        };
        assert_eq!(new_device_action(known_device), NewDeviceAction::Skip);
    }

    /// The shortcut in `validate_new_device_login` must never skip a login the decision would challenge.
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
        let required: Value = serde_json::from_str(&verification_required_error().to_string()).unwrap();
        assert_eq!(required["error"], "device_error");
        assert_eq!(required["error_description"], "New device verification required");
        assert_eq!(required["ErrorModel"]["Message"], "new device verification required");
        // Must not look like a 2FA response, the clients check that first.
        assert!(required.get("TwoFactorProviders2").is_none());

        let invalid: Value = serde_json::from_str(&invalid_otp_error().to_string()).unwrap();
        assert_eq!(invalid["error_description"], "Invalid New Device OTP");
        assert_eq!(invalid["ErrorModel"]["Message"], "invalid new device otp");
    }

    #[test]
    fn stored_code_survives_json_and_expires() {
        let mut data = NewDeviceVerificationData::from_json(&NewDeviceVerificationData::new("123456".into()).to_json())
            .expect("stored data must round trip");
        assert_eq!(data.token, "123456");
        assert_eq!(data.attempts, 0);
        assert!(!data.is_expired(600));

        data.add_attempt();
        assert_eq!(data.attempts, 1);

        data.token_sent -= TimeDelta::seconds(601);
        assert!(data.is_expired(600));
        assert!(!data.is_expired(3600));
    }
}
