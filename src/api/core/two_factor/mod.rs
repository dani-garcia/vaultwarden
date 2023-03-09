use chrono::{Duration, Utc};
use data_encoding::BASE32;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;

use crate::{
    api::{core::log_user_event, JsonResult, JsonUpcase, NumberOrString, PasswordData},
    auth::{ClientHeaders, Headers},
    crypto,
    db::{models::*, DbConn, DbPool},
    mail, CONFIG,
};

pub mod authenticator;
pub mod duo;
pub mod email;
pub mod webauthn;
pub mod yubikey;

pub fn routes() -> Vec<Route> {
    let mut routes = routes![
        get_twofactor,
        get_recover,
        recover,
        disable_twofactor,
        disable_twofactor_put,
        get_device_verification_settings,
    ];

    routes.append(&mut authenticator::routes());
    routes.append(&mut duo::routes());
    routes.append(&mut email::routes());
    routes.append(&mut webauthn::routes());
    routes.append(&mut yubikey::routes());

    routes
}

#[get("/two-factor")]
async fn get_twofactor(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let twofactors = TwoFactor::find_by_user(&headers.user.uuid, &mut conn).await;
    let twofactors_json: Vec<Value> = twofactors.iter().map(TwoFactor::to_json_provider).collect();

    Json(json!({
        "Data": twofactors_json,
        "Object": "list",
        "ContinuationToken": null,
    }))
}

#[post("/two-factor/get-recover", data = "<data>")]
fn get_recover(data: JsonUpcase<PasswordData>, headers: Headers) -> JsonResult {
    let data: PasswordData = data.into_inner().data;
    let user = headers.user;

    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": user.totp_recover,
        "Object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RecoverTwoFactor {
    MasterPasswordHash: String,
    Email: String,
    RecoveryCode: String,
}

#[post("/two-factor/recover", data = "<data>")]
async fn recover(data: JsonUpcase<RecoverTwoFactor>, client_headers: ClientHeaders, mut conn: DbConn) -> JsonResult {
    let data: RecoverTwoFactor = data.into_inner().data;

    use crate::db::models::User;

    // Get the user
    let mut user = match User::find_by_mail(&data.Email, &mut conn).await {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.RecoveryCode) {
        err!("Recovery code is incorrect. Try again.")
    }

    // Remove all twofactors from the user
    TwoFactor::delete_all_by_user(&user.uuid, &mut conn).await?;

    log_user_event(
        EventType::UserRecovered2fa as i32,
        &user.uuid,
        client_headers.device_type,
        &client_headers.ip.ip,
        &mut conn,
    )
    .await;

    // Remove the recovery code, not needed without twofactors
    user.totp_recover = None;
    user.save(&mut conn).await?;
    Ok(Json(Value::Object(serde_json::Map::new())))
}

async fn _generate_recover_code(user: &mut User, conn: &mut DbConn) {
    if user.totp_recover.is_none() {
        let totp_recover = crypto::encode_random_bytes::<20>(BASE32);
        user.totp_recover = Some(totp_recover);
        user.save(conn).await.ok();
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DisableTwoFactorData {
    MasterPasswordHash: String,
    Type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
async fn disable_twofactor(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;
    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let type_ = data.Type.into_i32()?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &mut conn).await {
        twofactor.delete(&mut conn).await?;
        log_user_event(EventType::UserDisabled2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn)
            .await;
    }

    let twofactor_disabled = TwoFactor::find_by_user(&user.uuid, &mut conn).await.is_empty();

    if twofactor_disabled {
        for user_org in
            UserOrganization::find_by_user_and_policy(&user.uuid, OrgPolicyType::TwoFactorAuthentication, &mut conn)
                .await
                .into_iter()
        {
            if user_org.atype < UserOrgType::Admin {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&user_org.org_uuid, &mut conn).await.unwrap();
                    mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
                }
                user_org.delete(&mut conn).await?;
            }
        }
    }

    Ok(Json(json!({
        "Enabled": false,
        "Type": type_,
        "Object": "twoFactorProvider"
    })))
}

#[put("/two-factor/disable", data = "<data>")]
async fn disable_twofactor_put(data: JsonUpcase<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    disable_twofactor(data, headers, conn).await
}

pub async fn send_incomplete_2fa_notifications(pool: DbPool) {
    debug!("Sending notifications for incomplete 2FA logins");

    if CONFIG.incomplete_2fa_time_limit() <= 0 || !CONFIG.mail_enabled() {
        return;
    }

    let mut conn = match pool.get().await {
        Ok(conn) => conn,
        _ => {
            error!("Failed to get DB connection in send_incomplete_2fa_notifications()");
            return;
        }
    };

    let now = Utc::now().naive_utc();
    let time_limit = Duration::minutes(CONFIG.incomplete_2fa_time_limit());
    let time_before = now - time_limit;
    let incomplete_logins = TwoFactorIncomplete::find_logins_before(&time_before, &mut conn).await;
    for login in incomplete_logins {
        let user = User::find_by_uuid(&login.user_uuid, &mut conn).await.expect("User not found");
        info!(
            "User {} did not complete a 2FA login within the configured time limit. IP: {}",
            user.email, login.ip_address
        );
        mail::send_incomplete_2fa_login(&user.email, &login.ip_address, &login.login_time, &login.device_name)
            .await
            .expect("Error sending incomplete 2FA email");
        login.delete(&mut conn).await.expect("Error deleting incomplete 2FA record");
    }
}

// This function currently is just a dummy and the actual part is not implemented yet.
// This also prevents 404 errors.
//
// See the following Bitwarden PR's regarding this feature.
// https://github.com/bitwarden/clients/pull/2843
// https://github.com/bitwarden/clients/pull/2839
// https://github.com/bitwarden/server/pull/2016
//
// The HTML part is hidden via the CSS patches done via the bw_web_build repo
#[get("/two-factor/get-device-verification-settings")]
fn get_device_verification_settings(_headers: Headers, _conn: DbConn) -> Json<Value> {
    Json(json!({
        "isDeviceVerificationSectionEnabled":false,
        "unknownDeviceVerificationEnabled":false,
        "object":"deviceVerificationSettings"
    }))
}
