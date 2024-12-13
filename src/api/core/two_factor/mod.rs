use chrono::{TimeDelta, Utc};
use data_encoding::BASE32;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;

use crate::{
    api::{
        core::{log_event, log_user_event},
        EmptyResult, JsonResult, PasswordOrOtpData,
    },
    auth::{ClientHeaders, Headers},
    crypto,
    db::{models::*, DbConn, DbPool},
    mail,
    util::NumberOrString,
    CONFIG,
};

pub mod authenticator;
pub mod duo;
pub mod duo_oidc;
pub mod email;
pub mod protected_actions;
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
    routes.append(&mut protected_actions::routes());

    routes
}

#[get("/two-factor")]
async fn get_twofactor(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let twofactors = TwoFactor::find_by_user(&headers.user.uuid, &mut conn).await;
    let twofactors_json: Vec<Value> = twofactors.iter().map(TwoFactor::to_json_provider).collect();

    Json(json!({
        "data": twofactors_json,
        "object": "list",
        "continuationToken": null,
    }))
}

#[post("/two-factor/get-recover", data = "<data>")]
async fn get_recover(data: Json<PasswordOrOtpData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, true, &mut conn).await?;

    Ok(Json(json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverTwoFactor {
    master_password_hash: String,
    email: String,
    recovery_code: String,
}

#[post("/two-factor/recover", data = "<data>")]
async fn recover(data: Json<RecoverTwoFactor>, client_headers: ClientHeaders, mut conn: DbConn) -> JsonResult {
    let data: RecoverTwoFactor = data.into_inner();

    use crate::db::models::User;

    // Get the user
    let Some(mut user) = User::find_by_mail(&data.email, &mut conn).await else {
        err!("Username or password is incorrect. Try again.")
    };

    // Check password
    if !user.check_valid_password(&data.master_password_hash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.recovery_code) {
        err!("Recovery code is incorrect. Try again.")
    }

    // Remove all twofactors from the user
    TwoFactor::delete_all_by_user(&user.uuid, &mut conn).await?;
    enforce_2fa_policy(&user, &user.uuid, client_headers.device_type, &client_headers.ip.ip, &mut conn).await?;

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
#[serde(rename_all = "camelCase")]
struct DisableTwoFactorData {
    master_password_hash: Option<String>,
    otp: Option<String>,
    r#type: NumberOrString,
}

#[post("/two-factor/disable", data = "<data>")]
async fn disable_twofactor(data: Json<DisableTwoFactorData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    let data: DisableTwoFactorData = data.into_inner();
    let user = headers.user;

    // Delete directly after a valid token has been provided
    PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    }
    .validate(&user, true, &mut conn)
    .await?;

    let type_ = data.r#type.into_i32()?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &mut conn).await {
        twofactor.delete(&mut conn).await?;
        log_user_event(EventType::UserDisabled2fa as i32, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn)
            .await;
    }

    if TwoFactor::find_by_user(&user.uuid, &mut conn).await.is_empty() {
        enforce_2fa_policy(&user, &user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await?;
    }

    Ok(Json(json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

#[put("/two-factor/disable", data = "<data>")]
async fn disable_twofactor_put(data: Json<DisableTwoFactorData>, headers: Headers, conn: DbConn) -> JsonResult {
    disable_twofactor(data, headers, conn).await
}

pub async fn enforce_2fa_policy(
    user: &User,
    act_uuid: &str,
    device_type: i32,
    ip: &std::net::IpAddr,
    conn: &mut DbConn,
) -> EmptyResult {
    for member in UserOrganization::find_by_user_and_policy(&user.uuid, OrgPolicyType::TwoFactorAuthentication, conn)
        .await
        .into_iter()
    {
        // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
        if member.atype < UserOrgType::Admin {
            if CONFIG.mail_enabled() {
                let org = Organization::find_by_uuid(&member.org_uuid, conn).await.unwrap();
                mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
            }
            let mut member = member;
            member.revoke();
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked as i32,
                &member.uuid,
                &member.org_uuid,
                act_uuid,
                device_type,
                ip,
                conn,
            )
            .await;
        }
    }

    Ok(())
}

pub async fn enforce_2fa_policy_for_org(
    org_uuid: &str,
    act_uuid: &str,
    device_type: i32,
    ip: &std::net::IpAddr,
    conn: &mut DbConn,
) -> EmptyResult {
    let org = Organization::find_by_uuid(org_uuid, conn).await.unwrap();
    for member in UserOrganization::find_confirmed_by_org(org_uuid, conn).await.into_iter() {
        // Don't enforce the policy for Admins and Owners.
        if member.atype < UserOrgType::Admin && TwoFactor::find_by_user(&member.user_uuid, conn).await.is_empty() {
            if CONFIG.mail_enabled() {
                let user = User::find_by_uuid(&member.user_uuid, conn).await.unwrap();
                mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
            }
            let mut member = member;
            member.revoke();
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked as i32,
                &member.uuid,
                org_uuid,
                act_uuid,
                device_type,
                ip,
                conn,
            )
            .await;
        }
    }

    Ok(())
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
    let time_limit = TimeDelta::try_minutes(CONFIG.incomplete_2fa_time_limit()).unwrap();
    let time_before = now - time_limit;
    let incomplete_logins = TwoFactorIncomplete::find_logins_before(&time_before, &mut conn).await;
    for login in incomplete_logins {
        let user = User::find_by_uuid(&login.user_uuid, &mut conn).await.expect("User not found");
        info!(
            "User {} did not complete a 2FA login within the configured time limit. IP: {}",
            user.email, login.ip_address
        );
        match mail::send_incomplete_2fa_login(
            &user.email,
            &login.ip_address,
            &login.login_time,
            &login.device_name,
            &DeviceType::from_i32(login.device_type).to_string(),
        )
        .await
        {
            Ok(_) => {
                if let Err(e) = login.delete(&mut conn).await {
                    error!("Error deleting incomplete 2FA record: {e:#?}");
                }
            }
            Err(e) => {
                error!("Error sending incomplete 2FA email: {e:#?}");
            }
        }
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
