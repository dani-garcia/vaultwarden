mod admin;
pub mod core;
mod icons;
mod identity;
mod notifications;
mod push;
mod web;

use rocket::serde::json::Json;
use serde_json::Value;

pub use crate::api::{
    admin::catchers as admin_catchers,
    admin::routes as admin_routes,
    core::catchers as core_catchers,
    core::purge_auth_requests,
    core::purge_sends,
    core::purge_trashed_ciphers,
    core::routes as core_routes,
    core::two_factor::send_incomplete_2fa_notifications,
    core::{emergency_notification_reminder_job, emergency_request_timeout_job},
    core::{event_cleanup_job, events_routes as core_events_routes},
    icons::routes as icons_routes,
    identity::routes as identity_routes,
    notifications::routes as notifications_routes,
    notifications::{AnonymousNotify, Notify, UpdateType, WS_ANONYMOUS_SUBSCRIPTIONS, WS_USERS},
    push::{
        push_cipher_update, push_folder_update, push_logout, push_send_update, push_user_update, register_push_device,
        unregister_push_device,
    },
    web::catchers as web_catchers,
    web::routes as web_routes,
    web::static_files,
};
use crate::db::{
    models::{OrgPolicy, OrgPolicyType, User},
    DbConn,
};
use crate::CONFIG;

// Type aliases for API methods results
pub type ApiResult<T> = Result<T, crate::error::Error>;
pub type JsonResult = ApiResult<Json<Value>>;
pub type EmptyResult = ApiResult<()>;

// Common structs representing JSON data received
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordOrOtpData {
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl PasswordOrOtpData {
    /// Tokens used via this struct can be used multiple times during the process
    /// First for the validation to continue, after that to enable or validate the following actions
    /// This is different per caller, so it can be adjusted to delete the token or not
    pub async fn validate(&self, user: &User, delete_if_valid: bool, conn: &DbConn) -> EmptyResult {
        use crate::api::core::two_factor::protected_actions::validate_protected_action_otp;

        match (self.master_password_hash.as_deref(), self.otp.as_deref()) {
            (Some(pw_hash), None) => {
                if !user.check_valid_password(pw_hash) {
                    err!("Invalid password");
                }
            }
            (None, Some(otp)) => {
                validate_protected_action_otp(otp, &user.uuid, delete_if_valid, conn).await?;
            }
            _ => err!("No validation provided"),
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordPolicy {
    min_complexity: Option<u8>,
    min_length: Option<u32>,
    require_lower: bool,
    require_upper: bool,
    require_numbers: bool,
    require_special: bool,
    enforce_on_login: bool,
}

// Fetch all valid Master Password Policies and merge them into one with all trues and largest numbers as one policy
async fn master_password_policy(user: &User, conn: &DbConn) -> Value {
    let master_password_policies: Vec<MasterPasswordPolicy> =
        OrgPolicy::find_accepted_and_confirmed_by_user_and_active_policy(
            &user.uuid,
            OrgPolicyType::MasterPassword,
            conn,
        )
        .await
        .into_iter()
        .filter_map(|p| serde_json::from_str(&p.data).ok())
        .collect();

    let mut mpp_json = if !master_password_policies.is_empty() {
        json!(master_password_policies.into_iter().reduce(|acc, policy| {
            MasterPasswordPolicy {
                min_complexity: acc.min_complexity.max(policy.min_complexity),
                min_length: acc.min_length.max(policy.min_length),
                require_lower: acc.require_lower || policy.require_lower,
                require_upper: acc.require_upper || policy.require_upper,
                require_numbers: acc.require_numbers || policy.require_numbers,
                require_special: acc.require_special || policy.require_special,
                enforce_on_login: acc.enforce_on_login || policy.enforce_on_login,
            }
        }))
    } else if CONFIG.sso_enabled() {
        CONFIG.sso_master_password_policy_value().unwrap_or(json!({}))
    } else {
        json!({})
    };

    // NOTE: Upstream still uses PascalCase here for `Object`!
    mpp_json["Object"] = json!("masterPasswordPolicy");
    mpp_json
}
