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
use crate::db::{models::User, DbConn};

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
    pub async fn validate(&self, user: &User, delete_if_valid: bool, conn: &mut DbConn) -> EmptyResult {
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
