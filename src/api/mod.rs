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
    core::purge_sends,
    core::purge_trashed_ciphers,
    core::routes as core_routes,
    core::two_factor::send_incomplete_2fa_notifications,
    core::{emergency_notification_reminder_job, emergency_request_timeout_job},
    core::{event_cleanup_job, events_routes as core_events_routes},
    icons::routes as icons_routes,
    identity::routes as identity_routes,
    notifications::routes as notifications_routes,
    notifications::{start_notification_server, Notify, UpdateType},
    push::{
        push_cipher_update, push_folder_update, push_logout, push_send_update, push_user_update, register_push_device,
        unregister_push_device,
    },
    web::catchers as web_catchers,
    web::routes as web_routes,
    web::static_files,
};
use crate::util;

// Type aliases for API methods results
type ApiResult<T> = Result<T, crate::error::Error>;
pub type JsonResult = ApiResult<Json<Value>>;
pub type EmptyResult = ApiResult<()>;

type JsonUpcase<T> = Json<util::UpCase<T>>;
type JsonUpcaseVec<T> = Json<Vec<util::UpCase<T>>>;
type JsonVec<T> = Json<Vec<T>>;

// Common structs representing JSON data received
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PasswordData {
    MasterPasswordHash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
enum NumberOrString {
    Number(i32),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_i32(&self) -> ApiResult<i32> {
        use std::num::ParseIntError as PIE;
        match self {
            NumberOrString::Number(n) => Ok(*n),
            NumberOrString::String(s) => {
                s.parse().map_err(|e: PIE| crate::Error::new("Can't convert to number", e.to_string()))
            }
        }
    }
}
