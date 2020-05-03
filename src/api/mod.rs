mod admin;
pub mod core;
mod icons;
mod identity;
mod notifications;
mod web;

pub use self::admin::routes as admin_routes;
pub use self::core::routes as core_routes;
pub use self::icons::routes as icons_routes;
pub use self::identity::routes as identity_routes;
pub use self::notifications::routes as notifications_routes;
pub use self::notifications::{start_notification_server, Notify, UpdateType};
pub use self::web::routes as web_routes;

use rocket_contrib::json::Json;
use serde_json::Value;

// Type aliases for API methods results
type ApiResult<T> = Result<T, crate::error::Error>;
pub type JsonResult = ApiResult<Json<Value>>;
pub type EmptyResult = ApiResult<()>;

use crate::util;
type JsonUpcase<T> = Json<util::UpCase<T>>;
type JsonUpcaseVec<T> = Json<Vec<util::UpCase<T>>>;

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

    fn into_i32(self) -> ApiResult<i32> {
        use std::num::ParseIntError as PIE;
        match self {
            NumberOrString::Number(n) => Ok(n),
            NumberOrString::String(s) => s
                .parse()
                .map_err(|e: PIE| crate::Error::new("Can't convert to number", e.to_string())),
        }
    }
}
