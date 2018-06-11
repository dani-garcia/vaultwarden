mod core;
mod icons;
mod identity;
mod web;

pub use self::core::routes as core_routes;
pub use self::icons::routes as icons_routes;
pub use self::identity::routes as identity_routes;
pub use self::web::routes as web_routes;

use rocket::response::status::BadRequest;
use rocket_contrib::Json;

// Type aliases for API methods results
type JsonResult = Result<Json, BadRequest<Json>>;
type EmptyResult = Result<(), BadRequest<Json>>;

use util;
type JsonUpcase<T> = Json<util::UpCase<T>>;

// Common structs representing JSON data received
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PasswordData {
    MasterPasswordHash: String
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum NumberOrString {
    Number(i32),
    String(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s
        }
    }

    fn into_i32(self) -> Option<i32> {
        match self {
            NumberOrString::Number(n) => Some(n),
            NumberOrString::String(s) => s.parse().ok()
        }  
    }
}
