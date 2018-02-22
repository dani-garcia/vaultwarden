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

// Common structs representing JSON data received
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PasswordData {
    masterPasswordHash: String
}
