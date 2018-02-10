mod core;
mod icons;
mod identity;
mod web;

pub use self::core::routes as core_routes;
pub use self::icons::routes as icons_routes;
pub use self::identity::routes as identity_routes;
pub use self::web::routes as web_routes;
