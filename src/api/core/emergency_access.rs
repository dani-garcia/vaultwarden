use rocket::Route;
use rocket_contrib::json::Json;

use crate::{api::JsonResult, auth::Headers, db::DbConn};

pub fn routes() -> Vec<Route> {
    routes![get_contacts,]
}

/// This endpoint is expected to return at least something.
/// If we return an error message that will trigger error toasts for the user.
/// To prevent this we just return an empty json result with no Data.
/// When this feature is going to be implemented it also needs to return this empty Data
/// instead of throwing an error/4XX unless it really is an error.
#[get("/emergency-access/trusted")]
fn get_contacts(_headers: Headers, _conn: DbConn) -> JsonResult {
    debug!("Emergency access is not supported.");

    Ok(Json(json!({
      "Data": [],
      "Object": "list",
      "ContinuationToken": null
    })))
}
