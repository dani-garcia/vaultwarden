//
// SCIM v2 provisioning endpoints (RFC 7643 / RFC 7644), Entra ID first.
//
// Mounted at /scim (see main.rs). Authentication is the per-organization
// static bearer token checked by guard::ScimToken. Management of that token
// is an admin-session concern and lives under /api via manage::routes().
//
pub mod guard;

mod discovery;
mod error;
mod manage;

use std::io::Cursor;

use rocket::{
    Catcher, Route,
    http::Status,
    request::Request,
    response::{self, Responder, Response},
};
use serde_json::Value;

pub use error::ScimError;
pub use manage::routes as manage_routes;

pub fn routes() -> Vec<Route> {
    discovery::routes()
}

// A JSON body with Content-Type application/scim+json, RFC 7644 section 3.1.
pub struct ScimResponse {
    status: Status,
    body: Value,
}

impl ScimResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status: Status::Ok,
            body,
        }
    }
}

impl Responder<'_, 'static> for ScimResponse {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let body = self.body.to_string();
        Response::build()
            .status(self.status)
            .header(error::scim_content_type())
            .sized_body(Some(body.len()), Cursor::new(body))
            .ok()
    }
}

// Catchers keep every error under /scim inside the SCIM envelope, including
// guard rejections (which carry only a status). The 401 body is a constant:
// all auth failure causes look identical to the caller.
pub fn catchers() -> Vec<Catcher> {
    catchers![scim_bad_request, scim_unauthorized, scim_not_found, scim_too_many_requests, scim_internal]
}

#[catch(400)]
fn scim_bad_request() -> ScimError {
    ScimError::bad_request("invalidValue", "Bad request")
}

#[catch(401)]
fn scim_unauthorized() -> ScimError {
    ScimError::unauthorized()
}

#[catch(404)]
fn scim_not_found() -> ScimError {
    ScimError::not_found()
}

#[catch(429)]
fn scim_too_many_requests() -> ScimError {
    ScimError::too_many_requests()
}

#[catch(500)]
fn scim_internal() -> ScimError {
    ScimError::internal()
}

#[cfg(all(test, sqlite))]
mod tests;
