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
mod filter;
mod groups;
mod manage;
mod models;
mod patch;
mod users;

use std::io::Cursor;

use rocket::{
    Catcher, Route,
    data::{Data, FromData, Outcome as DataOutcome},
    http::Status,
    request::Request,
    response::{self, Responder, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use error::ScimError;
pub use manage::routes as manage_routes;

pub fn routes() -> Vec<Route> {
    let mut routes = discovery::routes();
    routes.append(&mut users::routes());
    routes.append(&mut groups::routes());
    routes
}

// A JSON body limited by the "scim" size limit. Accepts both
// application/scim+json (what Entra sends) and application/json; rocket's
// own Json<T> would reject the former.
pub struct ScimJson<T>(pub T);

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for ScimJson<T> {
    type Error = ScimError;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let limit = request.limits().get("scim").unwrap_or_else(|| rocket::data::ByteUnit::Kibibyte(512));
        let bytes = match data.open(limit).into_bytes().await {
            Ok(bytes) if bytes.is_complete() => bytes.into_inner(),
            Ok(_) => return DataOutcome::Error((Status::PayloadTooLarge, ScimError::payload_too_large())),
            Err(_) => {
                return DataOutcome::Error((
                    Status::BadRequest,
                    ScimError::bad_request("invalidSyntax", "Unreadable body"),
                ));
            }
        };
        match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => DataOutcome::Success(ScimJson(value)),
            Err(e) => {
                warn!(target: "scim", "Rejecting unparseable SCIM body: {e}");
                DataOutcome::Error((Status::BadRequest, ScimError::bad_request("invalidSyntax", "Malformed SCIM body")))
            }
        }
    }
}

// A JSON body with Content-Type application/scim+json, RFC 7644 section 3.1.
pub struct ScimResponse {
    status: Status,
    location: Option<String>,
    body: Option<Value>,
}

impl ScimResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status: Status::Ok,
            location: None,
            body: Some(body),
        }
    }

    pub fn created(location: String, body: Value) -> Self {
        Self {
            status: Status::Created,
            location: Some(location),
            body: Some(body),
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: Status::NoContent,
            location: None,
            body: None,
        }
    }
}

impl Responder<'_, 'static> for ScimResponse {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let mut builder = Response::build();
        builder.status(self.status);
        if let Some(location) = self.location {
            builder.raw_header("Location", location);
        }
        if let Some(body) = self.body {
            let body = body.to_string();
            builder.header(error::scim_content_type()).sized_body(Some(body.len()), Cursor::new(body));
        }
        builder.ok()
    }
}

// Catchers keep every error under /scim inside the SCIM envelope, including
// guard rejections (which carry only a status). The 401 body is a constant:
// all auth failure causes look identical to the caller.
pub fn catchers() -> Vec<Catcher> {
    catchers![
        scim_bad_request,
        scim_unauthorized,
        scim_not_found,
        scim_payload_too_large,
        scim_too_many_requests,
        scim_internal
    ]
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

#[catch(413)]
fn scim_payload_too_large() -> ScimError {
    ScimError::payload_too_large()
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
