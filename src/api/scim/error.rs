//
// SCIM error envelope, RFC 7644 section 3.12.
//
// Every error leaving the /scim mount must use this shape. Auth failures are
// deliberately uniform: the guard logs the specific cause server-side and the
// caller always receives the same 401 body, so responses carry no signal about
// which check failed.
//
use std::io::Cursor;

use rocket::{
    http::{ContentType, Status},
    request::Request,
    response::{self, Responder, Response},
};

pub const SCIM_ERROR_URN: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[derive(Debug)]
pub struct ScimError {
    pub status: Status,
    pub scim_type: Option<&'static str>,
    pub detail: String,
}

impl ScimError {
    pub fn unauthorized() -> Self {
        Self {
            status: Status::Unauthorized,
            scim_type: None,
            detail: String::from("Unauthorized"),
        }
    }

    pub fn too_many_requests() -> Self {
        Self {
            status: Status::TooManyRequests,
            scim_type: None,
            detail: String::from("Too many requests"),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: Status::NotFound,
            scim_type: None,
            detail: String::from("Resource not found"),
        }
    }

    pub fn bad_request(scim_type: &'static str, detail: &str) -> Self {
        Self {
            status: Status::BadRequest,
            scim_type: Some(scim_type),
            detail: String::from(detail),
        }
    }

    pub fn internal() -> Self {
        Self {
            status: Status::InternalServerError,
            scim_type: None,
            detail: String::from("Internal server error"),
        }
    }

    fn body(&self) -> String {
        let mut body = json!({
            "schemas": [SCIM_ERROR_URN],
            "status": self.status.code.to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        body.to_string()
    }
}

pub fn scim_content_type() -> ContentType {
    ContentType::new("application", "scim+json")
}

impl Responder<'_, 'static> for ScimError {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let body = self.body();
        Response::build()
            .status(self.status)
            .header(scim_content_type())
            .sized_body(Some(body.len()), Cursor::new(body))
            .ok()
    }
}
