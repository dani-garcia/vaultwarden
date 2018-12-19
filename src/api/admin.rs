use rocket_contrib::json::Json;
use serde_json::Value;

use crate::api::{JsonResult, JsonUpcase};
use crate::CONFIG;

use crate::db::models::*;
use crate::db::DbConn;

use rocket::request::{self, FromRequest, Request};
use rocket::{Outcome, Route};

pub fn routes() -> Vec<Route> {
    routes![get_users, invite_user, delete_user]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    Email: String,
}

#[get("/users")]
fn get_users(_token: AdminToken, conn: DbConn) -> JsonResult {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    Ok(Json(Value::Array(users_json)))
}

#[post("/invite", data = "<data>")]
fn invite_user(data: JsonUpcase<InviteData>, _token: AdminToken, conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner().data;

    if User::find_by_mail(&data.Email, &conn).is_some() {
        err!("User already exists")
    }

    if !CONFIG.invitations_allowed {
        err!("Invitations are not allowed")
    }

    let mut invitation = Invitation::new(data.Email);
    invitation.save(&conn)?;

    // TODO: Might want to send an email?

    Ok(Json(json!({})))
}

#[post("/users/<uuid>/delete")]
fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    user.delete(&conn)?;
    Ok(Json(json!({})))
}

pub struct AdminToken {}

impl<'a, 'r> FromRequest<'a, 'r> for AdminToken {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let config_token = match CONFIG.admin_token.as_ref() {
            Some(token) => token,
            None => err_handler!("Admin panel is disabled"),
        };

        // Get access_token
        let access_token: &str = match request.headers().get_one("Authorization") {
            Some(a) => match a.rsplit("Bearer ").next() {
                Some(split) => split,
                None => err_handler!("No access token provided"),
            },
            None => err_handler!("No access token provided"),
        };

        // TODO: What authentication to use?
        // Option 1: Make it a config option
        // Option 2: Generate random token, and
        // Option 2a: Send it to admin email, like upstream
        // Option 2b: Print in console or save to data dir, so admin can check

        if access_token != config_token {
            err_handler!("Invalid admin token")
        }

        Outcome::Success(AdminToken {})
    }
}
