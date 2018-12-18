use rocket_contrib::json::Json;
use serde_json::Value;

use crate::db::models::*;
use crate::db::DbConn;

use crate::api::{EmptyResult, JsonResult, JsonUpcase};

use rocket::{Route, Outcome};
use rocket::request::{self, Request, FromRequest};

pub fn routes() -> Vec<Route> {
    routes![
        get_users,
        invite_user,
        delete_user,
    ]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    Email: String,
}

#[get("/users")]
fn get_users(_token: AdminToken, conn: DbConn) -> JsonResult {
    let users =  User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();
    
    Ok(Json(Value::Array(users_json)))
}

#[post("/users", data="<data>")]
fn invite_user(data: JsonUpcase<InviteData>, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner().data;

    if User::find_by_mail(&data.Email, &conn).is_some() {
        err!("User already exists")
    }

    err!("Unimplemented")
}

#[delete("/users/<uuid>")]
fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let _user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist")
    };

    // TODO: Enable this once we have a more secure auth method
    err!("Unimplemented")
    /*
    match user.delete(&conn) {
        Ok(_) => Ok(()),
        Err(e) => err!("Error deleting user", e)
    }
    */
}


pub struct AdminToken {}

impl<'a, 'r> FromRequest<'a, 'r> for AdminToken {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
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

        if access_token != "token123" {
            err_handler!("Invalid admin token")
        }

        Outcome::Success(AdminToken {})
    }
}