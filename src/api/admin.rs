use rocket_contrib::json::Json;
use serde_json::Value;

use rocket::http::{Cookie, Cookies};
use rocket::request::{self, FlashMessage, Form, FromRequest, Request};
use rocket::response::{content::Html, Flash, Redirect};
use rocket::{Outcome, Route};

use crate::api::{JsonResult, JsonUpcase};
use crate::auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp};
use crate::db::{models::*, DbConn};
use crate::error::Error;
use crate::mail;
use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    if CONFIG.admin_token.is_none() {
        return Vec::new();
    }

    routes![admin_login, post_admin_login, admin_page, invite_user, delete_user]
}

#[derive(FromForm)]
struct LoginForm {
    token: String,
}

const COOKIE_NAME: &'static str = "BWRS_ADMIN";
const ADMIN_PATH: &'static str = "/admin";

#[get("/", rank = 2)]
fn admin_login(flash: Option<FlashMessage>) -> Result<Html<String>, Error> {
    // If there is an error, show it
    let msg = flash
        .map(|msg| format!("{}: {}", msg.name(), msg.msg()))
        .unwrap_or_default();
    let error = json!({ "error": msg });

    // Return the page
    let text = CONFIG.templates.render("admin/admin_login", &error)?;
    Ok(Html(text))
}

#[post("/", data = "<data>")]
fn post_admin_login(data: Form<LoginForm>, mut cookies: Cookies, ip: ClientIp) -> Result<Redirect, Flash<Redirect>> {
    let data = data.into_inner();

    if !_validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        Err(Flash::error(
            Redirect::to(ADMIN_PATH),
            "Invalid admin token, please try again.",
        ))
    } else {
        // If the token received is valid, generate JWT and save it as a cookie
        let claims = generate_admin_claims();
        let jwt = encode_jwt(&claims);

        let cookie = Cookie::build(COOKIE_NAME, jwt)
            .path(ADMIN_PATH)
            .http_only(true)
            .finish();

        cookies.add(cookie);
        Ok(Redirect::to(ADMIN_PATH))
    }
}

fn _validate_token(token: &str) -> bool {
    match CONFIG.admin_token.as_ref() {
        None => false,
        Some(t) => t == token,
    }
}

#[derive(Serialize)]
struct AdminTemplateData {
    users: Vec<Value>,
}

#[get("/", rank = 1)]
fn admin_page(_token: AdminToken, conn: DbConn) -> Result<Html<String>, Error> {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    let data = AdminTemplateData { users: users_json };

    let text = CONFIG.templates.render("admin/admin_page", &data)?;
    Ok(Html(text))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    Email: String,
}

#[post("/invite", data = "<data>")]
fn invite_user(data: JsonUpcase<InviteData>, _token: AdminToken, conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner().data;
    let email = data.Email.clone();
    if User::find_by_mail(&data.Email, &conn).is_some() {
        err!("User already exists")
    }

    if !CONFIG.invitations_allowed {
        err!("Invitations are not allowed")
    }

    if let Some(ref mail_config) = CONFIG.mail {
        let mut user = User::new(email);
        user.save(&conn)?;
        let org_name = "bitwarden_rs";
        mail::send_invite(&user.email, &user.uuid, None, None, &org_name, None, mail_config)?;
    } else {
        let mut invitation = Invitation::new(data.Email);
        invitation.save(&conn)?;
    }

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
        let mut cookies = request.cookies();

        let access_token = match cookies.get(COOKIE_NAME) {
            Some(cookie) => cookie.value(),
            None => return Outcome::Forward(()), // If there is no cookie, redirect to login
        };

        let ip = match request.guard::<ClientIp>() {
            Outcome::Success(ip) => ip.ip,
            _ => err_handler!("Error getting Client IP"),
        };

        if decode_admin(access_token).is_err() {
            // Remove admin cookie
            cookies.remove(Cookie::named(COOKIE_NAME));
            error!("Invalid or expired admin JWT. IP: {}.", ip);
            return Outcome::Forward(());
        }

        Outcome::Success(AdminToken {})
    }
}
