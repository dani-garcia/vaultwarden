use serde_json::Value;

use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::{self, FlashMessage, Form, FromRequest, Request};
use rocket::response::{content::Html, Flash, Redirect};
use rocket::{Outcome, Route};
use rocket_contrib::json::Json;

use crate::api::{ApiResult, EmptyResult};
use crate::auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp};
use crate::config::ConfigBuilder;
use crate::db::{models::*, DbConn};
use crate::error::Error;
use crate::mail;
use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    if CONFIG.admin_token().is_none() {
        return routes![admin_disabled];
    }

    routes![
        admin_login,
        post_admin_login,
        admin_page,
        invite_user,
        delete_user,
        deauth_user,
        post_config,
        delete_config,
    ]
}

#[get("/")]
fn admin_disabled() -> &'static str {
    "The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it"
}

const COOKIE_NAME: &str = "BWRS_ADMIN";
const ADMIN_PATH: &str = "/admin";

const BASE_TEMPLATE: &str = "admin/base";
const VERSION: Option<&str> = option_env!("GIT_VERSION");

#[get("/", rank = 2)]
fn admin_login(flash: Option<FlashMessage>) -> ApiResult<Html<String>> {
    // If there is an error, show it
    let msg = flash.map(|msg| format!("{}: {}", msg.name(), msg.msg()));
    let json = json!({"page_content": "admin/login", "version": VERSION, "error": msg});

    // Return the page
    let text = CONFIG.render_template(BASE_TEMPLATE, &json)?;
    Ok(Html(text))
}

#[derive(FromForm)]
struct LoginForm {
    token: String,
}

#[post("/", data = "<data>")]
fn post_admin_login(data: Form<LoginForm>, mut cookies: Cookies, ip: ClientIp) -> Result<Redirect, Flash<Redirect>> {
    let data = data.into_inner();

    // If the token is invalid, redirect to login page
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
            .max_age(chrono::Duration::minutes(20))
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish();

        cookies.add(cookie);
        Ok(Redirect::to(ADMIN_PATH))
    }
}

fn _validate_token(token: &str) -> bool {
    match CONFIG.admin_token().as_ref() {
        None => false,
        Some(t) => crate::crypto::ct_eq(t, token),
    }
}

#[derive(Serialize)]
struct AdminTemplateData {
    page_content: String,
    version: Option<&'static str>,
    users: Vec<Value>,
    config: Value,
}

impl AdminTemplateData {
    fn new(users: Vec<Value>) -> Self {
        Self {
            page_content: String::from("admin/page"),
            version: VERSION,
            users,
            config: CONFIG.prepare_json(),
        }
    }

    fn render(self) -> Result<String, Error> {
        CONFIG.render_template(BASE_TEMPLATE, &self)
    }
}

#[get("/", rank = 1)]
fn admin_page(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    let text = AdminTemplateData::new(users_json).render()?;
    Ok(Html(text))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    email: String,
}

#[post("/invite", data = "<data>")]
fn invite_user(data: Json<InviteData>, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner();
    let email = data.email.clone();
    if User::find_by_mail(&data.email, &conn).is_some() {
        err!("User already exists")
    }

    if !CONFIG.invitations_allowed() {
        err!("Invitations are not allowed")
    }

    if CONFIG.mail_enabled() {
        let mut user = User::new(email);
        user.save(&conn)?;
        let org_name = "bitwarden_rs";
        mail::send_invite(&user.email, &user.uuid, None, None, &org_name, None)
    } else {
        let mut invitation = Invitation::new(data.email);
        invitation.save(&conn)
    }
}

#[post("/users/<uuid>/delete")]
fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    user.delete(&conn)
}

#[post("/users/<uuid>/deauth")]
fn deauth_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    Device::delete_all_by_user(&user.uuid, &conn)?;
    user.reset_security_stamp();

    user.save(&conn)
}

#[post("/config", data = "<data>")]
fn post_config(data: Json<ConfigBuilder>, _token: AdminToken) -> EmptyResult {
    let data: ConfigBuilder = data.into_inner();
    CONFIG.update_config(data)
}

#[post("/config/delete")]
fn delete_config(_token: AdminToken) -> EmptyResult {
    CONFIG.delete_user_config()
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
