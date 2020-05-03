use once_cell::sync::Lazy;
use serde_json::Value;
use std::process::Command;

use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::{self, FlashMessage, Form, FromRequest, Request};
use rocket::response::{content::Html, Flash, Redirect};
use rocket::{Outcome, Route};
use rocket_contrib::json::Json;

use crate::api::{ApiResult, EmptyResult, JsonResult};
use crate::auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp};
use crate::config::ConfigBuilder;
use crate::db::{backup_database, models::*, DbConn};
use crate::error::Error;
use crate::mail;
use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    if !CONFIG.disable_admin_token() && !CONFIG.is_admin_token_set() {
        return routes![admin_disabled];
    }

    routes![
        admin_login,
        get_users,
        post_admin_login,
        admin_page,
        invite_user,
        logout,
        delete_user,
        deauth_user,
        remove_2fa,
        update_revision_users,
        post_config,
        delete_config,
        backup_db,
        test_smtp,
    ]
}

static CAN_BACKUP: Lazy<bool> =
    Lazy::new(|| cfg!(feature = "sqlite") && Command::new("sqlite3").arg("-version").status().is_ok());

#[get("/")]
fn admin_disabled() -> &'static str {
    "The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it"
}

const COOKIE_NAME: &str = "BWRS_ADMIN";
const ADMIN_PATH: &str = "/admin";

const BASE_TEMPLATE: &str = "admin/base";
const VERSION: Option<&str> = option_env!("BWRS_VERSION");

fn admin_path() -> String {
    format!("{}{}", CONFIG.domain_path(), ADMIN_PATH)
}

#[get("/", rank = 2)]
fn admin_login(flash: Option<FlashMessage>) -> ApiResult<Html<String>> {
    // If there is an error, show it
    let msg = flash.map(|msg| format!("{}: {}", msg.name(), msg.msg()));
    let json = json!({"page_content": "admin/login", "version": VERSION, "error": msg, "urlpath": CONFIG.domain_path()});

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
            Redirect::to(admin_path()),
            "Invalid admin token, please try again.",
        ))
    } else {
        // If the token received is valid, generate JWT and save it as a cookie
        let claims = generate_admin_claims();
        let jwt = encode_jwt(&claims);

        let cookie = Cookie::build(COOKIE_NAME, jwt)
            .path(admin_path())
            .max_age(time::Duration::minutes(20))
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish();

        cookies.add(cookie);
        Ok(Redirect::to(admin_path()))
    }
}

fn _validate_token(token: &str) -> bool {
    match CONFIG.admin_token().as_ref() {
        None => false,
        Some(t) => crate::crypto::ct_eq(t.trim(), token.trim()),
    }
}

#[derive(Serialize)]
struct AdminTemplateData {
    page_content: String,
    version: Option<&'static str>,
    users: Vec<Value>,
    config: Value,
    can_backup: bool,
    logged_in: bool,
    urlpath: String,
}

impl AdminTemplateData {
    fn new(users: Vec<Value>) -> Self {
        Self {
            page_content: String::from("admin/page"),
            version: VERSION,
            users,
            config: CONFIG.prepare_json(),
            can_backup: *CAN_BACKUP,
            logged_in: true,
            urlpath: CONFIG.domain_path(),
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

    let mut user = User::new(email);
    user.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_invite(&user.email, &user.uuid, None, None, &CONFIG.invitation_org_name(), None)
    } else {
        let invitation = Invitation::new(data.email);
        invitation.save(&conn)
    }
}

#[post("/test/smtp", data = "<data>")]
fn test_smtp(data: Json<InviteData>, _token: AdminToken) -> EmptyResult {
    let data: InviteData = data.into_inner();

    if CONFIG.mail_enabled() {
        mail::send_test(&data.email)
    } else {
        err!("Mail is not enabled")
    }
}

#[get("/logout")]
fn logout(mut cookies: Cookies) -> Result<Redirect, ()> {
    cookies.remove(Cookie::named(COOKIE_NAME));
    Ok(Redirect::to(admin_path()))
}

#[get("/users")]
fn get_users(_token: AdminToken, conn: DbConn) -> JsonResult {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    Ok(Json(Value::Array(users_json)))
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

#[post("/users/<uuid>/remove-2fa")]
fn remove_2fa(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = match User::find_by_uuid(&uuid, &conn) {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    TwoFactor::delete_all_by_user(&user.uuid, &conn)?;
    user.totp_recover = None;
    user.save(&conn)
}

#[post("/users/update_revision")]
fn update_revision_users(_token: AdminToken, conn: DbConn) -> EmptyResult {
    User::update_all_revisions(&conn)
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

#[post("/config/backup_db")]
fn backup_db(_token: AdminToken) -> EmptyResult {
    if *CAN_BACKUP {
        backup_database()
    } else {
        err!("Can't back up current DB (either it's not SQLite or the 'sqlite' binary is not present)");
    }
}

pub struct AdminToken {}

impl<'a, 'r> FromRequest<'a, 'r> for AdminToken {
    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        if CONFIG.disable_admin_token() {
            Outcome::Success(AdminToken {})
        } else {
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
}
