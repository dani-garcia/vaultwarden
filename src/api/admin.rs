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
        get_users_json,
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
        users_overview,
        organizations_overview,
        diagnostics,
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

/// Used for `Location` response headers, which must specify an absolute URI
/// (see https://tools.ietf.org/html/rfc2616#section-14.30).
fn admin_url() -> String {
    // Don't use CONFIG.domain() directly, since the user may want to keep a
    // trailing slash there, particularly when running under a subpath.
    format!("{}{}{}", CONFIG.domain_origin(), CONFIG.domain_path(), ADMIN_PATH)
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
            Redirect::to(admin_url()),
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
        Ok(Redirect::to(admin_url()))
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
    users: Option<Vec<Value>>,
    organizations: Option<Vec<Value>>,
    diagnostics: Option<Value>,
    config: Value,
    can_backup: bool,
    logged_in: bool,
    urlpath: String,
}

impl AdminTemplateData {
    fn new() -> Self {
        Self {
            page_content: String::from("admin/settings"),
            version: VERSION,
            config: CONFIG.prepare_json(),
            can_backup: *CAN_BACKUP,
            logged_in: true,
            urlpath: CONFIG.domain_path(),
            users: None,
            organizations: None,
            diagnostics: None,
        }
    }

    fn users(users: Vec<Value>) -> Self {
        Self {
            page_content: String::from("admin/users"),
            version: VERSION,
            users: Some(users),
            config: CONFIG.prepare_json(),
            can_backup: *CAN_BACKUP,
            logged_in: true,
            urlpath: CONFIG.domain_path(),
            organizations: None,
            diagnostics: None,
        }
    }

    fn organizations(organizations: Vec<Value>) -> Self {
        Self {
            page_content: String::from("admin/organizations"),
            version: VERSION,
            organizations: Some(organizations),
            config: CONFIG.prepare_json(),
            can_backup: *CAN_BACKUP,
            logged_in: true,
            urlpath: CONFIG.domain_path(),
            users: None,
            diagnostics: None,
        }
    }

    fn diagnostics(diagnostics: Value) -> Self {
        Self {
            page_content: String::from("admin/diagnostics"),
            version: VERSION,
            organizations: None,
            config: CONFIG.prepare_json(),
            can_backup: *CAN_BACKUP,
            logged_in: true,
            urlpath: CONFIG.domain_path(),
            users: None,
            diagnostics: Some(diagnostics),
        }
    }

    fn render(self) -> Result<String, Error> {
        CONFIG.render_template(BASE_TEMPLATE, &self)
    }
}

#[get("/", rank = 1)]
fn admin_page(_token: AdminToken, _conn: DbConn) -> ApiResult<Html<String>> {
    let text = AdminTemplateData::new().render()?;
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
    Ok(Redirect::to(admin_url()))
}

#[get("/users")]
fn get_users_json(_token: AdminToken, conn: DbConn) -> JsonResult {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    Ok(Json(Value::Array(users_json)))
}

#[get("/users/overview")]
fn users_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter()
    .map(|u| {
        let mut usr = u.to_json(&conn);
        if let Some(ciphers) = Cipher::count_owned_by_user(&u.uuid, &conn) {
            usr["cipher_count"] = json!(ciphers);
        };
        usr
    }).collect();

    let text = AdminTemplateData::users(users_json).render()?;
    Ok(Html(text))
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

#[get("/organizations/overview")]
fn organizations_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let organizations = Organization::get_all(&conn);
    let organizations_json: Vec<Value> = organizations.iter().map(|o| o.to_json()).collect();

    let text = AdminTemplateData::organizations(organizations_json).render()?;
    Ok(Html(text))
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(non_snake_case)]
pub struct WebVaultVersion {
    version: String,
}

fn get_github_api(url: &str) -> Result<Value, Error> {
    use reqwest::{header::USER_AGENT, blocking::Client};
    let github_api = Client::builder().build()?;

    let res = github_api
        .get(url)
        .header(USER_AGENT, "Bitwarden_RS")
        .send()?;

    let res_status = res.status();
    if res_status != 200 {
        error!("Could not retrieve '{}', response code: {}", url, res_status);
    }

    let value: Value = res.error_for_status()?.json()?;
    Ok(value)
}

#[get("/diagnostics")]
fn diagnostics(_token: AdminToken, _conn: DbConn) -> ApiResult<Html<String>> {
    use std::net::ToSocketAddrs;
    use chrono::prelude::*;
    use crate::util::read_file_string;

    let vault_version_path = format!("{}/{}", CONFIG.web_vault_folder(), "version.json");
    let vault_version_str = read_file_string(&vault_version_path)?;
    let web_vault_version: WebVaultVersion = serde_json::from_str(&vault_version_str)?;

    let github_ips = ("github.com", 0).to_socket_addrs().map(|mut i| i.next());
    let dns_resolved = match github_ips {
        Ok(Some(a)) => a.ip().to_string(),
        _ => "Could not resolve domain name.".to_string(),
    };

    let bitwarden_rs_releases = get_github_api("https://api.github.com/repos/dani-garcia/bitwarden_rs/releases/latest");
    let latest_release = match &bitwarden_rs_releases {
        Ok(j) => j["tag_name"].as_str().unwrap(),
        _ => "-",
    };

    let bitwarden_rs_commits = get_github_api("https://api.github.com/repos/dani-garcia/bitwarden_rs/commits/master");
    let mut latest_commit = match &bitwarden_rs_commits {
        Ok(j) => j["sha"].as_str().unwrap(),
        _ => "-",
    };
    if latest_commit.len() >= 8 {
        latest_commit = &latest_commit[..8];
    }

    let bw_web_builds_releases = get_github_api("https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest");
    let latest_web_build = match &bw_web_builds_releases {
        Ok(j) => j["tag_name"].as_str().unwrap(),
        _ => "-",
    };

    let dt = Utc::now();
    let server_time = dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let diagnostics_json = json!({
        "dns_resolved": dns_resolved,
        "server_time": server_time,
        "web_vault_version": web_vault_version.version,
        "latest_release": latest_release,
        "latest_commit": latest_commit,
        "latest_web_build": latest_web_build.replace("v", ""),
    });

    let text = AdminTemplateData::diagnostics(diagnostics_json).render()?;
    Ok(Html(text))
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
