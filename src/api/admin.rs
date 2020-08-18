use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::process::Command;

use rocket::{
    http::{Cookie, Cookies, SameSite},
    request::{self, FlashMessage, Form, FromRequest, Outcome, Request},
    response::{content::Html, Flash, Redirect},
    Route,
};
use rocket_contrib::json::Json;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult},
    auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp},
    config::ConfigBuilder,
    db::{backup_database, models::*, DbConn, DbConnType},
    error::{Error, MapResult},
    mail,
    util::get_display_size,
    CONFIG,
};

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

static CAN_BACKUP: Lazy<bool> = Lazy::new(|| {
    DbConnType::from_url(&CONFIG.database_url())
        .map(|t| t == DbConnType::sqlite)
        .unwrap_or(false)
        && Command::new("sqlite3").arg("-version").status().is_ok()
});

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

struct Referer(Option<String>);

impl<'a, 'r> FromRequest<'a, 'r> for Referer {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(Referer(request.headers().get_one("Referer").map(str::to_string)))
    }
}

/// Used for `Location` response headers, which must specify an absolute URI
/// (see https://tools.ietf.org/html/rfc2616#section-14.30).
fn admin_url(referer: Referer) -> String {
    // If we get a referer use that to make it work when, DOMAIN is not set
    if let Some(mut referer) = referer.0 {
        if let Some(start_index) = referer.find(ADMIN_PATH) {
            referer.truncate(start_index + ADMIN_PATH.len());
            return referer;
        }
    }

    if CONFIG.domain_set() {
        // Don't use CONFIG.domain() directly, since the user may want to keep a
        // trailing slash there, particularly when running under a subpath.
        format!("{}{}{}", CONFIG.domain_origin(), CONFIG.domain_path(), ADMIN_PATH)
    } else {
        // Last case, when no referer or domain set, technically invalid but better than nothing
        ADMIN_PATH.to_string()
    }
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
fn post_admin_login(
    data: Form<LoginForm>,
    mut cookies: Cookies,
    ip: ClientIp,
    referer: Referer,
) -> Result<Redirect, Flash<Redirect>> {
    let data = data.into_inner();

    // If the token is invalid, redirect to login page
    if !_validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        Err(Flash::error(
            Redirect::to(admin_url(referer)),
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
        Ok(Redirect::to(admin_url(referer)))
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
fn logout(mut cookies: Cookies, referer: Referer) -> Result<Redirect, ()> {
    cookies.remove(Cookie::named(COOKIE_NAME));
    Ok(Redirect::to(admin_url(referer)))
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
            usr["cipher_count"] = json!(Cipher::count_owned_by_user(&u.uuid, &conn));
            usr["attachment_count"] = json!(Attachment::count_by_user(&u.uuid, &conn));
            usr["attachment_size"] = json!(get_display_size(Attachment::size_by_user(&u.uuid, &conn) as i32));
            usr
    }).collect();

    let text = AdminTemplateData::users(users_json).render()?;
    Ok(Html(text))
}

#[post("/users/<uuid>/delete")]
fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let user = User::find_by_uuid(&uuid, &conn).map_res("User doesn't exist")?;
    user.delete(&conn)
}

#[post("/users/<uuid>/deauth")]
fn deauth_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = User::find_by_uuid(&uuid, &conn).map_res("User doesn't exist")?;
    Device::delete_all_by_user(&user.uuid, &conn)?;
    user.reset_security_stamp();

    user.save(&conn)
}

#[post("/users/<uuid>/remove-2fa")]
fn remove_2fa(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = User::find_by_uuid(&uuid, &conn).map_res("User doesn't exist")?;
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
    let organizations_json: Vec<Value> = organizations.iter().map(|o| {
            let mut org = o.to_json();
            org["user_count"] = json!(UserOrganization::count_by_org(&o.uuid, &conn));
            org["cipher_count"] = json!(Cipher::count_by_org(&o.uuid, &conn));
            org["attachment_count"] = json!(Attachment::count_by_org(&o.uuid, &conn));
            org["attachment_size"] = json!(get_display_size(Attachment::size_by_org(&o.uuid, &conn) as i32));
            org
    }).collect();

    let text = AdminTemplateData::organizations(organizations_json).render()?;
    Ok(Html(text))
}

#[derive(Deserialize)]
struct WebVaultVersion {
    version: String,
}

#[derive(Deserialize)]
struct GitRelease {
    tag_name: String,
}

#[derive(Deserialize)]
struct GitCommit {
    sha: String,
}

fn get_github_api<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    use reqwest::{blocking::Client, header::USER_AGENT};
    use std::time::Duration;
    let github_api = Client::builder().build()?;

    Ok(
        github_api.get(url)
        .timeout(Duration::from_secs(10))
        .header(USER_AGENT, "Bitwarden_RS")
        .send()?
        .error_for_status()?
        .json::<T>()?
    )
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
    let (dns_resolved, dns_ok) = match github_ips {
        Ok(Some(a)) => (a.ip().to_string(), true),
        _ => ("Could not resolve domain name.".to_string(), false),
    };

    // If the DNS Check failed, do not even attempt to check for new versions since we were not able to resolve github.com
    let (latest_release, latest_commit, latest_web_build) = if dns_ok {
        (
            match get_github_api::<GitRelease>("https://api.github.com/repos/dani-garcia/bitwarden_rs/releases/latest") {
                Ok(r) => r.tag_name,
                _ => "-".to_string()
            },
            match get_github_api::<GitCommit>("https://api.github.com/repos/dani-garcia/bitwarden_rs/commits/master") {
                Ok(mut c) => {
                    c.sha.truncate(8);
                    c.sha
            },
                _ => "-".to_string()
            },
            match get_github_api::<GitRelease>("https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest") {
                Ok(r) => r.tag_name.trim_start_matches('v').to_string(),
                _ => "-".to_string()
            },
        )
    } else {
        ("-".to_string(), "-".to_string(), "-".to_string())
    };

    // Run the date check as the last item right before filling the json.
    // This should ensure that the time difference between the browser and the server is as minimal as possible.
    let dt = Utc::now();
    let server_time = dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let diagnostics_json = json!({
        "dns_resolved": dns_resolved,
        "server_time": server_time,
        "web_vault_version": web_vault_version.version,
        "latest_release": latest_release,
        "latest_commit": latest_commit,
        "latest_web_build": latest_web_build,
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
