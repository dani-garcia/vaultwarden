use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::env;

use rocket::{
    http::{Cookie, Cookies, SameSite, Status},
    request::{self, FlashMessage, Form, FromRequest, Outcome, Request},
    response::{content::Html, Flash, Redirect},
    Route,
};
use rocket_contrib::json::Json;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, NumberOrString},
    auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp},
    config::ConfigBuilder,
    db::{backup_database, get_sql_server_version, models::*, DbConn, DbConnType},
    error::{Error, MapResult},
    mail,
    util::{
        docker_base_image, format_naive_datetime_local, get_display_size, get_reqwest_client, is_running_in_docker,
    },
    CONFIG, VERSION,
};

pub fn routes() -> Vec<Route> {
    if !CONFIG.disable_admin_token() && !CONFIG.is_admin_token_set() {
        return routes![admin_disabled];
    }

    routes![
        admin_login,
        get_users_json,
        get_user_json,
        post_admin_login,
        admin_page,
        invite_user,
        logout,
        delete_user,
        deauth_user,
        disable_user,
        enable_user,
        remove_2fa,
        update_user_org_type,
        update_revision_users,
        post_config,
        delete_config,
        backup_db,
        test_smtp,
        users_overview,
        organizations_overview,
        delete_organization,
        diagnostics,
        get_diagnostics_config
    ]
}

static DB_TYPE: Lazy<&str> = Lazy::new(|| {
    DbConnType::from_url(&CONFIG.database_url())
        .map(|t| match t {
            DbConnType::sqlite => "SQLite",
            DbConnType::mysql => "MySQL",
            DbConnType::postgresql => "PostgreSQL",
        })
        .unwrap_or("Unknown")
});

static CAN_BACKUP: Lazy<bool> =
    Lazy::new(|| DbConnType::from_url(&CONFIG.database_url()).map(|t| t == DbConnType::sqlite).unwrap_or(false));

#[get("/")]
fn admin_disabled() -> &'static str {
    "The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it"
}

const COOKIE_NAME: &str = "VW_ADMIN";
const ADMIN_PATH: &str = "/admin";

const BASE_TEMPLATE: &str = "admin/base";

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

#[derive(Debug)]
struct IpHeader(Option<String>);

impl<'a, 'r> FromRequest<'a, 'r> for IpHeader {
    type Error = ();

    fn from_request(req: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        if req.headers().get_one(&CONFIG.ip_header()).is_some() {
            Outcome::Success(IpHeader(Some(CONFIG.ip_header())))
        } else if req.headers().get_one("X-Client-IP").is_some() {
            Outcome::Success(IpHeader(Some(String::from("X-Client-IP"))))
        } else if req.headers().get_one("X-Real-IP").is_some() {
            Outcome::Success(IpHeader(Some(String::from("X-Real-IP"))))
        } else if req.headers().get_one("X-Forwarded-For").is_some() {
            Outcome::Success(IpHeader(Some(String::from("X-Forwarded-For"))))
        } else {
            Outcome::Success(IpHeader(None))
        }
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
    let json = json!({
        "page_content": "admin/login",
        "version": VERSION,
        "error": msg,
        "urlpath": CONFIG.domain_path()
    });

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

    if crate::ratelimit::check_limit_admin(&ip.ip).is_err() {
        return Err(Flash::error(Redirect::to(admin_url(referer)), "Too many requests, try again later."));
    }

    // If the token is invalid, redirect to login page
    if !_validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        Err(Flash::error(Redirect::to(admin_url(referer)), "Invalid admin token, please try again."))
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
    page_data: Option<Value>,
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
            page_data: None,
        }
    }

    fn with_data(page_content: &str, page_data: Value) -> Self {
        Self {
            page_content: String::from(page_content),
            version: VERSION,
            page_data: Some(page_data),
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
fn admin_page(_token: AdminToken) -> ApiResult<Html<String>> {
    let text = AdminTemplateData::new().render()?;
    Ok(Html(text))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    email: String,
}

fn get_user_or_404(uuid: &str, conn: &DbConn) -> ApiResult<User> {
    if let Some(user) = User::find_by_uuid(uuid, conn) {
        Ok(user)
    } else {
        err_code!("User doesn't exist", Status::NotFound.code);
    }
}

#[post("/invite", data = "<data>")]
fn invite_user(data: Json<InviteData>, _token: AdminToken, conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    let email = data.email.clone();
    if User::find_by_mail(&data.email, &conn).is_some() {
        err_code!("User already exists", Status::Conflict.code)
    }

    let mut user = User::new(email);

    // TODO: After try_blocks is stabilized, this can be made more readable
    // See: https://github.com/rust-lang/rust/issues/31436
    (|| {
        if CONFIG.mail_enabled() {
            mail::send_invite(&user.email, &user.uuid, None, None, &CONFIG.invitation_org_name(), None)?;
        } else {
            let invitation = Invitation::new(user.email.clone());
            invitation.save(&conn)?;
        }

        user.save(&conn)
    })()
    .map_err(|e| e.with_code(Status::InternalServerError.code))?;

    Ok(Json(user.to_json(&conn)))
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
fn logout(mut cookies: Cookies, referer: Referer) -> Redirect {
    cookies.remove(Cookie::named(COOKIE_NAME));
    Redirect::to(admin_url(referer))
}

#[get("/users")]
fn get_users_json(_token: AdminToken, conn: DbConn) -> Json<Value> {
    let users = User::get_all(&conn);
    let users_json: Vec<Value> = users.iter().map(|u| u.to_json(&conn)).collect();

    Json(Value::Array(users_json))
}

#[get("/users/overview")]
fn users_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let users = User::get_all(&conn);
    let dt_fmt = "%Y-%m-%d %H:%M:%S %Z";
    let users_json: Vec<Value> = users
        .iter()
        .map(|u| {
            let mut usr = u.to_json(&conn);
            usr["cipher_count"] = json!(Cipher::count_owned_by_user(&u.uuid, &conn));
            usr["attachment_count"] = json!(Attachment::count_by_user(&u.uuid, &conn));
            usr["attachment_size"] = json!(get_display_size(Attachment::size_by_user(&u.uuid, &conn) as i32));
            usr["user_enabled"] = json!(u.enabled);
            usr["created_at"] = json!(format_naive_datetime_local(&u.created_at, dt_fmt));
            usr["last_active"] = match u.last_active(&conn) {
                Some(dt) => json!(format_naive_datetime_local(&dt, dt_fmt)),
                None => json!("Never"),
            };
            usr
        })
        .collect();

    let text = AdminTemplateData::with_data("admin/users", json!(users_json)).render()?;
    Ok(Html(text))
}

#[get("/users/<uuid>")]
fn get_user_json(uuid: String, _token: AdminToken, conn: DbConn) -> JsonResult {
    let user = get_user_or_404(&uuid, &conn)?;

    Ok(Json(user.to_json(&conn)))
}

#[post("/users/<uuid>/delete")]
fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let user = get_user_or_404(&uuid, &conn)?;
    user.delete(&conn)
}

#[post("/users/<uuid>/deauth")]
fn deauth_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn)?;
    Device::delete_all_by_user(&user.uuid, &conn)?;
    user.reset_security_stamp();

    user.save(&conn)
}

#[post("/users/<uuid>/disable")]
fn disable_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn)?;
    Device::delete_all_by_user(&user.uuid, &conn)?;
    user.reset_security_stamp();
    user.enabled = false;

    user.save(&conn)
}

#[post("/users/<uuid>/enable")]
fn enable_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn)?;
    user.enabled = true;

    user.save(&conn)
}

#[post("/users/<uuid>/remove-2fa")]
fn remove_2fa(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn)?;
    TwoFactor::delete_all_by_user(&user.uuid, &conn)?;
    user.totp_recover = None;
    user.save(&conn)
}

#[derive(Deserialize, Debug)]
struct UserOrgTypeData {
    user_type: NumberOrString,
    user_uuid: String,
    org_uuid: String,
}

#[post("/users/org_type", data = "<data>")]
fn update_user_org_type(data: Json<UserOrgTypeData>, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let data: UserOrgTypeData = data.into_inner();

    let mut user_to_edit = match UserOrganization::find_by_user_and_org(&data.user_uuid, &data.org_uuid, &conn) {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    let new_type = match UserOrgType::from_str(&data.user_type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permmission, check that there are at least another owner
        let num_owners = UserOrganization::find_by_org_and_type(&data.org_uuid, UserOrgType::Owner as i32, &conn).len();

        if num_owners <= 1 {
            err!("Can't change the type of the last owner")
        }
    }

    user_to_edit.atype = new_type as i32;
    user_to_edit.save(&conn)
}

#[post("/users/update_revision")]
fn update_revision_users(_token: AdminToken, conn: DbConn) -> EmptyResult {
    User::update_all_revisions(&conn)
}

#[get("/organizations/overview")]
fn organizations_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let organizations = Organization::get_all(&conn);
    let organizations_json: Vec<Value> = organizations
        .iter()
        .map(|o| {
            let mut org = o.to_json();
            org["user_count"] = json!(UserOrganization::count_by_org(&o.uuid, &conn));
            org["cipher_count"] = json!(Cipher::count_by_org(&o.uuid, &conn));
            org["attachment_count"] = json!(Attachment::count_by_org(&o.uuid, &conn));
            org["attachment_size"] = json!(get_display_size(Attachment::size_by_org(&o.uuid, &conn) as i32));
            org
        })
        .collect();

    let text = AdminTemplateData::with_data("admin/organizations", json!(organizations_json)).render()?;
    Ok(Html(text))
}

#[post("/organizations/<uuid>/delete")]
fn delete_organization(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let org = Organization::find_by_uuid(&uuid, &conn).map_res("Organization doesn't exist")?;
    org.delete(&conn)
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
    let github_api = get_reqwest_client();

    Ok(github_api.get(url).send()?.error_for_status()?.json::<T>()?)
}

fn has_http_access() -> bool {
    let http_access = get_reqwest_client();

    match http_access.head("https://github.com/dani-garcia/vaultwarden").send() {
        Ok(r) => r.status().is_success(),
        _ => false,
    }
}

#[get("/diagnostics")]
fn diagnostics(_token: AdminToken, ip_header: IpHeader, conn: DbConn) -> ApiResult<Html<String>> {
    use crate::util::read_file_string;
    use chrono::prelude::*;
    use std::net::ToSocketAddrs;

    // Get current running versions
    let web_vault_version: WebVaultVersion =
        match read_file_string(&format!("{}/{}", CONFIG.web_vault_folder(), "vw-version.json")) {
            Ok(s) => serde_json::from_str(&s)?,
            _ => match read_file_string(&format!("{}/{}", CONFIG.web_vault_folder(), "version.json")) {
                Ok(s) => serde_json::from_str(&s)?,
                _ => WebVaultVersion {
                    version: String::from("Version file missing"),
                },
            },
        };

    // Execute some environment checks
    let running_within_docker = is_running_in_docker();
    let has_http_access = has_http_access();
    let uses_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();

    // Check if we are able to resolve DNS entries
    let dns_resolved = match ("github.com", 0).to_socket_addrs().map(|mut i| i.next()) {
        Ok(Some(a)) => a.ip().to_string(),
        _ => "Could not resolve domain name.".to_string(),
    };

    // If the HTTP Check failed, do not even attempt to check for new versions since we were not able to connect with github.com anyway.
    // TODO: Maybe we need to cache this using a LazyStatic or something. Github only allows 60 requests per hour, and we use 3 here already.
    let (latest_release, latest_commit, latest_web_build) = if has_http_access {
        (
            match get_github_api::<GitRelease>("https://api.github.com/repos/dani-garcia/vaultwarden/releases/latest") {
                Ok(r) => r.tag_name,
                _ => "-".to_string(),
            },
            match get_github_api::<GitCommit>("https://api.github.com/repos/dani-garcia/vaultwarden/commits/main") {
                Ok(mut c) => {
                    c.sha.truncate(8);
                    c.sha
                }
                _ => "-".to_string(),
            },
            // Do not fetch the web-vault version when running within Docker.
            // The web-vault version is embedded within the container it self, and should not be updated manually
            if running_within_docker {
                "-".to_string()
            } else {
                match get_github_api::<GitRelease>(
                    "https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest",
                ) {
                    Ok(r) => r.tag_name.trim_start_matches('v').to_string(),
                    _ => "-".to_string(),
                }
            },
        )
    } else {
        ("-".to_string(), "-".to_string(), "-".to_string())
    };

    let ip_header_name = match &ip_header.0 {
        Some(h) => h,
        _ => "",
    };

    let diagnostics_json = json!({
        "dns_resolved": dns_resolved,
        "latest_release": latest_release,
        "latest_commit": latest_commit,
        "web_vault_enabled": &CONFIG.web_vault_enabled(),
        "web_vault_version": web_vault_version.version,
        "latest_web_build": latest_web_build,
        "running_within_docker": running_within_docker,
        "docker_base_image": docker_base_image(),
        "has_http_access": has_http_access,
        "ip_header_exists": &ip_header.0.is_some(),
        "ip_header_match": ip_header_name == CONFIG.ip_header(),
        "ip_header_name": ip_header_name,
        "ip_header_config": &CONFIG.ip_header(),
        "uses_proxy": uses_proxy,
        "db_type": *DB_TYPE,
        "db_version": get_sql_server_version(&conn),
        "admin_url": format!("{}/diagnostics", admin_url(Referer(None))),
        "overrides": &CONFIG.get_overrides().join(", "),
        "server_time_local": Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        "server_time": Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(), // Run the date/time check as the last item to minimize the difference
    });

    let text = AdminTemplateData::with_data("admin/diagnostics", diagnostics_json).render()?;
    Ok(Html(text))
}

#[get("/diagnostics/config")]
fn get_diagnostics_config(_token: AdminToken) -> Json<Value> {
    let support_json = CONFIG.get_support_json();
    Json(support_json)
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
fn backup_db(_token: AdminToken, conn: DbConn) -> EmptyResult {
    if *CAN_BACKUP {
        backup_database(&conn)
    } else {
        err!("Can't back up current DB (Only SQLite supports this feature)");
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
