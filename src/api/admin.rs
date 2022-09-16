use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::env;

use rocket::serde::json::Json;
use rocket::{
    form::Form,
    http::{Cookie, CookieJar, SameSite, Status},
    request::{self, FromRequest, Outcome, Request},
    response::{content::RawHtml as Html, Redirect},
    Route,
};

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

use futures::{stream, stream::StreamExt};

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
const DT_FMT: &str = "%Y-%m-%d %H:%M:%S %Z";

const BASE_TEMPLATE: &str = "admin/base";

fn admin_path() -> String {
    format!("{}{}", CONFIG.domain_path(), ADMIN_PATH)
}

struct Referer(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Referer {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(Referer(request.headers().get_one("Referer").map(str::to_string)))
    }
}

#[derive(Debug)]
struct IpHeader(Option<String>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IpHeader {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
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

#[derive(Responder)]
enum AdminResponse {
    #[response(status = 200)]
    Ok(ApiResult<Html<String>>),
    #[response(status = 401)]
    Unauthorized(ApiResult<Html<String>>),
    #[response(status = 429)]
    TooManyRequests(ApiResult<Html<String>>),
}

#[get("/", rank = 2)]
fn admin_login() -> ApiResult<Html<String>> {
    render_admin_login(None)
}

fn render_admin_login(msg: Option<&str>) -> ApiResult<Html<String>> {
    // If there is an error, show it
    let msg = msg.map(|msg| format!("Error: {msg}"));
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
fn post_admin_login(data: Form<LoginForm>, cookies: &CookieJar<'_>, ip: ClientIp) -> AdminResponse {
    let data = data.into_inner();

    if crate::ratelimit::check_limit_admin(&ip.ip).is_err() {
        return AdminResponse::TooManyRequests(render_admin_login(Some("Too many requests, try again later.")));
    }

    // If the token is invalid, redirect to login page
    if !_validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        AdminResponse::Unauthorized(render_admin_login(Some("Invalid admin token, please try again.")))
    } else {
        // If the token received is valid, generate JWT and save it as a cookie
        let claims = generate_admin_claims();
        let jwt = encode_jwt(&claims);

        let cookie = Cookie::build(COOKIE_NAME, jwt)
            .path(admin_path())
            .max_age(rocket::time::Duration::minutes(20))
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish();

        cookies.add(cookie);
        AdminResponse::Ok(render_admin_page())
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

fn render_admin_page() -> ApiResult<Html<String>> {
    let text = AdminTemplateData::new().render()?;
    Ok(Html(text))
}

#[get("/", rank = 1)]
fn admin_page(_token: AdminToken) -> ApiResult<Html<String>> {
    render_admin_page()
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    email: String,
}

async fn get_user_or_404(uuid: &str, conn: &DbConn) -> ApiResult<User> {
    if let Some(user) = User::find_by_uuid(uuid, conn).await {
        Ok(user)
    } else {
        err_code!("User doesn't exist", Status::NotFound.code);
    }
}

#[post("/invite", data = "<data>")]
async fn invite_user(data: Json<InviteData>, _token: AdminToken, conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    let email = data.email.clone();
    if User::find_by_mail(&data.email, &conn).await.is_some() {
        err_code!("User already exists", Status::Conflict.code)
    }

    let mut user = User::new(email);

    async fn _generate_invite(user: &User, conn: &DbConn) -> EmptyResult {
        if CONFIG.mail_enabled() {
            mail::send_invite(&user.email, &user.uuid, None, None, &CONFIG.invitation_org_name(), None).await
        } else {
            let invitation = Invitation::new(user.email.clone());
            invitation.save(conn).await
        }
    }

    _generate_invite(&user, &conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;
    user.save(&conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;

    Ok(Json(user.to_json(&conn).await))
}

#[post("/test/smtp", data = "<data>")]
async fn test_smtp(data: Json<InviteData>, _token: AdminToken) -> EmptyResult {
    let data: InviteData = data.into_inner();

    if CONFIG.mail_enabled() {
        mail::send_test(&data.email).await
    } else {
        err!("Mail is not enabled")
    }
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>, referer: Referer) -> Redirect {
    cookies.remove(Cookie::build(COOKIE_NAME, "").path(admin_path()).finish());
    Redirect::temporary(admin_url(referer))
}

#[get("/users")]
async fn get_users_json(_token: AdminToken, conn: DbConn) -> Json<Value> {
    let users_json = stream::iter(User::get_all(&conn).await)
        .then(|u| async {
            let u = u; // Move out this single variable
            let mut usr = u.to_json(&conn).await;
            usr["UserEnabled"] = json!(u.enabled);
            usr["CreatedAt"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
            usr
        })
        .collect::<Vec<Value>>()
        .await;

    Json(Value::Array(users_json))
}

#[get("/users/overview")]
async fn users_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let users_json = stream::iter(User::get_all(&conn).await)
        .then(|u| async {
            let u = u; // Move out this single variable
            let mut usr = u.to_json(&conn).await;
            usr["cipher_count"] = json!(Cipher::count_owned_by_user(&u.uuid, &conn).await);
            usr["attachment_count"] = json!(Attachment::count_by_user(&u.uuid, &conn).await);
            usr["attachment_size"] = json!(get_display_size(Attachment::size_by_user(&u.uuid, &conn).await as i32));
            usr["user_enabled"] = json!(u.enabled);
            usr["created_at"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
            usr["last_active"] = match u.last_active(&conn).await {
                Some(dt) => json!(format_naive_datetime_local(&dt, DT_FMT)),
                None => json!("Never"),
            };
            usr
        })
        .collect::<Vec<Value>>()
        .await;

    let text = AdminTemplateData::with_data("admin/users", json!(users_json)).render()?;
    Ok(Html(text))
}

#[get("/users/<uuid>")]
async fn get_user_json(uuid: String, _token: AdminToken, conn: DbConn) -> JsonResult {
    let u = get_user_or_404(&uuid, &conn).await?;
    let mut usr = u.to_json(&conn).await;
    usr["UserEnabled"] = json!(u.enabled);
    usr["CreatedAt"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
    Ok(Json(usr))
}

#[post("/users/<uuid>/delete")]
async fn delete_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let user = get_user_or_404(&uuid, &conn).await?;
    user.delete(&conn).await
}

#[post("/users/<uuid>/deauth")]
async fn deauth_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn).await?;
    Device::delete_all_by_user(&user.uuid, &conn).await?;
    user.reset_security_stamp();

    user.save(&conn).await
}

#[post("/users/<uuid>/disable")]
async fn disable_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn).await?;
    Device::delete_all_by_user(&user.uuid, &conn).await?;
    user.reset_security_stamp();
    user.enabled = false;

    user.save(&conn).await
}

#[post("/users/<uuid>/enable")]
async fn enable_user(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn).await?;
    user.enabled = true;

    user.save(&conn).await
}

#[post("/users/<uuid>/remove-2fa")]
async fn remove_2fa(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(&uuid, &conn).await?;
    TwoFactor::delete_all_by_user(&user.uuid, &conn).await?;
    user.totp_recover = None;
    user.save(&conn).await
}

#[derive(Deserialize, Debug)]
struct UserOrgTypeData {
    user_type: NumberOrString,
    user_uuid: String,
    org_uuid: String,
}

#[post("/users/org_type", data = "<data>")]
async fn update_user_org_type(data: Json<UserOrgTypeData>, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let data: UserOrgTypeData = data.into_inner();

    let mut user_to_edit = match UserOrganization::find_by_user_and_org(&data.user_uuid, &data.org_uuid, &conn).await {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    let new_type = match UserOrgType::from_str(&data.user_type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permmission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&data.org_uuid, UserOrgType::Owner, &conn).await <= 1 {
            err!("Can't change the type of the last owner")
        }
    }

    // This check is also done at api::organizations::{accept_invite(), _confirm_invite, _activate_user(), edit_user()}, update_user_org_type
    // It returns different error messages per function.
    if new_type < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_edit.user_uuid, &user_to_edit.org_uuid, true, &conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot modify this user to this type because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because it is a member of an organization which forbids it");
            }
        }
    }

    user_to_edit.atype = new_type;
    user_to_edit.save(&conn).await
}

#[post("/users/update_revision")]
async fn update_revision_users(_token: AdminToken, conn: DbConn) -> EmptyResult {
    User::update_all_revisions(&conn).await
}

#[get("/organizations/overview")]
async fn organizations_overview(_token: AdminToken, conn: DbConn) -> ApiResult<Html<String>> {
    let organizations_json = stream::iter(Organization::get_all(&conn).await)
        .then(|o| async {
            let o = o; //Move out this single variable
            let mut org = o.to_json();
            org["user_count"] = json!(UserOrganization::count_by_org(&o.uuid, &conn).await);
            org["cipher_count"] = json!(Cipher::count_by_org(&o.uuid, &conn).await);
            org["attachment_count"] = json!(Attachment::count_by_org(&o.uuid, &conn).await);
            org["attachment_size"] = json!(get_display_size(Attachment::size_by_org(&o.uuid, &conn).await as i32));
            org
        })
        .collect::<Vec<Value>>()
        .await;

    let text = AdminTemplateData::with_data("admin/organizations", json!(organizations_json)).render()?;
    Ok(Html(text))
}

#[post("/organizations/<uuid>/delete")]
async fn delete_organization(uuid: String, _token: AdminToken, conn: DbConn) -> EmptyResult {
    let org = Organization::find_by_uuid(&uuid, &conn).await.map_res("Organization doesn't exist")?;
    org.delete(&conn).await
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

async fn get_github_api<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let github_api = get_reqwest_client();

    Ok(github_api.get(url).send().await?.error_for_status()?.json::<T>().await?)
}

async fn has_http_access() -> bool {
    let http_access = get_reqwest_client();

    match http_access.head("https://github.com/dani-garcia/vaultwarden").send().await {
        Ok(r) => r.status().is_success(),
        _ => false,
    }
}

use cached::proc_macro::cached;
/// Cache this function to prevent API call rate limit. Github only allows 60 requests per hour, and we use 3 here already.
/// It will cache this function for 300 seconds (5 minutes) which should prevent the exhaustion of the rate limit.
#[cached(time = 300, sync_writes = true)]
async fn get_release_info(has_http_access: bool, running_within_docker: bool) -> (String, String, String) {
    // If the HTTP Check failed, do not even attempt to check for new versions since we were not able to connect with github.com anyway.
    if has_http_access {
        (
            match get_github_api::<GitRelease>("https://api.github.com/repos/dani-garcia/vaultwarden/releases/latest")
                .await
            {
                Ok(r) => r.tag_name,
                _ => "-".to_string(),
            },
            match get_github_api::<GitCommit>("https://api.github.com/repos/dani-garcia/vaultwarden/commits/main").await
            {
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
                )
                .await
                {
                    Ok(r) => r.tag_name.trim_start_matches('v').to_string(),
                    _ => "-".to_string(),
                }
            },
        )
    } else {
        ("-".to_string(), "-".to_string(), "-".to_string())
    }
}

#[get("/diagnostics")]
async fn diagnostics(_token: AdminToken, ip_header: IpHeader, conn: DbConn) -> ApiResult<Html<String>> {
    use chrono::prelude::*;
    use std::net::ToSocketAddrs;

    // Get current running versions
    let web_vault_version: WebVaultVersion =
        match std::fs::read_to_string(&format!("{}/{}", CONFIG.web_vault_folder(), "vw-version.json")) {
            Ok(s) => serde_json::from_str(&s)?,
            _ => match std::fs::read_to_string(&format!("{}/{}", CONFIG.web_vault_folder(), "version.json")) {
                Ok(s) => serde_json::from_str(&s)?,
                _ => WebVaultVersion {
                    version: String::from("Version file missing"),
                },
            },
        };

    // Execute some environment checks
    let running_within_docker = is_running_in_docker();
    let has_http_access = has_http_access().await;
    let uses_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();

    // Check if we are able to resolve DNS entries
    let dns_resolved = match ("github.com", 0).to_socket_addrs().map(|mut i| i.next()) {
        Ok(Some(a)) => a.ip().to_string(),
        _ => "Could not resolve domain name.".to_string(),
    };

    let (latest_release, latest_commit, latest_web_build) =
        get_release_info(has_http_access, running_within_docker).await;

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
        "db_version": get_sql_server_version(&conn).await,
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
async fn backup_db(_token: AdminToken, conn: DbConn) -> EmptyResult {
    if *CAN_BACKUP {
        backup_database(&conn).await
    } else {
        err!("Can't back up current DB (Only SQLite supports this feature)");
    }
}

pub struct AdminToken {}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if CONFIG.disable_admin_token() {
            Outcome::Success(AdminToken {})
        } else {
            let cookies = request.cookies();

            let access_token = match cookies.get(COOKIE_NAME) {
                Some(cookie) => cookie.value(),
                None => return Outcome::Forward(()), // If there is no cookie, redirect to login
            };

            let ip = match ClientIp::from_request(request).await {
                Outcome::Success(ip) => ip.ip,
                _ => err_handler!("Error getting Client IP"),
            };

            if decode_admin(access_token).is_err() {
                // Remove admin cookie
                cookies.remove(Cookie::build(COOKIE_NAME, "").path(admin_path()).finish());
                error!("Invalid or expired admin JWT. IP: {}.", ip);
                return Outcome::Forward(());
            }

            Outcome::Success(AdminToken {})
        }
    }
}
