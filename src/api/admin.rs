use once_cell::sync::Lazy;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::env;

use rocket::serde::json::Json;
use rocket::{
    form::Form,
    http::{Cookie, CookieJar, MediaType, SameSite, Status},
    request::{FromRequest, Outcome, Request},
    response::{content::RawHtml as Html, Redirect},
    Catcher, Route,
};

use crate::{
    api::{
        core::{log_event, two_factor},
        unregister_push_device, ApiResult, EmptyResult, JsonResult, Notify,
    },
    auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp, Secure},
    config::ConfigBuilder,
    db::{backup_database, get_sql_server_version, models::*, DbConn, DbConnType},
    error::{Error, MapResult},
    http_client::make_http_request,
    mail,
    util::{
        container_base_image, format_naive_datetime_local, get_display_size, get_web_vault_version,
        is_running_in_container, NumberOrString,
    },
    CONFIG, VERSION,
};

pub fn routes() -> Vec<Route> {
    if !CONFIG.disable_admin_token() && !CONFIG.is_admin_token_set() {
        return routes![admin_disabled];
    }

    routes![
        get_users_json,
        get_user_json,
        get_user_by_mail_json,
        post_admin_login,
        admin_page,
        admin_page_login,
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
        get_diagnostics_config,
        resend_user_invite,
        get_diagnostics_http,
    ]
}

pub fn catchers() -> Vec<Catcher> {
    if !CONFIG.disable_admin_token() && !CONFIG.is_admin_token_set() {
        catchers![]
    } else {
        catchers![admin_login]
    }
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

const ACTING_ADMIN_USER: &str = "vaultwarden-admin-00000-000000000000";

fn admin_path() -> String {
    format!("{}{}", CONFIG.domain_path(), ADMIN_PATH)
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

fn admin_url() -> String {
    format!("{}{}", CONFIG.domain_origin(), admin_path())
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

#[catch(401)]
fn admin_login(request: &Request<'_>) -> ApiResult<Html<String>> {
    if request.format() == Some(&MediaType::JSON) {
        err_code!("Authorization failed.", Status::Unauthorized.code);
    }
    let redirect = request.segments::<std::path::PathBuf>(0..).unwrap_or_default().display().to_string();
    render_admin_login(None, Some(redirect))
}

fn render_admin_login(msg: Option<&str>, redirect: Option<String>) -> ApiResult<Html<String>> {
    // If there is an error, show it
    let msg = msg.map(|msg| format!("Error: {msg}"));
    let json = json!({
        "page_content": "admin/login",
        "error": msg,
        "redirect": redirect,
        "urlpath": CONFIG.domain_path()
    });

    // Return the page
    let text = CONFIG.render_template(BASE_TEMPLATE, &json)?;
    Ok(Html(text))
}

#[derive(FromForm)]
struct LoginForm {
    token: String,
    redirect: Option<String>,
}

#[post("/", data = "<data>")]
fn post_admin_login(
    data: Form<LoginForm>,
    cookies: &CookieJar<'_>,
    ip: ClientIp,
    secure: Secure,
) -> Result<Redirect, AdminResponse> {
    let data = data.into_inner();
    let redirect = data.redirect;

    if crate::ratelimit::check_limit_admin(&ip.ip).is_err() {
        return Err(AdminResponse::TooManyRequests(render_admin_login(
            Some("Too many requests, try again later."),
            redirect,
        )));
    }

    // If the token is invalid, redirect to login page
    if !_validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        Err(AdminResponse::Unauthorized(render_admin_login(Some("Invalid admin token, please try again."), redirect)))
    } else {
        // If the token received is valid, generate JWT and save it as a cookie
        let claims = generate_admin_claims();
        let jwt = encode_jwt(&claims);

        let cookie = Cookie::build((COOKIE_NAME, jwt))
            .path(admin_path())
            .max_age(time::Duration::minutes(CONFIG.admin_session_lifetime()))
            .same_site(SameSite::Strict)
            .http_only(true)
            .secure(secure.https);

        cookies.add(cookie);
        if let Some(redirect) = redirect {
            Ok(Redirect::to(format!("{}{}", admin_path(), redirect)))
        } else {
            Err(AdminResponse::Ok(render_admin_page()))
        }
    }
}

fn _validate_token(token: &str) -> bool {
    match CONFIG.admin_token().as_ref() {
        None => false,
        Some(t) if t.starts_with("$argon2") => {
            use argon2::password_hash::PasswordVerifier;
            match argon2::password_hash::PasswordHash::new(t) {
                Ok(h) => {
                    // NOTE: hash params from `ADMIN_TOKEN` are used instead of what is configured in the `Argon2` instance.
                    argon2::Argon2::default().verify_password(token.trim().as_ref(), &h).is_ok()
                }
                Err(e) => {
                    error!("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: {e}");
                    false
                }
            }
        }
        Some(t) => crate::crypto::ct_eq(t.trim(), token.trim()),
    }
}

#[derive(Serialize)]
struct AdminTemplateData {
    page_content: String,
    page_data: Option<Value>,
    logged_in: bool,
    urlpath: String,
}

impl AdminTemplateData {
    fn new(page_content: &str, page_data: Value) -> Self {
        Self {
            page_content: String::from(page_content),
            page_data: Some(page_data),
            logged_in: true,
            urlpath: CONFIG.domain_path(),
        }
    }

    fn render(self) -> Result<String, Error> {
        CONFIG.render_template(BASE_TEMPLATE, &self)
    }
}

fn render_admin_page() -> ApiResult<Html<String>> {
    let settings_json = json!({
        "config": CONFIG.prepare_json(),
        "can_backup": *CAN_BACKUP,
    });
    let text = AdminTemplateData::new("admin/settings", settings_json).render()?;
    Ok(Html(text))
}

#[get("/")]
fn admin_page(_token: AdminToken) -> ApiResult<Html<String>> {
    render_admin_page()
}

#[get("/", rank = 2)]
fn admin_page_login() -> ApiResult<Html<String>> {
    render_admin_login(None, None)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    email: String,
}

async fn get_user_or_404(uuid: &str, conn: &mut DbConn) -> ApiResult<User> {
    if let Some(user) = User::find_by_uuid(uuid, conn).await {
        Ok(user)
    } else {
        err_code!("User doesn't exist", Status::NotFound.code);
    }
}

#[post("/invite", data = "<data>")]
async fn invite_user(data: Json<InviteData>, _token: AdminToken, mut conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    if User::find_by_mail(&data.email, &mut conn).await.is_some() {
        err_code!("User already exists", Status::Conflict.code)
    }

    let mut user = User::new(data.email);

    async fn _generate_invite(user: &User, conn: &mut DbConn) -> EmptyResult {
        if CONFIG.mail_enabled() {
            mail::send_invite(user, None, None, &CONFIG.invitation_org_name(), None).await
        } else {
            let invitation = Invitation::new(&user.email);
            invitation.save(conn).await
        }
    }

    _generate_invite(&user, &mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;
    user.save(&mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;

    Ok(Json(user.to_json(&mut conn).await))
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
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove(Cookie::build(COOKIE_NAME).path(admin_path()));
    Redirect::to(admin_path())
}

#[get("/users")]
async fn get_users_json(_token: AdminToken, mut conn: DbConn) -> Json<Value> {
    let users = User::get_all(&mut conn).await;
    let mut users_json = Vec::with_capacity(users.len());
    for u in users {
        let mut usr = u.to_json(&mut conn).await;
        usr["userEnabled"] = json!(u.enabled);
        usr["createdAt"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
        usr["lastActive"] = match u.last_active(&mut conn).await {
            Some(dt) => json!(format_naive_datetime_local(&dt, DT_FMT)),
            None => json!(None::<String>),
        };
        users_json.push(usr);
    }

    Json(Value::Array(users_json))
}

#[get("/users/overview")]
async fn users_overview(_token: AdminToken, mut conn: DbConn) -> ApiResult<Html<String>> {
    let users = User::get_all(&mut conn).await;
    let mut users_json = Vec::with_capacity(users.len());
    for u in users {
        let mut usr = u.to_json(&mut conn).await;
        usr["cipher_count"] = json!(Cipher::count_owned_by_user(&u.uuid, &mut conn).await);
        usr["attachment_count"] = json!(Attachment::count_by_user(&u.uuid, &mut conn).await);
        usr["attachment_size"] = json!(get_display_size(Attachment::size_by_user(&u.uuid, &mut conn).await));
        usr["user_enabled"] = json!(u.enabled);
        usr["created_at"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
        usr["last_active"] = match u.last_active(&mut conn).await {
            Some(dt) => json!(format_naive_datetime_local(&dt, DT_FMT)),
            None => json!("Never"),
        };
        users_json.push(usr);
    }

    let text = AdminTemplateData::new("admin/users", json!(users_json)).render()?;
    Ok(Html(text))
}

#[get("/users/by-mail/<mail>")]
async fn get_user_by_mail_json(mail: &str, _token: AdminToken, mut conn: DbConn) -> JsonResult {
    if let Some(u) = User::find_by_mail(mail, &mut conn).await {
        let mut usr = u.to_json(&mut conn).await;
        usr["userEnabled"] = json!(u.enabled);
        usr["createdAt"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
        Ok(Json(usr))
    } else {
        err_code!("User doesn't exist", Status::NotFound.code);
    }
}

#[get("/users/<uuid>")]
async fn get_user_json(uuid: &str, _token: AdminToken, mut conn: DbConn) -> JsonResult {
    let u = get_user_or_404(uuid, &mut conn).await?;
    let mut usr = u.to_json(&mut conn).await;
    usr["userEnabled"] = json!(u.enabled);
    usr["createdAt"] = json!(format_naive_datetime_local(&u.created_at, DT_FMT));
    Ok(Json(usr))
}

#[post("/users/<uuid>/delete")]
async fn delete_user(uuid: &str, token: AdminToken, mut conn: DbConn) -> EmptyResult {
    let user = get_user_or_404(uuid, &mut conn).await?;

    // Get the user_org records before deleting the actual user
    let user_orgs = UserOrganization::find_any_state_by_user(uuid, &mut conn).await;
    let res = user.delete(&mut conn).await;

    for user_org in user_orgs {
        log_event(
            EventType::OrganizationUserRemoved as i32,
            &user_org.uuid,
            &user_org.org_uuid,
            ACTING_ADMIN_USER,
            14, // Use UnknownBrowser type
            &token.ip.ip,
            &mut conn,
        )
        .await;
    }

    res
}

#[post("/users/<uuid>/deauth")]
async fn deauth_user(uuid: &str, _token: AdminToken, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let mut user = get_user_or_404(uuid, &mut conn).await?;

    nt.send_logout(&user, None).await;

    if CONFIG.push_enabled() {
        for device in Device::find_push_devices_by_user(&user.uuid, &mut conn).await {
            match unregister_push_device(device.push_uuid).await {
                Ok(r) => r,
                Err(e) => error!("Unable to unregister devices from Bitwarden server: {}", e),
            };
        }
    }

    Device::delete_all_by_user(&user.uuid, &mut conn).await?;
    user.reset_security_stamp();

    user.save(&mut conn).await
}

#[post("/users/<uuid>/disable")]
async fn disable_user(uuid: &str, _token: AdminToken, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let mut user = get_user_or_404(uuid, &mut conn).await?;
    Device::delete_all_by_user(&user.uuid, &mut conn).await?;
    user.reset_security_stamp();
    user.enabled = false;

    let save_result = user.save(&mut conn).await;

    nt.send_logout(&user, None).await;

    save_result
}

#[post("/users/<uuid>/enable")]
async fn enable_user(uuid: &str, _token: AdminToken, mut conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(uuid, &mut conn).await?;
    user.enabled = true;

    user.save(&mut conn).await
}

#[post("/users/<uuid>/remove-2fa")]
async fn remove_2fa(uuid: &str, token: AdminToken, mut conn: DbConn) -> EmptyResult {
    let mut user = get_user_or_404(uuid, &mut conn).await?;
    TwoFactor::delete_all_by_user(&user.uuid, &mut conn).await?;
    two_factor::enforce_2fa_policy(&user, ACTING_ADMIN_USER, 14, &token.ip.ip, &mut conn).await?;
    user.totp_recover = None;
    user.save(&mut conn).await
}

#[post("/users/<uuid>/invite/resend")]
async fn resend_user_invite(uuid: &str, _token: AdminToken, mut conn: DbConn) -> EmptyResult {
    if let Some(user) = User::find_by_uuid(uuid, &mut conn).await {
        //TODO: replace this with user.status check when it will be available (PR#3397)
        if !user.password_hash.is_empty() {
            err_code!("User already accepted invitation", Status::BadRequest.code);
        }

        if CONFIG.mail_enabled() {
            mail::send_invite(&user, None, None, &CONFIG.invitation_org_name(), None).await
        } else {
            Ok(())
        }
    } else {
        err_code!("User doesn't exist", Status::NotFound.code);
    }
}

#[derive(Debug, Deserialize)]
struct UserOrgTypeData {
    user_type: NumberOrString,
    user_uuid: String,
    org_uuid: String,
}

#[post("/users/org_type", data = "<data>")]
async fn update_user_org_type(data: Json<UserOrgTypeData>, token: AdminToken, mut conn: DbConn) -> EmptyResult {
    let data: UserOrgTypeData = data.into_inner();

    let Some(mut user_to_edit) =
        UserOrganization::find_by_user_and_org(&data.user_uuid, &data.org_uuid, &mut conn).await
    else {
        err!("The specified user isn't member of the organization")
    };

    let new_type = match UserOrgType::from_str(&data.user_type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&data.org_uuid, UserOrgType::Owner, &mut conn).await <= 1 {
            err!("Can't change the type of the last owner")
        }
    }

    // This check is also done at api::organizations::{accept_invite(), _confirm_invite, _activate_user(), edit_user()}, update_user_org_type
    // It returns different error messages per function.
    if new_type < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_edit.user_uuid, &user_to_edit.org_uuid, true, &mut conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                if CONFIG.email_2fa_auto_fallback() {
                    two_factor::email::find_and_activate_email_2fa(&user_to_edit.user_uuid, &mut conn).await?;
                } else {
                    err!("You cannot modify this user to this type because they have not setup 2FA");
                }
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because it is a member of an organization which forbids it");
            }
        }
    }

    log_event(
        EventType::OrganizationUserUpdated as i32,
        &user_to_edit.uuid,
        &data.org_uuid,
        ACTING_ADMIN_USER,
        14, // Use UnknownBrowser type
        &token.ip.ip,
        &mut conn,
    )
    .await;

    user_to_edit.atype = new_type;
    user_to_edit.save(&mut conn).await
}

#[post("/users/update_revision")]
async fn update_revision_users(_token: AdminToken, mut conn: DbConn) -> EmptyResult {
    User::update_all_revisions(&mut conn).await
}

#[get("/organizations/overview")]
async fn organizations_overview(_token: AdminToken, mut conn: DbConn) -> ApiResult<Html<String>> {
    let organizations = Organization::get_all(&mut conn).await;
    let mut organizations_json = Vec::with_capacity(organizations.len());
    for o in organizations {
        let mut org = o.to_json();
        org["user_count"] = json!(UserOrganization::count_by_org(&o.uuid, &mut conn).await);
        org["cipher_count"] = json!(Cipher::count_by_org(&o.uuid, &mut conn).await);
        org["collection_count"] = json!(Collection::count_by_org(&o.uuid, &mut conn).await);
        org["group_count"] = json!(Group::count_by_org(&o.uuid, &mut conn).await);
        org["event_count"] = json!(Event::count_by_org(&o.uuid, &mut conn).await);
        org["attachment_count"] = json!(Attachment::count_by_org(&o.uuid, &mut conn).await);
        org["attachment_size"] = json!(get_display_size(Attachment::size_by_org(&o.uuid, &mut conn).await));
        organizations_json.push(org);
    }

    let text = AdminTemplateData::new("admin/organizations", json!(organizations_json)).render()?;
    Ok(Html(text))
}

#[post("/organizations/<uuid>/delete")]
async fn delete_organization(uuid: &str, _token: AdminToken, mut conn: DbConn) -> EmptyResult {
    let org = Organization::find_by_uuid(uuid, &mut conn).await.map_res("Organization doesn't exist")?;
    org.delete(&mut conn).await
}

#[derive(Deserialize)]
struct GitRelease {
    tag_name: String,
}

#[derive(Deserialize)]
struct GitCommit {
    sha: String,
}

#[derive(Deserialize)]
struct TimeApi {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    seconds: u8,
}

async fn get_json_api<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    Ok(make_http_request(Method::GET, url)?.send().await?.error_for_status()?.json::<T>().await?)
}

async fn has_http_access() -> bool {
    let Ok(req) = make_http_request(Method::HEAD, "https://github.com/dani-garcia/vaultwarden") else {
        return false;
    };
    match req.send().await {
        Ok(r) => r.status().is_success(),
        _ => false,
    }
}

use cached::proc_macro::cached;
/// Cache this function to prevent API call rate limit. Github only allows 60 requests per hour, and we use 3 here already.
/// It will cache this function for 300 seconds (5 minutes) which should prevent the exhaustion of the rate limit.
#[cached(time = 300, sync_writes = true)]
async fn get_release_info(has_http_access: bool, running_within_container: bool) -> (String, String, String) {
    // If the HTTP Check failed, do not even attempt to check for new versions since we were not able to connect with github.com anyway.
    if has_http_access {
        (
            match get_json_api::<GitRelease>("https://api.github.com/repos/dani-garcia/vaultwarden/releases/latest")
                .await
            {
                Ok(r) => r.tag_name,
                _ => "-".to_string(),
            },
            match get_json_api::<GitCommit>("https://api.github.com/repos/dani-garcia/vaultwarden/commits/main").await {
                Ok(mut c) => {
                    c.sha.truncate(8);
                    c.sha
                }
                _ => "-".to_string(),
            },
            // Do not fetch the web-vault version when running within a container.
            // The web-vault version is embedded within the container it self, and should not be updated manually
            if running_within_container {
                "-".to_string()
            } else {
                match get_json_api::<GitRelease>(
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

async fn get_ntp_time(has_http_access: bool) -> String {
    if has_http_access {
        if let Ok(ntp_time) = get_json_api::<TimeApi>("https://www.timeapi.io/api/Time/current/zone?timeZone=UTC").await
        {
            return format!(
                "{year}-{month:02}-{day:02} {hour:02}:{minute:02}:{seconds:02} UTC",
                year = ntp_time.year,
                month = ntp_time.month,
                day = ntp_time.day,
                hour = ntp_time.hour,
                minute = ntp_time.minute,
                seconds = ntp_time.seconds
            );
        }
    }
    String::from("Unable to fetch NTP time.")
}

#[get("/diagnostics")]
async fn diagnostics(_token: AdminToken, ip_header: IpHeader, mut conn: DbConn) -> ApiResult<Html<String>> {
    use chrono::prelude::*;
    use std::net::ToSocketAddrs;

    // Execute some environment checks
    let running_within_container = is_running_in_container();
    let has_http_access = has_http_access().await;
    let uses_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();

    // Check if we are able to resolve DNS entries
    let dns_resolved = match ("github.com", 0).to_socket_addrs().map(|mut i| i.next()) {
        Ok(Some(a)) => a.ip().to_string(),
        _ => "Unable to resolve domain name.".to_string(),
    };

    let (latest_release, latest_commit, latest_web_build) =
        get_release_info(has_http_access, running_within_container).await;

    let ip_header_name = &ip_header.0.unwrap_or_default();

    // Get current running versions
    let web_vault_version = get_web_vault_version();

    let diagnostics_json = json!({
        "dns_resolved": dns_resolved,
        "current_release": VERSION,
        "latest_release": latest_release,
        "latest_commit": latest_commit,
        "web_vault_enabled": &CONFIG.web_vault_enabled(),
        "web_vault_version": web_vault_version,
        "latest_web_build": latest_web_build,
        "running_within_container": running_within_container,
        "container_base_image": if running_within_container { container_base_image() } else { "Not applicable" },
        "has_http_access": has_http_access,
        "ip_header_exists": !ip_header_name.is_empty(),
        "ip_header_match": ip_header_name.eq(&CONFIG.ip_header()),
        "ip_header_name": ip_header_name,
        "ip_header_config": &CONFIG.ip_header(),
        "uses_proxy": uses_proxy,
        "enable_websocket": &CONFIG.enable_websocket(),
        "db_type": *DB_TYPE,
        "db_version": get_sql_server_version(&mut conn).await,
        "admin_url": format!("{}/diagnostics", admin_url()),
        "overrides": &CONFIG.get_overrides().join(", "),
        "host_arch": env::consts::ARCH,
        "host_os":  env::consts::OS,
        "server_time_local": Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        "server_time": Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(), // Run the server date/time check as late as possible to minimize the time difference
        "ntp_time": get_ntp_time(has_http_access).await, // Run the ntp check as late as possible to minimize the time difference
    });

    let text = AdminTemplateData::new("admin/diagnostics", diagnostics_json).render()?;
    Ok(Html(text))
}

#[get("/diagnostics/config")]
fn get_diagnostics_config(_token: AdminToken) -> Json<Value> {
    let support_json = CONFIG.get_support_json();
    Json(support_json)
}

#[get("/diagnostics/http?<code>")]
fn get_diagnostics_http(code: u16, _token: AdminToken) -> EmptyResult {
    err_code!(format!("Testing error {code} response"), code);
}

#[post("/config", data = "<data>")]
fn post_config(data: Json<ConfigBuilder>, _token: AdminToken) -> EmptyResult {
    let data: ConfigBuilder = data.into_inner();
    if let Err(e) = CONFIG.update_config(data) {
        err!(format!("Unable to save config: {e:?}"))
    }
    Ok(())
}

#[post("/config/delete")]
fn delete_config(_token: AdminToken) -> EmptyResult {
    if let Err(e) = CONFIG.delete_user_config() {
        err!(format!("Unable to delete config: {e:?}"))
    }
    Ok(())
}

#[post("/config/backup_db")]
async fn backup_db(_token: AdminToken, mut conn: DbConn) -> ApiResult<String> {
    if *CAN_BACKUP {
        match backup_database(&mut conn).await {
            Ok(f) => Ok(format!("Backup to '{f}' was successful")),
            Err(e) => err!(format!("Backup was unsuccessful {e}")),
        }
    } else {
        err!("Can't back up current DB (Only SQLite supports this feature)");
    }
}

pub struct AdminToken {
    ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(ip) => ip,
            _ => err_handler!("Error getting Client IP"),
        };

        if CONFIG.disable_admin_token() {
            Outcome::Success(Self {
                ip,
            })
        } else {
            let cookies = request.cookies();

            let access_token = match cookies.get(COOKIE_NAME) {
                Some(cookie) => cookie.value(),
                None => {
                    let requested_page =
                        request.segments::<std::path::PathBuf>(0..).unwrap_or_default().display().to_string();
                    // When the requested page is empty, it is `/admin`, in that case, Forward, so it will render the login page
                    // Else, return a 401 failure, which will be caught
                    if requested_page.is_empty() {
                        return Outcome::Forward(Status::Unauthorized);
                    } else {
                        return Outcome::Error((Status::Unauthorized, "Unauthorized"));
                    }
                }
            };

            if decode_admin(access_token).is_err() {
                // Remove admin cookie
                cookies.remove(Cookie::build(COOKIE_NAME).path(admin_path()));
                error!("Invalid or expired admin JWT. IP: {}.", &ip.ip);
                return Outcome::Error((Status::Unauthorized, "Session expired"));
            }

            Outcome::Success(Self {
                ip,
            })
        }
    }
}
