pub mod accounts;
mod ciphers;
mod emergency_access;
mod events;
mod folders;
mod organizations;
mod public;
mod sends;
pub mod two_factor;

pub use accounts::purge_auth_requests;
pub use ciphers::{purge_trashed_ciphers, CipherData, CipherSyncData, CipherSyncType};
pub use emergency_access::{emergency_notification_reminder_job, emergency_request_timeout_job};
pub use events::{event_cleanup_job, log_event, log_user_event};
use reqwest::Method;
pub use sends::purge_sends;

pub fn routes() -> Vec<Route> {
    let mut eq_domains_routes = routes![get_eq_domains, post_eq_domains, put_eq_domains];
    let mut hibp_routes = routes![hibp_breach];
    let mut meta_routes = routes![alive, now, version, config, get_api_webauthn];

    let mut routes = Vec::new();
    routes.append(&mut accounts::routes());
    routes.append(&mut ciphers::routes());
    routes.append(&mut emergency_access::routes());
    routes.append(&mut events::routes());
    routes.append(&mut folders::routes());
    routes.append(&mut organizations::routes());
    routes.append(&mut two_factor::routes());
    routes.append(&mut sends::routes());
    routes.append(&mut public::routes());
    routes.append(&mut eq_domains_routes);
    routes.append(&mut hibp_routes);
    routes.append(&mut meta_routes);

    routes
}

pub fn events_routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.append(&mut events::main_routes());

    routes
}

//
// Move this somewhere else
//
use rocket::{serde::json::Json, serde::json::Value, Catcher, Route};

use crate::{
    api::{EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        models::{Membership, MembershipStatus, OrgPolicy, Organization, User},
        DbConn,
    },
    error::Error,
    http_client::make_http_request,
    mail,
    util::parse_experimental_client_feature_flags,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalDomain {
    r#type: i32,
    domains: Vec<String>,
    excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../static/global_domains.json");

#[get("/settings/domains")]
fn get_eq_domains(headers: Headers) -> Json<Value> {
    _get_eq_domains(headers, false)
}

fn _get_eq_domains(headers: Headers, no_excluded: bool) -> Json<Value> {
    let user = headers.user;
    use serde_json::from_str;

    let equivalent_domains: Vec<Vec<String>> = from_str(&user.equivalent_domains).unwrap();
    let excluded_globals: Vec<i32> = from_str(&user.excluded_globals).unwrap();

    let mut globals: Vec<GlobalDomain> = from_str(GLOBAL_DOMAINS).unwrap();

    for global in &mut globals {
        global.excluded = excluded_globals.contains(&global.r#type);
    }

    if no_excluded {
        globals.retain(|g| !g.excluded);
    }

    Json(json!({
        "equivalentDomains": equivalent_domains,
        "globalEquivalentDomains": globals,
        "object": "domains",
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

#[post("/settings/domains", data = "<data>")]
async fn post_eq_domains(data: Json<EquivDomainData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let data: EquivDomainData = data.into_inner();

    let excluded_globals = data.excluded_global_equivalent_domains.unwrap_or_default();
    let equivalent_domains = data.equivalent_domains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_string());

    user.save(&conn).await?;

    nt.send_user_update(UpdateType::SyncSettings, &user, &headers.device.push_uuid, &conn).await;

    Ok(Json(json!({})))
}

#[put("/settings/domains", data = "<data>")]
async fn put_eq_domains(data: Json<EquivDomainData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    post_eq_domains(data, headers, conn, nt).await
}

#[get("/hibp/breach?<username>")]
async fn hibp_breach(username: &str, _headers: Headers) -> JsonResult {
    let username: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
    if let Some(api_key) = crate::CONFIG.hibp_api_key() {
        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{username}?truncateResponse=false&includeUnverified=false"
        );

        let res = make_http_request(Method::GET, &url)?.header("hibp-api-key", api_key).send().await?;

        // If we get a 404, return a 404, it means no breached accounts
        if res.status() == 404 {
            return Err(Error::empty().with_code(404));
        }

        let value: Value = res.error_for_status()?.json().await?;
        Ok(Json(value))
    } else {
        Ok(Json(json!([{
            "name": "HaveIBeenPwned",
            "title": "Manual HIBP Check",
            "domain": "haveibeenpwned.com",
            "breachDate": "2019-08-18T00:00:00Z",
            "addedDate": "2019-08-18T00:00:00Z",
            "description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>"),
            "logoPath": "vw_static/hibp.png",
            "pwnCount": 0,
            "dataClasses": [
                "Error - No API key set!"
            ]
        }])))
    }
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
#[get("/alive")]
fn alive(_conn: DbConn) -> Json<String> {
    now()
}

#[get("/now")]
pub fn now() -> Json<String> {
    Json(crate::util::format_date(&chrono::Utc::now().naive_utc()))
}

#[get("/version")]
fn version() -> Json<&'static str> {
    Json(crate::VERSION.unwrap_or_default())
}

#[get("/webauthn")]
fn get_api_webauthn(_headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes key-rotation issues
    // It looks like this is used when login with passkeys is enabled, which Vaultwarden does not (yet) support
    // An empty list/data also works fine
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}

#[get("/config")]
fn config() -> Json<Value> {
    let domain = crate::CONFIG.domain();
    // Official available feature flags can be found here:
    // Server (v2025.6.2): https://github.com/bitwarden/server/blob/d094be3267f2030bd0dc62106bc6871cf82682f5/src/Core/Constants.cs#L103
    // Client (web-v2025.6.1): https://github.com/bitwarden/clients/blob/747c2fd6a1c348a57a76e4a7de8128466ffd3c01/libs/common/src/enums/feature-flag.enum.ts#L12
    // Android (v2025.6.0): https://github.com/bitwarden/android/blob/b5b022caaad33390c31b3021b2c1205925b0e1a2/app/src/main/kotlin/com/x8bit/bitwarden/data/platform/manager/model/FlagKey.kt#L22
    // iOS (v2025.6.0): https://github.com/bitwarden/ios/blob/ff06d9c6cc8da89f78f37f376495800201d7261a/BitwardenShared/Core/Platform/Models/Enum/FeatureFlag.swift#L7
    let mut feature_states =
        parse_experimental_client_feature_flags(&crate::CONFIG.experimental_client_feature_flags());
    feature_states.insert("duo-redirect".to_string(), true);
    feature_states.insert("email-verification".to_string(), true);
    feature_states.insert("unauth-ui-refresh".to_string(), true);
    feature_states.insert("enable-pm-flight-recorder".to_string(), true);
    feature_states.insert("mobile-error-reporting".to_string(), true);

    Json(json!({
        // Note: The clients use this version to handle backwards compatibility concerns
        // This means they expect a version that closely matches the Bitwarden server version
        // We should make sure that we keep this updated when we support the new server features
        // Version history:
        // - Individual cipher key encryption: 2024.2.0
        "version": "2025.6.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": crate::CONFIG.is_signup_disabled()
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "",
          "cloudRegion": null,
        },
        // Bitwarden uses this for the self-hosted servers to indicate the default push technology
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": feature_states,
        "object": "config",
    }))
}

pub fn catchers() -> Vec<Catcher> {
    catchers![api_not_found]
}

#[catch(404)]
fn api_not_found() -> Json<Value> {
    Json(json!({
        "error": {
            "code": 404,
            "reason": "Not Found",
            "description": "The requested resource could not be found."
        }
    }))
}

async fn accept_org_invite(
    user: &User,
    mut member: Membership,
    reset_password_key: Option<String>,
    conn: &DbConn,
) -> EmptyResult {
    if member.status != MembershipStatus::Invited as i32 {
        err!("User already accepted the invitation");
    }

    member.status = MembershipStatus::Accepted as i32;
    member.reset_password_key = reset_password_key;

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    OrgPolicy::check_user_allowed(&member, "join", conn).await?;

    member.save(conn).await?;

    if crate::CONFIG.mail_enabled() {
        let org = match Organization::find_by_uuid(&member.org_uuid, conn).await {
            Some(org) => org,
            None => err!("Organization not found."),
        };
        // User was invited to an organization, so they must be confirmed manually after acceptance
        mail::send_invite_accepted(&user.email, &member.invited_by_email.unwrap_or(org.billing_email), &org.name)
            .await?;
    }

    Ok(())
}
