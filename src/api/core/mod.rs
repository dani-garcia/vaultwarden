pub mod accounts;
pub mod two_factor;

mod ciphers;
mod emergency_access;
mod events;
mod folders;
mod organizations;
mod public;
mod sends;

pub use accounts::purge_auth_requests;
pub use ciphers::{CipherData, CipherSyncData, CipherSyncType, purge_trashed_ciphers};
pub use emergency_access::{emergency_notification_reminder_job, emergency_request_timeout_job};
pub use events::{event_cleanup_job, log_event, log_user_event};
pub use sends::purge_sends;

use reqwest::Method;
use rocket::{Catcher, Route, serde::json::Json, serde::json::Value};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{
        DbConn,
        models::{Membership, MembershipStatus, OrgPolicy, Organization, User},
    },
    error::Error,
    http_client::make_http_request,
    mail,
    util::{FeatureFlagFilter, parse_experimental_client_feature_flags},
};

pub fn routes() -> Vec<Route> {
    let mut eq_domains_routes = routes![get_settings_domains, post_settings_domains, put_settings_domains];
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalDomain {
    r#type: i32,
    domains: Vec<String>,
    excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../static/global_domains.json");

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[get("/settings/domains")]
fn get_settings_domains(headers: Headers) -> Json<Value> {
    get_eq_domains(&headers, false)
}

fn get_eq_domains(headers: &Headers, no_excluded: bool) -> Json<Value> {
    use serde_json::from_str;

    let user = &headers.user;

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
async fn post_settings_domains(
    data: Json<EquivDomainData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    use serde_json::to_string;

    let data: EquivDomainData = data.into_inner();

    let excluded_globals = data.excluded_global_equivalent_domains.unwrap_or_default();
    let equivalent_domains = data.equivalent_domains.unwrap_or_default();

    let mut user = headers.user;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_owned());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_owned());

    user.save(&conn).await?;

    nt.send_user_update(UpdateType::SyncSettings, &user, headers.device.push_uuid.as_ref(), &conn).await;

    Ok(Json(json!({})))
}

#[put("/settings/domains", data = "<data>")]
async fn put_settings_domains(
    data: Json<EquivDomainData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_settings_domains(data, headers, conn, nt).await
}

#[get("/hibp/breach?<username>")]
async fn hibp_breach(username: &str, _headers: Headers) -> JsonResult {
    let username: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
    if let Some(api_key) = CONFIG.hibp_api_key() {
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
    let domain = CONFIG.domain();
    // Official available feature flags can be found here:
    // Server (v2026.7.1): https://github.com/bitwarden/server/blob/97ad380f0f82b560d81c1e2e684cef9e85b3379e/src/Core/Constants.cs#L120
    // Client (v2026.7.0): https://github.com/bitwarden/clients/blob/adf0337e4a0f788b895933792fc04fa162669eff/libs/common/src/enums/feature-flag.enum.ts#L10
    // Android (v2026.7.0-bwpm): https://github.com/bitwarden/android/blob/36c892e1887b5051270ead6021afb16420663566/core/src/main/kotlin/com/bitwarden/core/data/manager/model/FlagKey.kt#L28
    // iOS (v2026.7.0-bwpm): https://github.com/bitwarden/ios/blob/e9514dc0f85092ef3cf2a2ccbe07dc5a4f661b0c/BitwardenShared/Core/Platform/Models/Enum/FeatureFlag.swift#L5
    let mut feature_states = parse_experimental_client_feature_flags(
        &CONFIG.experimental_client_feature_flags(),
        &FeatureFlagFilter::ValidOnly,
    );
    feature_states.insert("pm-19148-innovation-archive".to_owned(), true);

    Json(json!({
        // Note: The clients use this version to handle backwards compatibility concerns
        // This means they expect a version that closely matches the Bitwarden server version
        // We should make sure that we keep this updated when we support the new server features
        // Version history:
        // - Individual cipher key encryption: 2024.2.0
        // - Mobile app support for MasterPasswordUnlockData: 2025.8.0
        "version": "2026.6.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": CONFIG.is_signup_disabled(),
            // When enabled, this setting signals to clients that onboarding interstitials
            // (post-login welcome dialogs, extension install prompts, setup extension redirects, and premium upsell modals) should be suppressed
            "suppressOnboardingInterstitials": false
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
        // Not supported right now
        // Used for by clients to learn if the server requires extra work to establish a connection.
        // See: https://github.com/bitwarden/server/pull/6892 | https://github.com/bitwarden/server/commit/52955d1860b4dfb905f67bbe39d9b10bbd61ded0
        "communication": null,
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

    if CONFIG.mail_enabled() {
        let Some(org) = Organization::find_by_uuid(&member.org_uuid, conn).await else {
            err!("Organization not found.")
        };
        // User was invited to an organization, so they must be confirmed manually after acceptance
        mail::send_invite_accepted(&user.email, &member.invited_by_email.unwrap_or(org.billing_email), &org.name)
            .await?;
    }

    Ok(())
}
