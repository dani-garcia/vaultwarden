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
use std::sync::LazyLock;

pub fn routes() -> Vec<Route> {
    let mut eq_domains_routes = routes![get_eq_domains, post_eq_domains, put_eq_domains];
    let mut hibp_routes = routes![hibp_breach];
    let mut meta_routes = routes![
        alive,
        now,
        version,
        config,
        get_api_webauthn,
        get_api_webauthn_attestation_options,
        post_api_webauthn,
        post_api_webauthn_assertion_options,
        put_api_webauthn,
        delete_api_webauthn
    ];

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
    api::{EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType},
    auth::{self, Headers},
    db::{
        models::{Membership, MembershipStatus, OrgPolicy, Organization, User, UserId},
        DbConn,
    },
    error::{Error, MapResult},
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

static WEBAUTHN_CREATE_OPTIONS_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|webauthn_create_options", crate::CONFIG.domain_origin()));
static WEBAUTHN_UPDATE_ASSERTION_OPTIONS_ISSUER: LazyLock<String> =
    LazyLock::new(|| format!("{}|webauthn_update_assertion_options", crate::CONFIG.domain_origin()));
const REQUIRE_SSO_POLICY_TYPE: i32 = 4;

#[derive(Debug, Serialize, Deserialize)]
struct WebauthnCreateOptionsClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    sub: UserId,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebauthnUpdateAssertionOptionsClaims {
    nbf: i64,
    exp: i64,
    iss: String,
    sub: UserId,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebauthnCredentialCreateRequest {
    device_response: two_factor::webauthn::RegisterPublicKeyCredentialCopy,
    name: String,
    token: String,
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebauthnCredentialUpdateRequest {
    device_response: two_factor::webauthn::PublicKeyCredentialCopy,
    token: String,
    encrypted_user_key: String,
    encrypted_public_key: String,
    encrypted_private_key: String,
}

fn encode_webauthn_create_options_token(user_id: &UserId, state: String) -> String {
    let now = chrono::Utc::now();
    let claims = WebauthnCreateOptionsClaims {
        nbf: now.timestamp(),
        exp: (now + chrono::TimeDelta::try_minutes(7).unwrap()).timestamp(),
        iss: WEBAUTHN_CREATE_OPTIONS_ISSUER.to_string(),
        sub: user_id.clone(),
        state,
    };

    auth::encode_jwt(&claims)
}

fn decode_webauthn_create_options_token(token: &str) -> Result<WebauthnCreateOptionsClaims, Error> {
    auth::decode_jwt(token, WEBAUTHN_CREATE_OPTIONS_ISSUER.to_string()).map_res("Invalid WebAuthn token")
}

fn encode_webauthn_update_assertion_options_token(user_id: &UserId, state: String) -> String {
    let now = chrono::Utc::now();
    let claims = WebauthnUpdateAssertionOptionsClaims {
        nbf: now.timestamp(),
        exp: (now + chrono::TimeDelta::try_minutes(17).unwrap()).timestamp(),
        iss: WEBAUTHN_UPDATE_ASSERTION_OPTIONS_ISSUER.to_string(),
        sub: user_id.clone(),
        state,
    };

    auth::encode_jwt(&claims)
}

fn decode_webauthn_update_assertion_options_token(
    token: &str,
) -> Result<WebauthnUpdateAssertionOptionsClaims, Error> {
    auth::decode_jwt(token, WEBAUTHN_UPDATE_ASSERTION_OPTIONS_ISSUER.to_string()).map_res("Invalid WebAuthn token")
}

async fn ensure_passkey_creation_allowed(user_id: &UserId, conn: &DbConn) -> EmptyResult {
    // `RequireSso` (policy type 4) is not fully supported in Vaultwarden, but if present in DB
    // we still mirror official behavior by blocking passkey creation.
    if OrgPolicy::has_active_raw_policy_for_user(user_id, REQUIRE_SSO_POLICY_TYPE, conn).await {
        err!("Passkeys cannot be created for your account. SSO login is required.")
    }

    Ok(())
}

#[get("/settings/domains")]
fn get_eq_domains(headers: Headers) -> Json<Value> {
    _get_eq_domains(&headers, false)
}

fn _get_eq_domains(headers: &Headers, no_excluded: bool) -> Json<Value> {
    let user = &headers.user;
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
async fn get_api_webauthn(headers: Headers, conn: DbConn) -> JsonResult {
    let registrations = two_factor::webauthn::get_webauthn_login_registrations(&headers.user.uuid, &conn).await?;

    let data: Vec<Value> = registrations
        .into_iter()
        .map(|registration| {
            json!({
                "id": registration.login_credential_api_id(),
                "name": registration.name,
                "prfStatus": registration.prf_status(),
                "encryptedUserKey": registration.encrypted_user_key,
                "encryptedPublicKey": registration.encrypted_public_key,
                "object": "webauthnCredential"
            })
        })
        .collect();

    Ok(Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    })))
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn get_api_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    if !crate::CONFIG.domain_set() {
        err!("`DOMAIN` environment variable is not set. Webauthn disabled")
    }

    data.into_inner().validate(&headers.user, false, &conn).await?;
    ensure_passkey_creation_allowed(&headers.user.uuid, &conn).await?;

    let (options, state) = two_factor::webauthn::generate_webauthn_attestation_options(&headers.user, &conn).await?;
    let token = encode_webauthn_create_options_token(&headers.user.uuid, state);

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webauthnCredentialCreateOptions"
    })))
}

#[post("/webauthn", data = "<data>")]
async fn post_api_webauthn(data: Json<WebauthnCredentialCreateRequest>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let claims = decode_webauthn_create_options_token(&data.token)?;

    if claims.sub != headers.user.uuid {
        err!("The token associated with your request is expired. A valid token is required to continue.")
    }
    ensure_passkey_creation_allowed(&headers.user.uuid, &conn).await?;

    two_factor::webauthn::create_webauthn_login_credential(
        &headers.user.uuid,
        &claims.state,
        data.name,
        data.device_response,
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
        &conn,
    )
    .await?;

    Ok(())
}

#[post("/webauthn/assertion-options", data = "<data>")]
async fn post_api_webauthn_assertion_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    data.into_inner().validate(&headers.user, false, &conn).await?;

    let (options, state) = two_factor::webauthn::generate_webauthn_discoverable_login()?;
    let token = encode_webauthn_update_assertion_options_token(&headers.user.uuid, state);

    Ok(Json(json!({
        "options": options,
        "token": token,
        "object": "webAuthnLoginAssertionOptions"
    })))
}

#[put("/webauthn", data = "<data>")]
async fn put_api_webauthn(data: Json<WebauthnCredentialUpdateRequest>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let claims = decode_webauthn_update_assertion_options_token(&data.token)?;

    if claims.sub != headers.user.uuid {
        err!("The token associated with your request is invalid or has expired. A valid token is required to continue.")
    }

    two_factor::webauthn::update_webauthn_login_credential_keys(
        &headers.user.uuid,
        &claims.state,
        data.device_response,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
        &conn,
    )
    .await?;

    Ok(())
}

#[post("/webauthn/<id>/delete", data = "<data>")]
async fn delete_api_webauthn(id: String, data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> EmptyResult {
    data.into_inner().validate(&headers.user, false, &conn).await?;
    two_factor::webauthn::delete_webauthn_login_credential(&headers.user.uuid, &id, &conn).await?;
    Ok(())
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
        // - Mobile app support for MasterPasswordUnlockData: 2025.8.0
        "version": "2025.12.0",
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
