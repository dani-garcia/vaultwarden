//
// Integration tests for the SCIM endpoints, driven through a Rocket local
// client against a temporary sqlite database.
//
// Environment: a #[ctor] constructor calls test_support::init_hermetic_env()
// BEFORE main and before any test thread starts. CONFIG is a process-global
// LazyLock that reads the environment on first deref, so this is the only
// point where its inputs can be controlled race-free. The main crate forbids
// unsafe code, which is why the env mutation lives in the test-support crate.
//
// Tests that build a rocket + database serialize on TEST_LOCK: the sqlite
// file and the CONFIG global are shared process state.
//
use std::sync::LazyLock;

use rocket::{
    http::{Header, Status},
    local::asynchronous::{Client, LocalResponse},
};

use serde_json::Value;

use crate::{
    api::scim,
    crypto,
    db::{
        DbConn, DbPool,
        models::{Membership, MembershipId, MembershipType, Organization, OrganizationId, ScimApiKey, User},
    },
};

// Linking test-support activates its #[ctor] constructor, which points CONFIG
// at a hermetic temp environment before main. See test-support/src/lib.rs.
use test_support as _;

static TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

const SCIM_CONTENT_TYPE: &str = "application/scim+json";

// One pool for the whole test process: it is never dropped, so no test can
// hit "database is locked" from a previous test's lazily-dropped connections,
// and the embedded migrations run exactly once.
fn test_pool() -> &'static DbPool {
    static POOL: std::sync::OnceLock<DbPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        // main() installs the rustls provider at startup; the test binary
        // never runs main, and the CONFIG load path builds an http client
        // that needs it.
        rustls::crypto::ring::default_provider().install_default().expect("install rustls crypto provider");
        DbPool::from_config().expect("test db pool (migrations embedded)")
    })
}

async fn scim_client() -> (Client, DbPool) {
    let pool = test_pool().clone();
    let rocket = rocket::custom(rocket::Config::default())
        .mount("/scim", scim::routes())
        .register("/scim", scim::catchers())
        .manage(pool.clone());
    let client = Client::untracked(rocket).await.expect("local rocket client");
    (client, pool)
}

async fn seed_org(conn: &DbConn, name: &str) -> OrganizationId {
    let org = Organization::new(String::from(name), "admin@example.com", None, None);
    org.save(conn).await.expect("saving test org");
    org.uuid
}

// Mirrors manage::generate_scim_key and returns the full bearer token.
async fn seed_scim_key(conn: &DbConn, org_uuid: &OrganizationId) -> String {
    let secret = crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD);
    let key_hash = crypto::sha256_hex(secret.as_bytes());
    ScimApiKey::new(org_uuid.clone(), key_hash).save(conn).await.expect("saving scim key");
    format!("scim_v1.{org_uuid}.{secret}")
}

fn bearer(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {token}"))
}

async fn body_of(response: LocalResponse<'_>) -> String {
    response.into_string().await.expect("response body")
}

#[rocket::async_test]
async fn valid_token_reaches_discovery() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-authz-ok").await;
    let token = seed_scim_key(&conn, &org).await;

    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let content_type = response.headers().get_one("Content-Type").expect("content type");
    assert!(content_type.starts_with(SCIM_CONTENT_TYPE), "unexpected content type {content_type}");
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"));

    let response = client.get(format!("/scim/v2/{org}/ResourceTypes")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
    assert!(body.contains("\"endpoint\":\"/Users\""));

    let response = client.get(format!("/scim/v2/{org}/Schemas")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn auth_failures_are_uniform_401s() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");

    let org_a = seed_org(&conn, "scim-authz-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-authz-b").await;
    let _token_b = seed_scim_key(&conn, &org_b).await;
    // An org that exists but has no SCIM key configured.
    let org_c = seed_org(&conn, "scim-authz-c").await;

    let url_a = format!("/scim/v2/{org_a}/ServiceProviderConfig");

    let mut failures: Vec<(&str, LocalResponse<'_>)> = Vec::new();
    failures.push(("no auth header", client.get(&url_a).dispatch().await));
    failures
        .push(("not a bearer", client.get(&url_a).header(Header::new("Authorization", "Basic abc")).dispatch().await));
    failures.push(("malformed token", client.get(&url_a).header(bearer("garbage")).dispatch().await));
    failures.push((
        "wrong version prefix",
        client.get(&url_a).header(bearer(&format!("scim_v0.{org_a}.x"))).dispatch().await,
    ));
    failures.push((
        "wrong secret",
        client.get(&url_a).header(bearer(&format!("scim_v1.{org_a}.bm90LXRoZS1zZWNyZXQ"))).dispatch().await,
    ));
    failures.push((
        "token org != path org",
        client.get(format!("/scim/v2/{org_b}/ServiceProviderConfig")).header(bearer(&token_a)).dispatch().await,
    ));
    failures.push((
        "org without key",
        client
            .get(format!("/scim/v2/{org_c}/ServiceProviderConfig"))
            .header(bearer(&format!("scim_v1.{org_c}.c2VjcmV0")))
            .dispatch()
            .await,
    ));

    let mut bodies = Vec::new();
    for (case, response) in failures {
        assert_eq!(response.status(), Status::Unauthorized, "expected 401 for case: {case}");
        bodies.push((case, body_of(response).await));
    }

    // Every failure cause must produce a byte-identical body: no signal about
    // which check rejected the request.
    let (_, first) = &bodies[0];
    for (case, body) in &bodies {
        assert_eq!(body, first, "401 body differs for case: {case}");
    }
    assert!(first.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    assert!(first.contains("\"status\":\"401\""));
}

#[rocket::async_test]
async fn unknown_scim_route_is_scim_enveloped_404() {
    let _guard = TEST_LOCK.lock().await;
    let (client, _pool) = scim_client().await;

    let response = client.get("/scim/v2/some-org/Nope").dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    assert!(body.contains("\"status\":\"404\""));
}

#[test]
fn rate_limiter_returns_429_when_drained() {
    // Uses a synthetic IP so draining this bucket cannot affect the shared
    // bucket the HTTP tests consume from (the limiter is keyed by IP).
    let ip: std::net::IpAddr = "10.99.99.99".parse().expect("test ip");
    let burst = crate::CONFIG.scim_ratelimit_max_burst();
    let mut limited = false;
    for _ in 0..=burst {
        if crate::ratelimit::check_limit_scim(&ip).is_err() {
            limited = true;
            break;
        }
    }
    assert!(limited, "limiter never tripped after {burst} + 1 requests");
}

// ---------------------------------------------------------------------------
// Users lifecycle (Phase 1: provision, deprovision, restore)
// ---------------------------------------------------------------------------

fn scim_body(header_token: &str, body: &Value) -> (Header<'static>, Header<'static>, String) {
    (bearer(header_token), Header::new("Content-Type", "application/scim+json"), body.to_string())
}

async fn seed_user(conn: &DbConn, email: &str, with_password: bool) -> User {
    let mut user = User::new(email, None);
    if with_password {
        user.password_hash = vec![1, 2, 3];
    }
    user.save(conn).await.expect("saving test user");
    user
}

async fn seed_member(
    conn: &DbConn,
    org: &OrganizationId,
    email: &str,
    status: i32,
    atype: MembershipType,
) -> MembershipId {
    let user = seed_user(conn, email, true).await;
    let mut member = Membership::new(user.uuid, org.clone(), None);
    member.status = status;
    member.atype = atype as i32;
    member.save(conn).await.expect("saving test member");
    member.uuid
}

async fn member_status(conn: &DbConn, member_id: &MembershipId, org: &OrganizationId) -> i32 {
    Membership::find_by_uuid_and_org(member_id, org, conn).await.expect("membership row must exist").status
}

fn parse_json(body: &str) -> Value {
    serde_json::from_str(body).expect("valid json body")
}

#[rocket::async_test]
async fn post_creates_invited_user() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-post-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "Provision.Me@Example.com",
        "externalId": "entra-obj-001",
        "name": {"givenName": "Provision", "familyName": "Me"},
        "emails": [{"value": "Provision.Me@Example.com", "primary": true}],
        "active": true,
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;

    assert_eq!(response.status(), Status::Created);
    let location = response.headers().get_one("Location").expect("Location header").to_string();
    let parsed = parse_json(&body_of(response).await);

    // Mail is disabled and the user is new (no password): Invited (0).
    assert_eq!(parsed["active"], json!(true));
    assert_eq!(parsed["userName"], json!("provision.me@example.com"), "email must be stored lowercased");
    assert_eq!(parsed["externalId"], json!("entra-obj-001"));
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    assert!(location.ends_with(&format!("/scim/v2/{org}/Users/{member_id}")));

    assert_eq!(member_status(&conn, &member_id, &org).await, 0, "new shell user must land at Invited");
    assert!(User::find_by_mail("provision.me@example.com", &conn).await.is_some());
}

#[rocket::async_test]
async fn post_existing_credentialed_user_becomes_accepted() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-post-accepted-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_user(&conn, "has.password@example.com", true).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "has.password@example.com",
        "externalId": "entra-obj-002",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;

    assert_eq!(response.status(), Status::Created);
    let parsed = parse_json(&body_of(response).await);
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    // Mail disabled + existing credentials: straight to Accepted (1).
    assert_eq!(member_status(&conn, &member_id, &org).await, 1);
}

#[rocket::async_test]
async fn post_duplicate_is_409_uniqueness() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-dup-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup@example.com",
        "externalId": "entra-dup-1",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    // Same externalId again.
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("uniqueness"));

    // Same email, different externalId.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup@example.com",
        "externalId": "entra-dup-2",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
}

#[rocket::async_test]
async fn patch_active_lifecycle_hits_correct_status_offsets() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-patch-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let invited = seed_member(&conn, &org, "patch.invited@example.com", 0, MembershipType::User).await;
    let confirmed = seed_member(&conn, &org, "patch.confirmed@example.com", 2, MembershipType::User).await;

    let deactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
    });
    let activate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "value": {"active": true}}],
    });

    // Invited (0) revokes to -128, never -1.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(parse_json(&body_of(response).await)["active"], json!(false));
    assert_eq!(member_status(&conn, &invited, &org).await, -128);

    // Deprovisioning is idempotent.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &invited, &org).await, -128);

    // Restore is lossless: straight back to Invited (0).
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &invited, &org).await, 0);

    // Confirmed (2) revokes to -126 and restores to 2 with akey intact.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{confirmed}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &confirmed, &org).await, -126);

    let response = client.get(format!("/scim/v2/{org}/Users/{confirmed}")).header(bearer(&token)).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["active"], json!(false));

    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{confirmed}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &confirmed, &org).await, 2);
}

#[rocket::async_test]
async fn delete_revokes_and_keeps_the_row() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-delete-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "delete.me@example.com", 2, MembershipType::User).await;

    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    // The row survives (revoked), so restore stays lossless.
    assert_eq!(member_status(&conn, &member, &org).await, -126);

    // Idempotent.
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(member_status(&conn, &member, &org).await, -126);
}

#[rocket::async_test]
async fn last_confirmed_owner_cannot_be_revoked() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-owner-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let owner = seed_member(&conn, &org, "sole.owner@example.com", 2, MembershipType::Owner).await;

    let deactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{owner}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("mutability"));
    assert_eq!(member_status(&conn, &owner, &org).await, 2, "owner must remain untouched");

    // DELETE takes the same path.
    let response = client.delete(format!("/scim/v2/{org}/Users/{owner}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
    assert_eq!(member_status(&conn, &owner, &org).await, 2);
}

#[rocket::async_test]
async fn filter_round_trip_and_enumeration_shape() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-filter-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "filter.target@example.com", 1, MembershipType::User).await;

    // Mixed-case filter value must match the lowercased stored email.
    let filter = "userName eq \"Filter.Target@Example.COM\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1));
    assert_eq!(parsed["Resources"][0]["userName"], json!("filter.target@example.com"));

    // A miss is an empty 200 list, not a 404: Entra's Test Connection probes
    // exactly this, and a distinguishable miss would enable enumeration.
    let filter = "userName eq \"nobody-here@example.com\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(0));

    // Unsupported grammar is a 400 invalidFilter.
    let filter = "userName co \"partial\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidFilter"));
}

#[rocket::async_test]
async fn unknown_member_and_foreign_member_are_identical_404s() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-404-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-404-b").await;
    let _token_b = seed_scim_key(&conn, &org_b).await;
    let foreign = seed_member(&conn, &org_b, "foreign.member@example.com", 2, MembershipType::User).await;

    let response = client
        .get(format!("/scim/v2/{org_a}/Users/00000000-dead-beef-0000-000000000000"))
        .header(bearer(&token_a))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
    let unknown_body = body_of(response).await;

    // Another org's member id must be indistinguishable from a nonexistent one.
    let response = client.get(format!("/scim/v2/{org_a}/Users/{foreign}")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
    let foreign_body = body_of(response).await;
    assert_eq!(unknown_body, foreign_body);
}

#[rocket::async_test]
async fn post_inactive_creates_revoked_membership() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-inactive-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "born.disabled@example.com",
        "externalId": "entra-inactive-1",
        "active": "False",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["active"], json!(false));
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    assert_eq!(member_status(&conn, &member_id, &org).await, -128, "invited-then-revoked offset");
}

#[rocket::async_test]
async fn patch_unsupported_path_is_invalid_path() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-badpatch-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "bad.patch@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "wibble", "value": "New Name"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidPath"));
}

fn url_escape(raw: &str) -> String {
    // Percent-encode just enough for filter values in test URLs.
    raw.replace('%', "%25").replace(' ', "%20").replace('"', "%22")
}

// ---------------------------------------------------------------------------
// Full Users surface (Phase 2: PUT, attribute PATCH, pagination)
// ---------------------------------------------------------------------------

#[rocket::async_test]
async fn patch_displayname_rename_is_accepted_noop() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-rename-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "renamed.user@example.com", 2, MembershipType::User).await;

    // Entra sends this on every directory rename; it must not error and must
    // not change membership state.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "New Display Name"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["active"], json!(true));
    assert_eq!(member_status(&conn, &member, &org).await, 2);
}

#[rocket::async_test]
async fn patch_and_put_update_external_id_with_uniqueness() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-extid-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "extid.a@example.com", 1, MembershipType::User).await;
    let member_b = seed_member(&conn, &org, "extid.b@example.com", 1, MembershipType::User).await;

    // PATCH assigns an externalId.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-a-1"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_a}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(parse_json(&body_of(response).await)["externalId"], json!("ext-a-1"));

    // PUT replaces it and can toggle active in the same request.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "extid.a@example.com",
        "externalId": "ext-a-2",
        "active": false,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Users/{member_a}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["externalId"], json!("ext-a-2"));
    assert_eq!(parsed["active"], json!(false));
    assert_eq!(member_status(&conn, &member_a, &org).await, -127, "accepted (1) revoked to -127");

    // Duplicate externalId on another member is a 409.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-a-2"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_b}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
}

#[rocket::async_test]
async fn put_does_not_change_email_or_role() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-put-immutable-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "immutable@example.com", 2, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "changed@example.com",
        "displayName": "Different Person",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    // The response reflects the real state: the email did not change.
    assert_eq!(parsed["userName"], json!("immutable@example.com"));
    assert_eq!(member_status(&conn, &member, &org).await, 2);
}

#[rocket::async_test]
async fn pagination_edges() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-page-org").await;
    let token = seed_scim_key(&conn, &org).await;
    for i in 1..=3 {
        seed_member(&conn, &org, &format!("page{i}@example.com"), 1, MembershipType::User).await;
    }

    // Middle page.
    let response =
        client.get(format!("/scim/v2/{org}/Users?startIndex=2&count=1")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(1));
    assert_eq!(parsed["startIndex"], json!(2));

    // count=0 returns the total with no resources (RFC 7644 s3.4.2.4).
    let response = client.get(format!("/scim/v2/{org}/Users?count=0")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(0));

    // startIndex beyond the end is an empty page, not an error.
    let response = client.get(format!("/scim/v2/{org}/Users?startIndex=10")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(0));
}
