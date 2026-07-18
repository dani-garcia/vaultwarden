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

use crate::{
    api::scim,
    crypto,
    db::{
        DbConn, DbPool,
        models::{Organization, OrganizationId, ScimApiKey},
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
