#![allow(dead_code, unused_imports)]

#[cfg(feature = "enable_metrics")]
use once_cell::sync::Lazy;
#[cfg(feature = "enable_metrics")]
use prometheus::{
    register_gauge_vec, register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    Encoder, GaugeVec, HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder,
};

use crate::{db::DbConn, error::Error, CONFIG};
#[cfg(feature = "enable_metrics")]
use std::sync::{Arc, RwLock};
#[cfg(feature = "enable_metrics")]
use std::time::{SystemTime, UNIX_EPOCH};

// HTTP request metrics
#[cfg(feature = "enable_metrics")]
static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "vaultwarden_http_requests_total",
        "Total number of HTTP requests processed",
        &["method", "path", "status"]
    )
    .unwrap()
});

#[cfg(feature = "enable_metrics")]
static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "vaultwarden_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap()
});

// Database metrics
#[cfg(feature = "enable_metrics")]
static DB_CONNECTIONS_ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_db_connections_active", "Number of active database connections", &["database"])
        .unwrap()
});

#[cfg(feature = "enable_metrics")]
static DB_CONNECTIONS_IDLE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_db_connections_idle", "Number of idle database connections", &["database"])
        .unwrap()
});

<<<<<<< HEAD
=======
#[cfg(feature = "enable_metrics")]
static DB_QUERY_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "vaultwarden_db_query_duration_seconds",
        "Database query duration in seconds",
        &["operation"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

>>>>>>> dfe102f5 (feat: add comprehensive Prometheus metrics support)
// Authentication metrics
#[cfg(feature = "enable_metrics")]
static AUTH_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "vaultwarden_auth_attempts_total",
        "Total number of authentication attempts",
        &["method", "status"]
    )
    .unwrap()
});

<<<<<<< HEAD
=======
#[cfg(feature = "enable_metrics")]
static USER_SESSIONS_ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_user_sessions_active", "Number of active user sessions", &["user_type"])
        .unwrap()
});

>>>>>>> dfe102f5 (feat: add comprehensive Prometheus metrics support)
// Business metrics
#[cfg(feature = "enable_metrics")]
static USERS_TOTAL: Lazy<IntGaugeVec> =
    Lazy::new(|| register_int_gauge_vec!("vaultwarden_users_total", "Total number of users", &["status"]).unwrap());

#[cfg(feature = "enable_metrics")]
static ORGANIZATIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_organizations_total", "Total number of organizations", &["status"]).unwrap()
});

#[cfg(feature = "enable_metrics")]
static VAULT_ITEMS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_vault_items_total", "Total number of vault items", &["type", "organization"])
        .unwrap()
});

#[cfg(feature = "enable_metrics")]
static COLLECTIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_collections_total", "Total number of collections", &["organization"]).unwrap()
});

// System metrics
#[cfg(feature = "enable_metrics")]
static UPTIME_SECONDS: Lazy<GaugeVec> =
    Lazy::new(|| register_gauge_vec!("vaultwarden_uptime_seconds", "Uptime in seconds", &["version"]).unwrap());

#[cfg(feature = "enable_metrics")]
static BUILD_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_build_info", "Build information", &["version", "revision", "branch"]).unwrap()
});

/// Increment HTTP request counter
#[cfg(feature = "enable_metrics")]
pub fn increment_http_requests(method: &str, path: &str, status: u16) {
    HTTP_REQUESTS_TOTAL.with_label_values(&[method, path, &status.to_string()]).inc();
}

/// Observe HTTP request duration
#[cfg(feature = "enable_metrics")]
pub fn observe_http_request_duration(method: &str, path: &str, duration_seconds: f64) {
    HTTP_REQUEST_DURATION_SECONDS.with_label_values(&[method, path]).observe(duration_seconds);
}

/// Update database connection metrics
#[cfg(feature = "enable_metrics")]
pub fn update_db_connections(database: &str, active: i64, idle: i64) {
    DB_CONNECTIONS_ACTIVE.with_label_values(&[database]).set(active);
    DB_CONNECTIONS_IDLE.with_label_values(&[database]).set(idle);
}

<<<<<<< HEAD
/// Increment authentication attempts (success/failure tracking)
/// Tracks authentication success/failure by method (password, client_credentials, SSO, etc.)
/// Called from src/api/identity.rs login() after each authentication attempt
=======
/// Observe database query duration
#[cfg(feature = "enable_metrics")]
pub fn observe_db_query_duration(operation: &str, duration_seconds: f64) {
    DB_QUERY_DURATION_SECONDS.with_label_values(&[operation]).observe(duration_seconds);
}

/// Increment authentication attempts
>>>>>>> dfe102f5 (feat: add comprehensive Prometheus metrics support)
#[cfg(feature = "enable_metrics")]
pub fn increment_auth_attempts(method: &str, status: &str) {
    AUTH_ATTEMPTS_TOTAL.with_label_values(&[method, status]).inc();
}

// Database metrics
#[cfg(feature = "enable_metrics")]
static DB_CONNECTIONS_ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_db_connections_active", "Number of active database connections", &["database"])
        .unwrap()
});

#[cfg(feature = "enable_metrics")]
static DB_CONNECTIONS_IDLE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_db_connections_idle", "Number of idle database connections", &["database"])
        .unwrap()
});

#[cfg(feature = "enable_metrics")]
static DB_QUERY_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "vaultwarden_db_query_duration_seconds",
        "Database query duration in seconds",
        &["operation"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

// Authentication metrics
#[cfg(feature = "enable_metrics")]
static AUTH_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "vaultwarden_auth_attempts_total",
        "Total number of authentication attempts",
        &["method", "status"]
    )
    .unwrap()
});

#[cfg(feature = "enable_metrics")]
static USER_SESSIONS_ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_user_sessions_active", "Number of active user sessions", &["user_type"])
        .unwrap()
});

// Business metrics
#[cfg(feature = "enable_metrics")]
static USERS_TOTAL: Lazy<IntGaugeVec> =
    Lazy::new(|| register_int_gauge_vec!("vaultwarden_users_total", "Total number of users", &["status"]).unwrap());

#[cfg(feature = "enable_metrics")]
static ORGANIZATIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_organizations_total", "Total number of organizations", &["status"]).unwrap()
});

#[cfg(feature = "enable_metrics")]
static VAULT_ITEMS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_vault_items_total", "Total number of vault items", &["type", "organization"])
        .unwrap()
});

#[cfg(feature = "enable_metrics")]
static COLLECTIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_collections_total", "Total number of collections", &["organization"]).unwrap()
});

// System metrics
#[cfg(feature = "enable_metrics")]
static UPTIME_SECONDS: Lazy<GaugeVec> =
    Lazy::new(|| register_gauge_vec!("vaultwarden_uptime_seconds", "Uptime in seconds", &["version"]).unwrap());

#[cfg(feature = "enable_metrics")]
static BUILD_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_build_info", "Build information", &["version", "revision", "branch"]).unwrap()
});

/// Increment HTTP request counter
#[cfg(feature = "enable_metrics")]
pub fn increment_http_requests(method: &str, path: &str, status: u16) {
    HTTP_REQUESTS_TOTAL.with_label_values(&[method, path, &status.to_string()]).inc();
}

/// Observe HTTP request duration
#[cfg(feature = "enable_metrics")]
pub fn observe_http_request_duration(method: &str, path: &str, duration_seconds: f64) {
    HTTP_REQUEST_DURATION_SECONDS.with_label_values(&[method, path]).observe(duration_seconds);
}

/// Update database connection metrics
#[cfg(feature = "enable_metrics")]
pub fn update_db_connections(database: &str, active: i64, idle: i64) {
    DB_CONNECTIONS_ACTIVE.with_label_values(&[database]).set(active);
    DB_CONNECTIONS_IDLE.with_label_values(&[database]).set(idle);
}

/// Observe database query duration
#[cfg(feature = "enable_metrics")]
pub fn observe_db_query_duration(operation: &str, duration_seconds: f64) {
    DB_QUERY_DURATION_SECONDS.with_label_values(&[operation]).observe(duration_seconds);
}

/// Increment authentication attempts
#[cfg(feature = "enable_metrics")]
pub fn increment_auth_attempts(method: &str, status: &str) {
    AUTH_ATTEMPTS_TOTAL.with_label_values(&[method, status]).inc();
}

/// Update active user sessions
#[cfg(feature = "enable_metrics")]
pub fn update_user_sessions(user_type: &str, count: i64) {
    USER_SESSIONS_ACTIVE.with_label_values(&[user_type]).set(count);
}
/// Cached business metrics data
#[cfg(feature = "enable_metrics")]
#[derive(Clone)]
struct BusinessMetricsCache {
    timestamp: u64,
    users_enabled: i64,
    users_disabled: i64,
    organizations: i64,
    vault_counts: std::collections::HashMap<(String, String), i64>,
    collection_counts: std::collections::HashMap<String, i64>,
}

#[cfg(feature = "enable_metrics")]
static BUSINESS_METRICS_CACHE: Lazy<RwLock<Option<BusinessMetricsCache>>> = Lazy::new(|| RwLock::new(None));

/// Check if business metrics cache is still valid
#[cfg(feature = "enable_metrics")]
fn is_cache_valid() -> bool {
    let cache_timeout = CONFIG.metrics_business_cache_seconds();
    if let Ok(cache) = BUSINESS_METRICS_CACHE.read() {
        if let Some(ref cached) = *cache {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            return now - cached.timestamp < cache_timeout;
        }
    }
    false
}

/// Update cached business metrics
#[cfg(feature = "enable_metrics")]
fn update_cached_metrics(cache: BusinessMetricsCache) {
    if let Ok(mut cached) = BUSINESS_METRICS_CACHE.write() {
        *cached = Some(cache);
    }
}

/// Apply cached metrics to Prometheus gauges
#[cfg(feature = "enable_metrics")]
fn apply_cached_metrics(cache: &BusinessMetricsCache) {
    USERS_TOTAL.with_label_values(&["enabled"]).set(cache.users_enabled);
    USERS_TOTAL.with_label_values(&["disabled"]).set(cache.users_disabled);
    ORGANIZATIONS_TOTAL.with_label_values(&["active"]).set(cache.organizations);

    for ((cipher_type, org_label), count) in &cache.vault_counts {
        VAULT_ITEMS_TOTAL.with_label_values(&[cipher_type, org_label]).set(*count);
    }

    for (org_id, count) in &cache.collection_counts {
        COLLECTIONS_TOTAL.with_label_values(&[org_id]).set(*count);
    }
}

/// Update business metrics from database (with caching)
#[cfg(feature = "enable_metrics")]
pub async fn update_business_metrics(conn: &mut DbConn) -> Result<(), Error> {
    // Check if cache is still valid
    if is_cache_valid() {
        // Apply cached metrics without DB query
        if let Ok(cache) = BUSINESS_METRICS_CACHE.read() {
            if let Some(ref cached) = *cache {
                apply_cached_metrics(cached);
                return Ok(());
            }
        }
    }

    use crate::db::models::*;
    use std::collections::HashMap;

    // Count users
    let enabled_users = User::count_enabled(conn).await;
    let disabled_users = User::count_disabled(conn).await;

    // Count organizations
    let organizations_vec = Organization::get_all(conn).await;
    let active_orgs = organizations_vec.len() as i64;

    // Count vault items by type and organization
    let vault_counts = Cipher::count_by_type_and_org(conn).await;

    // Count collections per organization
    let mut collection_counts: HashMap<String, i64> = HashMap::new();
    for org in &organizations_vec {
        let count = Collection::count_by_org(&org.uuid, conn).await;
        collection_counts.insert(org.uuid.to_string(), count);
    }

    // Create cache entry
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let cache = BusinessMetricsCache {
        timestamp: now,
        users_enabled: enabled_users,
        users_disabled: disabled_users,
        organizations: active_orgs,
        vault_counts,
        collection_counts,
    };

    // Update cache and apply metrics
    update_cached_metrics(cache.clone());
    apply_cached_metrics(&cache);

    Ok(())
}

/// Initialize build info metrics
#[cfg(feature = "enable_metrics")]
pub fn init_build_info() {
    let version = crate::VERSION.unwrap_or("unknown");
    BUILD_INFO.with_label_values(&[version, "unknown", "unknown"]).set(1);
}

/// Update system uptime
#[cfg(feature = "enable_metrics")]
pub fn update_uptime(start_time: SystemTime) {
    if let Ok(elapsed) = start_time.elapsed() {
        let version = crate::VERSION.unwrap_or("unknown");
        UPTIME_SECONDS.with_label_values(&[version]).set(elapsed.as_secs_f64());
    }
}

/// Gather all metrics and return as Prometheus text format
#[cfg(feature = "enable_metrics")]
pub fn gather_metrics() -> Result<String, Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut output) {
        return Err(Error::new(format!("Failed to encode metrics: {}", e), ""));
    }
    match String::from_utf8(output) {
        Ok(s) => Ok(s),
        Err(e) => Err(Error::new(format!("Failed to convert metrics to string: {}", e), "")),
    }
}

// No-op implementations when metrics are disabled
#[cfg(not(feature = "enable_metrics"))]
pub fn increment_http_requests(_method: &str, _path: &str, _status: u16) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn observe_http_request_duration(_method: &str, _path: &str, _duration_seconds: f64) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn update_db_connections(_database: &str, _active: i64, _idle: i64) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn observe_db_query_duration(_operation: &str, _duration_seconds: f64) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn increment_auth_attempts(_method: &str, _status: &str) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn update_user_sessions(_user_type: &str, _count: i64) {}

#[cfg(not(feature = "enable_metrics"))]
pub async fn update_business_metrics(_conn: &mut DbConn) -> Result<(), Error> {
    Ok(())
}

#[cfg(not(feature = "enable_metrics"))]
pub fn init_build_info() {}

#[cfg(not(feature = "enable_metrics"))]
pub fn update_uptime(_start_time: SystemTime) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn gather_metrics() -> Result<String, Error> {
    Ok("Metrics not enabled".to_string())
}
