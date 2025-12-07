#![allow(dead_code, unused_imports)]

use crate::db::DbConn;

#[cfg(feature = "enable_metrics")]
use once_cell::sync::Lazy;
#[cfg(feature = "enable_metrics")]
use prometheus::{
    register_gauge_vec, register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    Encoder, GaugeVec, HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder,
};

#[cfg(feature = "enable_metrics")]
use crate::db::DbConn;

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
    register_int_gauge_vec!(
        "vaultwarden_db_connections_active",
        "Number of active database connections",
        &["database"]
    )
    .unwrap()
});

#[cfg(feature = "enable_metrics")]
static DB_CONNECTIONS_IDLE: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "vaultwarden_db_connections_idle",
        "Number of idle database connections",
        &["database"]
    )
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
    register_int_gauge_vec!(
        "vaultwarden_user_sessions_active",
        "Number of active user sessions",
        &["user_type"]
    )
    .unwrap()
});

// Business metrics
#[cfg(feature = "enable_metrics")]
static USERS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_users_total", "Total number of users", &["status"]).unwrap()
});

#[cfg(feature = "enable_metrics")]
static ORGANIZATIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_organizations_total", "Total number of organizations", &["status"]).unwrap()
});

#[cfg(feature = "enable_metrics")]
static VAULT_ITEMS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "vaultwarden_vault_items_total",
        "Total number of vault items",
        &["type", "organization"]
    )
    .unwrap()
});

#[cfg(feature = "enable_metrics")]
static COLLECTIONS_TOTAL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!("vaultwarden_collections_total", "Total number of collections", &["organization"]).unwrap()
});

// System metrics
#[cfg(feature = "enable_metrics")]
static UPTIME_SECONDS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!("vaultwarden_uptime_seconds", "Uptime in seconds", &["version"]).unwrap()
});

#[cfg(feature = "enable_metrics")]
static BUILD_INFO: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "vaultwarden_build_info",
        "Build information",
        &["version", "revision", "branch"]
    )
    .unwrap()
});

/// Increment HTTP request counter
#[cfg(feature = "enable_metrics")]
pub fn increment_http_requests(method: &str, path: &str, status: u16) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, path, &status.to_string()])
        .inc();
}

/// Observe HTTP request duration
#[cfg(feature = "enable_metrics")]
pub fn observe_http_request_duration(method: &str, path: &str, duration_seconds: f64) {
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, path])
        .observe(duration_seconds);
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
    DB_QUERY_DURATION_SECONDS
        .with_label_values(&[operation])
        .observe(duration_seconds);
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

/// Update business metrics from database
#[cfg(feature = "enable_metrics")]
pub async fn update_business_metrics(conn: &mut DbConn) -> Result<(), crate::error::Error> {
    use crate::db::models::*;

    // Count users
    let users = User::get_all(conn).await;
    let enabled_users = users.iter().filter(|(user, _)| user.enabled).count() as i64;
    let disabled_users = users.iter().filter(|(user, _)| !user.enabled).count() as i64;
    
    USERS_TOTAL.with_label_values(&["enabled"]).set(enabled_users);
    USERS_TOTAL.with_label_values(&["disabled"]).set(disabled_users);

    // Count organizations
    let organizations = Organization::get_all(conn).await;
    let active_orgs = organizations.len() as i64;
    ORGANIZATIONS_TOTAL.with_label_values(&["active"]).set(active_orgs);

    // Update vault items by type
    for (user, _) in &users {
        let ciphers = Cipher::find_owned_by_user(&user.uuid, conn).await;
        for cipher in ciphers {
            let cipher_type = match cipher.atype {
                1 => "login",
                2 => "note",
                3 => "card",
                4 => "identity",
                _ => "unknown",
            };
            let org_id_string;
            let org_label = if let Some(id) = &cipher.organization_uuid {
                org_id_string = id.to_string();
                &org_id_string
            } else {
                "personal"
            };
            VAULT_ITEMS_TOTAL.with_label_values(&[cipher_type, org_label]).inc();
        }
    }

    // Count collections per organization
    for org in &organizations {
        let collections = Collection::find_by_organization(&org.uuid, conn).await;
        COLLECTIONS_TOTAL
            .with_label_values(&[&org.uuid.to_string()])
            .set(collections.len() as i64);
    }

    Ok(())
}

/// Initialize build info metrics
#[cfg(feature = "enable_metrics")]
pub fn init_build_info() {
    let version = crate::VERSION.unwrap_or("unknown");
    BUILD_INFO
        .with_label_values(&[version, "unknown", "unknown"])
        .set(1);
}

/// Update system uptime
#[cfg(feature = "enable_metrics")]
pub fn update_uptime(start_time: std::time::SystemTime) {
    if let Ok(elapsed) = start_time.elapsed() {
        let version = crate::VERSION.unwrap_or("unknown");
        UPTIME_SECONDS
            .with_label_values(&[version])
            .set(elapsed.as_secs_f64());
    }
}

/// Gather all metrics and return as Prometheus text format
#[cfg(feature = "enable_metrics")]
pub fn gather_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    encoder.encode(&metric_families, &mut output)?;
    Ok(String::from_utf8(output)?)
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
pub async fn update_business_metrics(_conn: &mut DbConn) -> Result<(), crate::error::Error> {
    Ok(())
}

#[cfg(not(feature = "enable_metrics"))]
pub fn init_build_info() {}

#[cfg(not(feature = "enable_metrics"))]
pub fn update_uptime(_start_time: std::time::SystemTime) {}

#[cfg(not(feature = "enable_metrics"))]
pub fn gather_metrics() -> Result<String, Box<dyn std::error::Error>> {
    Ok("Metrics not enabled".to_string())
}