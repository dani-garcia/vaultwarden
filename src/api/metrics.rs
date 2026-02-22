use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    response::content::RawText,
    Route,
};

use crate::{auth::ClientIp, db::DbConn, CONFIG};

use log::error;

// Metrics endpoint routes
pub fn routes() -> Vec<Route> {
    if CONFIG.enable_metrics() {
        routes![get_metrics]
    } else {
        Vec::new()
    }
}

// Metrics authentication token guard
#[allow(dead_code)]
pub struct MetricsToken {
    ip: ClientIp,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MetricsToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match ClientIp::from_request(request).await {
            Outcome::Success(ip) => ip,
            _ => return Outcome::Error((Status::InternalServerError, "Error getting Client IP")),
        };

        // If no metrics token is configured, allow access
        let Some(configured_token) = CONFIG.metrics_token() else {
            return Outcome::Success(Self {
                ip,
            });
        };

        // Check for token in Authorization header or query parameter
        let provided_token = request
            .headers()
            .get_one("Authorization")
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .or_else(|| request.query_value::<&str>("token").and_then(|result| result.ok()));

        match provided_token {
            Some(token) => {
                if validate_metrics_token(token, &configured_token) {
                    Outcome::Success(Self {
                        ip,
                    })
                } else {
                    error!("Invalid metrics token. IP: {}", ip.ip);
                    Outcome::Error((Status::Unauthorized, "Invalid metrics token"))
                }
            }
            None => {
                error!("Missing metrics token. IP: {}", ip.ip);
                Outcome::Error((Status::Unauthorized, "Metrics token required"))
            }
        }
    }
}

fn validate_metrics_token(provided: &str, configured: &str) -> bool {
    if configured.starts_with("$argon2") {
        use argon2::password_hash::PasswordVerifier;
        match argon2::password_hash::PasswordHash::new(configured) {
            Ok(hash) => argon2::Argon2::default().verify_password(provided.trim().as_bytes(), &hash).is_ok(),
            Err(e) => {
                error!("Invalid Argon2 PHC in METRICS_TOKEN: {e}");
                false
            }
        }
    } else {
        crate::crypto::ct_eq(configured.trim(), provided.trim())
    }
}

/// Prometheus metrics endpoint
#[get("/")]
async fn get_metrics(_token: MetricsToken, mut conn: DbConn) -> Result<RawText<String>, Status> {
    // Update business metrics from database
    if let Err(e) = crate::metrics::update_business_metrics(&mut conn).await {
        error!("Failed to update business metrics: {e}");
        return Err(Status::InternalServerError);
    }

    // Gather all Prometheus metrics
    match crate::metrics::gather_metrics() {
        Ok(metrics) => Ok(RawText(metrics)),
        Err(e) => {
            error!("Failed to gather metrics: {e}");
            Err(Status::InternalServerError)
        }
    }
}

/// Health check endpoint that also updates some basic metrics
#[cfg(feature = "enable_metrics")]
pub fn update_health_metrics(_conn: &mut DbConn) {
    // Update basic system metrics
    use std::time::SystemTime;
    static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();
    let start_time = *START_TIME.get_or_init(SystemTime::now);

    crate::metrics::update_uptime(start_time);

    // Update database connection metrics
    // Note: This is a simplified version - in production you'd want to get actual pool stats
    crate::metrics::update_db_connections("main", 1, 0);
}

#[cfg(not(feature = "enable_metrics"))]
pub fn update_health_metrics(_conn: &mut DbConn) {}
