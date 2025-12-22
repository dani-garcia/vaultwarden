/// Metrics middleware for automatic HTTP request instrumentation
use rocket::{
    fairing::{Fairing, Info, Kind},
    Data, Request, Response,
};
use std::time::Instant;

pub struct MetricsFairing;

#[rocket::async_trait]
impl Fairing for MetricsFairing {
    fn info(&self) -> Info {
        Info {
            name: "Metrics Collection",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        req.local_cache(|| RequestTimer {
            start_time: Instant::now(),
        });
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let timer = req.local_cache(|| RequestTimer {
            start_time: Instant::now(),
        });
        let duration = timer.start_time.elapsed();
        let method = req.method().as_str();
        let path = normalize_path(req.uri().path().as_str());
        let status = res.status().code;

        // Record metrics
        crate::metrics::increment_http_requests(method, &path, status);
        crate::metrics::observe_http_request_duration(method, &path, duration.as_secs_f64());
    }
}

struct RequestTimer {
    start_time: Instant,
}

/// Normalize paths to avoid high cardinality metrics
/// Convert dynamic segments to static labels
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut normalized = Vec::new();

    for segment in segments {
        if segment.is_empty() {
            continue;
        }

<<<<<<< HEAD
        // Common patterns in Vaultwarden routes
        let normalized_segment = if is_uuid(segment) {
            "{id}"
        } else if segment.chars().all(|c| c.is_ascii_hexdigit()) && segment.len() > 10 {
            "{hash}"
        } else if segment.chars().all(|c| c.is_ascii_digit()) {
            "{number}"
        } else {
            segment
        };

        normalized.push(normalized_segment);
    }

    if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", normalized.join("/"))
    }
}

/// Check if a string looks like a UUID
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}
/// Check if a string looks like a UUID
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/api/accounts"), "/api/accounts");
        assert_eq!(normalize_path("/api/accounts/12345678-1234-5678-9012-123456789012"), "/api/accounts/{id}");
        assert_eq!(normalize_path("/attachments/abc123def456"), "/attachments/{hash}");
        assert_eq!(normalize_path("/api/organizations/123"), "/api/organizations/{number}");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("12345678-1234-5678-9012-123456789012"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("12345678123456781234567812345678")); // No dashes
        assert!(!is_uuid("123")); // Too short
    }
    }
}
