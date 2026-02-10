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

        let normalized_segment = if is_uuid(segment) {
            "{id}"
        } else if is_hex_hash(segment) {
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

/// Check if a string is a hex hash (32+ hex chars, typical for SHA256, MD5, etc)
fn is_hex_hash(s: &str) -> bool {
    s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit())
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
    fn test_normalize_path_preserves_static_routes() {
        assert_eq!(normalize_path("/api/accounts"), "/api/accounts");
        assert_eq!(normalize_path("/api/sync"), "/api/sync");
        assert_eq!(normalize_path("/icons"), "/icons");
    }

    #[test]
    fn test_normalize_path_replaces_uuid() {
        let uuid = "12345678-1234-5678-9012-123456789012";
        assert_eq!(
            normalize_path(&format!("/api/accounts/{uuid}")),
            "/api/accounts/{id}"
        );
        assert_eq!(
            normalize_path(&format!("/ciphers/{uuid}")),
            "/ciphers/{id}"
        );
    }

    #[test]
    fn test_normalize_path_replaces_sha256_hash() {
        // SHA256 hashes are 64 hex characters
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            normalize_path(&format!("/attachments/{sha256}")),
            "/attachments/{hash}"
        );
    }

    #[test]
    fn test_normalize_path_does_not_replace_short_hex() {
        // Only consider 32+ char hex strings as hashes
        assert_eq!(normalize_path("/api/hex123"), "/api/hex123");
        assert_eq!(normalize_path("/test/abc"), "/test/abc");
        assert_eq!(normalize_path("/api/abcdef1234567890"), "/api/abcdef1234567890"); // 16 chars
        assert_eq!(normalize_path("/files/0123456789abcdef"), "/files/0123456789abcdef"); // 16 chars
    }

    #[test]
    fn test_normalize_path_replaces_numbers() {
        assert_eq!(normalize_path("/api/organizations/123"), "/api/organizations/{number}");
        assert_eq!(normalize_path("/users/456/profile"), "/users/{number}/profile");
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_empty_segments() {
        assert_eq!(normalize_path("//api//accounts"), "/api/accounts");
    }

    #[test]
    fn test_is_uuid_valid() {
        assert!(is_uuid("12345678-1234-5678-9012-123456789012"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(is_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    }

    #[test]
    fn test_is_uuid_invalid_format() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("12345678123456781234567812345678"));
        assert!(!is_uuid("123"));
        assert!(!is_uuid(""));
        assert!(!is_uuid("12345678-1234-5678-9012-12345678901")); // Too short
        assert!(!is_uuid("12345678-1234-5678-9012-1234567890123")); // Too long
    }

    #[test]
    fn test_is_uuid_invalid_characters() {
        assert!(!is_uuid("12345678-1234-5678-9012-12345678901z"));
        assert!(!is_uuid("g2345678-1234-5678-9012-123456789012"));
    }

    #[test]
    fn test_is_uuid_invalid_dash_positions() {
        assert!(!is_uuid("12345678-1234-56789012-123456789012"));
        assert!(!is_uuid("12345678-1234-5678-90121-23456789012"));
    }
}
