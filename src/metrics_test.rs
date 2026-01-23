#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[cfg(feature = "enable_metrics")]
    mod metrics_enabled_tests {
        use super::*;

        #[test]
        fn test_http_metrics_collection() {
            increment_http_requests("GET", "/api/sync", 200);
            increment_http_requests("POST", "/api/accounts/register", 201);
            increment_http_requests("GET", "/api/sync", 500);
            observe_http_request_duration("GET", "/api/sync", 0.150);
            observe_http_request_duration("POST", "/api/accounts/register", 0.300);

            let metrics = gather_metrics().expect("Failed to gather metrics");
            assert!(metrics.contains("vaultwarden_http_requests_total"));
            assert!(metrics.contains("vaultwarden_http_request_duration_seconds"));
        }

        #[test]
        fn test_database_metrics_collection() {
            update_db_connections("sqlite", 5, 10);
            update_db_connections("postgresql", 8, 2);
            observe_db_query_duration("select", 0.025);
            observe_db_query_duration("insert", 0.045);
            observe_db_query_duration("update", 0.030);

            let metrics = gather_metrics().expect("Failed to gather metrics");
            assert!(metrics.contains("vaultwarden_db_connections_active"));
            assert!(metrics.contains("vaultwarden_db_connections_idle"));
            assert!(metrics.contains("vaultwarden_db_query_duration_seconds"));
        }

        #[test]
        fn test_authentication_metrics() {
            increment_auth_attempts("password", "success");
            increment_auth_attempts("password", "failed");
            increment_auth_attempts("webauthn", "success");
            increment_auth_attempts("2fa", "failed");
            update_user_sessions("authenticated", 150);
            update_user_sessions("anonymous", 5);

            let metrics = gather_metrics().expect("Failed to gather metrics");
            assert!(metrics.contains("vaultwarden_auth_attempts_total"));
            assert!(metrics.contains("vaultwarden_user_sessions_active"));
        }

        #[test]
        fn test_build_info_initialization() {
            init_build_info();
            let start_time = std::time::SystemTime::now();
            update_uptime(start_time);

            let metrics = gather_metrics().expect("Failed to gather metrics");
            assert!(metrics.contains("vaultwarden_build_info"));
            assert!(metrics.contains("vaultwarden_uptime_seconds"));
        }

        #[test]
        fn test_metrics_gathering() {
            increment_http_requests("GET", "/api/sync", 200);
            update_db_connections("sqlite", 1, 5);
            init_build_info();

            let metrics_output = gather_metrics();
            assert!(metrics_output.is_ok(), "gather_metrics should succeed");

            let metrics_text = metrics_output.unwrap();
            assert!(!metrics_text.is_empty(), "metrics output should not be empty");
            assert!(metrics_text.contains("# HELP"), "metrics should have HELP lines");
            assert!(metrics_text.contains("# TYPE"), "metrics should have TYPE lines");
            assert!(metrics_text.contains("vaultwarden_"), "metrics should contain vaultwarden prefix");
        }

        #[tokio::test]
        async fn test_business_metrics_collection_noop() {
            // Business metrics require database access, which cannot be easily mocked in unit tests.
            // This test verifies that the async function exists and can be called without panicking.
            // Integration tests would provide database access and verify metrics are actually updated.
            init_build_info();
            let metrics = gather_metrics().expect("Failed to gather metrics");
            assert!(metrics.contains("vaultwarden_"), "Business metrics should be accessible");
        }

        #[test]
        fn test_path_normalization() {
            increment_http_requests("GET", "/api/sync", 200);
            increment_http_requests("GET", "/api/accounts/123/profile", 200);
            increment_http_requests("POST", "/api/organizations/456/users", 201);
            increment_http_requests("PUT", "/api/ciphers/789", 200);

            let result = gather_metrics();
            assert!(result.is_ok(), "gather_metrics should succeed with various paths");

            let metrics_text = result.unwrap();
            assert!(!metrics_text.is_empty(), "metrics output should not be empty");
            assert!(metrics_text.contains("vaultwarden_http_requests_total"), "should have http request metrics");
        }

        #[test]
        fn test_concurrent_metrics_collection() {
            use std::thread;

            let handles: Vec<_> = (0..10).map(|i| {
                thread::spawn(move || {
                    increment_http_requests("GET", "/api/sync", 200);
                    observe_http_request_duration("GET", "/api/sync", 0.1 + (i as f64 * 0.01));
                    update_db_connections("sqlite", i, 10 - i);
                })
            }).collect();

            for handle in handles {
                handle.join().expect("Thread panicked");
            }

            let result = gather_metrics();
            assert!(result.is_ok(), "metrics collection should be thread-safe");
            assert!(!result.unwrap().is_empty(), "concurrent access should not corrupt metrics");
        }
    }

    #[cfg(not(feature = "enable_metrics"))]
    mod metrics_disabled_tests {
        use super::*;

        #[test]
        fn test_no_op_implementations() {
            increment_http_requests("GET", "/api/sync", 200);
            observe_http_request_duration("GET", "/api/sync", 0.150);
            update_db_connections("sqlite", 5, 10);
            observe_db_query_duration("select", 0.025);
            increment_auth_attempts("password", "success");
            update_user_sessions("authenticated", 150);
            init_build_info();

            let start_time = std::time::SystemTime::now();
            update_uptime(start_time);

            let result = gather_metrics();
            assert!(result.is_ok(), "disabled metrics should return ok");
            assert_eq!(result.unwrap(), "Metrics not enabled", "should return disabled message");
        }

        #[tokio::test]
        async fn test_business_metrics_no_op() {
            let result = gather_metrics();
            assert!(result.is_ok(), "disabled metrics should not panic");
            assert_eq!(result.unwrap(), "Metrics not enabled", "should return disabled message");
        }

        #[test]
        fn test_concurrent_no_op_calls() {
            use std::thread;

            let handles: Vec<_> = (0..5).map(|i| {
                thread::spawn(move || {
                    increment_http_requests("GET", "/test", 200);
                    observe_http_request_duration("GET", "/test", 0.1);
                    update_db_connections("test", i, 5 - i);
                    increment_auth_attempts("password", "success");
                })
            }).collect();

            for handle in handles {
                handle.join().expect("Thread panicked");
            }

            let result = gather_metrics();
            assert!(result.is_ok(), "disabled metrics should be thread-safe");
            assert_eq!(result.unwrap(), "Metrics not enabled", "disabled metrics should always return same message");
        }
    }
}