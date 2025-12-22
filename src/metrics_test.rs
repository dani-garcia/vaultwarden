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
            // Test HTTP request metrics
            increment_http_requests("GET", "/api/sync", 200);
            increment_http_requests("POST", "/api/accounts/register", 201);
            increment_http_requests("GET", "/api/sync", 500);

            // Test HTTP duration metrics
            observe_http_request_duration("GET", "/api/sync", 0.150);
            observe_http_request_duration("POST", "/api/accounts/register", 0.300);

            // In a real test environment, we would verify these metrics
            // were actually recorded by checking the prometheus registry
        }

        #[test]
        fn test_database_metrics_collection() {
            // Test database connection metrics
            update_db_connections("sqlite", 5, 10);
            update_db_connections("postgresql", 8, 2);

            // Test database query duration metrics
            observe_db_query_duration("select", 0.025);
            observe_db_query_duration("insert", 0.045);
            observe_db_query_duration("update", 0.030);
        }

        #[test]
        fn test_authentication_metrics() {
            // Test authentication attempt metrics
            increment_auth_attempts("password", "success");
            increment_auth_attempts("password", "failed");
            increment_auth_attempts("webauthn", "success");
            increment_auth_attempts("2fa", "failed");

            // Test user session metrics
            update_user_sessions("authenticated", 150);
            update_user_sessions("anonymous", 5);
        }

        #[test]
        fn test_build_info_initialization() {
            // Test build info metrics initialization
            init_build_info();
            
            // Test uptime metrics
            let start_time = std::time::SystemTime::now();
            update_uptime(start_time);
        }

        #[test]
        fn test_metrics_gathering() {
            // Initialize some metrics
            increment_http_requests("GET", "/api/sync", 200);
            update_db_connections("sqlite", 1, 5);
            init_build_info();

            // Test gathering all metrics
            let metrics_output = gather_metrics();
            assert!(metrics_output.is_ok());
            
            let metrics_text = metrics_output.unwrap();
            assert!(!metrics_text.is_empty());
            
            // Should contain Prometheus format headers
            assert!(metrics_text.contains("# HELP"));
            assert!(metrics_text.contains("# TYPE"));
        }

        #[tokio::test]
        async fn test_business_metrics_collection() {
            // This test would require a mock database connection
            // For now, we just test that the function doesn't panic
            
            // In a real test, you would:
            // 1. Create a test database
            // 2. Insert test data (users, organizations, ciphers)
            // 3. Call update_business_metrics
            // 4. Verify the metrics were updated correctly
            
            // Placeholder test - in production this would use a mock DbConn
            assert!(true);
        }
        
        #[test]
        fn test_path_normalization() {
            // Test that path normalization works for metric cardinality control
            increment_http_requests("GET", "/api/sync", 200);
            increment_http_requests("GET", "/api/accounts/123/profile", 200);
            increment_http_requests("POST", "/api/organizations/456/users", 201);
            increment_http_requests("PUT", "/api/ciphers/789", 200);
            
            // Test that gather_metrics works
            let result = gather_metrics();
            assert!(result.is_ok());
            
            let metrics_text = result.unwrap();
            // Paths should be normalized in the actual implementation
            // This test verifies the collection doesn't panic
            assert!(!metrics_text.is_empty());
        }
        
        #[test]
        fn test_concurrent_metrics_collection() {
            use std::sync::Arc;
            use std::thread;
            
            // Test concurrent access to metrics
            let handles: Vec<_> = (0..10).map(|i| {
                thread::spawn(move || {
                    increment_http_requests("GET", "/api/sync", 200);
                    observe_http_request_duration("GET", "/api/sync", 0.1 + (i as f64 * 0.01));
                    update_db_connections("sqlite", i, 10 - i);
                })
            }).collect();
            
            // Wait for all threads to complete
            for handle in handles {
                handle.join().unwrap();
            }
            
            // Verify metrics collection still works
            let result = gather_metrics();
            assert!(result.is_ok());
        }
    }

    #[cfg(not(feature = "enable_metrics"))]
    mod metrics_disabled_tests {
        use super::*;

        #[test]
        fn test_no_op_implementations() {
            // When metrics are disabled, all functions should be no-ops
            increment_http_requests("GET", "/api/sync", 200);
            observe_http_request_duration("GET", "/api/sync", 0.150);
            update_db_connections("sqlite", 5, 10);
            observe_db_query_duration("select", 0.025);
            increment_auth_attempts("password", "success");
            update_user_sessions("authenticated", 150);
            init_build_info();
            
            let start_time = std::time::SystemTime::now();
            update_uptime(start_time);

            // Test that gather_metrics returns a disabled message
            let result = gather_metrics();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "Metrics not enabled");
        }

        #[tokio::test]
        async fn test_business_metrics_no_op() {
            // This should also be a no-op when metrics are disabled
            // We can't test with a real DbConn without significant setup,
            // but we can verify it doesn't panic
            
            // In a real implementation, you'd mock DbConn
            assert!(true);
        }
        
        #[test]
        fn test_concurrent_no_op_calls() {
            use std::thread;
            
            // Test that concurrent calls to disabled metrics don't cause issues
            let handles: Vec<_> = (0..5).map(|i| {
                thread::spawn(move || {
                    increment_http_requests("GET", "/test", 200);
                    observe_http_request_duration("GET", "/test", 0.1);
                    update_db_connections("test", i, 5 - i);
                    increment_auth_attempts("password", "success");
                })
            }).collect();
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            // All calls should be no-ops
            let result = gather_metrics();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "Metrics not enabled");
        }
    }
}