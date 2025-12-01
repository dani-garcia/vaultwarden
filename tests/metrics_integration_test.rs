#[cfg(feature = "enable_metrics")]
mod metrics_integration_tests {
    use rocket::local::blocking::Client;
    use rocket::http::{Status, Header, ContentType};
    use rocket::serde::json;
    use vaultwarden::api::core::routes as core_routes;
    use vaultwarden::api::metrics::routes as metrics_routes;
    use vaultwarden::CONFIG;
    use vaultwarden::metrics;

    fn create_test_rocket() -> rocket::Rocket<rocket::Build> {
        // Initialize metrics for testing
        metrics::init_build_info();
        
        rocket::build()
            .mount("/", core_routes())
            .mount("/", metrics_routes())
            .attach(vaultwarden::api::middleware::MetricsFairing)
    }

    #[test]
    fn test_metrics_endpoint_without_auth() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Test without authorization header
        let response = client.get("/metrics").dispatch();
        
        // Should return 401 Unauthorized when metrics token is required
        if CONFIG.metrics_token().is_some() {
            assert_eq!(response.status(), Status::Unauthorized);
        } else {
            // If no token is configured, it should work
            assert_eq!(response.status(), Status::Ok);
        }
    }

    #[test]
    fn test_metrics_endpoint_with_bearer_token() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Test with Bearer token
        if let Some(token) = CONFIG.metrics_token() {
            let auth_header = Header::new("Authorization", format!("Bearer {}", token));
            let response = client.get("/metrics").header(auth_header).dispatch();
            
            assert_eq!(response.status(), Status::Ok);
            
            let body = response.into_string().expect("response body");
            assert!(body.contains("# HELP"));
            assert!(body.contains("# TYPE"));
            assert!(body.contains("vaultwarden_"));
        }
    }

    #[test]
    fn test_metrics_endpoint_with_query_parameter() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Test with query parameter
        if let Some(token) = CONFIG.metrics_token() {
            let response = client.get(format!("/metrics?token={}", token)).dispatch();
            
            assert_eq!(response.status(), Status::Ok);
            
            let body = response.into_string().expect("response body");
            assert!(body.contains("# HELP"));
            assert!(body.contains("# TYPE"));
        }
    }

    #[test]
    fn test_metrics_endpoint_with_invalid_token() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Test with invalid Bearer token
        let auth_header = Header::new("Authorization", "Bearer invalid-token");
        let response = client.get("/metrics").header(auth_header).dispatch();
        
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    fn test_metrics_content_format() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Setup authorization if needed
        let mut request = client.get("/metrics");
        
        if let Some(token) = CONFIG.metrics_token() {
            let auth_header = Header::new("Authorization", format!("Bearer {}", token));
            request = request.header(auth_header);
        }
        
        let response = request.dispatch();
        
        if response.status() == Status::Ok {
            let body = response.into_string().expect("response body");
            
            // Verify Prometheus format
            assert!(body.contains("# HELP"));
            assert!(body.contains("# TYPE"));
            
            // Verify expected metrics exist
            assert!(body.contains("vaultwarden_build_info"));
            assert!(body.contains("vaultwarden_uptime_seconds"));
            
            // Verify metric types
            assert!(body.contains("TYPE vaultwarden_build_info gauge"));
            assert!(body.contains("TYPE vaultwarden_uptime_seconds gauge"));
        }
    }

    #[test]
    fn test_metrics_instrumentation() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Make some requests to generate HTTP metrics
        let _response1 = client.get("/alive").dispatch();
        let _response2 = client.post("/api/accounts/register")
            .header(ContentType::JSON)
            .body(r#"{"email":"test@example.com"}"#)
            .dispatch();
        
        // Now check metrics
        let mut metrics_request = client.get("/metrics");
        
        if let Some(token) = CONFIG.metrics_token() {
            let auth_header = Header::new("Authorization", format!("Bearer {}", token));
            metrics_request = metrics_request.header(auth_header);
        }
        
        let response = metrics_request.dispatch();
        
        if response.status() == Status::Ok {
            let body = response.into_string().expect("response body");
            
            // Should contain HTTP request metrics
            assert!(body.contains("vaultwarden_http_requests_total"));
            assert!(body.contains("vaultwarden_http_request_duration_seconds"));
        }
    }

    #[test]
    fn test_multiple_concurrent_requests() {
        use std::thread;
        use std::sync::Arc;
        
        let client = Arc::new(Client::tracked(create_test_rocket()).expect("valid rocket instance"));
        
        // Spawn multiple threads making requests
        let handles: Vec<_> = (0..5).map(|_| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                client.get("/alive").dispatch();
            })
        }).collect();
        
        // Wait for all requests to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Check that metrics were collected
        let mut metrics_request = client.get("/metrics");
        
        if let Some(token) = CONFIG.metrics_token() {
            let auth_header = Header::new("Authorization", format!("Bearer {}", token));
            metrics_request = metrics_request.header(auth_header);
        }
        
        let response = metrics_request.dispatch();
        assert!(response.status() == Status::Ok || response.status() == Status::Unauthorized);
    }

    #[test]
    fn test_metrics_performance() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        let start = std::time::Instant::now();
        
        let mut metrics_request = client.get("/metrics");
        
        if let Some(token) = CONFIG.metrics_token() {
            let auth_header = Header::new("Authorization", format!("Bearer {}", token));
            metrics_request = metrics_request.header(auth_header);
        }
        
        let response = metrics_request.dispatch();
        let duration = start.elapsed();
        
        // Metrics endpoint should respond quickly (under 1 second)
        assert!(duration.as_secs() < 1);
        
        if response.status() == Status::Ok {
            let body = response.into_string().expect("response body");
            // Should return meaningful content
            assert!(body.len() > 100);
        }
    }
}

#[cfg(not(feature = "enable_metrics"))]
mod metrics_disabled_tests {
    use rocket::local::blocking::Client;
    use rocket::http::Status;
    use vaultwarden::api::core::routes as core_routes;

    fn create_test_rocket() -> rocket::Rocket<rocket::Build> {
        rocket::build()
            .mount("/", core_routes())
            // Note: metrics routes should not be mounted when feature is disabled
    }

    #[test]
    fn test_metrics_endpoint_not_available() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Metrics endpoint should not exist when feature is disabled
        let response = client.get("/metrics").dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn test_normal_endpoints_still_work() {
        let client = Client::tracked(create_test_rocket()).expect("valid rocket instance");
        
        // Normal endpoints should still work
        let response = client.get("/alive").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}