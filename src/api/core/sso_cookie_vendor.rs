use std::collections::HashMap;

use rocket::{
    http::{CookieJar, Status},
    response::{content::RawHtml as Html, Redirect},
    Route,
};

use crate::CONFIG;

/// Maximum allowed length for the redirect URI.
/// Matches the official Bitwarden server limit.
const MAX_REDIRECT_URI_LENGTH: usize = 8192;

/// Maximum number of sharded cookie suffixes to check (0 through 19).
const MAX_SHARD_COUNT: usize = 20;

pub fn routes() -> Vec<Route> {
    routes![sso_cookie_vendor]
}

/// Error HTML response matching the official Bitwarden server format.
fn error_html(status_code: u16) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head>\
         <body><p>Error code {status_code}. Please return to the Bitwarden app and try again.</p></body></html>"
    ))
}

/// GET /sso-cookie-vendor
///
/// This endpoint is called after the user authenticates through the reverse proxy.
/// It reads the proxy auth cookie from the request and redirects the native client
/// to a bitwarden:// deep link containing the cookie value.
///
/// No Bitwarden authentication is required — the proxy handles auth.
#[get("/sso-cookie-vendor")]
fn sso_cookie_vendor(cookies: &CookieJar<'_>) -> Result<Redirect, (Status, Html<String>)> {
    let cookie_name = CONFIG.sso_cookie_vendor_cookie_name();

    if cookie_name.is_empty() {
        return Err((Status::InternalServerError, error_html(500)));
    }

    // Extract cookies from the jar into a HashMap for processing
    let mut cookie_map = HashMap::new();
    // Check the main cookie
    if let Some(cookie) = cookies.get(&cookie_name) {
        cookie_map.insert(cookie_name.clone(), cookie.value().to_string());
    }
    // Check sharded cookies
    for i in 0..MAX_SHARD_COUNT {
        let shard_name = format!("{cookie_name}-{i}");
        if let Some(cookie) = cookies.get(&shard_name) {
            cookie_map.insert(shard_name, cookie.value().to_string());
        }
    }

    let redirect_uri = build_redirect_uri(&cookie_name, &cookie_map)?;

    if redirect_uri.len() > MAX_REDIRECT_URI_LENGTH {
        return Err((Status::BadRequest, error_html(400)));
    }

    Ok(Redirect::found(redirect_uri))
}

/// Build the bitwarden:// redirect URI from a map of cookie names to values.
///
/// Checks for a single (non-sharded) cookie first. If found, it takes precedence.
/// Otherwise, checks for sharded cookies ({name}-0 through {name}-19).
fn build_redirect_uri(
    cookie_name: &str,
    cookies: &HashMap<String, String>,
) -> Result<String, (Status, Html<String>)> {
    // Check for the single (non-sharded) cookie — takes precedence over shards
    if let Some(value) = cookies.get(cookie_name) {
        let encoded_value = url_encode(value);
        return Ok(format!("bitwarden://sso-cookie-vendor?{cookie_name}={encoded_value}&d=1"));
    }

    // Check for sharded cookies: {name}-0, {name}-1, ..., {name}-19
    let mut shards: Vec<(String, String)> = Vec::new();
    for i in 0..MAX_SHARD_COUNT {
        let shard_name = format!("{cookie_name}-{i}");
        if let Some(value) = cookies.get(&shard_name) {
            shards.push((shard_name, url_encode(value)));
        }
    }

    if shards.is_empty() {
        return Err((Status::NotFound, error_html(404)));
    }

    let params: Vec<String> = shards.into_iter().map(|(name, value)| format!("{name}={value}")).collect();
    Ok(format!("bitwarden://sso-cookie-vendor?{}&d=1", params.join("&")))
}

/// URL-encode a cookie value using percent-encoding for the query string.
fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_simple() {
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn test_url_encode_special_chars() {
        let encoded = url_encode("eyJhbGci.test=value&other");
        assert!(encoded.contains("eyJhbGci.test"));
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn test_error_html_format() {
        let html = error_html(404);
        let content = html.0;
        assert!(content.contains("<!DOCTYPE html>"));
        assert!(content.contains("Error code 404"));
        assert!(content.contains("Please return to the Bitwarden app and try again."));
    }

    #[test]
    fn test_error_html_500() {
        let html = error_html(500);
        assert!(html.0.contains("Error code 500"));
    }

    #[test]
    fn test_error_html_400() {
        let html = error_html(400);
        assert!(html.0.contains("Error code 400"));
    }

    #[test]
    fn test_single_cookie_found() {
        let mut cookies = HashMap::new();
        cookies.insert("CF_Authorization".to_string(), "jwt_token_value".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        assert_eq!(uri, "bitwarden://sso-cookie-vendor?CF_Authorization=jwt_token_value&d=1");
    }

    #[test]
    fn test_sharded_cookies_found() {
        let mut cookies = HashMap::new();
        cookies.insert("CF_Authorization-0".to_string(), "part0".to_string());
        cookies.insert("CF_Authorization-1".to_string(), "part1".to_string());
        cookies.insert("CF_Authorization-2".to_string(), "part2".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        assert!(uri.starts_with("bitwarden://sso-cookie-vendor?"));
        assert!(uri.contains("CF_Authorization-0=part0"));
        assert!(uri.contains("CF_Authorization-1=part1"));
        assert!(uri.contains("CF_Authorization-2=part2"));
        assert!(uri.ends_with("&d=1"));
    }

    #[test]
    fn test_single_cookie_preferred_over_shards() {
        let mut cookies = HashMap::new();
        // Add both single and sharded cookies
        cookies.insert("CF_Authorization".to_string(), "single_value".to_string());
        cookies.insert("CF_Authorization-0".to_string(), "shard0".to_string());
        cookies.insert("CF_Authorization-1".to_string(), "shard1".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // Single cookie should take precedence — no shards in the URI
        assert_eq!(uri, "bitwarden://sso-cookie-vendor?CF_Authorization=single_value&d=1");
        assert!(!uri.contains("CF_Authorization-0"));
    }

    #[test]
    fn test_cookie_not_found_returns_404() {
        let cookies = HashMap::new();

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_err());
        let (status, html) = result.unwrap_err();
        assert_eq!(status, Status::NotFound);
        assert!(html.0.contains("Error code 404"));
    }

    #[test]
    fn test_uri_too_long_returns_400() {
        let mut cookies = HashMap::new();
        // Create a very long cookie value that will exceed MAX_REDIRECT_URI_LENGTH
        let long_value = "x".repeat(MAX_REDIRECT_URI_LENGTH + 1);
        cookies.insert("CF_Authorization".to_string(), long_value);

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // The URI exceeds the limit — the caller (sso_cookie_vendor handler) checks this
        assert!(uri.len() > MAX_REDIRECT_URI_LENGTH);
    }

    #[test]
    fn test_cookie_value_url_encoded() {
        let mut cookies = HashMap::new();
        cookies.insert("CF_Authorization".to_string(), "value with spaces&special=chars".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        assert!(!uri.contains(" "));
        assert!(uri.contains("value+with+spaces%26special%3Dchars"));
    }

    #[test]
    fn test_sharded_cookies_ordered() {
        let mut cookies = HashMap::new();
        // Insert in non-sequential order to verify ordering
        cookies.insert("CF_Authorization-2".to_string(), "part2".to_string());
        cookies.insert("CF_Authorization-0".to_string(), "part0".to_string());
        cookies.insert("CF_Authorization-1".to_string(), "part1".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // Shards should appear in order 0, 1, 2 regardless of insertion order
        let q = uri.find("CF_Authorization-0").unwrap();
        let r = uri.find("CF_Authorization-1").unwrap();
        let s = uri.find("CF_Authorization-2").unwrap();
        assert!(q < r);
        assert!(r < s);
    }

    #[test]
    fn test_d_sentinel_always_present() {
        let mut cookies = HashMap::new();
        cookies.insert("MyAuth".to_string(), "val".to_string());

        let result = build_redirect_uri("MyAuth", &cookies);
        let uri = result.unwrap();
        assert!(uri.ends_with("&d=1"));
    }
}
