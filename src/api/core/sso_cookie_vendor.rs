//! SSO cookie vending for the Bitwarden mobile and desktop apps behind an authenticating proxy.
//!
//! When Vaultwarden runs behind a reverse proxy that gates every request on an identity provider
//! (Cloudflare Access, Authentik, Authelia, oauth2-proxy), the Bitwarden mobile and desktop apps
//! cannot finish logging in. The proxy answers their API calls with a browser redirect to the
//! identity provider, and their HTTP clients have no cookie jar or browser to follow it with.
//!
//! Bitwarden's answer is cookie vending. The server advertises the flow through the
//! `communication.bootstrap` object in `/api/config`, the app opens a system browser at the
//! identity provider, and the browser lands on the route in this module once the proxy has set its
//! auth cookie. The route hands that cookie back to the app as a `bitwarden://` deep link, and the
//! app attaches it to every later API request so the proxy lets those requests through.
//!
//! Vaultwarden authenticates nobody here. The proxy is the gate, and the vault's own master
//! password unlock still runs afterwards. The route is registered only when
//! `SSO_COOKIE_VENDOR_ENABLED` is true, so installs that have not opted in are unaffected.
//!
//! This is the server half of bitwarden/server#6880, #6892, and #6903. For operator-facing setup,
//! see `docs/sso-cookie-vendor.md`.

use std::collections::HashMap;

use rocket::{
    Route,
    http::{CookieJar, Status},
    response::{Redirect, content::RawHtml as Html},
};

use crate::CONFIG;

/// Maximum length of the `bitwarden://` deep link, in bytes.
///
/// Matches the limit the Bitwarden server enforces, so an oversize token fails the same way on
/// both servers instead of producing a link the app or the operating system truncates silently.
const MAX_REDIRECT_URI_LENGTH: usize = 8192;

/// Number of sharded cookie suffixes to look for, `-0` through `-19`.
///
/// Cloudflare Access splits its auth JWT across numbered cookies when the token outgrows the
/// per-cookie size limit, so reading only the unsuffixed name would miss the token entirely.
const MAX_SHARD_COUNT: usize = 20;

/// Returns the routes this module serves.
///
/// The caller in `api::core::routes` invokes this only when `SSO_COOKIE_VENDOR_ENABLED` is true,
/// so the endpoint does not exist on installs that leave the feature off.
pub fn routes() -> Vec<Route> {
    routes![sso_cookie_vendor]
}

/// Returns the HTML error page for `status_code`, in the format the Bitwarden server uses.
///
/// A browser renders this response, not an API client, so the page tells the user to return to the
/// app rather than describing why the lookup failed.
fn error_html(status_code: u16) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head>\
         <body><p>Error code {status_code}. Please return to the Bitwarden app and try again.</p></body></html>"
    ))
}

/// Vends the reverse proxy's auth cookie to the calling app as a `bitwarden://` deep link.
///
/// The browser arrives at `GET /api/sso-cookie-vendor` after the proxy has authenticated the user,
/// so the request already carries the proxy's cookie. The response is a 302 to
/// `bitwarden://sso-cookie-vendor?<cookie-name>=<value>&d=1`, which the operating system hands to
/// the Bitwarden app. The `d=1` parameter is the sentinel Bitwarden's clients look for.
///
/// # Errors
///
/// Every failure renders an HTML page rather than a JSON body, because a browser displays it:
///
/// - 500 when `SSO_COOKIE_VENDOR_COOKIE_NAME` is empty. Config validation rejects that combination
///   at startup and on admin-panel updates, so reaching it means the config was bypassed.
/// - 404 when the request carries neither the cookie nor any of its shards. This is the response
///   an unconfigured Bitwarden server gives, and the clients already handle it.
/// - 400 when the deep link would exceed `MAX_REDIRECT_URI_LENGTH`.
#[get("/sso-cookie-vendor")]
fn sso_cookie_vendor(cookies: &CookieJar<'_>) -> Result<Redirect, (Status, Html<String>)> {
    let cookie_name = CONFIG.sso_cookie_vendor_cookie_name();

    if cookie_name.is_empty() {
        return Err((Status::InternalServerError, error_html(500)));
    }

    // Copy the relevant cookies out of the jar so that link building stays a plain function over a
    // map, which the tests below can drive without standing up a request.
    let mut cookie_map = HashMap::new();
    if let Some(cookie) = cookies.get(&cookie_name) {
        cookie_map.insert(cookie_name.clone(), cookie.value().to_owned());
    }
    for i in 0..MAX_SHARD_COUNT {
        let shard_name = format!("{cookie_name}-{i}");
        if let Some(cookie) = cookies.get(&shard_name) {
            cookie_map.insert(shard_name, cookie.value().to_owned());
        }
    }

    let redirect_uri = build_redirect_uri(&cookie_name, &cookie_map)?;

    // Measured on the finished link rather than on the raw cookie, because percent-encoding and
    // the shard names both count against what the app has to receive.
    if redirect_uri.len() > MAX_REDIRECT_URI_LENGTH {
        return Err((Status::BadRequest, error_html(400)));
    }

    Ok(Redirect::found(redirect_uri))
}

/// Builds the `bitwarden://` deep link from the cookies found on the request.
///
/// An unsuffixed cookie wins over any shards, matching the Bitwarden server. When only shards are
/// present, every shard found is forwarded in ascending suffix order so the app can reassemble the
/// token. The counting loop, not the map's iteration order, is what makes that order deterministic.
///
/// # Errors
///
/// Returns 404 and an HTML error page when neither the unsuffixed cookie nor any shard is present.
fn build_redirect_uri(cookie_name: &str, cookies: &HashMap<String, String>) -> Result<String, (Status, Html<String>)> {
    if let Some(value) = cookies.get(cookie_name) {
        let encoded_value = url_encode(value);
        return Ok(format!("bitwarden://sso-cookie-vendor?{cookie_name}={encoded_value}&d=1"));
    }

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

/// Percent-encodes a cookie value for the deep link's query string.
///
/// Uses `application/x-www-form-urlencoded` serialization so a value containing `&` or `=` cannot
/// be read by the receiving app as an extra query parameter.
fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    //! The tests drive `build_redirect_uri` directly rather than the route, because the route needs a
    //! live `CookieJar` and the configured cookie name. The status codes the route maps these
    //! results to are documented on `sso_cookie_vendor`.

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
        cookies.insert("CF_Authorization".to_string(), "single_value".to_string());
        cookies.insert("CF_Authorization-0".to_string(), "shard0".to_string());
        cookies.insert("CF_Authorization-1".to_string(), "shard1".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // The unsuffixed cookie wins, and no shard reaches the link.
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
    fn test_oversize_cookie_exceeds_uri_limit() {
        let mut cookies = HashMap::new();
        // A cookie long enough to push the finished link past the cap.
        let long_value = "x".repeat(MAX_REDIRECT_URI_LENGTH + 1);
        cookies.insert("CF_Authorization".to_string(), long_value);

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // Building succeeds. The 400 comes from `sso_cookie_vendor`, which applies the cap.
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
        // Inserted out of order: the link must still come back in suffix order.
        cookies.insert("CF_Authorization-2".to_string(), "part2".to_string());
        cookies.insert("CF_Authorization-0".to_string(), "part0".to_string());
        cookies.insert("CF_Authorization-1".to_string(), "part1".to_string());

        let result = build_redirect_uri("CF_Authorization", &cookies);
        assert!(result.is_ok());
        let uri = result.unwrap();
        // Shards appear as 0, 1, 2 whatever order the map yields them in.
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
