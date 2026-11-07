//! SSO cookie vending, which lets the Bitwarden apps log in through an authenticating reverse proxy.
//!
//! The app opens a browser at the proxy's login page, and once the proxy has set its auth cookie the
//! browser lands on this route. The route hands that cookie back to the app via a `bitwarden://` deep
//! link, which the app then sends with every request.
//!
//! Port of the Bitwarden server implementation: https://github.com/bitwarden/server/pull/6903

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rocket::{
    Route,
    http::{CookieJar, Status},
    response::{Redirect, content::RawHtml as Html},
};

use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![sso_cookie_vendor]
}

/// Maximum length of the deep link, same as upstream.
const MAX_REDIRECT_URI_LENGTH: usize = 8192;

/// Large tokens get split into `<name>-0` through `<name>-19` (Cloudflare Access does this).
const MAX_SHARD_COUNT: usize = 20;

/// Everything except the RFC 3986 unreserved characters, matching .NET's `Uri.EscapeDataString`.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn error_html(status_code: u16) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head>\
         <body><p>Error code {status_code}. Please return to the Bitwarden app and try again.</p></body></html>"
    ))
}

#[get("/sso-cookie-vendor")]
fn sso_cookie_vendor(cookies: &CookieJar<'_>) -> Result<Redirect, (Status, Html<String>)> {
    let cookie_name = CONFIG.sso_cookie_vendor_cookie_name();
    if cookie_name.is_empty() {
        return Err((Status::InternalServerError, error_html(500)));
    }

    let Some(redirect_uri) = build_redirect_uri(&cookie_name, |name| cookies.get(name).map(|c| c.value().to_owned()))
    else {
        return Err((Status::NotFound, error_html(404)));
    };

    if redirect_uri.len() > MAX_REDIRECT_URI_LENGTH {
        return Err((Status::BadRequest, error_html(400)));
    }

    Ok(Redirect::found(redirect_uri))
}

/// Builds the deep link from the unsuffixed cookie, or else from its shards.
/// Empty values are treated as missing, and shards are read in order up to the first missing one.
/// Returns `None` when no usable cookie was found.
fn build_redirect_uri(cookie_name: &str, get_cookie: impl Fn(&str) -> Option<String>) -> Option<String> {
    let non_empty = |name: &str| get_cookie(name).filter(|v| !v.is_empty());

    let mut params = Vec::new();
    if let Some(value) = non_empty(cookie_name) {
        params.push(format!("{cookie_name}={}", encode(&value)));
    } else {
        for i in 0..MAX_SHARD_COUNT {
            let shard_name = format!("{cookie_name}-{i}");
            let Some(value) = non_empty(&shard_name) else {
                break;
            };
            params.push(format!("{shard_name}={}", encode(&value)));
        }
    }

    if params.is_empty() {
        return None;
    }

    // `d=1` lets the clients detect a truncated link
    params.push("d=1".to_owned());
    Some(format!("bitwarden://sso-cookie-vendor?{}", params.join("&")))
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn build(cookies: &[(&str, &str)]) -> Option<String> {
        let cookies: HashMap<String, String> =
            cookies.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        build_redirect_uri("CF_Authorization", |name| cookies.get(name).cloned())
    }

    #[test]
    fn test_single_cookie() {
        assert_eq!(
            build(&[("CF_Authorization", "jwt_token_value")]).unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization=jwt_token_value&d=1"
        );
    }

    #[test]
    fn test_single_cookie_preferred_over_shards() {
        assert_eq!(
            build(&[("CF_Authorization", "single"), ("CF_Authorization-0", "shard0")]).unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization=single&d=1"
        );
    }

    #[test]
    fn test_empty_single_cookie_falls_back_to_shards() {
        assert_eq!(
            build(&[("CF_Authorization", ""), ("CF_Authorization-0", "shard0")]).unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization-0=shard0&d=1"
        );
    }

    #[test]
    fn test_sharded_cookies_in_order() {
        assert_eq!(
            build(&[("CF_Authorization-2", "part2"), ("CF_Authorization-0", "part0"), ("CF_Authorization-1", "part1")])
                .unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization-0=part0&CF_Authorization-1=part1&CF_Authorization-2=part2&d=1"
        );
    }

    #[test]
    fn test_shards_stop_at_first_gap() {
        assert_eq!(
            build(&[("CF_Authorization-0", "part0"), ("CF_Authorization-2", "part2")]).unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization-0=part0&d=1"
        );
    }

    #[test]
    fn test_shards_stop_at_first_empty() {
        assert_eq!(
            build(&[("CF_Authorization-0", "part0"), ("CF_Authorization-1", ""), ("CF_Authorization-2", "part2")])
                .unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization-0=part0&d=1"
        );
    }

    #[test]
    fn test_shards_must_start_at_zero() {
        assert_eq!(build(&[("CF_Authorization-1", "part1")]), None);
    }

    #[test]
    fn test_no_cookie() {
        assert_eq!(build(&[]), None);
        assert_eq!(build(&[("CF_Authorization", "")]), None);
    }

    #[test]
    fn test_value_encoding_matches_escape_data_string() {
        assert_eq!(
            build(&[("CF_Authorization", "a b&c=d+e/f~g_h-i.j")]).unwrap(),
            "bitwarden://sso-cookie-vendor?CF_Authorization=a%20b%26c%3Dd%2Be%2Ff~g_h-i.j&d=1"
        );
    }

    #[test]
    fn test_redirect_uri_is_valid_for_rocket() {
        // `Redirect` turns an unparsable URI into a 500, so make sure every character we emit is accepted
        let all_ascii: String = (0x20u8..0x7f).map(char::from).collect();
        let uri = build(&[("CF_Authorization-0", &all_ascii), ("CF_Authorization-1", "ünïcødé")]).unwrap();
        assert!(rocket::http::uri::Reference::parse_owned(uri).is_ok());
    }

    #[test]
    fn test_error_html() {
        assert!(error_html(404).0.contains("Error code 404. Please return to the Bitwarden app and try again."));
    }
}
