//
// Web Headers and caching
//
use std::{collections::HashMap, io::Cursor, ops::Deref, path::Path};

use num_traits::ToPrimitive;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{ContentType, Header, HeaderMap, Method, Status},
    request::FromParam,
    response::{self, Responder},
    Data, Orbit, Request, Response, Rocket,
};

use tokio::{
    runtime::Handle,
    time::{sleep, Duration},
};

use crate::CONFIG;

pub struct AppHeaders();

#[rocket::async_trait]
impl Fairing for AppHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Application Headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let req_uri_path = req.uri().path();
        let req_headers = req.headers();

        // Check if this connection is an Upgrade/WebSocket connection and return early
        // We do not want add any extra headers, this could cause issues with reverse proxies or CloudFlare
        if req_uri_path.ends_with("notifications/hub") || req_uri_path.ends_with("notifications/anonymous-hub") {
            match (req_headers.get_one("connection"), req_headers.get_one("upgrade")) {
                (Some(c), Some(u))
                    if c.to_lowercase().contains("upgrade") && u.to_lowercase().contains("websocket") =>
                {
                    // Remove headers which could cause websocket connection issues
                    res.remove_header("X-Frame-Options");
                    res.remove_header("X-Content-Type-Options");
                    res.remove_header("Permissions-Policy");
                    return;
                }
                (_, _) => (),
            }
        }

        // NOTE: When modifying or adding security headers be sure to also update the diagnostic checks in `src/static/scripts/admin_diagnostics.js` in `checkSecurityHeaders`
        res.set_raw_header("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()");
        res.set_raw_header("Referrer-Policy", "same-origin");
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        res.set_raw_header("X-Robots-Tag", "noindex, nofollow");
        // Obsolete in modern browsers, unsafe (XS-Leak), and largely replaced by CSP
        res.set_raw_header("X-XSS-Protection", "0");

        // Do not send the Content-Security-Policy (CSP) Header and X-Frame-Options for the *-connector.html files.
        // This can cause issues when some MFA requests needs to open a popup or page within the clients like WebAuthn, or Duo.
        // This is the same behavior as upstream Bitwarden.
        if !req_uri_path.ends_with("connector.html") {
            // # Frame Ancestors:
            // Chrome Web Store: https://chrome.google.com/webstore/detail/bitwarden-free-password-m/nngceckbapebfimnlniiiahkandclblb
            // Edge Add-ons: https://microsoftedge.microsoft.com/addons/detail/bitwarden-free-password/jbkfoedolllekgbhcbcoahefnbanhhlh?hl=en-US
            // Firefox Browser Add-ons: https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/
            // # img/child/frame src:
            // Have I Been Pwned to allow those calls to work.
            // # Connect src:
            // Leaked Passwords check: api.pwnedpasswords.com
            // 2FA/MFA Site check: api.2fa.directory
            // # Mail Relay: https://bitwarden.com/blog/add-privacy-and-security-using-email-aliases-with-bitwarden/
            // app.simplelogin.io, app.addy.io, api.fastmail.com, quack.duckduckgo.com
            let csp = format!(
                "default-src 'self'; \
                base-uri 'self'; \
                form-action 'self'; \
                object-src 'self' blob:; \
                script-src 'self' 'wasm-unsafe-eval'; \
                style-src 'self' 'unsafe-inline'; \
                child-src 'self' https://*.duosecurity.com https://*.duofederal.com; \
                frame-src 'self' https://*.duosecurity.com https://*.duofederal.com; \
                frame-ancestors 'self' \
                  chrome-extension://nngceckbapebfimnlniiiahkandclblb \
                  chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh \
                  moz-extension://* \
                  {allowed_iframe_ancestors}; \
                img-src 'self' data: \
                  https://haveibeenpwned.com \
                  {icon_service_csp}; \
                connect-src 'self' \
                  https://api.pwnedpasswords.com \
                  https://api.2fa.directory \
                  https://app.simplelogin.io/api/ \
                  https://app.addy.io/api/ \
                  https://api.fastmail.com/ \
                  https://api.forwardemail.net \
                  {allowed_connect_src};\
                ",
                icon_service_csp = CONFIG._icon_service_csp(),
                allowed_iframe_ancestors = CONFIG.allowed_iframe_ancestors(),
                allowed_connect_src = CONFIG.allowed_connect_src(),
            );
            res.set_raw_header("Content-Security-Policy", csp);
            res.set_raw_header("X-Frame-Options", "SAMEORIGIN");
        } else {
            // It looks like this header get's set somewhere else also, make sure this is not sent for these files, it will cause MFA issues.
            res.remove_header("X-Frame-Options");
        }

        // Disable cache unless otherwise specified
        if !res.headers().contains("cache-control") {
            res.set_raw_header("Cache-Control", "no-cache, no-store, max-age=0");
        }
    }
}

pub struct Cors();

impl Cors {
    fn get_header(headers: &HeaderMap<'_>, name: &str) -> String {
        match headers.get_one(name) {
            Some(h) => h.to_string(),
            _ => String::new(),
        }
    }

    // Check a request's `Origin` header against the list of allowed origins.
    // If a match exists, return it. Otherwise, return None.
    fn get_allowed_origin(headers: &HeaderMap<'_>) -> Option<String> {
        let origin = Cors::get_header(headers, "Origin");
        let domain_origin = CONFIG.domain_origin();
        let safari_extension_origin = "file://";
        if origin == domain_origin || origin == safari_extension_origin {
            Some(origin)
        } else {
            None
        }
    }
}

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Cors",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let req_headers = request.headers();

        if let Some(origin) = Cors::get_allowed_origin(req_headers) {
            response.set_header(Header::new("Access-Control-Allow-Origin", origin));
        }

        // Preflight request
        if request.method() == Method::Options {
            let req_allow_headers = Cors::get_header(req_headers, "Access-Control-Request-Headers");
            let req_allow_method = Cors::get_header(req_headers, "Access-Control-Request-Method");

            response.set_header(Header::new("Access-Control-Allow-Methods", req_allow_method));
            response.set_header(Header::new("Access-Control-Allow-Headers", req_allow_headers));
            response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            response.set_status(Status::Ok);
            response.set_header(ContentType::Plain);
            response.set_sized_body(Some(0), Cursor::new(""));
        }
    }
}

pub struct Cached<R> {
    response: R,
    is_immutable: bool,
    ttl: u64,
}

impl<R> Cached<R> {
    pub fn long(response: R, is_immutable: bool) -> Cached<R> {
        Self {
            response,
            is_immutable,
            ttl: 604800, // 7 days
        }
    }

    pub fn short(response: R, is_immutable: bool) -> Cached<R> {
        Self {
            response,
            is_immutable,
            ttl: 600, // 10 minutes
        }
    }

    pub fn ttl(response: R, ttl: u64, is_immutable: bool) -> Cached<R> {
        Self {
            response,
            is_immutable,
            ttl,
        }
    }
}

impl<'r, R: 'r + Responder<'r, 'static> + Send> Responder<'r, 'static> for Cached<R> {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let mut res = self.response.respond_to(request)?;

        let cache_control_header = if self.is_immutable {
            format!("public, immutable, max-age={}", self.ttl)
        } else {
            format!("public, max-age={}", self.ttl)
        };
        res.set_raw_header("Cache-Control", cache_control_header);

        let time_now = Local::now();
        let expiry_time = time_now + chrono::TimeDelta::try_seconds(self.ttl.try_into().unwrap()).unwrap();
        res.set_raw_header("Expires", format_datetime_http(&expiry_time));
        Ok(res)
    }
}

pub struct SafeString(String);

impl fmt::Display for SafeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for SafeString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for SafeString {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl<'r> FromParam<'r> for SafeString {
    type Error = ();

    #[inline(always)]
    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        if param.chars().all(|c| matches!(c, 'a'..='z' | 'A'..='Z' |'0'..='9' | '-')) {
            Ok(SafeString(param.to_string()))
        } else {
            Err(())
        }
    }
}

// Log all the routes from the main paths list, and the attachments endpoint
// Effectively ignores, any static file route, and the alive endpoint
const LOGGED_ROUTES: [&str; 7] = ["/api", "/admin", "/identity", "/icons", "/attachments", "/events", "/notifications"];

// Boolean is extra debug, when true, we ignore the whitelist above and also print the mounts
pub struct BetterLogging(pub bool);
#[rocket::async_trait]
impl Fairing for BetterLogging {
    fn info(&self) -> Info {
        Info {
            name: "Better Logging",
            kind: Kind::Liftoff | Kind::Request | Kind::Response,
        }
    }

    async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
        if self.0 {
            info!(target: "routes", "Routes loaded:");
            let mut routes: Vec<_> = rocket.routes().collect();
            routes.sort_by_key(|r| r.uri.path());
            for route in routes {
                if route.rank < 0 {
                    info!(target: "routes", "{:<6} {}", route.method, route.uri);
                } else {
                    info!(target: "routes", "{:<6} {} [{}]", route.method, route.uri, route.rank);
                }
            }
        }

        let config = rocket.config();
        let scheme = if config.tls_enabled() {
            "https"
        } else {
            "http"
        };
        let addr = format!("{}://{}:{}", &scheme, &config.address, &config.port);
        info!(target: "start", "Rocket has launched from {}", addr);
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let method = request.method();
        if !self.0 && method == Method::Options {
            return;
        }
        let uri = request.uri();
        let uri_path = uri.path();
        let uri_path_str = uri_path.url_decode_lossy();
        let uri_subpath = uri_path_str.strip_prefix(&CONFIG.domain_path()).unwrap_or(&uri_path_str);
        if self.0 || LOGGED_ROUTES.iter().any(|r| uri_subpath.starts_with(r)) {
            match uri.query() {
                Some(q) => info!(target: "request", "{} {}?{}", method, uri_path_str, &q[..q.len().min(30)]),
                None => info!(target: "request", "{} {}", method, uri_path_str),
            };
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if !self.0 && request.method() == Method::Options {
            return;
        }
        let uri_path = request.uri().path();
        let uri_path_str = uri_path.url_decode_lossy();
        let uri_subpath = uri_path_str.strip_prefix(&CONFIG.domain_path()).unwrap_or(&uri_path_str);
        if self.0 || LOGGED_ROUTES.iter().any(|r| uri_subpath.starts_with(r)) {
            let status = response.status();
            if let Some(ref route) = request.route() {
                info!(target: "response", "{} => {}", route, status)
            } else {
                info!(target: "response", "{}", status)
            }
        }
    }
}

pub fn get_display_size(size: i64) -> String {
    const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];

    // If we're somehow too big for a f64, just return the size in bytes
    let Some(mut size) = size.to_f64() else {
        return format!("{size} bytes");
    };

    let mut unit_counter = 0;

    loop {
        if size > 1024. {
            size /= 1024.;
            unit_counter += 1;
        } else {
            break;
        }
    }

    format!("{:.2} {}", size, UNITS[unit_counter])
}

pub fn get_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

//
// String util methods
//

use std::str::FromStr;

#[inline]
pub fn upcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[inline]
pub fn lcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
    }
}

pub fn try_parse_string<S, T>(string: Option<S>) -> Option<T>
where
    S: AsRef<str>,
    T: FromStr,
{
    if let Some(Ok(value)) = string.map(|s| s.as_ref().parse::<T>()) {
        Some(value)
    } else {
        None
    }
}

//
// Env methods
//

use std::env;

pub fn get_env_str_value(key: &str) -> Option<String> {
    let key_file = format!("{key}_FILE");
    let value_from_env = env::var(key);
    let value_file = env::var(&key_file);

    match (value_from_env, value_file) {
        (Ok(_), Ok(_)) => panic!("You should not define both {key} and {key_file}!"),
        (Ok(v_env), Err(_)) => Some(v_env),
        (Err(_), Ok(v_file)) => match std::fs::read_to_string(v_file) {
            Ok(content) => Some(content.trim().to_string()),
            Err(e) => panic!("Failed to load {key}: {e:?}"),
        },
        _ => None,
    }
}

pub fn get_env<V>(key: &str) -> Option<V>
where
    V: FromStr,
{
    try_parse_string(get_env_str_value(key))
}

pub fn get_env_bool(key: &str) -> Option<bool> {
    const TRUE_VALUES: &[&str] = &["true", "t", "yes", "y", "1"];
    const FALSE_VALUES: &[&str] = &["false", "f", "no", "n", "0"];

    match get_env_str_value(key) {
        Some(val) if TRUE_VALUES.contains(&val.to_lowercase().as_ref()) => Some(true),
        Some(val) if FALSE_VALUES.contains(&val.to_lowercase().as_ref()) => Some(false),
        _ => None,
    }
}

//
// Date util methods
//

use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

/// Formats a UTC-offset `NaiveDateTime` in the format used by Bitwarden API
/// responses with "date" fields (`CreationDate`, `RevisionDate`, etc.).
pub fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Validates and formats a RFC3339 timestamp
/// If parsing fails it will return the start of the unix datetime
pub fn validate_and_format_date(dt: &str) -> String {
    match DateTime::parse_from_rfc3339(dt) {
        Ok(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        _ => String::from("1970-01-01T00:00:00.000000Z"),
    }
}

/// Formats a `DateTime<Local>` using the specified format string.
///
/// For a `DateTime<Local>`, the `%Z` specifier normally formats as the
/// time zone's UTC offset (e.g., `+00:00`). In this function, if the
/// `TZ` environment variable is set, then `%Z` instead formats as the
/// abbreviation for that time zone (e.g., `UTC`).
pub fn format_datetime_local(dt: &DateTime<Local>, fmt: &str) -> String {
    // Try parsing the `TZ` environment variable to enable formatting `%Z` as
    // a time zone abbreviation.
    if let Ok(tz) = env::var("TZ") {
        if let Ok(tz) = tz.parse::<chrono_tz::Tz>() {
            return dt.with_timezone(&tz).format(fmt).to_string();
        }
    }

    // Otherwise, fall back to formatting `%Z` as a UTC offset.
    dt.format(fmt).to_string()
}

/// Formats a UTC-offset `NaiveDateTime` as a datetime in the local time zone.
///
/// This function basically converts the `NaiveDateTime` to a `DateTime<Local>`,
/// and then calls [format_datetime_local](crate::util::format_datetime_local).
pub fn format_naive_datetime_local(dt: &NaiveDateTime, fmt: &str) -> String {
    format_datetime_local(&Local.from_utc_datetime(dt), fmt)
}

/// Formats a `DateTime<Local>` as required for HTTP
///
/// https://httpwg.org/specs/rfc7231.html#http.date
pub fn format_datetime_http(dt: &DateTime<Local>) -> String {
    let expiry_time = DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt.naive_utc(), chrono::Utc);

    // HACK: HTTP expects the date to always be GMT (UTC) rather than giving an
    // offset (which would always be 0 in UTC anyway)
    expiry_time.to_rfc2822().replace("+0000", "GMT")
}

pub fn parse_date(date: &str) -> NaiveDateTime {
    DateTime::parse_from_rfc3339(date).unwrap().naive_utc()
}

//
// Deployment environment methods
//

/// Returns true if the program is running in Docker, Podman or Kubernetes.
pub fn is_running_in_container() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || Path::new("/run/secrets/kubernetes.io").exists()
        || Path::new("/var/run/secrets/kubernetes.io").exists()
}

/// Simple check to determine on which container base image vaultwarden is running.
/// We build images based upon Debian or Alpine, so these we check here.
pub fn container_base_image() -> &'static str {
    if Path::new("/etc/debian_version").exists() {
        "Debian"
    } else if Path::new("/etc/alpine-release").exists() {
        "Alpine"
    } else {
        "Unknown"
    }
}

#[derive(Deserialize)]
struct WebVaultVersion {
    version: String,
}

pub fn get_web_vault_version() -> String {
    let version_files = [
        format!("{}/vw-version.json", CONFIG.web_vault_folder()),
        format!("{}/version.json", CONFIG.web_vault_folder()),
    ];

    for version_file in version_files {
        if let Ok(version_str) = std::fs::read_to_string(&version_file) {
            if let Ok(version) = serde_json::from_str::<WebVaultVersion>(&version_str) {
                return String::from(version.version.trim_start_matches('v'));
            }
        }
    }

    String::from("Version file missing")
}

//
// Deserialization methods
//

use std::fmt;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

pub type JsonMap = serde_json::Map<String, Value>;

#[derive(Serialize, Deserialize)]
pub struct LowerCase<T: DeserializeOwned> {
    #[serde(deserialize_with = "lowercase_deserialize")]
    #[serde(flatten)]
    pub data: T,
}

impl Default for LowerCase<Value> {
    fn default() -> Self {
        Self {
            data: Value::Null,
        }
    }
}

// https://github.com/serde-rs/serde/issues/586
pub fn lowercase_deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let d = deserializer.deserialize_any(LowerCaseVisitor)?;
    T::deserialize(d).map_err(de::Error::custom)
}

struct LowerCaseVisitor;

impl<'de> Visitor<'de> for LowerCaseVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object or an array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result_map = JsonMap::new();

        while let Some((key, value)) = map.next_entry()? {
            result_map.insert(_process_key(key), convert_json_key_lcase_first(value));
        }

        Ok(Value::Object(result_map))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result_seq = Vec::<Value>::new();

        while let Some(value) = seq.next_element()? {
            result_seq.push(convert_json_key_lcase_first(value));
        }

        Ok(Value::Array(result_seq))
    }
}

// Inner function to handle a special case for the 'ssn' key.
// This key is part of the Identity Cipher (Social Security Number)
fn _process_key(key: &str) -> String {
    match key.to_lowercase().as_ref() {
        "ssn" => "ssn".into(),
        _ => lcase_first(key),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    pub fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_i32(&self) -> Result<i32, crate::Error> {
        use std::num::ParseIntError as PIE;
        match self {
            NumberOrString::Number(n) => match n.to_i32() {
                Some(n) => Ok(n),
                None => err!("Number does not fit in i32"),
            },
            NumberOrString::String(s) => {
                s.parse().map_err(|e: PIE| crate::Error::new("Can't convert to number", e.to_string()))
            }
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_i64(&self) -> Result<i64, crate::Error> {
        use std::num::ParseIntError as PIE;
        match self {
            NumberOrString::Number(n) => Ok(*n),
            NumberOrString::String(s) => {
                s.parse().map_err(|e: PIE| crate::Error::new("Can't convert to number", e.to_string()))
            }
        }
    }
}

//
// Retry methods
//

pub fn retry<F, T, E>(mut func: F, max_tries: u32) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut tries = 0;

    loop {
        match func() {
            ok @ Ok(_) => return ok,
            err @ Err(_) => {
                tries += 1;

                if tries >= max_tries {
                    return err;
                }
                Handle::current().block_on(sleep(Duration::from_millis(500)));
            }
        }
    }
}

pub async fn retry_db<F, T, E>(mut func: F, max_tries: u32) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::error::Error,
{
    let mut tries = 0;

    loop {
        match func() {
            ok @ Ok(_) => return ok,
            Err(e) => {
                tries += 1;

                if tries >= max_tries && max_tries > 0 {
                    return Err(e);
                }

                warn!("Can't connect to database, retrying: {:?}", e);

                sleep(Duration::from_millis(1_000)).await;
            }
        }
    }
}

pub fn convert_json_key_lcase_first(src_json: Value) -> Value {
    match src_json {
        Value::Array(elm) => {
            let mut new_array: Vec<Value> = Vec::with_capacity(elm.len());

            for obj in elm {
                new_array.push(convert_json_key_lcase_first(obj));
            }
            Value::Array(new_array)
        }

        Value::Object(obj) => {
            let mut json_map = JsonMap::new();
            for (key, value) in obj.into_iter() {
                match (key, value) {
                    (key, Value::Object(elm)) => {
                        let inner_value = convert_json_key_lcase_first(Value::Object(elm));
                        json_map.insert(_process_key(&key), inner_value);
                    }

                    (key, Value::Array(elm)) => {
                        let mut inner_array: Vec<Value> = Vec::with_capacity(elm.len());

                        for inner_obj in elm {
                            inner_array.push(convert_json_key_lcase_first(inner_obj));
                        }

                        json_map.insert(_process_key(&key), Value::Array(inner_array));
                    }

                    (key, value) => {
                        json_map.insert(_process_key(&key), value);
                    }
                }
            }

            Value::Object(json_map)
        }

        value => value,
    }
}

/// Parses the experimental client feature flags string into a HashMap.
pub fn parse_experimental_client_feature_flags(experimental_client_feature_flags: &str) -> HashMap<String, bool> {
    let feature_states = experimental_client_feature_flags.split(',').map(|f| (f.trim().to_owned(), true)).collect();

    feature_states
}

/// TODO: This is extracted from IpAddr::is_global, which is unstable:
/// https://doc.rust-lang.org/nightly/std/net/enum.IpAddr.html#method.is_global
/// Remove once https://github.com/rust-lang/rust/issues/27709 is merged
#[allow(clippy::nonminimal_bool)]
#[cfg(any(not(feature = "unstable"), test))]
pub fn is_global_hardcoded(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !(ip.octets()[0] == 0 // "This network"
            || ip.is_private()
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000)) //ip.is_shared()
            || ip.is_loopback()
            || ip.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            ||(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
            || ip.is_documentation()
            || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18) // ip.is_benchmarking()
            || (ip.octets()[0] & 240 == 240 && !ip.is_broadcast()) //ip.is_reserved()
            || ip.is_broadcast())
        }
        std::net::IpAddr::V6(ip) => {
            !(ip.is_unspecified()
            || ip.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x2F).contains(&b))
                ))
            || ((ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)) // ip.is_documentation()
            || ((ip.segments()[0] & 0xfe00) == 0xfc00) //ip.is_unique_local()
            || ((ip.segments()[0] & 0xffc0) == 0xfe80)) //ip.is_unicast_link_local()
        }
    }
}

#[cfg(not(feature = "unstable"))]
pub use is_global_hardcoded as is_global;

#[cfg(feature = "unstable")]
#[inline(always)]
pub fn is_global(ip: std::net::IpAddr) -> bool {
    ip.is_global()
}

/// These are some tests to check that the implementations match
/// The IPv4 can be all checked in 30 seconds or so and they are correct as of nightly 2023-07-17
/// The IPV6 can't be checked in a reasonable time, so we check over a hundred billion random ones, so far correct
/// Note that the is_global implementation is subject to change as new IP RFCs are created
///
/// To run while showing progress output:
/// cargo +nightly test --release --features sqlite,unstable -- --nocapture --ignored
#[cfg(test)]
#[cfg(feature = "unstable")]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    #[ignore]
    fn test_ipv4_global() {
        for a in 0..u8::MAX {
            println!("Iter: {}/255", a);
            for b in 0..u8::MAX {
                for c in 0..u8::MAX {
                    for d in 0..u8::MAX {
                        let ip = IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
                        assert_eq!(ip.is_global(), is_global_hardcoded(ip), "IP mismatch: {}", ip)
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_ipv6_global() {
        use rand::Rng;

        std::thread::scope(|s| {
            for t in 0..16 {
                let handle = s.spawn(move || {
                    let mut v = [0u8; 16];
                    let mut rng = rand::thread_rng();

                    for i in 0..20 {
                        println!("Thread {t} Iter: {i}/50");
                        for _ in 0..500_000_000 {
                            rng.fill(&mut v);
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(v));
                            assert_eq!(ip.is_global(), is_global_hardcoded(ip), "IP mismatch: {ip}");
                        }
                    }
                });
            }
        });
    }
}
