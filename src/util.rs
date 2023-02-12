//
// Web Headers and caching
//
use std::io::{Cursor, ErrorKind};

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
        res.set_raw_header("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()");
        res.set_raw_header("Referrer-Policy", "same-origin");
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        // Obsolete in modern browsers, unsafe (XS-Leak), and largely replaced by CSP
        res.set_raw_header("X-XSS-Protection", "0");

        let req_uri_path = req.uri().path();

        // Do not send the Content-Security-Policy (CSP) Header and X-Frame-Options for the *-connector.html files.
        // This can cause issues when some MFA requests needs to open a popup or page within the clients like WebAuthn, or Duo.
        // This is the same behaviour as upstream Bitwarden.
        if !req_uri_path.ends_with("connector.html") {
            // # Frame Ancestors:
            // Chrome Web Store: https://chrome.google.com/webstore/detail/bitwarden-free-password-m/nngceckbapebfimnlniiiahkandclblb
            // Edge Add-ons: https://microsoftedge.microsoft.com/addons/detail/bitwarden-free-password/jbkfoedolllekgbhcbcoahefnbanhhlh?hl=en-US
            // Firefox Browser Add-ons: https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/
            // # img/child/frame src:
            // Have I Been Pwned and Gravator to allow those calls to work.
            // # Connect src:
            // Leaked Passwords check: api.pwnedpasswords.com
            // 2FA/MFA Site check: api.2fa.directory
            // # Mail Relay: https://bitwarden.com/blog/add-privacy-and-security-using-email-aliases-with-bitwarden/
            // app.simplelogin.io, app.anonaddy.com, api.fastmail.com, quack.duckduckgo.com
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
                  https://www.gravatar.com \
                  {icon_service_csp}; \
                connect-src 'self' \
                  https://api.pwnedpasswords.com \
                  https://api.2fa.directory \
                  https://app.simplelogin.io/api/ \
                  https://app.anonaddy.com/api/ \
                  https://api.fastmail.com/ \
                  ;\
                ",
                icon_service_csp = CONFIG._icon_service_csp(),
                allowed_iframe_ancestors = CONFIG.allowed_iframe_ancestors()
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

        let time_now = chrono::Local::now();
        let expiry_time = time_now + chrono::Duration::seconds(self.ttl.try_into().unwrap());
        res.set_raw_header("Expires", format_datetime_http(&expiry_time));
        Ok(res)
    }
}

pub struct SafeString(String);

impl std::fmt::Display for SafeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
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
const LOGGED_ROUTES: [&str; 6] =
    ["/api", "/admin", "/identity", "/icons", "/notifications/hub/negotiate", "/attachments"];

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

//
// File handling
//
use std::{
    fs::{self, File},
    io::Result as IOResult,
    path::Path,
};

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn write_file(path: &str, content: &[u8]) -> Result<(), crate::error::Error> {
    use std::io::Write;
    let mut f = match File::create(path) {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == ErrorKind::PermissionDenied {
                error!("Can't create '{}': Permission denied", path);
            }
            return Err(From::from(e));
        }
    };

    f.write_all(content)?;
    f.flush()?;
    Ok(())
}

pub fn delete_file(path: &str) -> IOResult<()> {
    let res = fs::remove_file(path);

    if let Some(parent) = Path::new(path).parent() {
        // If the directory isn't empty, this returns an error, which we ignore
        // We only want to delete the folder if it's empty
        fs::remove_dir(parent).ok();
    }

    res
}

pub fn get_display_size(size: i32) -> String {
    const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];

    let mut size: f64 = size.into();
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
        (Err(_), Ok(v_file)) => match fs::read_to_string(v_file) {
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

// Format used by Bitwarden API
const DATETIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";

/// Formats a UTC-offset `NaiveDateTime` in the format used by Bitwarden API
/// responses with "date" fields (`CreationDate`, `RevisionDate`, etc.).
pub fn format_date(dt: &NaiveDateTime) -> String {
    dt.format(DATETIME_FORMAT).to_string()
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
    let expiry_time: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_utc(dt.naive_utc(), chrono::Utc);

    // HACK: HTTP expects the date to always be GMT (UTC) rather than giving an
    // offset (which would always be 0 in UTC anyway)
    expiry_time.to_rfc2822().replace("+0000", "GMT")
}

pub fn parse_date(date: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(date, DATETIME_FORMAT).unwrap()
}

//
// Deployment environment methods
//

/// Returns true if the program is running in Docker or Podman.
pub fn is_running_in_docker() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

/// Simple check to determine on which docker base image vaultwarden is running.
/// We build images based upon Debian or Alpine, so these we check here.
pub fn docker_base_image() -> &'static str {
    if Path::new("/etc/debian_version").exists() {
        "Debian"
    } else if Path::new("/etc/alpine-release").exists() {
        "Alpine"
    } else {
        "Unknown"
    }
}

//
// Deserialization methods
//

use std::fmt;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{self, Value};

pub type JsonMap = serde_json::Map<String, Value>;

#[derive(Serialize, Deserialize)]
pub struct UpCase<T: DeserializeOwned> {
    #[serde(deserialize_with = "upcase_deserialize")]
    #[serde(flatten)]
    pub data: T,
}

// https://github.com/serde-rs/serde/issues/586
pub fn upcase_deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let d = deserializer.deserialize_any(UpCaseVisitor)?;
    T::deserialize(d).map_err(de::Error::custom)
}

struct UpCaseVisitor;

impl<'de> Visitor<'de> for UpCaseVisitor {
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
            result_map.insert(upcase_first(key), upcase_value(value));
        }

        Ok(Value::Object(result_map))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result_seq = Vec::<Value>::new();

        while let Some(value) = seq.next_element()? {
            result_seq.push(upcase_value(value));
        }

        Ok(Value::Array(result_seq))
    }
}

fn upcase_value(value: Value) -> Value {
    if let Value::Object(map) = value {
        let mut new_value = json!({});

        for (key, val) in map.into_iter() {
            let processed_key = _process_key(&key);
            new_value[processed_key] = upcase_value(val);
        }
        new_value
    } else if let Value::Array(array) = value {
        // Initialize array with null values
        let mut new_value = json!(vec![Value::Null; array.len()]);

        for (index, val) in array.into_iter().enumerate() {
            new_value[index] = upcase_value(val);
        }
        new_value
    } else {
        value
    }
}

// Inner function to handle some speciale case for the 'ssn' key.
// This key is part of the Identity Cipher (Social Security Number)
fn _process_key(key: &str) -> String {
    match key.to_lowercase().as_ref() {
        "ssn" => "SSN".into(),
        _ => self::upcase_first(key),
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
                Handle::current().block_on(async move { sleep(Duration::from_millis(500)).await });
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

use reqwest::{header, Client, ClientBuilder};

pub fn get_reqwest_client() -> Client {
    match get_reqwest_client_builder().build() {
        Ok(client) => client,
        Err(e) => {
            error!("Possible trust-dns error, trying with trust-dns disabled: '{e}'");
            get_reqwest_client_builder().trust_dns(false).build().expect("Failed to build client")
        }
    }
}

pub fn get_reqwest_client_builder() -> ClientBuilder {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("Vaultwarden"));
    Client::builder().default_headers(headers).timeout(Duration::from_secs(10))
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
            for (key, value) in obj.iter() {
                match (key, value) {
                    (key, Value::Object(elm)) => {
                        let inner_value = convert_json_key_lcase_first(Value::Object(elm.clone()));
                        json_map.insert(lcase_first(key), inner_value);
                    }

                    (key, Value::Array(elm)) => {
                        let mut inner_array: Vec<Value> = Vec::with_capacity(elm.len());

                        for inner_obj in elm {
                            inner_array.push(convert_json_key_lcase_first(inner_obj.clone()));
                        }

                        json_map.insert(lcase_first(key), Value::Array(inner_array));
                    }

                    (key, value) => {
                        json_map.insert(lcase_first(key), value.clone());
                    }
                }
            }

            Value::Object(json_map)
        }

        value => value,
    }
}
