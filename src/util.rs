//
// Web Headers and caching
//
use std::io::Cursor;

use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{ContentType, Header, HeaderMap, Method, Status},
    response::{self, Responder},
    Data, Request, Response, Rocket,
};

use crate::CONFIG;

pub struct AppHeaders();

impl Fairing for AppHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Application Headers",
            kind: Kind::Response,
        }
    }

    fn on_response(&self, _req: &Request, res: &mut Response) {
        res.set_raw_header("Feature-Policy", "accelerometer 'none'; ambient-light-sensor 'none'; autoplay 'none'; camera 'none'; encrypted-media 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; picture-in-picture 'none'; sync-xhr 'self' https://haveibeenpwned.com https://2fa.directory; usb 'none'; vr 'none'");
        res.set_raw_header("Referrer-Policy", "same-origin");
        res.set_raw_header("X-Frame-Options", "SAMEORIGIN");
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        res.set_raw_header("X-XSS-Protection", "1; mode=block");
        let csp = format!("frame-ancestors 'self' chrome-extension://nngceckbapebfimnlniiiahkandclblb moz-extension://* {};", CONFIG.allowed_iframe_ancestors());
        res.set_raw_header("Content-Security-Policy", csp);

        // Disable cache unless otherwise specified
        if !res.headers().contains("cache-control") {
            res.set_raw_header("Cache-Control", "no-cache, no-store, max-age=0");
        }
    }
}

pub struct CORS();

impl CORS {
    fn get_header(headers: &HeaderMap, name: &str) -> String {
        match headers.get_one(name) {
            Some(h) => h.to_string(),
            _ => "".to_string(),
        }
    }

    fn valid_url(url: String) -> String {
        match url.as_ref() {
            "file://" => "*".to_string(),
            _ => url,
        }
    }
}

impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "CORS",
            kind: Kind::Response,
        }
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        let req_headers = request.headers();

        // We need to explicitly get the Origin header for Access-Control-Allow-Origin
        let req_allow_origin = CORS::valid_url(CORS::get_header(req_headers, "Origin"));

        response.set_header(Header::new("Access-Control-Allow-Origin", req_allow_origin));

        if request.method() == Method::Options {
            let req_allow_headers = CORS::get_header(req_headers, "Access-Control-Request-Headers");
            let req_allow_method = CORS::get_header(req_headers, "Access-Control-Request-Method");

            response.set_header(Header::new("Access-Control-Allow-Methods", req_allow_method));
            response.set_header(Header::new("Access-Control-Allow-Headers", req_allow_headers));
            response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
            response.set_status(Status::Ok);
            response.set_header(ContentType::Plain);
            response.set_sized_body(Cursor::new(""));
        }
    }
}

pub struct Cached<R>(R, &'static str);

impl<R> Cached<R> {
    pub const fn long(r: R) -> Cached<R> {
        // 7 days
        Self(r, "public, max-age=604800")
    }

    pub const fn short(r: R) -> Cached<R> {
        // 10 minutes
        Self(r, "public, max-age=600")
    }
}

impl<'r, R: Responder<'r>> Responder<'r> for Cached<R> {
    fn respond_to(self, req: &Request) -> response::Result<'r> {
        match self.0.respond_to(req) {
            Ok(mut res) => {
                res.set_raw_header("Cache-Control", self.1);
                Ok(res)
            }
            e @ Err(_) => e,
        }
    }
}

// Log all the routes from the main paths list, and the attachments endpoint
// Effectively ignores, any static file route, and the alive endpoint
const LOGGED_ROUTES: [&str; 6] = [
    "/api",
    "/admin",
    "/identity",
    "/icons",
    "/notifications/hub/negotiate",
    "/attachments",
];

// Boolean is extra debug, when true, we ignore the whitelist above and also print the mounts
pub struct BetterLogging(pub bool);
impl Fairing for BetterLogging {
    fn info(&self) -> Info {
        Info {
            name: "Better Logging",
            kind: Kind::Launch | Kind::Request | Kind::Response,
        }
    }

    fn on_launch(&self, rocket: &Rocket) {
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
        let scheme = if config.tls_enabled() { "https" } else { "http" };
        let addr = format!("{}://{}:{}", &scheme, &config.address, &config.port);
        info!(target: "start", "Rocket has launched from {}", addr);
    }

    fn on_request(&self, request: &mut Request<'_>, _data: &Data) {
        let method = request.method();
        if !self.0 && method == Method::Options {
            return;
        }
        let uri = request.uri();
        let uri_path = uri.path();
        let uri_subpath = uri_path.strip_prefix(&CONFIG.domain_path()).unwrap_or(uri_path);
        if self.0 || LOGGED_ROUTES.iter().any(|r| uri_subpath.starts_with(r)) {
            match uri.query() {
                Some(q) => info!(target: "request", "{} {}?{}", method, uri_path, &q[..q.len().min(30)]),
                None => info!(target: "request", "{} {}", method, uri_path),
            };
        }
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        if !self.0 && request.method() == Method::Options {
            return;
        }
        let uri_path = request.uri().path();
        let uri_subpath = uri_path.strip_prefix(&CONFIG.domain_path()).unwrap_or(uri_path);
        if self.0 || LOGGED_ROUTES.iter().any(|r| uri_subpath.starts_with(r)) {
            let status = response.status();
            if let Some(route) = request.route() {
                info!(target: "response", "{} => {} {}", route, status.code, status.reason)
            } else {
                info!(target: "response", "{} {}", status.code, status.reason)
            }
        }
    }
}

//
// File handling
//
use std::{
    fs::{self, File},
    io::{Read, Result as IOResult},
    path::Path,
};

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn read_file(path: &str) -> IOResult<Vec<u8>> {
    let mut contents: Vec<u8> = Vec::new();

    let mut file = File::open(Path::new(path))?;
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

pub fn read_file_string(path: &str) -> IOResult<String> {
    let mut contents = String::new();

    let mut file = File::open(Path::new(path))?;
    file.read_to_string(&mut contents)?;

    Ok(contents)
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

const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];

pub fn get_display_size(size: i32) -> String {
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

pub fn upcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
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

pub fn get_env_str_value(key: &str) -> Option<String>
{
    let key_file = format!("{}_FILE", key);
    let value_from_env = env::var(key);
    let value_file = env::var(&key_file);

    match (value_from_env, value_file) {
        (Ok(_), Ok(_)) => panic!("You should not define both {} and {}!", key, key_file),
        (Ok(v_env), Err(_)) => Some(v_env),
        (Err(_), Ok(v_file)) => match fs::read_to_string(v_file) {
            Ok(content) => Some(content.trim().to_string()),
            Err(e) => panic!("Failed to load {}: {:?}", key, e)
        },
        _ => None
    }
}

pub fn get_env<V>(key: &str) -> Option<V>
where
    V: FromStr,
{
    try_parse_string(get_env_str_value(key))
}

const TRUE_VALUES: &[&str] = &["true", "t", "yes", "y", "1"];
const FALSE_VALUES: &[&str] = &["false", "f", "no", "n", "0"];

pub fn get_env_bool(key: &str) -> Option<bool> {
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
use chrono_tz::Tz;

/// Formats a UTC-offset `NaiveDateTime` in the format used by Bitwarden API
/// responses with "date" fields (`CreationDate`, `RevisionDate`, etc.).
pub fn format_date(dt: &NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
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
        if let Ok(tz) = tz.parse::<Tz>() {
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

//
// Deployment environment methods
//

/// Returns true if the program is running in Docker or Podman.
pub fn is_running_in_docker() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

//
// Deserialization methods
//

use std::fmt;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{self, Value};

pub type JsonMap = serde_json::Map<String, Value>;

#[derive(PartialEq, Serialize, Deserialize)]
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

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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

fn _process_key(key: &str) -> String {
    match key.to_lowercase().as_ref() {
        "ssn" => "SSN".into(),
        _ => self::upcase_first(key),
    }
}

//
// Retry methods
//

pub fn retry<F, T, E>(func: F, max_tries: u32) -> Result<T, E>
where
    F: Fn() -> Result<T, E>,
{
    use std::{thread::sleep, time::Duration};
    let mut tries = 0;

    loop {
        match func() {
            ok @ Ok(_) => return ok,
            err @ Err(_) => {
                tries += 1;

                if tries >= max_tries {
                    return err;
                }

                sleep(Duration::from_millis(500));
            }
        }
    }
}

pub fn retry_db<F, T, E>(func: F, max_tries: u32) -> Result<T, E>
where
    F: Fn() -> Result<T, E>,
    E: std::error::Error,
{
    use std::{thread::sleep, time::Duration};
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

                sleep(Duration::from_millis(1_000));
            }
        }
    }
}
