///
/// Web Headers
///
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Request, Response};

pub struct AppHeaders ();

impl Fairing for AppHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Application Headers",
            kind: Kind::Response,
        }
    }

    fn on_response(&self, _req: &Request, res: &mut Response) {
        res.set_raw_header("Referrer-Policy", "same-origin");
        res.set_raw_header("X-Frame-Options", "SAMEORIGIN");
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        res.set_raw_header("X-XSS-Protection", "1; mode=block");
        let csp = "frame-ancestors 'self' chrome-extension://nngceckbapebfimnlniiiahkandclblb moz-extension://*;";
        res.set_raw_header("Content-Security-Policy", csp);

        // Disable cache unless otherwise specified
        if !res.headers().contains("cache-control") {
            res.set_raw_header("Cache-Control", "no-cache, no-store, max-age=0");
        }
    }
}


///
/// File handling
///
use std::fs::{self, File};
use std::io::{Read, Result as IOResult};
use std::path::Path;

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn read_file(path: &str) -> IOResult<Vec<u8>> {
    let mut contents: Vec<u8> = Vec::new();
    
    let mut file = File::open(Path::new(path))?;
    file.read_to_end(&mut contents)?;

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
    let mut size = size as f64;
    let mut unit_counter = 0;

    loop {
        if size > 1024. {
            size /= 1024.;
            unit_counter += 1;
        } else {
            break;
        }
    };

    // Round to two decimals
    size = (size * 100.).round() / 100.;
    format!("{} {}", size, UNITS[unit_counter])
}

pub fn get_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}


///
/// String util methods
///

use std::str::FromStr;
use std::ops::Try;

pub fn upcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

pub fn try_parse_string<S, T, U>(string: impl Try<Ok = S, Error=U>) -> Option<T> where S: AsRef<str>, T: FromStr {
    if let Ok(Ok(value)) = string.into_result().map(|s| s.as_ref().parse::<T>()) {
        Some(value)
    } else {
        None
    }
}

pub fn try_parse_string_or<S, T, U>(string: impl Try<Ok = S, Error=U>, default: T) -> T where S: AsRef<str>, T: FromStr {
    if let Ok(Ok(value)) = string.into_result().map(|s| s.as_ref().parse::<T>()) {
        value
    } else {
        default
    }
}


///
/// Env methods
/// 

use std::env;

pub fn get_env<V>(key: &str) -> Option<V> where V: FromStr {
    try_parse_string(env::var(key))
}

pub fn get_env_or<V>(key: &str, default: V) -> V where V: FromStr {
    try_parse_string_or(env::var(key), default)
}

///
/// Date util methods
///

use chrono::NaiveDateTime;

const DATETIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";

pub fn format_date(date: &NaiveDateTime) -> String {
    date.format(DATETIME_FORMAT).to_string()
}

///
/// Deserialization methods
///

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

/// https://github.com/serde-rs/serde/issues/586
pub fn upcase_deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where T: DeserializeOwned,
          D: Deserializer<'de>
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
        where A: MapAccess<'de>
    {
        let mut result_map = JsonMap::new();

        while let Some((key, value)) = map.next_entry()? {
            result_map.insert(upcase_first(key), upcase_value(&value));
        }

        Ok(Value::Object(result_map))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where A: SeqAccess<'de> {
        let mut result_seq = Vec::<Value>::new();

        while let Some(value) = seq.next_element()? {
            result_seq.push(upcase_value(&value));
        }

        Ok(Value::Array(result_seq))
    }
}

fn upcase_value(value: &Value) -> Value {
    if let Some(map) = value.as_object() {
        let mut new_value = json!({});
        
        for (key, val) in map {
            let processed_key = _process_key(key);
            new_value[processed_key] = upcase_value(val);
        }
        new_value
    
    } else if let Some(array) = value.as_array() {
        // Initialize array with null values
        let mut new_value = json!(vec![Value::Null; array.len()]);

        for (index, val) in array.iter().enumerate() {
            new_value[index] = upcase_value(val);
        }
        new_value
    
    } else {
        value.clone()
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

pub fn retry<F, T, E>(func: F, max_tries: i32) -> Result<T, E>
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
