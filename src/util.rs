///
/// Macros
///
#[macro_export]
macro_rules! err {
    ($err:expr, $err_desc:expr, $msg:expr) => {
        err_json!(json!({
          "error": $err,
          "error_description": $err_desc,
          "ErrorModel": {
            "Message": $msg,
            "ValidationErrors": null,
            "Object": "error"
          }
        }))
    };
    ($msg:expr) => { err!("default_error", "default_error_description", $msg) }
}

#[macro_export]
macro_rules! err_json {
    ($expr:expr) => {{
        println!("ERROR: {}", $expr);
        return Err($crate::rocket::response::status::BadRequest(Some($crate::rocket_contrib::Json($expr))));
    }}
}

#[macro_export]
macro_rules! err_handler {
    ($expr:expr) => {{
        println!("ERROR: {}", $expr);
        return $crate::rocket::Outcome::Failure(($crate::rocket::http::Status::Unauthorized, $expr));
    }}
}

///
/// File handling
///

use std::path::Path;
use std::io::Read;
use std::fs::{self, File};

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(Path::new(path))
        .map_err(|e| format!("Error opening file: {}", e))?;

    let mut contents: Vec<u8> = Vec::new();

    file.read_to_end(&mut contents)
        .map_err(|e| format!("Error reading file: {}", e))?;

    Ok(contents)
}

pub fn delete_file(path: &str) -> bool {
    let res = fs::remove_file(path).is_ok();

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


///
/// String util methods
///

use std::str::FromStr;

pub fn upcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

pub fn parse_option_string<S, T>(string: Option<S>) -> Option<T> where S: AsRef<str>, T: FromStr {
    if let Some(Ok(value)) = string.map(|s| s.as_ref().parse::<T>()) {
        Some(value)
    } else {
        None
    }
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
        _ => self::upcase_first(key)
    }
}
