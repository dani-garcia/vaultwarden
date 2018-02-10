///
/// Macros
///
#[macro_export]
macro_rules! err {
    ($expr:expr) => {{
        err_json!(json!($expr));
    }}
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
use std::fs::File;

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

pub fn parse_option_string<S, T>(string: Option<S>) -> Option<T> where S: Into<String>, T: FromStr {
    if let Some(Ok(value)) = string.map(|s| s.into().parse::<T>()) {
        Some(value)
    } else {
        None
    }
}

///
/// Date util methods
///

use chrono::NaiveDateTime;

const DATETIME_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.6fZ";

pub fn format_date(date: &NaiveDateTime) -> String {
    date.format(DATETIME_FORMAT).to_string()
}
