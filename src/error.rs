//
// Error generator macro
//
use crate::db::models::EventType;
use crate::http_client::CustomHttpClientError;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::error::Error as StdError;

macro_rules! make_error {
    ( $( $name:ident ( $ty:ty ): $src_fn:expr, $usr_msg_fun:expr ),+ $(,)? ) => {
        const BAD_REQUEST: u16 = 400;

        pub enum ErrorKind { $($name( $ty )),+ }

        #[derive(Debug)]
        pub struct ErrorEvent { pub event: EventType }
        pub struct Error { message: String, error: ErrorKind, error_code: u16, event: Option<ErrorEvent> }

        $(impl From<$ty> for Error {
            fn from(err: $ty) -> Self { Error::from((stringify!($name), err)) }
        })+
        $(impl<S: Into<String>> From<(S, $ty)> for Error {
            fn from(val: (S, $ty)) -> Self {
                Error { message: val.0.into(), error: ErrorKind::$name(val.1), error_code: BAD_REQUEST, event: None }
            }
        })+
        impl StdError for Error {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                match &self.error {$( ErrorKind::$name(e) => $src_fn(e), )+}
            }
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match &self.error {$(
                   ErrorKind::$name(e) => f.write_str(&$usr_msg_fun(e, &self.message)),
                )+}
            }
        }
    };
}

use diesel::r2d2::Error as R2d2Err;
use diesel::r2d2::PoolError as R2d2PoolErr;
use diesel::result::Error as DieselErr;
use diesel::ConnectionError as DieselConErr;
use handlebars::RenderError as HbErr;
use jsonwebtoken::errors::Error as JwtErr;
use lettre::address::AddressError as AddrErr;
use lettre::error::Error as LettreErr;
use lettre::transport::smtp::Error as SmtpErr;
use opendal::Error as OpenDALErr;
use openssl::error::ErrorStack as SSLErr;
use regex::Error as RegexErr;
use reqwest::Error as ReqErr;
use rocket::error::Error as RocketErr;
use serde_json::{Error as SerdeErr, Value};
use std::io::Error as IoErr;
use std::time::SystemTimeError as TimeErr;
use webauthn_rs::prelude::WebauthnError as WebauthnErr;
use yubico::yubicoerror::YubicoError as YubiErr;

#[derive(Serialize)]
pub struct Empty {}

pub struct Compact {}

// Error struct
// Contains a String error message, meant for the user and an enum variant, with an error of different types.
//
// After the variant itself, there are two expressions. The first one indicates whether the error contains a source error (that we pretty print).
// The second one contains the function used to obtain the response sent to the client
make_error! {
    // Just an empty error
    Empty(Empty):     _no_source, _serialize,
    // Used to represent err! calls
    Simple(String):  _no_source,  _api_error,
    Compact(Compact):  _no_source,  _compact_api_error,

    // Used in our custom http client to handle non-global IPs and blocked domains
    CustomHttpClient(CustomHttpClientError): _has_source, _api_error,

    // Used for special return values, like 2FA errors
    Json(Value):           _no_source,  _serialize,
    Db(DieselErr):         _has_source, _api_error,
    R2d2(R2d2Err):         _has_source, _api_error,
    R2d2Pool(R2d2PoolErr): _has_source, _api_error,
    Serde(SerdeErr):       _has_source, _api_error,
    JWt(JwtErr):           _has_source, _api_error,
    Handlebars(HbErr):     _has_source, _api_error,

    Io(IoErr):       _has_source, _api_error,
    Time(TimeErr):   _has_source, _api_error,
    Req(ReqErr):     _has_source, _api_error,
    Regex(RegexErr): _has_source, _api_error,
    Yubico(YubiErr): _has_source, _api_error,

    Lettre(LettreErr): _has_source, _api_error,
    Address(AddrErr):  _has_source, _api_error,
    Smtp(SmtpErr):     _has_source, _api_error,
    OpenSSL(SSLErr):   _has_source, _api_error,
    Rocket(RocketErr): _has_source, _api_error,

    DieselCon(DieselConErr): _has_source, _api_error,
    Webauthn(WebauthnErr):   _has_source, _api_error,

    OpenDAL(OpenDALErr): _has_source, _api_error,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.source() {
            Some(e) => write!(f, "{}.\n[CAUSE] {:#?}", self.message, e),
            None => match self.error {
                ErrorKind::Empty(_) => Ok(()),
                ErrorKind::Simple(ref s) => {
                    if &self.message == s {
                        write!(f, "{}", self.message)
                    } else {
                        write!(f, "{}. {}", self.message, s)
                    }
                }
                ErrorKind::Json(_) => write!(f, "{}", self.message),
                _ => unreachable!(),
            },
        }
    }
}

impl Error {
    pub fn new<M: Into<String>, N: Into<String>>(usr_msg: M, log_msg: N) -> Self {
        (usr_msg, log_msg.into()).into()
    }

    pub fn new_msg<M: Into<String> + Clone>(usr_msg: M) -> Self {
        (usr_msg.clone(), usr_msg.into()).into()
    }

    pub fn empty() -> Self {
        Empty {}.into()
    }

    #[must_use]
    pub fn with_msg<M: Into<String>>(mut self, msg: M) -> Self {
        self.message = msg.into();
        self
    }

    #[must_use]
    pub fn with_kind(mut self, kind: ErrorKind) -> Self {
        self.error = kind;
        self
    }

    #[must_use]
    pub const fn with_code(mut self, code: u16) -> Self {
        self.error_code = code;
        self
    }

    #[must_use]
    pub fn with_event(mut self, event: ErrorEvent) -> Self {
        self.event = Some(event);
        self
    }

    pub fn get_event(&self) -> &Option<ErrorEvent> {
        &self.event
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait MapResult<S> {
    fn map_res(self, msg: &str) -> Result<S, Error>;
}

impl<S, E: Into<Error>> MapResult<S> for Result<S, E> {
    fn map_res(self, msg: &str) -> Result<S, Error> {
        self.map_err(|e| e.into().with_msg(msg))
    }
}

impl<E: Into<Error>> MapResult<()> for Result<usize, E> {
    fn map_res(self, msg: &str) -> Result<(), Error> {
        self.and(Ok(())).map_res(msg)
    }
}

impl<S> MapResult<S> for Option<S> {
    fn map_res(self, msg: &str) -> Result<S, Error> {
        self.ok_or_else(|| Error::new(msg, ""))
    }
}

const fn _has_source<T>(e: T) -> Option<T> {
    Some(e)
}
fn _no_source<T, S>(_: T) -> Option<S> {
    None
}

fn _serialize(e: &impl Serialize, _msg: &str) -> String {
    serde_json::to_string(e).unwrap()
}

/// This will serialize the default ApiErrorResponse
/// It will add the needed fields which are mostly empty or have multiple copies of the message
/// This is more efficient than having a larger struct and use the Serialize derive
/// It also prevents using `json!()` calls to create the final output
impl Serialize for ApiErrorResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(serde::Serialize)]
        struct ErrorModel<'a> {
            message: &'a str,
            object: &'static str,
        }

        let mut state = serializer.serialize_struct("ApiErrorResponse", 9)?;

        state.serialize_field("message", self.0.message)?;

        let mut validation_errors = std::collections::HashMap::with_capacity(1);
        validation_errors.insert("", vec![self.0.message]);
        state.serialize_field("validationErrors", &validation_errors)?;

        let error_model = ErrorModel {
            message: self.0.message,
            object: "error",
        };
        state.serialize_field("errorModel", &error_model)?;

        state.serialize_field("error", "")?;
        state.serialize_field("error_description", "")?;
        state.serialize_field("exceptionMessage", &None::<()>)?;
        state.serialize_field("exceptionStackTrace", &None::<()>)?;
        state.serialize_field("innerExceptionMessage", &None::<()>)?;
        state.serialize_field("object", "error")?;

        state.end()
    }
}

/// This will serialize the smaller CompactApiErrorResponse
/// It will add the needed fields which are mostly empty
/// This is more efficient than having a larger struct and use the Serialize derive
/// It also prevents using `json!()` calls to create the final output
impl Serialize for CompactApiErrorResponse<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CompactApiErrorResponse", 6)?;

        state.serialize_field("message", self.0.message)?;
        state.serialize_field("validationErrors", &None::<()>)?;
        state.serialize_field("exceptionMessage", &None::<()>)?;
        state.serialize_field("exceptionStackTrace", &None::<()>)?;
        state.serialize_field("innerExceptionMessage", &None::<()>)?;
        state.serialize_field("object", "error")?;

        state.end()
    }
}

/// Main API Error struct template
/// This struct which we can be used by both ApiErrorResponse and CompactApiErrorResponse
/// is small and doesn't contain unneeded empty fields. This is more memory efficient, but also less code to compile
struct ApiErrorMsg<'a> {
    message: &'a str,
}
/// Default API Error response struct
/// The custom serialization adds all other needed fields
struct ApiErrorResponse<'a>(ApiErrorMsg<'a>);
/// Compact API Error response struct used for some newer error responses
/// The custom serialization adds all other needed fields
struct CompactApiErrorResponse<'a>(ApiErrorMsg<'a>);

fn _api_error(_: &impl std::any::Any, msg: &str) -> String {
    let response = ApiErrorMsg {
        message: msg,
    };
    serde_json::to_string(&ApiErrorResponse(response)).unwrap()
}

fn _compact_api_error(_: &impl std::any::Any, msg: &str) -> String {
    let response = ApiErrorMsg {
        message: msg,
    };
    serde_json::to_string(&CompactApiErrorResponse(response)).unwrap()
}

//
// Rocket responder impl
//
use std::io::Cursor;

use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};

impl Responder<'_, 'static> for Error {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        match self.error {
            ErrorKind::Empty(_) | ErrorKind::Simple(_) | ErrorKind::Compact(_) => {} // Don't print the error in this situation
            _ => error!(target: "error", "{self:#?}"),
        };

        let code = Status::from_code(self.error_code).unwrap_or(Status::BadRequest);
        let body = self.to_string();
        Response::build().status(code).header(ContentType::JSON).sized_body(Some(body.len()), Cursor::new(body)).ok()
    }
}

//
// Error return macros
//
#[macro_export]
macro_rules! err {
    ($kind:ident, $msg:expr) => {{
        let msg = $msg;
        error!("{msg}");
        return Err($crate::error::Error::new_msg(msg).with_kind($crate::error::ErrorKind::$kind($crate::error::$kind {})));
    }};
    ($msg:expr) => {{
        let msg = $msg;
        error!("{msg}");
        return Err($crate::error::Error::new_msg(msg));
    }};
    ($msg:expr, ErrorEvent $err_event:tt) => {{
        let msg = $msg;
        error!("{msg}");
        return Err($crate::error::Error::new_msg(msg).with_event($crate::error::ErrorEvent $err_event));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        let usr_msg = $usr_msg;
        let log_value = $log_value;
        error!("{usr_msg}. {log_value}");
        return Err($crate::error::Error::new(usr_msg, log_value));
    }};
    ($usr_msg:expr, $log_value:expr, ErrorEvent $err_event:tt) => {{
        let usr_msg = $usr_msg;
        let log_value = $log_value;
        error!("{usr_msg}. {log_value}");
        return Err($crate::error::Error::new(usr_msg, log_value).with_event($crate::error::ErrorEvent $err_event));
    }};
}

#[macro_export]
macro_rules! err_silent {
    ($msg:expr) => {{
        return Err($crate::error::Error::new_msg($msg));
    }};
    ($msg:expr, ErrorEvent $err_event:tt) => {{
        return Err($crate::error::Error::new_msg($msg).with_event($crate::error::ErrorEvent $err_event));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        return Err($crate::error::Error::new($usr_msg, $log_value));
    }};
    ($usr_msg:expr, $log_value:expr, ErrorEvent $err_event:tt) => {{
        return Err($crate::error::Error::new($usr_msg, $log_value).with_event($crate::error::ErrorEvent $err_event));
    }};
}

#[macro_export]
macro_rules! err_code {
    ($msg:expr, $err_code:expr) => {{
        let msg = $msg;
        error!("{msg}");
        return Err($crate::error::Error::new_msg(msg).with_code($err_code));
    }};
    ($usr_msg:expr, $log_value:expr, $err_code:expr) => {{
        let usr_msg = $usr_msg;
        let log_value = $log_value;
        error!("{usr_msg}. {log_value}");
        return Err($crate::error::Error::new(usr_msg, log_value).with_code($err_code));
    }};
}

#[macro_export]
macro_rules! err_discard {
    ($msg:expr, $data:expr) => {{
        std::io::copy(&mut $data.open(), &mut std::io::sink()).ok();
        return Err($crate::error::Error::new_msg($msg));
    }};
    ($usr_msg:expr, $log_value:expr, $data:expr) => {{
        std::io::copy(&mut $data.open(), &mut std::io::sink()).ok();
        return Err($crate::error::Error::new($usr_msg, $log_value));
    }};
}

#[macro_export]
macro_rules! err_json {
    ($expr:expr, $log_value:expr) => {{
        return Err(($log_value, $expr).into());
    }};
    ($expr:expr, $log_value:expr, $err_event:expr, ErrorEvent) => {{
        return Err(($log_value, $expr).into().with_event($err_event));
    }};
}

#[macro_export]
macro_rules! err_handler {
    ($expr:expr) => {{
        error!(target: "auth", "Unauthorized Error: {}", $expr);
        return ::rocket::request::Outcome::Error((rocket::http::Status::Unauthorized, $expr));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        let usr_msg = $usr_msg;
        let log_value = $log_value;
        error!(target: "auth", "Unauthorized Error: {usr_msg}. {log_value}");
        return ::rocket::request::Outcome::Error((rocket::http::Status::Unauthorized, usr_msg));
    }};
}
