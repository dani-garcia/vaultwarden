//
// Error generator macro
//
use std::error::Error as StdError;

macro_rules! make_error {
    ( $( $name:ident ( $ty:ty ): $src_fn:expr, $usr_msg_fun:expr ),+ $(,)? ) => {
        const BAD_REQUEST: u16 = 400;

        pub enum ErrorKind { $($name( $ty )),+ }
        pub struct Error { message: String, error: ErrorKind, error_code: u16 }

        $(impl From<$ty> for Error {
            fn from(err: $ty) -> Self { Error::from((stringify!($name), err)) }
        })+
        $(impl<S: Into<String>> From<(S, $ty)> for Error {
            fn from(val: (S, $ty)) -> Self {
                Error { message: val.0.into(), error: ErrorKind::$name(val.1), error_code: BAD_REQUEST }
            }
        })+
        impl StdError for Error {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                match &self.error {$( ErrorKind::$name(e) => $src_fn(e), )+}
            }
        }
        impl std::fmt::Display for Error {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match &self.error {$(
                   ErrorKind::$name(e) => f.write_str(&$usr_msg_fun(e, &self.message)),
                )+}
            }
        }
    };
}

use diesel::result::Error as DieselErr;
use diesel::r2d2::PoolError as R2d2Err;
use handlebars::RenderError as HbErr;
use jsonwebtoken::errors::Error as JWTErr;
use regex::Error as RegexErr;
use reqwest::Error as ReqErr;
use serde_json::{Error as SerdeErr, Value};
use std::io::Error as IOErr;

use std::time::SystemTimeError as TimeErr;
use u2f::u2ferror::U2fError as U2fErr;
use yubico::yubicoerror::YubicoError as YubiErr;

use lettre::address::AddressError as AddrErr;
use lettre::error::Error as LettreErr;
use lettre::message::mime::FromStrError as FromStrErr;
use lettre::transport::smtp::error::Error as SmtpErr;

#[derive(Serialize)]
pub struct Empty {}

// Error struct
// Contains a String error message, meant for the user and an enum variant, with an error of different types.
//
// After the variant itself, there are two expressions. The first one indicates whether the error contains a source error (that we pretty print).
// The second one contains the function used to obtain the response sent to the client
make_error! {
    // Just an empty error
    EmptyError(Empty):     _no_source, _serialize,
    // Used to represent err! calls
    SimpleError(String):  _no_source,  _api_error,
    // Used for special return values, like 2FA errors
    JsonError(Value):     _no_source,  _serialize,
    DbError(DieselErr):   _has_source, _api_error,
    R2d2Error(R2d2Err):   _has_source, _api_error,
    U2fError(U2fErr):     _has_source, _api_error,
    SerdeError(SerdeErr): _has_source, _api_error,
    JWTError(JWTErr):     _has_source, _api_error,
    TemplError(HbErr):    _has_source, _api_error,
    //WsError(ws::Error): _has_source, _api_error,
    IOError(IOErr):       _has_source, _api_error,
    TimeError(TimeErr):   _has_source, _api_error,
    ReqError(ReqErr):     _has_source, _api_error,
    RegexError(RegexErr): _has_source, _api_error,
    YubiError(YubiErr):   _has_source, _api_error,

    LetreError(LettreErr):    _has_source, _api_error,
    AddressError(AddrErr):    _has_source, _api_error,
    SmtpError(SmtpErr):       _has_source, _api_error,
    FromStrError(FromStrErr): _has_source, _api_error,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.source() {
            Some(e) => write!(f, "{}.\n[CAUSE] {:#?}", self.message, e),
            None => match self.error {
                ErrorKind::EmptyError(_) => Ok(()),
                ErrorKind::SimpleError(ref s) => {
                    if &self.message == s {
                        write!(f, "{}", self.message)
                    } else {
                        write!(f, "{}. {}", self.message, s)
                    }
                }
                ErrorKind::JsonError(_) => write!(f, "{}", self.message),
                _ => unreachable!(),
            },
        }
    }
}

impl Error {
    pub fn new<M: Into<String>, N: Into<String>>(usr_msg: M, log_msg: N) -> Self {
        (usr_msg, log_msg.into()).into()
    }

    pub fn empty() -> Self {
        Empty {}.into()
    }

    pub fn with_msg<M: Into<String>>(mut self, msg: M) -> Self {
        self.message = msg.into();
        self
    }

    pub const fn with_code(mut self, code: u16) -> Self {
        self.error_code = code;
        self
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

fn _serialize(e: &impl serde::Serialize, _msg: &str) -> String {
    serde_json::to_string(e).unwrap()
}

fn _api_error(_: &impl std::any::Any, msg: &str) -> String {
    let json = json!({
        "Message": "",
        "error": "",
        "error_description": "",
        "ValidationErrors": {"": [ msg ]},
        "ErrorModel": {
            "Message": msg,
            "Object": "error"
        },
        "Object": "error"
    });
    _serialize(&json, "")
}

//
// Rocket responder impl
//
use std::io::Cursor;

use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};

impl<'r> Responder<'r> for Error {
    fn respond_to(self, _: &Request) -> response::Result<'r> {
        match self.error {
            ErrorKind::EmptyError(_) => {} // Don't print the error in this situation
            _ => error!(target: "error", "{:#?}", self),
        };

        let code = Status::from_code(self.error_code).unwrap_or(Status::BadRequest);

        Response::build()
            .status(code)
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}

//
// Error return macros
//
#[macro_export]
macro_rules! err {
    ($msg:expr) => {{
        return Err(crate::error::Error::new($msg, $msg));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        return Err(crate::error::Error::new($usr_msg, $log_value));
    }};
}

#[macro_export]
macro_rules! err_discard {
    ($msg:expr, $data:expr) => {{
        std::io::copy(&mut $data.open(), &mut std::io::sink()).ok();
        return Err(crate::error::Error::new($msg, $msg));
    }};
    ($usr_msg:expr, $log_value:expr, $data:expr) => {{
        std::io::copy(&mut $data.open(), &mut std::io::sink()).ok();
        return Err(crate::error::Error::new($usr_msg, $log_value));
    }};
}

#[macro_export]
macro_rules! err_json {
    ($expr:expr, $log_value:expr) => {{
        return Err(($log_value, $expr).into());
    }};
}

#[macro_export]
macro_rules! err_handler {
    ($expr:expr) => {{
        error!(target: "auth", "Unauthorized Error: {}", $expr);
        return ::rocket::request::Outcome::Failure((rocket::http::Status::Unauthorized, $expr));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        error!(target: "auth", "Unauthorized Error: {}. {}", $usr_msg, $log_value);
        return ::rocket::request::Outcome::Failure((rocket::http::Status::Unauthorized, $usr_msg));
    }};
}
