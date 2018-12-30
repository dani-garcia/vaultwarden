//
// Error generator macro
//
use std::error::Error as StdError;

macro_rules! make_error {
    ( $( $name:ident ( $ty:ty ): $src_fn:expr, $usr_msg_fun:expr ),+ $(,)* ) => {
        #[derive(Display)]
        enum ErrorKind { $($name( $ty )),+ }
        pub struct Error { message: String, error: ErrorKind }

        $(impl From<$ty> for Error {
            fn from(err: $ty) -> Self { Error::from((stringify!($name), err)) }
        })+
        $(impl<S: Into<String>> From<(S, $ty)> for Error {
            fn from(val: (S, $ty)) -> Self {
                Error { message: val.0.into(), error: ErrorKind::$name(val.1) }
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

use diesel::result::Error as DieselError;
use jsonwebtoken::errors::Error as JwtError;
use serde_json::{Error as SerError, Value};
use std::io::Error as IOError;
use u2f::u2ferror::U2fError as U2fErr;

// Error struct
// Contains a String error message, meant for the user and an enum variant, with an error of different types.
//
// After the variant itself, there are two expressions. The first one indicates whether the error contains a source error (that we pretty print).
// The second one contains the function used to obtain the response sent to the client
make_error! {
    // Used to represent err! calls
    SimpleError(String):  _no_source,  _api_error,
    // Used for special return values, like 2FA errors
    JsonError(Value):     _no_source,  _serialize,
    DbError(DieselError): _has_source, _api_error,
    U2fError(U2fErr):     _has_source, _api_error,
    SerdeError(SerError): _has_source, _api_error,
    JWTError(JwtError):   _has_source, _api_error,
    IoErrror(IOError):    _has_source, _api_error,
    //WsError(ws::Error): _has_source, _api_error,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.source() {
            Some(e) => write!(f, "{}.\n[CAUSE] {:#?}", self.message, e),
            None => write!(f, "{}. {}", self.message, self.error),
        }
    }
}

impl Error {
    pub fn new<M: Into<String>, N: Into<String>>(usr_msg: M, log_msg: N) -> Self {
        (usr_msg, log_msg.into()).into()
    }

    pub fn with_msg<M: Into<String>>(mut self, msg: M) -> Self {
        self.message = msg.into();
        self
    }
}

pub trait MapResult<S, E> {
    fn map_res(self, msg: &str) -> Result<S, E>;
}

impl<S, E: Into<Error>> MapResult<S, Error> for Result<S, E> {
    fn map_res(self, msg: &str) -> Result<S, Error> {
        self.map_err(|e| e.into().with_msg(msg))
    }
}

impl<E: Into<Error>> MapResult<(), Error> for Result<usize, E> {
    fn map_res(self, msg: &str) -> Result<(), Error> {
        self.and(Ok(())).map_res(msg)
    }
}

fn _has_source<T>(e: T) -> Option<T> {
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
        let usr_msg = format!("{}", self);
        error!("{:#?}", self);

        Response::build()
            .status(Status::BadRequest)
            .header(ContentType::JSON)
            .sized_body(Cursor::new(usr_msg))
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
macro_rules! err_json {
    ($expr:expr) => {{
        return Err(crate::error::Error::from($expr));
    }};
}

#[macro_export]
macro_rules! err_handler {
    ($expr:expr) => {{
        return rocket::Outcome::Failure((rocket::http::Status::Unauthorized, $expr));
    }};
}
