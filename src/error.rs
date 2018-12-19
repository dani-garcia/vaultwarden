//
// Error generator macro
//
macro_rules! make_error {
    ( $struct:ident; $( $name:ident ( $ty:ty, _): $show_cause:expr, $usr_msg_fun:expr ),+ $(,)* ) => {
        #[derive(Debug)]
        #[allow(unused_variables, dead_code)]
        pub enum $struct {
            $($name( $ty, String )),+
        }
        $(impl From<$ty> for $struct {
            fn from(err: $ty) -> Self {
                $struct::$name(err, String::from(stringify!($name)))
            }
        })+
        $(impl From<($ty, String)> for $struct {
            fn from(err: ($ty, String)) -> Self {
                $struct::$name(err.0, err.1)
            }
        })+
        impl $struct {
            pub fn with_msg<M: Into<String>>(self, msg: M) -> Self {
                match self {$(
                   $struct::$name(e, _) => $struct::$name(e, msg.into()),
                )+}
            }
            // First value is log message, second is user message
            pub fn display_error(self) -> String {
                match &self {$(
                   $struct::$name(e, s) => {
                       let log_msg = format!("{}. {}", &s, &e);

                        error!("{}", log_msg);
                        if $show_cause {
                            error!("[CAUSE] {:?}", e);
                        }

                        $usr_msg_fun(e, s)
                   },
                )+}
            }
        }

    };
}

use diesel::result::{Error as DieselError, QueryResult};
use serde_json::{Value, Error as SerError};
use u2f::u2ferror::U2fError as U2fErr;

// Error struct
// Each variant has two elements, the first is an error of different types, used for logging purposes
// The second is a String, and it's contents are displayed to the user when the error occurs. Inside the macro, this is represented as _
// 
// After the variant itself, there are two expressions. The first one is a bool to indicate whether the error cause will be printed to the log.
// The second one contains the function used to obtain the response sent to the client
make_error! {
    Error;
    // Used to represent err! calls
    SimpleError(String,  _): false, _api_error,
    // Used for special return values, like 2FA errors
    JsonError(Value,     _): false, _serialize,
    DbError(DieselError, _): true,  _api_error,
    U2fError(U2fErr,     _): true,  _api_error,
    SerdeError(SerError, _): true,  _api_error,
    //WsError(ws::Error, _): true,  _api_error,
}

impl Error {
    pub fn new<M: Into<String>, N: Into<String>>(usr_msg: M, log_msg: N) -> Self {
        Error::SimpleError(log_msg.into(), usr_msg.into())
    }
}

pub trait MapResult<S, E> {
    fn map_res(self, msg: &str) -> Result<(), E>;
}

impl MapResult<(), Error> for QueryResult<usize> {
    fn map_res(self, msg: &str) -> Result<(), Error> {
        self.and(Ok(())).map_err(Error::from).map_err(|e| e.with_msg(msg))
    }
}

use serde::Serialize;
use std::any::Any;

fn _serialize(e: &impl Serialize, _: &impl Any) -> String {
    serde_json::to_string(e).unwrap()
}

fn _api_error(_: &impl Any, msg: &str) -> String {
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

    _serialize(&json, &false)
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
        // TODO: We could put the security headers here

        let usr_msg = self.display_error();

        Response::build()
            .status(Status::BadRequest)
            .header(ContentType::JSON)
            .sized_body(Cursor::new(usr_msg))
            .ok()
    }
}

///
/// Error return macros
///
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
