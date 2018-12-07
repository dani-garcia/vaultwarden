use std::ops::Deref;

use diesel::{Connection as DieselConnection, ConnectionError};
use diesel::sqlite::SqliteConnection;
use diesel::r2d2;
use diesel::r2d2::ConnectionManager;

use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::{Outcome, Request, State};

use crate::CONFIG;

/// An alias to the database connection used
type Connection = SqliteConnection;

/// An alias to the type for a pool of Diesel SQLite connections.
type Pool = r2d2::Pool<ConnectionManager<Connection>>;

/// Connection request guard type: a wrapper around an r2d2 pooled connection.
pub struct DbConn(pub r2d2::PooledConnection<ConnectionManager<Connection>>);

pub mod schema;
pub mod models;

/// Initializes a database pool.
pub fn init_pool() -> Pool {
    let manager = ConnectionManager::new(&*CONFIG.database_url);

    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool")
}

pub fn get_connection() -> Result<Connection, ConnectionError> {
    Connection::establish(&CONFIG.database_url)
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DbConn, ()> {
        let pool = request.guard::<State<Pool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(DbConn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ()))
        }
    }
}

// For the convenience of using an &DbConn as a &Database.
impl Deref for DbConn {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
