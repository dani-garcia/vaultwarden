use std::ops::Deref;

use diesel::r2d2;
use diesel::r2d2::ConnectionManager;
use diesel::{Connection as DieselConnection, ConnectionError};

use rocket::http::Status;
use rocket::request::{self, FromRequest};
use rocket::{Outcome, Request, State};

use crate::error::Error;
use chrono::prelude::*;
use std::process::Command;

use crate::CONFIG;

/// An alias to the database connection used
#[cfg(feature = "sqlite")]
type Connection = diesel::sqlite::SqliteConnection;
#[cfg(feature = "mysql")]
type Connection = diesel::mysql::MysqlConnection;
#[cfg(feature = "postgresql")]
type Connection = diesel::pg::PgConnection;

/// An alias to the type for a pool of Diesel connections.
type Pool = r2d2::Pool<ConnectionManager<Connection>>;

/// Connection request guard type: a wrapper around an r2d2 pooled connection.
pub struct DbConn(pub r2d2::PooledConnection<ConnectionManager<Connection>>);

pub mod models;
#[cfg(feature = "sqlite")]
#[path = "schemas/sqlite/schema.rs"]
pub mod schema;
#[cfg(feature = "mysql")]
#[path = "schemas/mysql/schema.rs"]
pub mod schema;
#[cfg(feature = "postgresql")]
#[path = "schemas/postgresql/schema.rs"]
pub mod schema;

/// Initializes a database pool.
pub fn init_pool() -> Pool {
    let manager = ConnectionManager::new(CONFIG.database_url());
    println!(CONFIG.db_connection_pool_max_size())
    r2d2::Pool::builder()
        .max_size(CONFIG.db_connection_pool_max_size())
        .build(manager)
        .expect("Failed to create pool")
}

pub fn get_connection() -> Result<Connection, ConnectionError> {
    Connection::establish(&CONFIG.database_url())
}

/// Creates a back-up of the database using sqlite3
pub fn backup_database() -> Result<(), Error> {
    use std::path::Path;
    let db_url = CONFIG.database_url();
    let db_path = Path::new(&db_url).parent().unwrap();

    let now: DateTime<Utc> = Utc::now();
    let file_date = now.format("%Y%m%d").to_string();
    let backup_command: String = format!("{}{}{}", ".backup 'db_", file_date, ".sqlite3'");

    Command::new("sqlite3")
        .current_dir(db_path)
        .args(&["db.sqlite3", &backup_command])
        .output()
        .expect("Can't open database, sqlite3 is not available, make sure it's installed and available on the PATH");

    Ok(())
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DbConn, ()> {
        // https://github.com/SergioBenitez/Rocket/commit/e3c1a4ad3ab9b840482ec6de4200d30df43e357c
        let pool = try_outcome!(request.guard::<State<Pool>>());
        match pool.get() {
            Ok(conn) => Outcome::Success(DbConn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ())),
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
