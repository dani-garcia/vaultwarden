use std::{sync::Arc, time::Duration};

use diesel::{
    connection::SimpleConnection,
    r2d2::{ConnectionManager, CustomizeConnection, Pool, PooledConnection},
};

use rocket::{
    http::Status,
    outcome::IntoOutcome,
    request::{FromRequest, Outcome},
    Request,
};

use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    error::{Error, MapResult},
    CONFIG,
};

// These changes are based on Rocket 0.5-rc wrapper of Diesel: https://github.com/SergioBenitez/Rocket/blob/v0.5-rc/contrib/sync_db_pools
// A wrapper around spawn_blocking that propagates panics to the calling code.
pub async fn run_blocking<F, R>(job: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(ret) => ret,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => unreachable!("spawn_blocking tasks are never cancelled"),
        },
    }
}

#[derive(diesel::MultiConnection)]
pub enum DbConnInner {
    #[cfg(sqlite)]
    Sqlite(diesel::sqlite::SqliteConnection),
    #[cfg(mysql)]
    Mysql(diesel::mysql::MysqlConnection),
    #[cfg(postgresql)]
    Postgresql(diesel::pg::PgConnection),
}

#[derive(Eq, PartialEq)]
pub enum DbConnType {
    #[cfg(sqlite)]
    Sqlite,
    #[cfg(mysql)]
    Mysql,
    #[cfg(postgresql)]
    Postgresql,
}

pub struct DbConn {
    conn: Arc<Mutex<Option<PooledConnection<ConnectionManager<DbConnInner>>>>>,
    permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub struct DbConnOptions {
    pub init_stmts: String,
}

impl CustomizeConnection<DbConnInner, diesel::r2d2::Error> for DbConnOptions {
    fn on_acquire(&self, conn: &mut DbConnInner) -> Result<(), diesel::r2d2::Error> {
        if !self.init_stmts.is_empty() {
            conn.batch_execute(&self.init_stmts).map_err(diesel::r2d2::Error::QueryError)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct DbPool {
    pool: Option<Pool<ConnectionManager<DbConnInner>>>,
    semaphore: Arc<Semaphore>,
}

impl Drop for DbConn {
    fn drop(&mut self) {
        let conn = Arc::clone(&self.conn);
        let permit = self.permit.take();
        tokio::task::spawn_blocking(move || {
            let mut conn = tokio::runtime::Handle::current().block_on(conn.lock_owned());
            if let Some(conn) = conn.take() {
                drop(conn);
            }
            drop(permit);
        });
    }
}

impl Drop for DbPool {
    fn drop(&mut self) {
        let pool = self.pool.take();
        // Only use spawn_blocking if the Tokio runtime is still available
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || drop(pool));
        }
        // Otherwise the pool will be dropped on the current thread
    }
}

impl DbPool {
    pub fn from_config() -> Result<Self, Error> {
        let url = CONFIG.database_url();
        let conn_type = DbConnType::from_url(&url)?;
        match conn_type {
            #[cfg(sqlite)]
            DbConnType::Sqlite => {
                #[cfg(feature = "sqlite")]
                {
                    sqlite_migrations::run_migrations(&url)?;
                }
            }
            #[cfg(mysql)]
            DbConnType::Mysql => {
                #[cfg(feature = "mysql")]
                {
                    mysql_migrations::run_migrations(&url)?;
                }
            }
            #[cfg(postgresql)]
            DbConnType::Postgresql => {
                #[cfg(feature = "postgresql")]
                {
                    postgresql_migrations::run_migrations(&url)?;
                }
            }
        }

        let max_conns = CONFIG.database_max_conns();
        let manager = ConnectionManager::<DbConnInner>::new(&url);
        let pool = Pool::builder()
            .max_size(max_conns)
            .connection_timeout(Duration::from_secs(CONFIG.database_timeout()))
            .connection_customizer(Box::new(DbConnOptions {
                init_stmts: conn_type.get_init_stmts(),
            }))
            .build(manager)
            .map_res("Failed to create pool")?;

        Ok(DbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(max_conns as usize)),
        })
    }

    pub async fn get(&self) -> Result<DbConn, Error> {
        let duration = Duration::from_secs(CONFIG.database_timeout());
        let permit = match timeout(duration, Arc::clone(&self.semaphore).acquire_owned()).await {
            Ok(p) => p.expect("Semaphore should be open"),
            Err(_) => {
                err!("Timeout waiting for database connection");
            }
        };

        let p = self.pool.as_ref().expect("DbPool.pool should always be Some()");
        let pool = p.clone();
        let c =
            run_blocking(move || pool.get_timeout(duration)).await.map_res("Error retrieving connection from pool")?;
        Ok(DbConn {
            conn: Arc::new(Mutex::new(Some(c))),
            permit: Some(permit),
        })
    }
}

impl DbConnType {
    // pub enum Backend
    pub fn from_url(url: &str) -> Result<Self, Error> {
        // Mysql
        if url.len() > 6 && &url[..6] == "mysql:" {
            #[cfg(feature = "mysql")]
            return Ok(DbConnType::Mysql);

            #[cfg(not(feature = "mysql"))]
            err!("`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled")

        // Postgresql
        } else if url.len() > 11 && (&url[..11] == "postgresql:" || &url[..9] == "postgres:") {
            #[cfg(feature = "postgresql")]
            return Ok(DbConnType::Postgresql);

            #[cfg(not(feature = "postgresql"))]
            err!("`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled")

        //Sqlite
        } else {
            #[cfg(feature = "sqlite")]
            return Ok(DbConnType::Sqlite);

            #[cfg(not(feature = "sqlite"))]
            err!("`DATABASE_URL` looks like a SQLite URL, but 'sqlite' feature is not enabled")
        }
    }

    pub fn get_init_stmts(&self) -> String {
        let init_stmts = CONFIG.database_conn_init();
        if !init_stmts.is_empty() {
            init_stmts
        } else {
            self.default_init_stmts()
        }
    }

    pub fn default_init_stmts(&self) -> String {
        match self {
            #[cfg(sqlite)]
            Self::Sqlite => "PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;".to_string(),
            #[cfg(mysql)]
            Self::Mysql => String::new(),
            #[cfg(postgresql)]
            Self::Postgresql => String::new(),
        }
    }
}

// Shared base code for the db_run macro.
macro_rules! db_run_base {
    ( $conn:ident ) => {
        #[allow(unused)]
        use diesel::prelude::*;
        #[allow(unused)]
        use $crate::db::models::{self, *};
        #[allow(unused)]
        use $crate::db::schema::{self, *};

        let conn = $conn.conn.clone();
        let mut conn = conn.lock_owned().await;
        let $conn = conn.as_mut().expect("internal invariant broken: self.conn is Some");
    };
}

#[macro_export]
macro_rules! db_run {
    ( $conn:ident: $body:block ) => {{
        db_run_base!($conn);
        tokio::task::block_in_place(move || $body ) // Run blocking can't be used due to the 'static limitation, use block_in_place instead
    }};

    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {{
        db_run_base!($conn);
        match std::ops::DerefMut::deref_mut($conn) {
            $($(
            #[cfg($db)]
            paste::paste!($crate::db::DbConnInner::[<$db:camel>](ref mut $conn)) => {
                tokio::task::block_in_place(move || $body ) // Run blocking can't be used due to the 'static limitation, use block_in_place instead
            },
        )+)+}
    }};
}

#[path = "schemas/schema.rs"]
pub mod schema;

// Reexport the models, needs to be after the macros are defined so it can access them
pub mod models;

#[allow(unused_variables)] // Since we do not use `conn` in PostgreSQL and MySQL
pub async fn backup_database(conn: &DbConn) -> Result<(), Error> {
    db_run! {conn:
        postgresql, mysql {
            err!("PostgreSQL and MySQL/MariaDB do not support this backup feature");
        }
        sqlite {
            use std::path::Path;
            let db_url = CONFIG.database_url();
            let db_path = Path::new(&db_url).parent().unwrap().to_string_lossy();
            let file_date = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
            diesel::sql_query(format!("VACUUM INTO '{db_path}/db_{file_date}.sqlite3'")).execute(conn)?;
            Ok(())
        }
    }
}

/// Get the SQL Server version
pub async fn get_sql_server_version(conn: &DbConn) -> String {
    db_run! {conn:
        postgresql, mysql {
            sql_function!{
                fn version() -> diesel::sql_types::Text;
            }
            diesel::select(version()).get_result::<String>(conn).unwrap_or_else(|_| "Unknown".to_string())
        }
        sqlite {
            sql_function!{
                fn sqlite_version() -> diesel::sql_types::Text;
            }
            diesel::select(sqlite_version()).get_result::<String>(conn).unwrap_or_else(|_| "Unknown".to_string())
        }
    }
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for DbConn {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.rocket().state::<DbPool>() {
            Some(p) => p.get().await.map_err(|_| ()).into_outcome(Status::ServiceUnavailable),
            None => Outcome::Failure((Status::InternalServerError, ())),
        }
    }
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    pub fn run_migrations(url: &str) -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        // Establish a connection to the sqlite database (this will create a new one, if it does
        // not exist, and exit if there is an error).
        let mut connection = diesel::sqlite::SqliteConnection::establish(url)?;

        // Run the migrations after successfully establishing a connection
        // Disable Foreign Key Checks during migration
        // Scoped to a connection.
        diesel::sql_query("PRAGMA foreign_keys = OFF")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        // Turn on WAL in SQLite
        if crate::CONFIG.enable_db_wal() {
            diesel::sql_query("PRAGMA journal_mode=wal").execute(&mut connection).expect("Failed to turn on WAL");
        }

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(mysql)]
mod mysql_migrations {
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

    pub fn run_migrations(url: &str) -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::mysql::MysqlConnection::establish(url)?;
        // Disable Foreign Key Checks during migration

        // Scoped to a connection/session.
        diesel::sql_query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(postgresql)]
mod postgresql_migrations {
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgresql");

    pub fn run_migrations(url: &str) -> Result<(), super::Error> {
        use diesel::Connection;
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::pg::PgConnection::establish(url)?;
        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}
