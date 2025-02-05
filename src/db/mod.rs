use std::{sync::Arc, time::Duration};

use diesel::{
    connection::SimpleConnection,
    r2d2::{ConnectionManager, CustomizeConnection, Pool, PooledConnection},
};

use rocket::{
    http::Status,
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

#[cfg(sqlite)]
#[path = "schemas/sqlite/schema.rs"]
pub mod __sqlite_schema;

#[cfg(mysql)]
#[path = "schemas/mysql/schema.rs"]
pub mod __mysql_schema;

#[cfg(postgresql)]
#[path = "schemas/postgresql/schema.rs"]
pub mod __postgresql_schema;

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

// This is used to generate the main DbConn and DbPool enums, which contain one variant for each database supported
macro_rules! generate_connections {
    ( $( $name:ident: $ty:ty ),+ ) => {
        #[allow(non_camel_case_types, dead_code)]
        #[derive(Eq, PartialEq)]
        pub enum DbConnType { $( $name, )+ }

        pub struct DbConn {
            conn: Arc<Mutex<Option<DbConnInner>>>,
            permit: Option<OwnedSemaphorePermit>,
        }

        #[allow(non_camel_case_types)]
        pub enum DbConnInner { $( #[cfg($name)] $name(PooledConnection<ConnectionManager< $ty >>), )+ }

        #[derive(Debug)]
        pub struct DbConnOptions {
            pub init_stmts: String,
        }

        $( // Based on <https://stackoverflow.com/a/57717533>.
        #[cfg($name)]
        impl CustomizeConnection<$ty, diesel::r2d2::Error> for DbConnOptions {
            fn on_acquire(&self, conn: &mut $ty) -> Result<(), diesel::r2d2::Error> {
                if !self.init_stmts.is_empty() {
                    conn.batch_execute(&self.init_stmts).map_err(diesel::r2d2::Error::QueryError)?;
                }
                Ok(())
            }
        })+

        #[derive(Clone)]
        pub struct DbPool {
            // This is an 'Option' so that we can drop the pool in a 'spawn_blocking'.
            pool: Option<DbPoolInner>,
            semaphore: Arc<Semaphore>
        }

        #[allow(non_camel_case_types)]
        #[derive(Clone)]
        pub enum DbPoolInner { $( #[cfg($name)] $name(Pool<ConnectionManager< $ty >>), )+ }

        impl Drop for DbConn {
            fn drop(&mut self) {
                let conn = Arc::clone(&self.conn);
                let permit = self.permit.take();

                // Since connection can't be on the stack in an async fn during an
                // await, we have to spawn a new blocking-safe thread...
                tokio::task::spawn_blocking(move || {
                    // And then re-enter the runtime to wait on the async mutex, but in a blocking fashion.
                    let mut conn = tokio::runtime::Handle::current().block_on(conn.lock_owned());

                    if let Some(conn) = conn.take() {
                        drop(conn);
                    }

                    // Drop permit after the connection is dropped
                    drop(permit);
                });
            }
        }

        impl Drop for DbPool {
            fn drop(&mut self) {
                let pool = self.pool.take();
                tokio::task::spawn_blocking(move || drop(pool));
            }
        }

        impl DbPool {
            // For the given database URL, guess its type, run migrations, create pool, and return it
            pub fn from_config() -> Result<Self, Error> {
                let url = CONFIG.database_url();
                let conn_type = DbConnType::from_url(&url)?;

                match conn_type { $(
                    DbConnType::$name => {
                        #[cfg($name)]
                        {
                            paste::paste!{ [< $name _migrations >]::run_migrations()?; }
                            let manager = ConnectionManager::new(&url);
                            let pool = Pool::builder()
                                .max_size(CONFIG.database_max_conns())
                                .connection_timeout(Duration::from_secs(CONFIG.database_timeout()))
                                .connection_customizer(Box::new(DbConnOptions{
                                    init_stmts: conn_type.get_init_stmts()
                                }))
                                .build(manager)
                                .map_res("Failed to create pool")?;
                            Ok(DbPool {
                                pool: Some(DbPoolInner::$name(pool)),
                                semaphore: Arc::new(Semaphore::new(CONFIG.database_max_conns() as usize)),
                            })
                        }
                        #[cfg(not($name))]
                        unreachable!("Trying to use a DB backend when it's feature is disabled")
                    },
                )+ }
            }
            // Get a connection from the pool
            pub async fn get(&self) -> Result<DbConn, Error> {
                let duration = Duration::from_secs(CONFIG.database_timeout());
                let permit = match timeout(duration, Arc::clone(&self.semaphore).acquire_owned()).await {
                    Ok(p) => p.expect("Semaphore should be open"),
                    Err(_) => {
                        err!("Timeout waiting for database connection");
                    }
                };

                match self.pool.as_ref().expect("DbPool.pool should always be Some()") {  $(
                    #[cfg($name)]
                    DbPoolInner::$name(p) => {
                        let pool = p.clone();
                        let c = run_blocking(move || pool.get_timeout(duration)).await.map_res("Error retrieving connection from pool")?;

                        Ok(DbConn {
                            conn: Arc::new(Mutex::new(Some(DbConnInner::$name(c)))),
                            permit: Some(permit)
                        })
                    },
                )+ }
            }
        }
    };
}

#[cfg(not(query_logger))]
generate_connections! {
    sqlite: diesel::sqlite::SqliteConnection,
    mysql: diesel::mysql::MysqlConnection,
    postgresql: diesel::pg::PgConnection
}

#[cfg(query_logger)]
generate_connections! {
    sqlite: diesel_logger::LoggingConnection<diesel::sqlite::SqliteConnection>,
    mysql: diesel_logger::LoggingConnection<diesel::mysql::MysqlConnection>,
    postgresql: diesel_logger::LoggingConnection<diesel::pg::PgConnection>
}

impl DbConnType {
    pub fn from_url(url: &str) -> Result<DbConnType, Error> {
        // Mysql
        if url.starts_with("mysql:") {
            #[cfg(mysql)]
            return Ok(DbConnType::mysql);

            #[cfg(not(mysql))]
            err!("`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled")

        // Postgres
        } else if url.starts_with("postgresql:") || url.starts_with("postgres:") {
            #[cfg(postgresql)]
            return Ok(DbConnType::postgresql);

            #[cfg(not(postgresql))]
            err!("`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled")

        //Sqlite
        } else {
            #[cfg(sqlite)]
            return Ok(DbConnType::sqlite);

            #[cfg(not(sqlite))]
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
            Self::sqlite => "PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;".to_string(),
            Self::mysql => String::new(),
            Self::postgresql => String::new(),
        }
    }
}

#[macro_export]
macro_rules! db_run {
    // Same for all dbs
    ( $conn:ident: $body:block ) => {
        db_run! { $conn: sqlite, mysql, postgresql $body }
    };

    ( @raw $conn:ident: $body:block ) => {
        db_run! { @raw $conn: sqlite, mysql, postgresql $body }
    };

    // Different code for each db
    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {{
        #[allow(unused)] use diesel::prelude::*;
        #[allow(unused)] use $crate::db::FromDb;

        let conn = $conn.conn.clone();
        let mut conn = conn.lock_owned().await;
        match conn.as_mut().expect("internal invariant broken: self.connection is Some") {
                $($(
                #[cfg($db)]
                $crate::db::DbConnInner::$db($conn) => {
                    paste::paste! {
                        #[allow(unused)] use $crate::db::[<__ $db _schema>]::{self as schema, *};
                        #[allow(unused)] use [<__ $db _model>]::*;
                    }

                    tokio::task::block_in_place(move || { $body }) // Run blocking can't be used due to the 'static limitation, use block_in_place instead
                },
            )+)+
        }
    }};

    ( @raw $conn:ident: $( $($db:ident),+ $body:block )+ ) => {{
        #[allow(unused)] use diesel::prelude::*;
        #[allow(unused)] use $crate::db::FromDb;

        let conn = $conn.conn.clone();
        let mut conn = conn.lock_owned().await;
        match conn.as_mut().expect("internal invariant broken: self.connection is Some") {
                $($(
                #[cfg($db)]
                $crate::db::DbConnInner::$db($conn) => {
                    paste::paste! {
                        #[allow(unused)] use $crate::db::[<__ $db _schema>]::{self as schema, *};
                        // @ RAW: #[allow(unused)] use [<__ $db _model>]::*;
                    }

                    tokio::task::block_in_place(move || { $body }) // Run blocking can't be used due to the 'static limitation, use block_in_place instead
                },
            )+)+
        }
    }};
}

pub trait FromDb {
    type Output;
    #[allow(clippy::wrong_self_convention)]
    fn from_db(self) -> Self::Output;
}

impl<T: FromDb> FromDb for Vec<T> {
    type Output = Vec<T::Output>;
    #[inline(always)]
    fn from_db(self) -> Self::Output {
        self.into_iter().map(FromDb::from_db).collect()
    }
}

impl<T: FromDb> FromDb for Option<T> {
    type Output = Option<T::Output>;
    #[inline(always)]
    fn from_db(self) -> Self::Output {
        self.map(FromDb::from_db)
    }
}

// For each struct eg. Cipher, we create a CipherDb inside a module named __$db_model (where $db is sqlite, mysql or postgresql),
// to implement the Diesel traits. We also provide methods to convert between them and the basic structs. Later, that module will be auto imported when using db_run!
#[macro_export]
macro_rules! db_object {
    ( $(
        $( #[$attr:meta] )*
        pub struct $name:ident {
            $( $( #[$field_attr:meta] )* $vis:vis $field:ident : $typ:ty ),+
            $(,)?
        }
    )+ ) => {
        // Create the normal struct, without attributes
        $( pub struct $name { $( /*$( #[$field_attr] )**/ $vis $field : $typ, )+ } )+

        #[cfg(sqlite)]
        pub mod __sqlite_model     { $( db_object! { @db sqlite     |  $( #[$attr] )* | $name |  $( $( #[$field_attr] )* $field : $typ ),+ } )+ }
        #[cfg(mysql)]
        pub mod __mysql_model      { $( db_object! { @db mysql      |  $( #[$attr] )* | $name |  $( $( #[$field_attr] )* $field : $typ ),+ } )+ }
        #[cfg(postgresql)]
        pub mod __postgresql_model { $( db_object! { @db postgresql |  $( #[$attr] )* | $name |  $( $( #[$field_attr] )* $field : $typ ),+ } )+ }
    };

    ( @db $db:ident | $( #[$attr:meta] )* | $name:ident | $( $( #[$field_attr:meta] )* $vis:vis $field:ident : $typ:ty),+) => {
        paste::paste! {
            #[allow(unused)] use super::*;
            #[allow(unused)] use diesel::prelude::*;
            #[allow(unused)] use $crate::db::[<__ $db _schema>]::*;

            $( #[$attr] )*
            pub struct [<$name Db>] { $(
                $( #[$field_attr] )* $vis $field : $typ,
            )+ }

            impl [<$name Db>] {
                #[allow(clippy::wrong_self_convention)]
                #[inline(always)] pub fn to_db(x: &super::$name) -> Self { Self { $( $field: x.$field.clone(), )+ } }
            }

            impl $crate::db::FromDb for [<$name Db>] {
                type Output = super::$name;
                #[allow(clippy::wrong_self_convention)]
                #[inline(always)] fn from_db(self) -> Self::Output { super::$name { $( $field: self.$field, )+ } }
            }
        }
    };
}

// Reexport the models, needs to be after the macros are defined so it can access them
pub mod models;

/// Creates a back-up of the sqlite database
/// MySQL/MariaDB and PostgreSQL are not supported.
pub async fn backup_database(conn: &mut DbConn) -> Result<String, Error> {
    db_run! {@raw conn:
        postgresql, mysql {
            let _ = conn;
            err!("PostgreSQL and MySQL/MariaDB do not support this backup feature");
        }
        sqlite {
            let db_url = CONFIG.database_url();
            let db_path = std::path::Path::new(&db_url).parent().unwrap();
            let backup_file = db_path
                .join(format!("db_{}.sqlite3", chrono::Utc::now().format("%Y%m%d_%H%M%S")))
                .to_string_lossy()
                .into_owned();
            diesel::sql_query(format!("VACUUM INTO '{backup_file}'")).execute(conn)?;
            Ok(backup_file)
        }
    }
}

/// Get the SQL Server version
pub async fn get_sql_server_version(conn: &mut DbConn) -> String {
    db_run! {@raw conn:
        postgresql, mysql {
            define_sql_function!{
                fn version() -> diesel::sql_types::Text;
            }
            diesel::select(version()).get_result::<String>(conn).unwrap_or_else(|_| "Unknown".to_string())
        }
        sqlite {
            define_sql_function!{
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
            Some(p) => match p.get().await {
                Ok(dbconn) => Outcome::Success(dbconn),
                _ => Outcome::Error((Status::ServiceUnavailable, ())),
            },
            None => Outcome::Error((Status::InternalServerError, ())),
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

    pub fn run_migrations() -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        let url = crate::CONFIG.database_url();

        // Establish a connection to the sqlite database (this will create a new one, if it does
        // not exist, and exit if there is an error).
        let mut connection = diesel::sqlite::SqliteConnection::establish(&url)?;

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

    pub fn run_migrations() -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::mysql::MysqlConnection::establish(&crate::CONFIG.database_url())?;
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

    pub fn run_migrations() -> Result<(), super::Error> {
        use diesel::Connection;
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::pg::PgConnection::establish(&crate::CONFIG.database_url())?;
        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}
