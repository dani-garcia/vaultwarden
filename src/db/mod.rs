use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request, State,
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

// This is used to generate the main DbConn and DbPool enums, which contain one variant for each database supported
macro_rules! generate_connections {
    ( $( $name:ident: $ty:ty ),+ ) => {
        #[allow(non_camel_case_types, dead_code)]
        #[derive(Eq, PartialEq)]
        pub enum DbConnType { $( $name, )+ }

        #[allow(non_camel_case_types)]
        pub enum DbConn { $( #[cfg($name)] $name(PooledConnection<ConnectionManager< $ty >>), )+ }

        #[allow(non_camel_case_types)]
        #[derive(Clone)]
        pub enum DbPool { $( #[cfg($name)] $name(Pool<ConnectionManager< $ty >>), )+ }

        impl DbPool {
            // For the given database URL, guess it's type, run migrations create pool and return it
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
                                .build(manager)
                                .map_res("Failed to create pool")?;
                            return Ok(Self::$name(pool));
                        }
                        #[cfg(not($name))]
                        #[allow(unreachable_code)]
                        return unreachable!("Trying to use a DB backend when it's feature is disabled");
                    },
                )+ }
            }
            // Get a connection from the pool
            pub fn get(&self) -> Result<DbConn, Error> {
                match self {  $(
                    #[cfg($name)]
                    Self::$name(p) => Ok(DbConn::$name(p.get().map_res("Error retrieving connection from pool")?)),
                )+ }
            }
        }
    };
}

generate_connections! {
    sqlite: diesel::sqlite::SqliteConnection,
    mysql: diesel::mysql::MysqlConnection,
    postgresql: diesel::pg::PgConnection
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
}

#[macro_export]
macro_rules! db_run {
    // Same for all dbs
    ( $conn:ident: $body:block ) => {
        db_run! { $conn: sqlite, mysql, postgresql $body }
    };

    // Different code for each db
    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {{
        #[allow(unused)] use diesel::prelude::*;
        match $conn {
            $($(
                #[cfg($db)]
                crate::db::DbConn::$db(ref $conn) => {
                    paste::paste! {
                        #[allow(unused)] use crate::db::[<__ $db _schema>]::{self as schema, *};
                        #[allow(unused)] use [<__ $db _model>]::*;
                        #[allow(unused)] use crate::db::FromDb;
                    }
                    $body
                },
            )+)+
        }}
    };

    // Same for all dbs
    ( @raw $conn:ident: $body:block ) => {
        db_run! { @raw $conn: sqlite, mysql, postgresql $body }
    };

    // Different code for each db
    ( @raw $conn:ident: $( $($db:ident),+ $body:block )+ ) => {
        #[allow(unused)] use diesel::prelude::*;
        #[allow(unused_variables)]
        match $conn {
            $($(
                #[cfg($db)]
                crate::db::DbConn::$db(ref $conn) => {
                    $body
                },
            )+)+
        }
    };
}

pub trait FromDb {
    type Output;
    #[allow(clippy::wrong_self_convention)]
    fn from_db(self) -> Self::Output;
}

impl<T: FromDb> FromDb for Vec<T> {
    type Output = Vec<T::Output>;
    #[allow(clippy::wrong_self_convention)]
    #[inline(always)]
    fn from_db(self) -> Self::Output {
        self.into_iter().map(crate::db::FromDb::from_db).collect()
    }
}

impl<T: FromDb> FromDb for Option<T> {
    type Output = Option<T::Output>;
    #[allow(clippy::wrong_self_convention)]
    #[inline(always)]
    fn from_db(self) -> Self::Output {
        self.map(crate::db::FromDb::from_db)
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
            #[allow(unused)] use crate::db::[<__ $db _schema>]::*;

            $( #[$attr] )*
            pub struct [<$name Db>] { $(
                $( #[$field_attr] )* $vis $field : $typ,
            )+ }

            impl [<$name Db>] {
                #[allow(clippy::wrong_self_convention)]
                #[inline(always)] pub fn to_db(x: &super::$name) -> Self { Self { $( $field: x.$field.clone(), )+ } }
            }

            impl crate::db::FromDb for [<$name Db>] {
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
pub fn backup_database(conn: &DbConn) -> Result<(), Error> {
    db_run! {@raw conn:
        postgresql, mysql {
            err!("PostgreSQL and MySQL/MariaDB do not support this backup feature");
        }
        sqlite {
            use std::path::Path;
            let db_url = CONFIG.database_url();
            let db_path = Path::new(&db_url).parent().unwrap().to_string_lossy();
            let file_date = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
            diesel::sql_query(format!("VACUUM INTO '{}/db_{}.sqlite3'", db_path, file_date)).execute(conn)?;
            Ok(())
        }
    }
}

/// Get the SQL Server version
pub fn get_sql_server_version(conn: &DbConn) -> String {
    db_run! {@raw conn:
        postgresql, mysql {
            no_arg_sql_function!(version, diesel::sql_types::Text);
            diesel::select(version).get_result::<String>(conn).unwrap_or_else(|_| "Unknown".to_string())
        }
        sqlite {
            no_arg_sql_function!(sqlite_version, diesel::sql_types::Text);
            diesel::select(sqlite_version).get_result::<String>(conn).unwrap_or_else(|_| "Unknown".to_string())
        }
    }
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<DbConn, ()> {
        // https://github.com/SergioBenitez/Rocket/commit/e3c1a4ad3ab9b840482ec6de4200d30df43e357c
        let pool = try_outcome!(request.guard::<State<DbPool>>());
        match pool.get() {
            Ok(conn) => Outcome::Success(conn),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ())),
        }
    }
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    embed_migrations!("migrations/sqlite");

    pub fn run_migrations() -> Result<(), super::Error> {
        // Make sure the directory exists
        let url = crate::CONFIG.database_url();
        let path = std::path::Path::new(&url);

        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                error!("Error creating database directory");
                std::process::exit(1);
            }
        }

        use diesel::{Connection, RunQueryDsl};
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = diesel::sqlite::SqliteConnection::establish(&crate::CONFIG.database_url())?;
        // Disable Foreign Key Checks during migration

        // Scoped to a connection.
        diesel::sql_query("PRAGMA foreign_keys = OFF")
            .execute(&connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        // Turn on WAL in SQLite
        if crate::CONFIG.enable_db_wal() {
            diesel::sql_query("PRAGMA journal_mode=wal").execute(&connection).expect("Failed to turn on WAL");
        }

        embedded_migrations::run_with_output(&connection, &mut std::io::stdout())?;
        Ok(())
    }
}

#[cfg(mysql)]
mod mysql_migrations {
    embed_migrations!("migrations/mysql");

    pub fn run_migrations() -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = diesel::mysql::MysqlConnection::establish(&crate::CONFIG.database_url())?;
        // Disable Foreign Key Checks during migration

        // Scoped to a connection/session.
        diesel::sql_query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        embedded_migrations::run_with_output(&connection, &mut std::io::stdout())?;
        Ok(())
    }
}

#[cfg(postgresql)]
mod postgresql_migrations {
    embed_migrations!("migrations/postgresql");

    pub fn run_migrations() -> Result<(), super::Error> {
        use diesel::{Connection, RunQueryDsl};
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = diesel::pg::PgConnection::establish(&crate::CONFIG.database_url())?;
        // Disable Foreign Key Checks during migration

        // FIXME: Per https://www.postgresql.org/docs/12/sql-set-constraints.html,
        // "SET CONSTRAINTS sets the behavior of constraint checking within the
        // current transaction", so this setting probably won't take effect for
        // any of the migrations since it's being run outside of a transaction.
        // Migrations that need to disable foreign key checks should run this
        // from within the migration script itself.
        diesel::sql_query("SET CONSTRAINTS ALL DEFERRED")
            .execute(&connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        embedded_migrations::run_with_output(&connection, &mut std::io::stdout())?;
        Ok(())
    }
}
