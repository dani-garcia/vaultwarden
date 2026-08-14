mod query_logger;

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use diesel::{
    Connection, RunQueryDsl,
    connection::SimpleConnection,
    r2d2::{CustomizeConnection, Pool, PooledConnection},
};
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    CONFIG,
    error::{Error, MapResult},
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

// This is used to generate the main DbConn and DbPool enums, which contain one variant for each database supported
#[derive(diesel::MultiConnection)]
pub enum DbConnInner {
    #[cfg(mysql)]
    Mysql(diesel::mysql::MysqlConnection),
    #[cfg(postgresql)]
    Postgresql(diesel::pg::PgConnection),
    #[cfg(sqlite)]
    Sqlite(diesel::sqlite::SqliteConnection),
}

/// Custom connection manager that implements manual connection establishment
pub struct DbConnManager {
    database_url: String,
}

impl DbConnManager {
    pub fn new(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_owned(),
        }
    }

    fn establish_connection(&self) -> Result<DbConnInner, diesel::r2d2::Error> {
        match DbConnType::from_url(&self.database_url) {
            #[cfg(mysql)]
            Ok(DbConnType::Mysql) => {
                let conn = diesel::mysql::MysqlConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Mysql(conn))
            }
            #[cfg(postgresql)]
            Ok(DbConnType::Postgresql) => {
                let conn = diesel::pg::PgConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Postgresql(conn))
            }
            #[cfg(sqlite)]
            Ok(DbConnType::Sqlite) => {
                let conn = diesel::sqlite::SqliteConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Sqlite(conn))
            }

            Err(e) => Err(diesel::r2d2::Error::ConnectionError(diesel::ConnectionError::InvalidConnectionUrl(
                format!("Unable to estabilsh a connection: {e:?}"),
            ))),
        }
    }
}

impl diesel::r2d2::ManageConnection for DbConnManager {
    type Connection = DbConnInner;
    type Error = diesel::r2d2::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        self.establish_connection()
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        use diesel::r2d2::R2D2Connection;
        conn.ping().map_err(diesel::r2d2::Error::QueryError)
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        use diesel::r2d2::R2D2Connection;
        conn.is_broken()
    }
}

#[derive(Eq, PartialEq)]
pub enum DbConnType {
    #[cfg(mysql)]
    Mysql,
    #[cfg(postgresql)]
    Postgresql,
    #[cfg(sqlite)]
    Sqlite,
}

pub static ACTIVE_DB_TYPE: OnceLock<DbConnType> = OnceLock::new();

pub struct DbConn {
    conn: Arc<Mutex<Option<PooledConnection<DbConnManager>>>>,
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
    // This is an 'Option' so that we can drop the pool in a 'spawn_blocking'.
    pool: Option<Pool<DbConnManager>>,
    semaphore: Arc<Semaphore>,
}

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
        // Only use spawn_blocking if the Tokio runtime is still available
        // Otherwise the pool will be dropped on the current thread
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || drop(pool));
        }
    }
}

impl DbPool {
    // For the given database URL, guess its type, run migrations, create pool, and return it
    pub fn from_config() -> Result<Self, Error> {
        let db_url = CONFIG.database_url();
        let conn_type = DbConnType::from_url(&db_url)?;

        // Only set the default instrumentation if the log level is specifically set to either warn, info or debug
        if log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Warn)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Info)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Debug)
        {
            drop(diesel::connection::set_default_instrumentation(query_logger::simple_logger));
        }

        match conn_type {
            #[cfg(mysql)]
            DbConnType::Mysql => {
                mysql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(postgresql)]
            DbConnType::Postgresql => {
                postgresql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(sqlite)]
            DbConnType::Sqlite => {
                sqlite_migrations::run_migrations(&db_url)?;
            }
        }

        let max_conns = CONFIG.database_max_conns();
        let manager = DbConnManager::new(&db_url);
        let pool = Pool::builder()
            .max_size(max_conns)
            .min_idle(Some(CONFIG.database_min_conns()))
            .idle_timeout(Some(Duration::from_secs(CONFIG.database_idle_timeout())))
            .connection_timeout(Duration::from_secs(CONFIG.database_timeout()))
            .connection_customizer(Box::new(DbConnOptions {
                init_stmts: conn_type.get_init_stmts(),
            }))
            .build(manager)
            .map_res("Failed to create pool")?;

        // Set a global to determine the database more easily throughout the rest of the code
        if ACTIVE_DB_TYPE.set(conn_type).is_err() {
            error!("Tried to set the active database connection type more than once.");
        }

        Ok(DbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(max_conns as usize)),
        })
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
    pub fn from_url(url: &str) -> Result<Self, Error> {
        // Mysql
        if url.len() > 6 && &url[..6] == "mysql:" {
            #[cfg(mysql)]
            return Ok(DbConnType::Mysql);

            #[cfg(not(mysql))]
            err!("`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled")

        // Postgresql
        } else if url.len() > 11 && (&url[..11] == "postgresql:" || &url[..9] == "postgres:") {
            #[cfg(postgresql)]
            return Ok(DbConnType::Postgresql);

            #[cfg(not(postgresql))]
            err!("`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled")

        // Sqlite (explicit)
        } else if url.len() > 7 && &url[..7] == "sqlite:" {
            #[cfg(sqlite)]
            return Ok(DbConnType::Sqlite);

            #[cfg(not(sqlite))]
            err!("`DATABASE_URL` is a SQLite URL, but the 'sqlite' feature is not enabled")
        }

        // No recognized scheme — assume legacy bare-path SQLite, but the database file must already exist.
        // This prevents misconfigured URLs (typos, quoted strings) from silently creating a new empty SQLite database.
        #[cfg(sqlite)]
        {
            if std::path::Path::new(url).exists() {
                return Ok(DbConnType::Sqlite);
            }
            err!(format!(
                "`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://) \
                    and no existing SQLite database was found at '{url}'. \
                    If you intend to use SQLite, use an explicit `sqlite://` scheme in your `DATABASE_URL`. \
                    Otherwise, check your DATABASE_URL for typos or quoting issues."
            ))
        }

        #[cfg(not(sqlite))]
        err!("`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://)")
    }

    pub fn get_init_stmts(&self) -> String {
        let init_stmts = CONFIG.database_conn_init();
        if init_stmts.is_empty() {
            self.default_init_stmts()
        } else {
            init_stmts
        }
    }

    pub fn default_init_stmts(&self) -> String {
        match self {
            #[cfg(mysql)]
            Self::Mysql => String::new(),
            #[cfg(postgresql)]
            Self::Postgresql => String::new(),
            #[cfg(sqlite)]
            Self::Sqlite => "PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;".to_owned(),
        }
    }
}

impl DbConn {
    pub async fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DbConnInner) -> R + Send,
        R: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        let mut conn = conn.lock_owned().await;
        let conn = conn.as_mut().expect("Internal invariant broken: self.conn is Some");

        // Run blocking can't be used due to the 'static limitation, use block_in_place instead
        tokio::task::block_in_place(move || f(conn))
    }
}

#[macro_export]
macro_rules! db_run {
    ( $conn:ident: $body:block ) => {
        $conn.run(move |$conn| $body).await
    };

    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {
        $conn.run(move |$conn| {
            match $conn {
                $($(
                #[cfg($db)]
                pastey::paste!(&mut $crate::db::DbConnInner::[<$db:camel>](ref mut $conn)) => {
                    $body
                },
            )+)+}
        }).await
    };
}

// Write all ToSql<Text, DB> and FromSql<Text, DB> given a serializable/deserializable type.
#[macro_export]
macro_rules! impl_FromToSqlText {
    ($name:ty) => {
        #[cfg(mysql)]
        impl ToSql<Text, diesel::mysql::Mysql> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(postgresql)]
        impl ToSql<Text, diesel::pg::Pg> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(sqlite)]
        impl ToSql<Text, diesel::sqlite::Sqlite> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
                serde_json::to_string(self).map_err(Into::into).map(|str| {
                    out.set_value(str);
                    diesel::serialize::IsNull::No
                })
            }
        }

        impl<DB: diesel::backend::Backend> FromSql<Text, DB> for $name
        where
            String: FromSql<Text, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                <String as FromSql<Text, DB>>::from_sql(bytes)
                    .and_then(|str| serde_json::from_str(&str).map_err(Into::into))
            }
        }
    };
}

pub mod schema;

// Reexport the models, needs to be after the macros are defined so it can access them
pub mod models;

/// Creates a back-up of the sqlite database
/// MySQL/MariaDB and PostgreSQL are not supported.
#[cfg(sqlite)]
pub fn backup_sqlite() -> Result<String, Error> {
    use diesel::Connection;

    let db_url = CONFIG.database_url();
    if DbConnType::from_url(&CONFIG.database_url()).is_ok_and(|t| t == DbConnType::Sqlite) {
        // Strip the sqlite:// prefix if present to get the raw file path
        let file_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        // Open a read-only connection for the backup
        let mut conn = diesel::sqlite::SqliteConnection::establish(&format!("sqlite://{file_path}?mode=ro"))?;

        let db_path = std::path::Path::new(file_path).parent().unwrap();
        let backup_file = db_path
            .join(format!("db_{}.sqlite3", chrono::Utc::now().format("%Y%m%d_%H%M%S")))
            .to_string_lossy()
            .into_owned();

        diesel::sql_query("VACUUM INTO ?")
            .bind::<diesel::sql_types::Text, _>(&backup_file)
            .execute(&mut conn)
            .map(|_| ())
            .map_res("VACUUM INTO failed")?;

        Ok(backup_file)
    } else {
        err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
    }
}

#[cfg(not(sqlite))]
pub fn backup_sqlite() -> Result<String, Error> {
    err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
}

/// Get the SQL Server version
pub async fn get_sql_server_version(conn: &DbConn) -> String {
    db_run! { conn:
        postgresql,mysql {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
        }
        sqlite {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("sqlite_version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
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

const CUSTOM_ROLE_REPAIR_MIGRATION: &str = "20260723120000";
const CUSTOM_COLLECTION_PERMISSIONS_MIGRATION: &str = "20260716120000";
const DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION: &str = "20260724120000";
const CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION: &str = "20260630120000";
const CUSTOM_ACCESS_PERMISSIONS_MIGRATION: &str = "20260724130000";
const CONFIRM_PERMANENT_AUTHORITY_MIGRATION: &str = "20260810120000";
const CUSTOM_ROLE_SAME_RUN_MARKER_TABLE: &str = "__vw_custom_role_same_run_0716";
/// Records which memberships were legacy Managers, written by
/// {`CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION`} before it reuses `atype = 3` for the Custom role.
///
/// Its *presence* doubles as the marker that {`CUSTOM_ROLE_REPAIR_MIGRATION`} ran in its current
/// form. Both files were rewritten after an earlier revision of this feature branch shipped, and
/// Diesel never re-runs a migration whose version is already in the ledger -- so a database upgraded
/// by that earlier revision carries the repair migration's version without any of the effects the
/// current one has.
const CUSTOM_ROLE_LEGACY_MANAGER_TABLE: &str = "__vw_custom_role_legacy_manager";
/// Marks that this database's Custom-role history is accounted for.
///
/// Created by {`CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION`} in its current form -- so every database
/// migrated by the code that ships today has it -- or by an operator who has audited an older
/// history by hand. Nothing else creates it, which is what makes it usable as evidence.
///
/// It is deliberately separate from {`CUSTOM_ROLE_LEGACY_MANAGER_TABLE`}. That one holds data an
/// operator may legitimately have to write after the fact, so its existence cannot also stand for
/// "the history behind this data was reviewed" -- creating it empty to make an error message go away
/// would otherwise silently pass as an audit.
const CUSTOM_ROLE_HISTORY_VERIFIED_TABLE: &str = "__vw_custom_role_history_verified";
/// An owner's decision that the group-derived collection authority
/// {`CUSTOM_ROLE_REPAIR_MIGRATION`} materializes onto the membership may become permanent.
///
/// Written by an operator, read and consumed by {`CONFIRM_PERMANENT_AUTHORITY_MIGRATION`}. The
/// preflight looks ahead for the same condition that migration checks, so the decision is asked for
/// with the full recovery text instead of surfacing as its bare duplicate-key abort.
const PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE: &str = "__vw_ack_permanent_collection_authority";

/// One of the three groups of granular permission columns, each added by its own migration.
///
/// A partially present group means the migration was interrupted between its `ALTER TABLE`
/// statements. On MySQL/MariaDB that is reachable because DDL commits implicitly, so the ledger entry
/// can be missing while some columns already exist; re-running the migration then fails forever with
/// `Duplicate column name`. Detect it and hand the operator an unambiguous fix instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionColumnGroup {
    Manage,
    Collection,
    Access,
}

impl PermissionColumnGroup {
    const fn migration(self) -> &'static str {
        match self {
            Self::Manage => CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION,
            Self::Collection => CUSTOM_COLLECTION_PERMISSIONS_MIGRATION,
            Self::Access => CUSTOM_ACCESS_PERMISSIONS_MIGRATION,
        }
    }

    /// SQL list literal of the group's column names, for the `IN (...)` lookups.
    const fn column_list(self) -> &'static str {
        match self {
            Self::Manage => "'manage_users', 'manage_groups', 'manage_policies'",
            Self::Collection => "'create_new_collections', 'edit_any_collection', 'delete_any_collection'",
            Self::Access => "'access_event_logs', 'access_import_export', 'access_reports'",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Manage => "custom management-permission",
            Self::Collection => "custom collection-permission",
            Self::Access => "custom access-permission",
        }
    }

    /// Whether this group's migration derives its values from the legacy `access_all` column.
    ///
    /// Only the collection group does (`create_new_collections = access_all` and friends). That makes
    /// it the one group whose migration can no longer be executed once `access_all` has been dropped by
    /// {`DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION`}, so it must never be recommended for a replay
    /// afterwards. The other two only add columns (and convert the retired Manager type), which stays
    /// valid at any point in the chain.
    const fn reads_legacy_access_all(self) -> bool {
        matches!(self, Self::Collection)
    }
}

const PARTIAL_PERMISSION_COLUMNS_RECOVERY: &str = concat!(
    "\n\nThis happens when a migration was interrupted between its ALTER TABLE statements (on ",
    "MySQL/MariaDB every DDL statement commits on its own, so columns can exist without the ledger ",
    "entry). Because the migration never completed, Vaultwarden never wrote to these columns: they ",
    "only hold their FALSE default, so dropping them loses nothing and lets the migration run again ",
    "from a clean state.\n\n",
    "List the columns that are already present:\n",
    "SELECT column_name\n",
    "FROM information_schema.columns\n",
    "WHERE table_name = 'users_organizations'\n",
    "  AND column_name IN ('manage_users', 'manage_groups', 'manage_policies',\n",
    "                      'create_new_collections', 'edit_any_collection', 'delete_any_collection',\n",
    "                      'access_event_logs', 'access_import_export', 'access_reports');\n\n",
    "(On SQLite: SELECT name FROM pragma_table_info('users_organizations');)\n\n",
    "Then, with every Vaultwarden instance stopped and a backup taken, drop exactly the columns of ",
    "the affected group that the message above names, e.g.:\n",
    "ALTER TABLE users_organizations DROP COLUMN <COLUMN_NAME>;\n\n",
    "Afterwards restart Vaultwarden so the migration applies the whole group in one go."
);

/// Deliberately *not* the same advice as [`PARTIAL_PERMISSION_COLUMNS_RECOVERY`].
///
/// Here the ledger entry is present, so the migration did complete once and Vaultwarden has been
/// running with those columns: the ones that are still there can hold real granted permissions. The
/// missing columns cannot have been lost by an interrupted migration -- something dropped them
/// afterwards -- so telling the operator to drop the remainder would destroy live authorization data.
/// It would not even recover the instance: with the ledger entry in place, the next start finds zero
/// columns for a recorded migration and refuses again.
const PERMISSION_LEDGER_MISMATCH_RECOVERY: &str = concat!(
    "\n\nUnlike an interrupted migration, this state means the migration already completed once, so ",
    "the columns that are still present can hold real permissions that members were granted. Do not ",
    "drop them: that destroys authorization data, and it does not fix the refusal either, because the ",
    "ledger entry stays behind.\n\n",
    "Restoring the database backup taken before the columns went missing is the only lossless fix. ",
    "Run the upgrade again against that restored copy.\n\n",
    "If the lost permissions are genuinely expendable, the migration can be replayed from scratch ",
    "instead. With every Vaultwarden instance stopped and a backup taken, drop the remaining columns ",
    "of the affected group that the message above names AND remove its ledger entry, so the migration ",
    "is pending again rather than recorded-but-missing:\n",
    "ALTER TABLE users_organizations DROP COLUMN <COLUMN_NAME>;\n",
    "DELETE FROM __diesel_schema_migrations WHERE version = '<MIGRATION_VERSION>';\n\n",
    "Every member of the affected organizations then has to be re-checked, because the permissions ",
    "come back as FALSE."
);

/// Recovery for a damaged collection-permission group *after* `access_all` has been dropped.
///
/// Neither of the two texts above applies there. Both ultimately rely on the migration running again --
/// by leaving it pending, or by deleting its ledger row -- but `2026-07-16-120000` computes its three
/// columns *from* `access_all`, which `2026-07-24-120000` has already removed. A replay therefore fails
/// with "no such column: access_all" on every start, and on MySQL/MariaDB it fails *after* its three
/// `ADD COLUMN`s have committed, leaving the database stuck in the very state that was being repaired.
/// The way out is to reach the completed shape without executing that SQL at all.
const COLLECTION_PERMISSIONS_AFTER_DROP_RECOVERY: &str = concat!(
    "\n\nThis group cannot be migrated again on this database: migration ",
    "2026-07-16-120000 derives its three columns from the membership access_all column, and ",
    "2026-07-24-120000 has already dropped that column. Leaving the migration pending, or deleting its ",
    "ledger entry so it runs again, therefore fails on every start -- and on MySQL/MariaDB it fails only ",
    "after its own ALTER TABLE statements have committed.\n\n",
    "Restoring the database backup taken before these columns went missing is the only lossless fix. ",
    "Run the upgrade again against that restored copy.\n\n",
    "If the lost permissions are expendable, bring the group to its completed shape by hand instead, ",
    "with every Vaultwarden instance stopped and a backup taken. Add whichever of the three columns the ",
    "message above reports as missing:\n",
    "ALTER TABLE users_organizations ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE;\n",
    "ALTER TABLE users_organizations ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE;\n",
    "ALTER TABLE users_organizations ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE;\n\n",
    "Then make sure the migration counts as done, so it is never executed:\n",
    "INSERT INTO __diesel_schema_migrations (version) VALUES ('20260716120000');\n\n",
    "(Skip that INSERT if the entry is already there -- the message above says whether it is.)\n\n",
    "Every Custom member of every organization then has to be re-checked, because the three collection ",
    "permissions come back as FALSE and nothing can reconstruct their previous values."
);

const LEGACY_USER_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nList the affected memberships:\n",
    "SELECT uuid, user_uuid, org_uuid, status\n",
    "FROM users_organizations\n",
    "WHERE atype = 2\n",
    "  AND access_all = TRUE;\n\n",
    "The bit gave these members read/write reach over every collection of the organization, including ",
    "collections created later, but no collection-management authority -- and it stopped applying as ",
    "soon as the membership was revoked. The new role model has no equivalent, so an owner has to pick ",
    "one of the two meanings per membership, with every Vaultwarden instance stopped and a backup ",
    "taken.\n\n",
    "The reach is no longer wanted -- this is also the right choice for an invited, accepted or revoked ",
    "membership: clear the bit. The member keeps every collection they are explicitly assigned to.\n",
    "UPDATE users_organizations\n",
    "SET access_all = FALSE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>';\n\n",
    "The reach has to survive: write it out as explicit assignments first, then clear the bit. Do this ",
    "only for a confirmed membership, and only if a snapshot is acceptable -- collections created after ",
    "this point are not added, and unlike access_all these rows are not tied to the membership status.\n",
    "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)\n",
    "SELECT uo.user_uuid, c.uuid, FALSE, FALSE, FALSE\n",
    "FROM users_organizations uo\n",
    "INNER JOIN collections c ON c.org_uuid = uo.org_uuid\n",
    "WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND NOT EXISTS (\n",
    "    SELECT 1 FROM users_collections uc\n",
    "    WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = c.uuid\n",
    "  );\n\n",
    "Existing assignments are left untouched by that statement, so re-check their read_only / ",
    "hide_passwords values: access_all used to override both.\n\n",
    "If the member genuinely needs organization-wide reach afterwards, give them the Custom role with ",
    "the 'Edit any collection' permission from the web vault once the upgrade has completed. That is ",
    "the supported, visible and revocable equivalent."
);

const INTERRUPTED_ACCESS_ALL_DROP_RECOVERY: &str = concat!(
    "\n\nThe drop itself carries no data, so the schema is already in its intended final state and ",
    "only the ledger entry is missing. Vaultwarden completes this automatically on MySQL/MariaDB, ",
    "where it is reachable because DDL commits implicitly. On this backend DDL is transactional, so ",
    "the state points at a manual schema change. With every Vaultwarden instance stopped and a ",
    "backup taken, record the migration:\n",
    "INSERT INTO __diesel_schema_migrations (version) VALUES ('20260724120000');\n\n",
    "Afterwards restart Vaultwarden so the remaining migrations run."
);

const ACCESS_ALL_DROP_MISMATCH_RECOVERY: &str = concat!(
    "\n\nThis state cannot arise from a normal upgrade -- the column is removed before the migration ",
    "is recorded. Verify whether the column was re-added manually. If it was, and its values are no ",
    "longer needed, drop it again with every Vaultwarden instance stopped and a backup taken:\n",
    "ALTER TABLE users_organizations DROP COLUMN access_all;\n\n",
    "Otherwise restore the database backup taken before the upgrade and run the upgrade again."
);

const OUT_OF_ORDER_ACCESS_PERMISSIONS_RECOVERY: &str = concat!(
    "\n\nDo not run the pending migrations on this database. In particular, the SQLite ",
    "2026-07-24-120000 migration rebuilds users_organizations from the schema that existed before ",
    "the three access-permission columns were added. If 2026-07-24-130000 already ran, that rebuild ",
    "would drop access_event_logs, access_import_export and access_reports -- including any granted ",
    "values -- while Diesel would skip the already-recorded migration that adds them.\n\n",
    "Restoring the database backup taken before the migrations were applied out of order and running ",
    "the upgrade again is the lossless fix. If no such backup exists, keep every Vaultwarden instance ",
    "stopped and have a database administrator preserve the three access-permission values while ",
    "bringing the schema and migration ledger back to the documented version order. Do not delete the ",
    "20260724130000 ledger entry or run 20260724120000 without first preserving those values."
);

const UNVERIFIED_CUSTOM_ROLE_HISTORY_RECOVERY: &str = concat!(
    "\n\nIf you still have the backup from before this database was first upgraded, restoring it and ",
    "upgrading again is simplest and needs no decision at all. Otherwise work through the three points ",
    "below with every Vaultwarden instance stopped and a backup taken. Which of them apply depends on ",
    "how far the earlier revision got, which its ledger entries tell you:\n",
    "SELECT version FROM __diesel_schema_migrations WHERE version >= '20260630120000' ORDER BY version;\n\n",
    "1) Which memberships were legacy Managers -- always. The upgrade reuses atype 3 for the Custom ",
    "role, so after it has run a converted Manager and a Custom member created later are identical. ",
    "Without this record the remaining migrations cannot repair legacy authority, and the rollback ",
    "scripts in tools/custom_role_rollback/ cannot map roles back. Create the table and record every ",
    "membership that held the Manager role before the first upgrade:\n",
    "CREATE TABLE __vw_custom_role_legacy_manager (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);\n",
    "INSERT INTO __vw_custom_role_legacy_manager (users_organizations_uuid) VALUES ('<MEMBERSHIP_UUID>');\n",
    "Leaving it empty is a valid answer and means \"no membership was a legacy Manager\".\n\n",
    "2) Permissions granted by an earlier 20260809120000 -- if that version is in your ledger. It set ",
    "edit_any_collection and delete_any_collection on every Custom member of a group with access_all, ",
    "including members that were never Managers, so Create-only became Create+Edit+Delete and a member ",
    "with no permissions became Edit+Delete -- which also implies full collection access. Nothing can ",
    "tell those apart from deliberate grants any more, so review them and clear what you did not ",
    "intend:\n",
    "SELECT uo.uuid, uo.org_uuid, uo.status, uo.create_new_collections, uo.edit_any_collection,\n",
    "       uo.delete_any_collection\n",
    "FROM users_organizations uo\n",
    "INNER JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid\n",
    "INNER JOIN groups g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid\n",
    "WHERE uo.atype = 4 AND g.access_all = TRUE;\n\n",
    "3) A plain User carrying membership access_all -- if 20260723120000 is in your ledger. The earlier ",
    "revision converted that state into direct assignments to the collections that existed at the time ",
    "and then dropped the column; the current one refuses it instead, because the reach also covered ",
    "collections created later. Those assignments are indistinguishable from ordinary ones now:\n",
    "SELECT uc.user_uuid, uc.collection_uuid, uc.read_only, uc.hide_passwords, uc.manage\n",
    "FROM users_collections uc\n",
    "INNER JOIN users_organizations uo ON uo.user_uuid = uc.user_uuid\n",
    "INNER JOIN collections c ON c.uuid = uc.collection_uuid AND c.org_uuid = uo.org_uuid\n",
    "WHERE uo.atype = 2;\n\n",
    "Then record that the history was audited. This is a separate statement on purpose: creating the ",
    "table in point 1 writes data, and data alone must not pass as a review of where it came from.\n",
    "CREATE TABLE __vw_custom_role_history_verified (verified INTEGER NOT NULL PRIMARY KEY);\n\n",
    "Use CHAR(36) instead of TEXT for the uuid column on MySQL/MariaDB and PostgreSQL."
);

/// The one question this feature has to ask, phrased before the upgrade rather than during it.
///
/// {`CONFIRM_PERMANENT_AUTHORITY_MIGRATION`} refuses the same condition from inside the migration, as
/// the backstop for a bare migration runner. On the normal startup path that abort would reach the
/// operator as nothing but `UNIQUE constraint failed: __vw_permanent_authority_guard.blocked` (or
/// `Duplicate entry '1' for key 'PRIMARY'` on MariaDB), because Diesel only reports the driver error
/// -- so the decision, the review query and the acknowledgement all have to be printed from here.
const PERMANENT_COLLECTION_AUTHORITY_RECOVERY: &str = concat!(
    "\n\nBefore the Custom role, a Manager who reached every collection through an organization-local ",
    "group with access_all held that authority *while* the group relationship lasted: it ended with ",
    "the group, with its accessAll, and with the membership leaving it, and it was inert whenever ",
    "ORG_GROUPS_ENABLED was false. The new model has no permission that is bound to a group like ",
    "that -- edit_any_collection and delete_any_collection live on the membership -- so migration ",
    "20260723120000 writes the authority onto the membership, and the result is deliberately not ",
    "identical to what it replaces:\n",
    "  * it no longer lapses when the last qualifying group disappears, or when accessAll is ",
    "cleared;\n",
    "  * it applies even with the groups feature switched off;\n",
    "  * edit_any_collection additionally satisfies has_full_access(), so the member reaches every ",
    "collection of the organization directly rather than through the group.\n\n",
    "Granting that silently would be a migration handing out durable organization-wide collection ",
    "edit and delete on its own authority; skipping it silently would take a capability away. ",
    "Neither is Vaultwarden's to choose, so an owner decides. Review the affected memberships with ",
    "every Vaultwarden instance stopped and a backup taken.\n\n",
    "Before migration 20260630120000 has run (legacy Manager is still atype 3):\n",
    "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status\n",
    "FROM users_organizations uo\n",
    "WHERE uo.atype = 3\n",
    "  AND EXISTS (\n",
    "    SELECT 1 FROM groups_users gu\n",
    "    INNER JOIN \"groups\" g ON g.uuid = gu.groups_uuid\n",
    "      AND g.organizations_uuid = uo.org_uuid\n",
    "    WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = TRUE);\n\n",
    "If 20260630120000 is already in the migration ledger but the three collection-permission ",
    "columns do not exist yet, use this query instead. It includes recorded converted Managers and ",
    "an unrecorded Custom membership whose own access_all bit 20260716120000 will turn into all ",
    "three permissions:\n",
    "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status, uo.access_all,\n",
    "       (uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))\n",
    "           AS was_legacy_manager\n",
    "FROM users_organizations uo\n",
    "WHERE (uo.atype = 3 OR (uo.atype = 4 AND (\n",
    "         uo.access_all = TRUE OR uo.uuid IN (\n",
    "           SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))))\n",
    "  AND EXISTS (\n",
    "    SELECT 1 FROM groups_users gu\n",
    "    INNER JOIN \"groups\" g ON g.uuid = gu.groups_uuid\n",
    "      AND g.organizations_uuid = uo.org_uuid\n",
    "    WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = TRUE);\n\n",
    "After the permission columns exist:\n",
    "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status,\n",
    "       uo.create_new_collections, uo.edit_any_collection, uo.delete_any_collection,\n",
    "       (uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))\n",
    "           AS was_legacy_manager\n",
    "FROM users_organizations uo\n",
    "WHERE uo.atype = 4\n",
    "  AND (uo.edit_any_collection = TRUE OR uo.delete_any_collection = TRUE)\n",
    "  AND EXISTS (\n",
    "    SELECT 1 FROM groups_users gu\n",
    "    INNER JOIN \"groups\" g ON g.uuid = gu.groups_uuid\n",
    "      AND g.organizations_uuid = uo.org_uuid\n",
    "    WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = TRUE);\n\n",
    "(Quote `groups` with backticks instead of double quotes on MySQL/MariaDB, here and below.)\n\n",
    "Reading the result:\n",
    "  * was_legacy_manager = 1 -- a converted Manager. Review it even when create_new_collections is ",
    "set. That permission can be changed independently after an earlier migration materialized the ",
    "group-derived edit/delete grant, so its current value is not reliable historical provenance. A ",
    "membership whose own legacy access_all supplied all three permissions may therefore be listed ",
    "conservatively even though its authority was already permanent.\n",
    "  * was_legacy_manager = 0 -- never a Manager. Before the collection columns exist, its own ",
    "membership access_all will become all three permissions in 20260716120000. After the columns ",
    "exist on a database first upgraded by an earlier revision of this feature branch, ",
    "20260809120000 may instead have granted edit_any_collection and delete_any_collection in bulk ",
    "to every Custom member of an access_all group. Check either result against what you intended.\n",
    "  * An invited or revoked membership is listed as well. It holds no authority today -- every ",
    "guard requires a confirmed membership -- but the permission is what it would come back with if ",
    "it is ever restored, so the decision belongs here too.\n\n",
    "Clearing what you do not want to keep differs according to whether the collection-permission ",
    "columns exist yet.\n\n",
    "Before those columns exist, the authority being reviewed is still tied to the qualifying group ",
    "relationship, so end that -- for ",
    "the one membership, or for the whole group at once:\n",
    "DELETE FROM groups_users\n",
    "WHERE users_organizations_uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND groups_uuid = '<GROUP_UUID>';\n",
    "UPDATE \"groups\" SET access_all = FALSE WHERE uuid = '<GROUP_UUID>';\n",
    "Whatever still matches the applicable pre-column query afterwards is what the acknowledgement ",
    "below covers. ",
    "Removing the membership from the group also takes away the access it has today, which clearing ",
    "the permission columns after the upgrade would not -- that is the same decision either way, just ",
    "made before rather than after.\n\n",
    "Once the permission columns exist, clear them directly. Doing it after the upgrade is equally ",
    "safe: Vaultwarden does not start until the acknowledgement is recorded, so nothing is ever live ",
    "in between.\n",
    "UPDATE users_organizations\n",
    "SET edit_any_collection = FALSE, delete_any_collection = FALSE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>';\n\n",
    "Then record the decision once, and restart:\n",
    "CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);\n\n",
    "The acknowledgement is consumed by 20260810120000, so one decision covers one upgrade. It grants ",
    "nothing and revokes nothing by itself -- whatever you leave set is what the members keep."
);

const ALREADY_DROPPED_RECOVERY: &str = concat!(
    "\n\nThe permission values cannot be recomputed from the current schema. Restore the database backup taken ",
    "before the upgrade and run the upgrade again against that restored copy."
);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "These are independent facts read from a historical database schema and migration ledger"
)]
struct CustomRoleMigrationFacts {
    memberships_table_exists: bool,
    migration_table_exists: bool,
    access_all_column_exists: bool,
    manage_permission_columns: i64,
    manage_permissions_migration_applied: bool,
    collection_permission_columns: i64,
    collection_permissions_migration_applied: bool,
    access_permission_columns: i64,
    access_permissions_migration_applied: bool,
    repair_migration_applied: bool,
    access_all_drop_migration_applied: bool,
    legacy_user_access_all_count: i64,
    same_run_0716_marker: bool,
    legacy_manager_record_exists: bool,
    history_verified: bool,
    confirm_permanent_authority_migration_applied: bool,
    permanent_collection_authority_ack: bool,
    /// Memberships {`CONFIRM_PERMANENT_AUTHORITY_MIGRATION`} will stop the upgrade for, counted from
    /// whichever schema shape this database currently has — see
    /// [`permanent_authority_lookahead_query`].
    unconfirmed_permanent_authority_count: i64,
}

impl CustomRoleMigrationFacts {
    /// `(columns present, migration recorded)` for one permission column group.
    const fn permission_columns(self, group: PermissionColumnGroup) -> (i64, bool) {
        match group {
            PermissionColumnGroup::Manage => {
                (self.manage_permission_columns, self.manage_permissions_migration_applied)
            }
            PermissionColumnGroup::Collection => {
                (self.collection_permission_columns, self.collection_permissions_migration_applied)
            }
            PermissionColumnGroup::Access => {
                (self.access_permission_columns, self.access_permissions_migration_applied)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustomRolePreflightDecision {
    Proceed,
    CompleteMysqlCollectionMigration,
    CompleteInterruptedAccessAllDrop,
    RefuseAlreadyDropped,
    RefuseMissingAccessAll,
    RefuseMissingMigrationLedger,
    RefuseLegacyUserAccessAll,
    RefuseUnverifiedCustomRoleHistory,
    RefuseUnconfirmedPermanentCollectionAuthority,
    RefuseInterruptedAccessAllDrop,
    RefuseAccessAllDropLedgerMismatch,
    RefuseOutOfOrderAccessPermissionsMigration,
    RefusePartialPermissionSchema(PermissionColumnGroup),
    RefusePermissionLedgerMismatch(PermissionColumnGroup),
}

const fn needs_permanent_collection_authority_decision(facts: CustomRoleMigrationFacts) -> bool {
    !facts.confirm_permanent_authority_migration_applied
        && !facts.permanent_collection_authority_ack
        && facts.unconfirmed_permanent_authority_count != 0
}

fn custom_role_preflight_decision(
    facts: CustomRoleMigrationFacts,
    can_complete_mysql_partial_migration: bool,
) -> CustomRolePreflightDecision {
    if !facts.memberships_table_exists {
        return CustomRolePreflightDecision::Proceed;
    }
    if !facts.migration_table_exists {
        return CustomRolePreflightDecision::RefuseMissingMigrationLedger;
    }

    // The legacy reconstruction below only makes sense while the repair migration is still ahead of
    // us. Everything *after* it -- the access_all drop and the third permission column group -- still
    // has to be checked on every start: both run after the repair, and on MySQL/MariaDB each DDL
    // statement commits on its own, so a crash between the statement and Diesel's ledger insert
    // leaves a durable partial state. Returning early for every repaired database would hide exactly
    // those states, and the generic Diesel retry then fails on every following start with
    // `Unknown column` (1091) or `Duplicate column name` (1060).
    // The first Custom-role migration is recorded, but not by the version of it that ships today:
    // an earlier revision of this feature branch wrote that ledger entry, and Diesel never runs a
    // recorded version again. Several things then differ silently from a fresh upgrade, none of them
    // reconstructible from the schema afterwards, so stop before the remaining migrations run.
    //
    // Checked against the whole chain rather than only the repair migration, because the divergence
    // starts at the very first one: `atype = 3` has already been reused for the Custom role, without
    // anything recording which memberships that value used to mean "Manager" for.
    //
    // Checked against the history marker rather than the legacy-Manager record, because the record
    // is data an operator has to be able to write during recovery -- gating on it would let the act
    // of silencing the error double as the audit it is asking for.
    //
    // Both tables are required. The marker alone would leave the later migrations and the rollback
    // scripts without the data they need; the record alone would mean the audit never happened.
    if facts.manage_permissions_migration_applied && !(facts.history_verified && facts.legacy_manager_record_exists) {
        return CustomRolePreflightDecision::RefuseUnverifiedCustomRoleHistory;
    }

    // The access-permission migration is ordered immediately after the membership access_all drop.
    // A database carrying the later ledger entry while the drop is still pending is not a harmless
    // gap: SQLite's portable drop rebuild has a fixed pre-access-permissions column list and would
    // destroy those three columns and their values. Diesel would then skip the already-recorded
    // migration that adds them. Refuse the non-prefix ledger before any automatic MySQL repair or
    // pending migration can mutate the database.
    if facts.access_permissions_migration_applied && !facts.access_all_drop_migration_applied {
        return CustomRolePreflightDecision::RefuseOutOfOrderAccessPermissionsMigration;
    }

    // Automatic MySQL repairs are mutations. Remember a repairable state here, but do not select it
    // until every refusal below has been evaluated. In particular, recording a missing ledger row or
    // completing 0716 before discovering another damaged permission group (or an unanswered owner
    // decision) would make the eventual "Nothing has been changed" refusal false.
    let mut automatic_repair = None;

    if facts.repair_migration_applied {
        // The drop is a single statement with no data component, so it is all-or-nothing: either the
        // column is still there and the migration is pending, or the column is gone and the
        // migration is recorded.
        if facts.access_all_column_exists == facts.access_all_drop_migration_applied {
            if facts.access_all_drop_migration_applied {
                return CustomRolePreflightDecision::RefuseAccessAllDropLedgerMismatch;
            } else if can_complete_mysql_partial_migration {
                // Only reachable on MySQL/MariaDB, and the schema is already in its intended final
                // state. Defer recording the migration until every refusal has been checked.
                automatic_repair = Some(CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop);
            } else {
                return CustomRolePreflightDecision::RefuseInterruptedAccessAllDrop;
            }
        }
    } else {
        // Once access_all has been dropped, its former value can no longer be reconstructed. Never
        // guess at it.
        if facts.access_all_drop_migration_applied {
            return CustomRolePreflightDecision::RefuseAlreadyDropped;
        }
        if !facts.access_all_column_exists {
            return CustomRolePreflightDecision::RefuseMissingAccessAll;
        }

        // A plain User carrying membership `access_all` has no representation in the new model: the
        // bit gave unlimited *reach* over every collection, present and future, without any
        // management authority, and the role that replaces it cannot express that. Converting the
        // reach into direct per-collection assignments would silently turn a dynamic guarantee into a
        // point-in-time snapshot, and -- because a `users_collections` row is not bound to the
        // membership status the way `access_all` was -- would hand a revoked or never-confirmed member
        // durable assignments that outlive this schema. Refuse and let an owner decide.
        if facts.legacy_user_access_all_count != 0 {
            return CustomRolePreflightDecision::RefuseLegacyUserAccessAll;
        }
    }

    // Every permission column group must be either completely absent (its migration is still pending)
    // or completely present with its ledger entry. Anything else is an interrupted migration whose
    // re-run would fail with `Duplicate column name`, so refuse with an actionable message. The single
    // historical exception is the collection group on MySQL, where the known-good partial state is
    // completed in place.
    for group in [PermissionColumnGroup::Manage, PermissionColumnGroup::Collection, PermissionColumnGroup::Access] {
        match facts.permission_columns(group) {
            (0, false) | (3, true) => {}
            (3, false)
                if group == PermissionColumnGroup::Collection
                    && can_complete_mysql_partial_migration
                    && !facts.repair_migration_applied
                    && facts.access_all_column_exists =>
            {
                // This is the historical MySQL 0716 partial state: its DDL committed, while the
                // ledger and the later 0723 repair are both still pending. `access_all` is required
                // by both the validation and completion queries. Merely remember the repair here so
                // a later permission group or the permanent-authority decision can still refuse
                // without any preceding mutation.
                automatic_repair = Some(CustomRolePreflightDecision::CompleteMysqlCollectionMigration);
            }
            (_, true) => return CustomRolePreflightDecision::RefusePermissionLedgerMismatch(group),
            _ => return CustomRolePreflightDecision::RefusePartialPermissionSchema(group),
        }
    }

    // Last, because it is the only refusal that is not about a damaged database: the schema is fine
    // and the upgrade is ready to run, but one step of it changes a meaning that nothing in the new
    // model can express, and that is an owner's decision rather than a migration's. Checked here
    // rather than left to the migration's own guard so the question arrives with the review query
    // and the acknowledgement attached — Diesel would surface that guard as nothing but its
    // driver-level duplicate-key error.
    if needs_permanent_collection_authority_decision(facts) {
        return CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority;
    }

    automatic_repair.unwrap_or(CustomRolePreflightDecision::Proceed)
}

fn custom_role_preflight_error(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> Error {
    let detail = match decision {
        CustomRolePreflightDecision::RefuseAlreadyDropped => format!(
            "The membership access_all column was already dropped by migration \
             {DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION}, but the required repair migration \
             {CUSTOM_ROLE_REPAIR_MIGRATION} is not recorded. The former permission values cannot \
             be reconstructed safely."
        ),
        CustomRolePreflightDecision::RefuseMissingAccessAll => format!(
            "The membership access_all column is missing before repair migration \
             {CUSTOM_ROLE_REPAIR_MIGRATION}; refusing to infer deleted permissions."
        ),
        CustomRolePreflightDecision::RefuseMissingMigrationLedger => {
            "The users_organizations table exists, but the Diesel migration ledger does not. \
             Refusing to guess which schema and data migrations were previously applied."
                .to_owned()
        }
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => format!(
            "Found {} membership(s) of the plain User type carrying the legacy access_all bit. That \
             combination has no representation in the Custom role model: it grants dynamic reach over \
             every collection without any management authority.",
            facts.legacy_user_access_all_count
        ),
        CustomRolePreflightDecision::RefuseUnverifiedCustomRoleHistory => format!(
            "Migration {CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION} is recorded, but the tables it \
             creates today are not both present ({CUSTOM_ROLE_LEGACY_MANAGER_TABLE}: {}, \
             {CUSTOM_ROLE_HISTORY_VERIFIED_TABLE}: {}). This database was upgraded by an earlier \
             revision of the Custom-role change, whose migrations had different effects and which \
             Diesel will not re-run.",
            if facts.legacy_manager_record_exists {
                "present"
            } else {
                "missing"
            },
            if facts.history_verified {
                "present"
            } else {
                "missing"
            }
        ),
        CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority => format!(
            "Migration {CONFIRM_PERMANENT_AUTHORITY_MIGRATION} needs a decision before it can run: {} \
             membership(s) match collection authority that may have come from an organization-local \
             access_all group. The current permissions cannot distinguish every group-derived grant \
             from independently changed or legacy membership-level authority, so the check is \
             deliberately conservative rather than silently making a possible group-derived grant \
             permanent. Nothing has been changed.",
            facts.unconfirmed_permanent_authority_count
        ),
        CustomRolePreflightDecision::RefusePartialPermissionSchema(group) => format!(
            "Found {} of the three {} columns ({}) without a completed {} migration. The migration \
             was interrupted between its ALTER TABLE statements.",
            facts.permission_columns(group).0,
            group.description(),
            group.column_list(),
            group.migration()
        ),
        CustomRolePreflightDecision::RefusePermissionLedgerMismatch(group) => format!(
            "Migration {} is recorded, but only {} of its three {} columns ({}) exist.",
            group.migration(),
            facts.permission_columns(group).0,
            group.description(),
            group.column_list()
        ),
        CustomRolePreflightDecision::RefuseInterruptedAccessAllDrop => format!(
            "The membership access_all column is already gone, but migration \
             {DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION} is not recorded. The column was dropped without \
             its ledger entry, so re-running the migration would fail on every start."
        ),
        CustomRolePreflightDecision::RefuseAccessAllDropLedgerMismatch => format!(
            "Migration {DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION} is recorded, but the membership \
             access_all column still exists. Schema and migration ledger disagree."
        ),
        CustomRolePreflightDecision::RefuseOutOfOrderAccessPermissionsMigration => format!(
            "Migration {CUSTOM_ACCESS_PERMISSIONS_MIGRATION} is recorded while its required earlier \
             migration {DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION} is not. The Custom-role migration ledger \
             is not a valid prefix, and continuing could destroy stored access-permission values. \
             Nothing has been changed."
        ),
        CustomRolePreflightDecision::Proceed
        | CustomRolePreflightDecision::CompleteMysqlCollectionMigration
        | CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop => {
            unreachable!("successful preflight decisions do not produce errors")
        }
    };
    let recovery = match decision {
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => LEGACY_USER_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseUnverifiedCustomRoleHistory => UNVERIFIED_CUSTOM_ROLE_HISTORY_RECOVERY,
        CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority => {
            PERMANENT_COLLECTION_AUTHORITY_RECOVERY
        }
        // Once access_all is gone, the collection group's migration can no longer run at all, so
        // neither of the two generic texts may be handed out -- both end in a replay.
        CustomRolePreflightDecision::RefusePartialPermissionSchema(group)
        | CustomRolePreflightDecision::RefusePermissionLedgerMismatch(group)
            if group.reads_legacy_access_all() && !facts.access_all_column_exists =>
        {
            COLLECTION_PERMISSIONS_AFTER_DROP_RECOVERY
        }
        CustomRolePreflightDecision::RefusePartialPermissionSchema(_) => PARTIAL_PERMISSION_COLUMNS_RECOVERY,
        CustomRolePreflightDecision::RefusePermissionLedgerMismatch(_) => PERMISSION_LEDGER_MISMATCH_RECOVERY,
        CustomRolePreflightDecision::RefuseAlreadyDropped => ALREADY_DROPPED_RECOVERY,
        CustomRolePreflightDecision::RefuseInterruptedAccessAllDrop => INTERRUPTED_ACCESS_ALL_DROP_RECOVERY,
        CustomRolePreflightDecision::RefuseAccessAllDropLedgerMismatch => ACCESS_ALL_DROP_MISMATCH_RECOVERY,
        CustomRolePreflightDecision::RefuseOutOfOrderAccessPermissionsMigration => {
            OUT_OF_ORDER_ACCESS_PERMISSIONS_RECOVERY
        }
        _ => "",
    };

    std::io::Error::other(format!(
        "Custom-role migration preflight stopped startup: {detail} Back up the database and resolve \
         the legacy membership state manually before restarting.{recovery}"
    ))
    .into()
}

/// Counts the memberships {`CONFIRM_PERMANENT_AUTHORITY_MIGRATION`} will refuse to convert without an
/// owner's acknowledgement — from whichever schema shape the database has *right now*.
///
/// Two broad shapes, because the preflight runs before any migration does and the answer has to be
/// the same either way:
///
///   * **After the collection columns exist** the authority is already materialized, so this is the
///     migration's own predicate verbatim. `create_new_collections` is deliberately not used as a
///     provenance proxy: owners can change that independent permission after an earlier revision
///     materialized group-derived edit/delete, so its current value cannot prove where those two
///     permissions came from. Keeping the two predicates textually parallel is the point.
///   * **Before them** — the ordinary upgrade from a release without this feature — the columns are
///     not there yet and the answer has to be predicted from the legacy schema. `atype = 3` is the
///     retired Manager role, which {`CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION`} both records and
///     converts to Custom. Between the two migrations `atype = 4` rows can exist without the columns;
///     they are only attributable through the record, which is guaranteed to be present by then (the
///     history refusal above requires it whenever `20260630120000` is recorded). A Manager that also
///     carried membership `access_all` is conservatively included: asking an owner again is safer than
///     treating a mutable modern permission as immutable historical evidence. An unrecorded Custom
///     membership carrying `access_all` is included too: 0716 will turn that stored bit into 1/1/1,
///     which the later materialized guard will preserve and ask about if the membership is also in an
///     organization-local `access_all` group.
///
/// `groups` is the backend's quoting of the reserved identifier. Returns `None` when neither shape is
/// readable, which is also exactly when the migration cannot run yet.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "These independent booleans describe historical schema and migration-ledger facts"
)]
fn permanent_authority_lookahead_query(
    collection_columns_present: bool,
    access_all_column_exists: bool,
    legacy_manager_record_exists: bool,
    collection_permissions_migration_applied: bool,
    repair_migration_applied: bool,
    groups: &str,
) -> Option<String> {
    let in_access_all_group = format!(
        "EXISTS ( \
             SELECT 1 \
             FROM groups_users AS gu \
             INNER JOIN {groups} AS g ON g.uuid = gu.groups_uuid \
             WHERE gu.users_organizations_uuid = uo.uuid \
               AND g.organizations_uuid = uo.org_uuid \
               AND g.access_all = TRUE \
         )"
    );
    let on_record = format!("uo.uuid IN (SELECT users_organizations_uuid FROM {CUSTOM_ROLE_LEGACY_MANAGER_TABLE})");

    if collection_columns_present && collection_permissions_migration_applied && repair_migration_applied {
        // Do not infer provenance from `create_new_collections`. It is an independently mutable
        // permission, so an owner can turn a group-derived 0/1/1 grant into 1/1/1 after an earlier
        // revision ran. Excluding that current shape would silently accept the very permanent
        // edit/delete authority this question exists to review. Conservatively ask about every
        // materialized edit/delete grant that still has the qualifying group relationship.
        Some(format!(
            "SELECT COUNT(*) AS count FROM users_organizations AS uo \
             WHERE uo.atype = 4 \
               AND (uo.edit_any_collection = TRUE OR uo.delete_any_collection = TRUE) \
               AND {in_access_all_group}"
        ))
    } else if access_all_column_exists {
        // This branch also covers both historical states in which the columns exist but the repair is
        // still pending: MySQL DDL committed without the 0716 ledger, or an earlier recorded 0716 did
        // not contain today's group update. In either case 20260723120000 will materialize the
        // provenance-bound group authority. 0716 also turns an unrecorded Custom membership's own
        // `access_all` bit into 1/1/1. Project both end states instead of trusting temporary 0/0/0
        // values, so the owner is asked before any automatic completion or pending migration.
        let pending_conversion = if legacy_manager_record_exists {
            format!(
                "(uo.atype = 3 OR (uo.atype = 4 AND \
                  ({on_record} OR uo.access_all = TRUE)))"
            )
        } else {
            "(uo.atype = 3 OR (uo.atype = 4 AND uo.access_all = TRUE))".to_owned()
        };
        // When the collection columns already exist, also retain any materialized Custom grant that
        // is not part of the legacy-Manager record. The pending repair does not create that grant, but
        // the later confirmation migration will still preserve it permanently. `OR` keeps both sets
        // in one membership-level count without double-counting recorded rows that already have 0/1/1.
        let pending_or_materialized_authority = if collection_columns_present {
            format!(
                "({pending_conversion} OR (uo.atype = 4 AND \
                  (uo.edit_any_collection = TRUE OR uo.delete_any_collection = TRUE)))"
            )
        } else {
            pending_conversion
        };
        Some(format!(
            "SELECT COUNT(*) AS count FROM users_organizations AS uo \
             WHERE {pending_or_materialized_authority} \
               AND {in_access_all_group}"
        ))
    } else {
        None
    }
}

/// Requires every existing relation the PostgreSQL preflight and migration chain share to resolve to
/// the schema in which unqualified `CREATE TABLE` statements will create new bookkeeping objects.
///
/// `to_regclass` correctly follows `search_path` for an existing relation, but `CREATE TABLE` uses
/// `current_schema()`. With `search_path = decoy, real` and Vaultwarden's tables in `real`, reading the
/// former while creating provenance in the latter splits one migration across schemas. Returning one
/// row is the only safe shape; zero means the caller must refuse before any migration runs.
#[cfg(any(postgresql, test))]
const fn postgresql_migration_namespace_query() -> &'static str {
    "SELECT COUNT(*) AS count \
     FROM pg_class AS memberships \
     INNER JOIN pg_namespace AS current_ns ON current_ns.nspname = current_schema() \
     WHERE memberships.oid = to_regclass('users_organizations') \
       AND memberships.relnamespace = current_ns.oid \
       AND NOT EXISTS ( \
           SELECT 1 \
           FROM (VALUES \
               ('__diesel_schema_migrations'), \
               ('groups'), \
               ('groups_users'), \
               ('__vw_custom_role_legacy_manager'), \
               ('__vw_custom_role_history_verified'), \
               ('__vw_custom_role_same_run_0716'), \
               ('__vw_ack_permanent_collection_authority') \
           ) AS relation(name) \
           INNER JOIN pg_class AS resolved ON resolved.oid = to_regclass(relation.name) \
           WHERE resolved.relnamespace <> memberships.relnamespace \
       )"
}

/// The shapes a half-applied {`CUSTOM_COLLECTION_PERMISSIONS_MIGRATION`} may legitimately have left
/// behind, expressed as a count of the rows that have any *other* shape.
///
/// `allow_same_run_group_derived` additionally permits the result of that migration's second data
/// statement. That statement is driven by {`CUSTOM_ROLE_LEGACY_MANAGER_TABLE`}, so the allowance
/// carries the same condition: a 0/1/1 row belonging to a membership that is *not* on record as a
/// legacy Manager cannot have come from the migration that ships today, and counting it as expected
/// would let the automatic recovery adopt a grant nothing can account for. The caller therefore only
/// passes `true` when that record actually exists — without it the shape is undecidable, and the
/// recovery refuses rather than guessing.
#[cfg(any(mysql, test))]
fn mysql_partial_unexpected_values_query(allow_same_run_group_derived: bool) -> String {
    let same_run_group_derived = if allow_same_run_group_derived {
        format!(
            " OR \
             (atype = 4 \
              AND access_all = FALSE \
              AND create_new_collections = FALSE \
              AND edit_any_collection = TRUE \
              AND delete_any_collection = TRUE \
              AND uuid IN (SELECT users_organizations_uuid FROM {CUSTOM_ROLE_LEGACY_MANAGER_TABLE}) \
              AND EXISTS ( \
                  SELECT 1 \
                  FROM groups_users AS gu \
                  INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid \
                  WHERE gu.users_organizations_uuid = users_organizations.uuid \
                    AND g.organizations_uuid = users_organizations.org_uuid \
                    AND g.access_all = TRUE \
              ))"
        )
    } else {
        String::new()
    };

    format!(
        "SELECT COUNT(*) AS count FROM users_organizations \
         WHERE NOT ( \
             (create_new_collections = FALSE \
              AND edit_any_collection = FALSE \
              AND delete_any_collection = FALSE) \
             OR \
             (atype = 4 \
              AND create_new_collections = access_all \
              AND edit_any_collection = access_all \
              AND delete_any_collection = access_all) \
             {same_run_group_derived} \
         )"
    )
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::sqlite::SqliteConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    fn table_exists(
        connection: &mut diesel::sqlite::SqliteConnection,
        table: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM sqlite_master \
                 WHERE type = 'table' AND name = '{table}'"
            ),
        )
        .map(|value| value != 0)
    }

    fn migration_applied(
        connection: &mut diesel::sqlite::SqliteConnection,
        version: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                 WHERE version = '{version}'"
            ),
        )
        .map(|value| value != 0)
    }

    fn preflight(connection: &mut diesel::sqlite::SqliteConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_table_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
             WHERE name = 'access_all'",
        )? != 0;
        let permission_columns = |connection: &mut diesel::sqlite::SqliteConnection,
                                  group: super::PermissionColumnGroup|
         -> Result<i64, diesel::result::Error> {
            count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
                     WHERE name IN ({})",
                    group.column_list()
                ),
            )
        };
        let manage_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Manage)?;
        let collection_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Collection)?;
        let access_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Access)?;

        let manage_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION)?;
        let collection_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_COLLECTION_PERMISSIONS_MIGRATION)?;
        let access_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ACCESS_PERMISSIONS_MIGRATION)?;
        let repair_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_REPAIR_MIGRATION)?;
        let access_all_drop_migration_applied =
            migration_table_exists && migration_applied(connection, super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION)?;
        let same_run_marker_table_exists = table_exists(connection, super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE)?;
        let legacy_manager_record_exists = table_exists(connection, super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE)?;
        let history_verified = table_exists(connection, super::CUSTOM_ROLE_HISTORY_VERIFIED_TABLE)?;
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype = 2 \
                       AND access_all = TRUE",
            )?
        } else {
            0
        };

        let confirm_permanent_authority_migration_applied =
            migration_table_exists && migration_applied(connection, super::CONFIRM_PERMANENT_AUTHORITY_MIGRATION)?;
        let permanent_collection_authority_ack =
            table_exists(connection, super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE)?;
        let unconfirmed_permanent_authority_count = match super::permanent_authority_lookahead_query(
            collection_permission_columns == 3,
            access_all_column_exists,
            legacy_manager_record_exists,
            collection_permissions_migration_applied,
            repair_migration_applied,
            "\"groups\"",
        ) {
            Some(query) => count(connection, query)?,
            None => 0,
        };

        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_table_exists,
            access_all_column_exists,
            manage_permission_columns,
            manage_permissions_migration_applied,
            collection_permission_columns,
            collection_permissions_migration_applied,
            access_permission_columns,
            access_permissions_migration_applied,
            repair_migration_applied,
            access_all_drop_migration_applied,
            legacy_user_access_all_count,
            same_run_0716_marker,
            legacy_manager_record_exists,
            history_verified,
            confirm_permanent_authority_migration_applied,
            permanent_collection_authority_ack,
            unconfirmed_permanent_authority_count,
        };

        let decision = super::custom_role_preflight_decision(facts, false);
        if decision == super::CustomRolePreflightDecision::Proceed {
            Ok(())
        } else {
            Err(super::custom_role_preflight_error(decision, facts))
        }
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Establish a connection to the sqlite database (this will create a new one, if it does
        // not exist, and exit if there is an error).
        let mut connection = diesel::sqlite::SqliteConnection::establish(db_url)?;

        preflight(&mut connection)?;

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
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::mysql::MysqlConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    fn table_exists(
        connection: &mut diesel::mysql::MysqlConnection,
        table: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name = '{table}'"
            ),
        )
        .map(|value| value != 0)
    }

    fn migration_applied(
        connection: &mut diesel::mysql::MysqlConnection,
        version: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                 WHERE version = '{version}'"
            ),
        )
        .map(|value| value != 0)
    }

    fn complete_partial_collection_migration(
        connection: &mut diesel::mysql::MysqlConnection,
        allow_same_run_group_derived: bool,
    ) -> Result<(), super::Error> {
        // MySQL implicitly committed the three historical ALTER TABLE statements before the
        // unquoted `groups` identifier made the migration fail. Complete that exact, known state
        // without dropping columns or inventing values.
        let matching_column_definitions = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
               AND table_name = 'users_organizations' \
               AND column_name IN \
                   ('create_new_collections', 'edit_any_collection', 'delete_any_collection') \
               AND data_type = 'tinyint' \
               AND is_nullable = 'NO' \
               AND LOWER(COALESCE(CAST(column_default AS CHAR), '')) IN ('0', 'false')",
        )?;
        let unexpected_values =
            count(connection, super::mysql_partial_unexpected_values_query(allow_same_run_group_derived))?;

        if matching_column_definitions != 3 || unexpected_values != 0 {
            return Err(std::io::Error::other(format!(
                "Custom-role migration preflight found the historical MySQL partial \
                 {version} schema, but its column definitions or data were modified \
                 (matching columns: {matching_column_definitions}/3, unexpected rows: \
                 {unexpected_values}). Refusing automatic recovery. Back up the database and \
                 resolve the partial migration manually before restarting.",
                version = super::CUSTOM_COLLECTION_PERMISSIONS_MIGRATION,
            ))
            .into());
        }

        connection.transaction::<(), diesel::result::Error, _>(|connection| {
            // This is the first data statement from the canonical migration. It also resets an
            // exact, same-run group-derived 0/1/1 row to 0/0/0. That is deliberate: this completion
            // path is not where legacy group authority is decided. Nothing derives it at request
            // time any more -- the live fallback is gone -- so the reset is not "the group still
            // covers it"; it is "leave the columns at the value this statement defines, and let the
            // repair migration re-establish the authority from the legacy-Manager record". The
            // canonical file's second statement is deliberately *not* replayed here, because the
            // record it has to be driven by is the same one 2026-07-23-120000 reads a moment later.
            //
            // The two runs therefore converge: a recorded legacy Manager in an access_all group gets
            // its 0/1/1 back from 2026-07-23-120000, and a membership that is not on the record
            // keeps 0/0/0 -- which is the whole point of driving the grant by provenance.
            diesel::sql_query(
                "UPDATE users_organizations \
                 SET create_new_collections = access_all, \
                     edit_any_collection = access_all, \
                     delete_any_collection = access_all \
                 WHERE atype = 4",
            )
            .execute(connection)?;

            diesel::sql_query(format!(
                "INSERT INTO __diesel_schema_migrations (version) \
                 VALUES ('{}')",
                super::CUSTOM_COLLECTION_PERMISSIONS_MIGRATION
            ))
            .execute(connection)?;
            Ok(())
        })?;

        Ok(())
    }

    fn complete_interrupted_access_all_drop(
        connection: &mut diesel::mysql::MysqlConnection,
    ) -> Result<(), super::Error> {
        // MySQL/MariaDB commit DDL implicitly, so the single `ALTER TABLE ... DROP COLUMN access_all`
        // can be durable while Diesel's ledger insert that follows it is not. Re-running the
        // migration would then fail with error 1091 (Unknown column) on every start. The statement
        // has no data component and the preflight has just confirmed the column is gone, so the
        // schema already is what the migration wanted: record it and let the rest of the chain run.
        // Do not rely on the server/session autocommit setting or on a later pending migration to
        // commit this repair. With autocommit=0 and no later migration, a plain INSERT is rolled back
        // when this freshly established connection closes, so every start rediscovers the same
        // interrupted drop. Diesel's transaction commits the ledger entry before preflight continues.
        connection.transaction::<(), diesel::result::Error, _>(|connection| {
            diesel::sql_query(format!(
                "INSERT INTO __diesel_schema_migrations (version) VALUES ('{}')",
                super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION
            ))
            .execute(connection)?;
            Ok(())
        })?;

        Ok(())
    }

    /// Read everything [`super::custom_role_preflight_decision`] answers from, once.
    ///
    /// Separate from `preflight` because two of its decisions repair the database instead of
    /// refusing, and every fact below can change when they do.
    fn inspect(
        connection: &mut diesel::mysql::MysqlConnection,
    ) -> Result<super::CustomRoleMigrationFacts, super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            // Nothing to read, and nothing to decide: the default answers `Proceed`.
            return Ok(super::CustomRoleMigrationFacts::default());
        }

        let migration_table_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
               AND table_name = 'users_organizations' \
               AND column_name = 'access_all'",
        )? != 0;
        let permission_columns = |connection: &mut diesel::mysql::MysqlConnection,
                                  group: super::PermissionColumnGroup|
         -> Result<i64, diesel::result::Error> {
            count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM information_schema.columns                      WHERE table_schema = DATABASE()                        AND table_name = 'users_organizations'                        AND column_name IN ({})",
                    group.column_list()
                ),
            )
        };
        let manage_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Manage)?;
        let collection_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Collection)?;
        let access_permission_columns = permission_columns(connection, super::PermissionColumnGroup::Access)?;

        let manage_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION)?;
        let collection_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_COLLECTION_PERMISSIONS_MIGRATION)?;
        let access_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ACCESS_PERMISSIONS_MIGRATION)?;
        let repair_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_REPAIR_MIGRATION)?;
        let access_all_drop_migration_applied =
            migration_table_exists && migration_applied(connection, super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION)?;
        let same_run_marker_table_exists = table_exists(connection, super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE)?;
        let legacy_manager_record_exists = table_exists(connection, super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE)?;
        let history_verified = table_exists(connection, super::CUSTOM_ROLE_HISTORY_VERIFIED_TABLE)?;
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype = 2 \
                       AND access_all = TRUE",
            )?
        } else {
            0
        };

        let confirm_permanent_authority_migration_applied =
            migration_table_exists && migration_applied(connection, super::CONFIRM_PERMANENT_AUTHORITY_MIGRATION)?;
        let permanent_collection_authority_ack =
            table_exists(connection, super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE)?;
        let unconfirmed_permanent_authority_count = match super::permanent_authority_lookahead_query(
            collection_permission_columns == 3,
            access_all_column_exists,
            legacy_manager_record_exists,
            collection_permissions_migration_applied,
            repair_migration_applied,
            "`groups`",
        ) {
            Some(query) => count(connection, query)?,
            None => 0,
        };

        Ok(super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_table_exists,
            access_all_column_exists,
            manage_permission_columns,
            manage_permissions_migration_applied,
            collection_permission_columns,
            collection_permissions_migration_applied,
            access_permission_columns,
            access_permissions_migration_applied,
            repair_migration_applied,
            access_all_drop_migration_applied,
            legacy_user_access_all_count,
            same_run_0716_marker,
            legacy_manager_record_exists,
            history_verified,
            confirm_permanent_authority_migration_applied,
            permanent_collection_authority_ack,
            unconfirmed_permanent_authority_count,
        })
    }

    /// The two repairs below each record exactly one migration, so neither can be chosen twice.
    /// The bound is not load-bearing for them -- it is there so a future repair that forgets to
    /// advance the ledger cannot spin here instead of failing.
    const MAX_AUTOMATIC_REPAIRS: usize = 2;

    fn preflight(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        // A repair is not the end of the preflight, it is the start of another pass. Both repairs
        // record a migration, and 0716 completion also normalizes its permission values, so every
        // fact has to be read again afterwards. `custom_role_preflight_decision` evaluates all
        // refusals before it returns either repair action; the loop therefore mutates only a snapshot
        // that has already passed the schema, history and owner checks, then verifies the resulting
        // snapshot from scratch.
        for _ in 0..=MAX_AUTOMATIC_REPAIRS {
            let facts = inspect(connection)?;
            match super::custom_role_preflight_decision(facts, true) {
                super::CustomRolePreflightDecision::Proceed => return Ok(()),
                super::CustomRolePreflightDecision::CompleteMysqlCollectionMigration => {
                    // The same-run allowance reads the legacy-Manager record, so it may only be
                    // offered when that record exists. Everywhere this decision is normally reachable
                    // it does -- the history refusal already requires it -- but the recovery must not
                    // depend on that: without the record the group-derived shape cannot be attributed
                    // to anything, and refusing is the correct answer.
                    complete_partial_collection_migration(
                        connection,
                        facts.same_run_0716_marker && facts.legacy_manager_record_exists,
                    )?;
                }
                super::CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop => {
                    complete_interrupted_access_all_drop(connection)?;
                }
                decision => return Err(super::custom_role_preflight_error(decision, facts)),
            }
        }

        Err(std::io::Error::other(
            "Custom-role migration preflight kept finding a state it had just repaired. Each \
             automatic repair records a migration and can only apply once, so this means the ledger \
             insert did not take effect. Back up the database and resolve the partial migration \
             manually before restarting.",
        )
        .into())
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::mysql::MysqlConnection::establish(db_url)?;

        preflight(&mut connection)?;

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
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgresql");

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::pg::PgConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    /// Resolved through `to_regclass`, i.e. exactly the way an unqualified name in a migration is
    /// resolved -- and deliberately *not* through `table_schema = current_schema()`.
    ///
    /// `current_schema()` is the first *existing* schema on the `search_path`, which is where new
    /// objects are created. It is not necessarily the schema an existing table is found in: with
    /// `search_path = decoy, real` and the tables in `real`, `current_schema()` answers `decoy`, the
    /// lookup finds nothing, and `preflight` returns early on `!memberships_table_exists` -- silently
    /// skipping every check while Diesel then runs the migrations against `real`. `to_regclass`
    /// walks the same path the migrations do, so the preflight and the statements it is guarding can
    /// no longer disagree about which table they mean. (`tools/custom_role_rollback/postgresql.sql`
    /// defends against the same split by binding the namespace once.)
    fn table_exists(connection: &mut diesel::pg::PgConnection, table: &str) -> Result<bool, diesel::result::Error> {
        count(connection, format!("SELECT COUNT(*) AS count FROM pg_class WHERE oid = to_regclass('{table}')"))
            .map(|value| value != 0)
    }

    /// Columns of `users_organizations`, resolved through the same `to_regclass` lookup as
    /// [`table_exists`] so a `search_path` split cannot make the schema and the column checks
    /// describe two different tables.
    fn column_count(
        connection: &mut diesel::pg::PgConnection,
        column_list: &str,
    ) -> Result<i64, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 \
                   AND NOT attisdropped \
                   AND attname IN ({column_list})"
            ),
        )
    }

    fn migration_applied(
        connection: &mut diesel::pg::PgConnection,
        version: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                 WHERE version = '{version}'"
            ),
        )
        .map(|value| value != 0)
    }

    fn preflight(connection: &mut diesel::pg::PgConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_table_exists = table_exists(connection, "__diesel_schema_migrations")?;
        if migration_table_exists && count(connection, super::postgresql_migration_namespace_query())? != 1 {
            return Err(std::io::Error::other(
                "Custom-role migration preflight stopped startup: PostgreSQL resolves Vaultwarden's \
                 existing migration relations in a different schema from current_schema(). An \
                 unqualified migration would read users_organizations from one schema and create its \
                 provenance or acknowledgement tables in another. Nothing has been changed. Set the \
                 connection search_path so the schema containing users_organizations, groups, \
                 groups_users and __diesel_schema_migrations is first, remove any shadow relations, \
                 then restart.",
            )
            .into());
        }
        let access_all_column_exists = column_count(connection, "'access_all'")? != 0;
        let manage_permission_columns = column_count(connection, super::PermissionColumnGroup::Manage.column_list())?;
        let collection_permission_columns =
            column_count(connection, super::PermissionColumnGroup::Collection.column_list())?;
        let access_permission_columns = column_count(connection, super::PermissionColumnGroup::Access.column_list())?;

        let manage_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_MANAGE_PERMISSIONS_MIGRATION)?;
        let collection_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_COLLECTION_PERMISSIONS_MIGRATION)?;
        let access_permissions_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ACCESS_PERMISSIONS_MIGRATION)?;
        let repair_migration_applied =
            migration_table_exists && migration_applied(connection, super::CUSTOM_ROLE_REPAIR_MIGRATION)?;
        let access_all_drop_migration_applied =
            migration_table_exists && migration_applied(connection, super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION)?;
        let same_run_marker_table_exists = table_exists(connection, super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE)?;
        let legacy_manager_record_exists = table_exists(connection, super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE)?;
        let history_verified = table_exists(connection, super::CUSTOM_ROLE_HISTORY_VERIFIED_TABLE)?;
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype = 2 \
                       AND access_all = TRUE",
            )?
        } else {
            0
        };

        let confirm_permanent_authority_migration_applied =
            migration_table_exists && migration_applied(connection, super::CONFIRM_PERMANENT_AUTHORITY_MIGRATION)?;
        let permanent_collection_authority_ack =
            table_exists(connection, super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE)?;
        let unconfirmed_permanent_authority_count = match super::permanent_authority_lookahead_query(
            collection_permission_columns == 3,
            access_all_column_exists,
            legacy_manager_record_exists,
            collection_permissions_migration_applied,
            repair_migration_applied,
            "\"groups\"",
        ) {
            Some(query) => count(connection, query)?,
            None => 0,
        };

        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_table_exists,
            access_all_column_exists,
            manage_permission_columns,
            manage_permissions_migration_applied,
            collection_permission_columns,
            collection_permissions_migration_applied,
            access_permission_columns,
            access_permissions_migration_applied,
            repair_migration_applied,
            access_all_drop_migration_applied,
            legacy_user_access_all_count,
            same_run_0716_marker,
            legacy_manager_record_exists,
            history_verified,
            confirm_permanent_authority_migration_applied,
            permanent_collection_authority_ack,
            unconfirmed_permanent_authority_count,
        };

        let decision = super::custom_role_preflight_decision(facts, false);
        if decision == super::CustomRolePreflightDecision::Proceed {
            Ok(())
        } else {
            Err(super::custom_role_preflight_error(decision, facts))
        }
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::pg::PgConnection::establish(db_url)?;

        preflight(&mut connection)?;

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

/// Executes the real migration files against a throwaway SQLite database.
///
/// Everything else in this file tests the *decision* the preflight makes; nothing tested the SQL the
/// decision is protecting. The one rule those files encode -- legacy authority is granted from the
/// recorded provenance, never from the shape of a membership -- is invisible to a Rust test unless
/// the statements actually run, and it is a rule that was already lost once: `2026-07-16-120000`
/// kept granting `edit_any_collection` / `delete_any_collection` to every Custom member of an
/// `access_all` group after `2026-07-23-120000` and `2026-08-09-120000` had been narrowed to the
/// record. `edit_any_collection` satisfies `has_full_access()`, so that reached every cipher in the
/// organization.
#[cfg(all(test, sqlite))]
mod custom_role_migration_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{
        Connection, RunQueryDsl,
        sql_types::{BigInt, Text},
        sqlite::SqliteConnection,
    };

    const ADD_COLLECTION_PERMISSIONS: &str =
        include_str!("../../migrations/sqlite/2026-07-16-120000_add_custom_collection_permissions/up.sql");
    const DROP_MEMBERSHIP_ACCESS_ALL: &str =
        include_str!("../../migrations/sqlite/2026-07-24-120000_drop_membership_access_all/up.sql");
    const MATERIALIZE_GROUP_AUTHORITY: &str =
        include_str!("../../migrations/sqlite/2026-08-09-120000_materialize_legacy_group_collection_authority/up.sql");
    const CONFIRM_PERMANENT_AUTHORITY: &str =
        include_str!("../../migrations/sqlite/2026-08-10-120000_confirm_permanent_collection_authority/up.sql");

    const HISTORY_VERIFIED: &str = "
        CREATE TABLE __vw_custom_role_history_verified (verified INTEGER NOT NULL PRIMARY KEY);
    ";
    const PERMANENT_AUTHORITY_ACK: &str = "
        CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);
    ";

    /// The shape `users_organizations` has when `2026-07-16-120000` runs: `2026-06-30-120000` has
    /// added the three management columns and converted `atype = 3` to `4`, and membership
    /// `access_all` still exists (`2026-07-24-120000` drops it later).
    const SCHEMA_BEFORE_0716: &str = "
        CREATE TABLE users_organizations (
            uuid TEXT NOT NULL PRIMARY KEY,
            user_uuid TEXT NOT NULL,
            org_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE,
            akey TEXT NOT NULL DEFAULT '',
            status INTEGER NOT NULL DEFAULT 2,
            atype INTEGER NOT NULL,
            manage_users BOOLEAN NOT NULL DEFAULT FALSE,
            manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
            manage_policies BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY,
            organizations_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups_users (
            groups_uuid TEXT NOT NULL,
            users_organizations_uuid TEXT NOT NULL,
            PRIMARY KEY (groups_uuid, users_organizations_uuid)
        );
    ";

    const LEGACY_MANAGER_RECORD: &str = "
        CREATE TABLE __vw_custom_role_legacy_manager (
            users_organizations_uuid TEXT NOT NULL PRIMARY KEY
        );
    ";

    /// `users_organizations` as the release *before* this feature leaves it: membership `access_all`,
    /// the retired Manager role, and none of the nine permission columns. This is the schema the
    /// preflight refuses from on an ordinary upgrade, which is the common path.
    const LEGACY_SCHEMA: &str = "
        CREATE TABLE users_organizations (
            uuid TEXT NOT NULL PRIMARY KEY,
            user_uuid TEXT NOT NULL,
            org_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE,
            status INTEGER NOT NULL DEFAULT 2,
            atype INTEGER NOT NULL
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY,
            organizations_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups_users (
            groups_uuid TEXT NOT NULL,
            users_organizations_uuid TEXT NOT NULL,
            PRIMARY KEY (groups_uuid, users_organizations_uuid)
        );
    ";

    /// The one membership the question is actually about, in its pre-upgrade shape.
    const LEGACY_GROUP_DERIVED_MANAGER: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
            ('m_mgr', 'u1', 'org', FALSE, 3);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm_mgr');
    ";

    /// Two memberships that are byte-identical in role and group membership and differ only in their
    /// recorded provenance, plus a recorded Manager that is in no group at all.
    const MEMBERSHIPS: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
            ('m_recorded',   'u1', 'org', FALSE, 4),
            ('m_unrecorded', 'u2', 'org', FALSE, 4),
            ('m_no_group',   'u3', 'org', FALSE, 4);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all', 'm_recorded'),
            ('g_all', 'm_unrecorded');
    ";

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[derive(diesel::QueryableByName)]
    struct ReviewMembership {
        #[diesel(sql_type = Text)]
        uuid: String,
    }

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count).unwrap()
    }

    fn collection_permissions(connection: &mut SqliteConnection, membership: &str) -> (bool, bool, bool) {
        let flag = |connection: &mut SqliteConnection, column: &str| {
            count(
                connection,
                &format!(
                    "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE uuid = '{membership}' AND {column} = TRUE"
                ),
            ) != 0
        };
        (
            flag(connection, "create_new_collections"),
            flag(connection, "edit_any_collection"),
            flag(connection, "delete_any_collection"),
        )
    }

    fn connect(setup: &[&str]) -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        for statements in setup {
            connection.batch_execute(statements).unwrap();
        }
        connection
    }

    /// Everything up to and including `2026-07-16-120000`, so the collection permission columns hold
    /// whatever the real migration put there. `record` lists the memberships written to
    /// {`CUSTOM_ROLE_LEGACY_MANAGER_TABLE`} before it runs, which is what `2026-06-30-120000` does.
    ///
    /// `access_all` is left in place; `2026-07-24-120000` drops it, but neither of the two migrations
    /// under test reads it and keeping it makes the fixtures legible.
    fn connect_after_0716(memberships: &str, record: &[&str]) -> SqliteConnection {
        let mut connection = connect(&[SCHEMA_BEFORE_0716, LEGACY_MANAGER_RECORD, memberships]);
        for uuid in record {
            connection
                .batch_execute(&format!(
                    "INSERT INTO __vw_custom_role_legacy_manager (users_organizations_uuid) VALUES ('{uuid}')"
                ))
                .unwrap();
        }
        connection.batch_execute(ADD_COLLECTION_PERMISSIONS).unwrap();
        connection
    }

    fn table_exists(connection: &mut SqliteConnection, table: &str) -> bool {
        count(
            connection,
            &format!("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
        ) != 0
    }

    /// What the startup preflight would answer for this database, through the very query it uses.
    fn lookahead_count(connection: &mut SqliteConnection) -> i64 {
        let record = table_exists(connection, super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE);
        let query = super::permanent_authority_lookahead_query(true, true, record, true, true, "\"groups\"")
            .expect("the collection columns exist in these fixtures");
        count(connection, &query)
    }

    /// Membership `access_all` is a stored value, not a shape, so it carries its own evidence and is
    /// converted for every Custom member that holds it.
    #[test]
    fn membership_access_all_becomes_all_three_collection_permissions() {
        let mut connection = connect(&[SCHEMA_BEFORE_0716, LEGACY_MANAGER_RECORD, MEMBERSHIPS]);
        connection
            .batch_execute("UPDATE users_organizations SET access_all = TRUE WHERE uuid = 'm_unrecorded'")
            .unwrap();

        connection.batch_execute(ADD_COLLECTION_PERMISSIONS).unwrap();

        assert_eq!(collection_permissions(&mut connection, "m_unrecorded"), (true, true, true));
    }

    /// 20260630120000 was available before 20260716120000, so this is a legitimate feature-branch
    /// upgrade prefix: Managers are already converted and recorded, while a newer, unrecorded Custom
    /// membership still carries its own legacy access_all bit and the collection columns are pending.
    /// 0716 will turn that bit into 1/1/1, after which the conservative 0810 guard asks about it when
    /// it also belongs to an organization-local access_all group. The startup lookahead must agree
    /// before either migration runs, and its recovery query has to be executable on this exact shape.
    #[test]
    fn ledgered_0630_unrecorded_custom_access_all_matches_the_later_guard() {
        let mut connection = connect(&[
            SCHEMA_BEFORE_0716,
            LEGACY_MANAGER_RECORD,
            HISTORY_VERIFIED,
            "CREATE TABLE __diesel_schema_migrations (version TEXT NOT NULL PRIMARY KEY);
             INSERT INTO __diesel_schema_migrations (version) VALUES ('20260630120000');
             INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
             INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype)
             VALUES ('m_custom', 'u1', 'org', TRUE, 4);
             INSERT INTO groups_users (groups_uuid, users_organizations_uuid)
             VALUES ('g_all', 'm_custom');",
        ]);
        let lookahead = super::permanent_authority_lookahead_query(false, true, true, false, false, "\"groups\"")
            .expect("access_all makes the pending 0716 result projectable");
        assert_eq!(count(&mut connection, &lookahead), 1);

        let review = "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status, uo.access_all,
                    (uo.uuid IN (SELECT users_organizations_uuid
                                 FROM __vw_custom_role_legacy_manager)) AS was_legacy_manager
             FROM users_organizations uo
             WHERE (uo.atype = 3 OR (uo.atype = 4 AND (
                      uo.access_all = TRUE OR uo.uuid IN (
                        SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))))
               AND EXISTS (
                 SELECT 1 FROM groups_users gu
                 INNER JOIN \"groups\" g ON g.uuid = gu.groups_uuid
                   AND g.organizations_uuid = uo.org_uuid
                 WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = TRUE)";
        let rows = diesel::sql_query(review).load::<ReviewMembership>(&mut connection).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uuid, "m_custom");
        assert!(super::PERMANENT_COLLECTION_AUTHORITY_RECOVERY.contains("If 20260630120000 is already"));
        assert!(super::PERMANENT_COLLECTION_AUTHORITY_RECOVERY.contains("uo.access_all = TRUE OR uo.uuid IN"));

        connection.batch_execute(ADD_COLLECTION_PERMISSIONS).unwrap();
        assert_eq!(collection_permissions(&mut connection, "m_custom"), (true, true, true));
        assert!(
            connection.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err(),
            "the preflight projection and the real 0810 guard must agree"
        );
    }

    #[test]
    fn out_of_order_access_permissions_would_be_destroyed_by_the_pending_sqlite_rebuild() {
        let mut connection = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        connection
            .batch_execute(
                "CREATE TABLE users (uuid TEXT NOT NULL PRIMARY KEY);
                 CREATE TABLE organizations (uuid TEXT NOT NULL PRIMARY KEY);
                 INSERT INTO users (uuid) VALUES ('u1'), ('u2'), ('u3');
                 INSERT INTO organizations (uuid) VALUES ('org');
                 ALTER TABLE users_organizations ADD COLUMN reset_password_key TEXT;
                 ALTER TABLE users_organizations ADD COLUMN external_id TEXT;
                 ALTER TABLE users_organizations ADD COLUMN invited_by_email TEXT DEFAULT NULL;
                 ALTER TABLE users_organizations ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT FALSE;
                 ALTER TABLE users_organizations ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT FALSE;
                 ALTER TABLE users_organizations ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT FALSE;
                 UPDATE users_organizations
                 SET access_event_logs = TRUE, access_import_export = TRUE, access_reports = TRUE
                 WHERE uuid = 'm_recorded';",
            )
            .unwrap();

        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM users_organizations
                 WHERE uuid = 'm_recorded'
                   AND access_event_logs = TRUE
                   AND access_import_export = TRUE
                   AND access_reports = TRUE"
            ),
            1,
            "the historical later migration can hold live grants"
        );

        connection.batch_execute(DROP_MEMBERSHIP_ACCESS_ALL).unwrap();

        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations')
                 WHERE name IN ('access_event_logs', 'access_import_export', 'access_reports')"
            ),
            0,
            "this pins why the preflight must refuse before running the unchanged migration file"
        );
    }

    /// The regression this test exists for. `m_recorded` and `m_unrecorded` differ in nothing a
    /// query at request time could see -- same role, same organization, same `access_all` group --
    /// so only the provenance record may decide, and it must not leak organization-wide collection
    /// authority to the membership that has none.
    #[test]
    fn group_derived_authority_is_granted_only_to_recorded_legacy_managers() {
        let mut connection = connect(&[SCHEMA_BEFORE_0716, LEGACY_MANAGER_RECORD, MEMBERSHIPS]);
        connection
            .batch_execute(
                "INSERT INTO __vw_custom_role_legacy_manager (users_organizations_uuid) \
                 VALUES ('m_recorded'), ('m_no_group')",
            )
            .unwrap();

        connection.batch_execute(ADD_COLLECTION_PERMISSIONS).unwrap();

        // Edit and delete, never create: creating collections historically required membership
        // `access_all`, which this member does not have.
        assert_eq!(collection_permissions(&mut connection, "m_recorded"), (false, true, true));
        // Not on record: identical in shape, and it gets nothing.
        assert_eq!(collection_permissions(&mut connection, "m_unrecorded"), (false, false, false));
        // On record, but its authority never came from a group.
        assert_eq!(collection_permissions(&mut connection, "m_no_group"), (false, false, false));
    }

    /// Without the record the grant is undecidable, so the migration refuses -- and it has to refuse
    /// *before* the `ALTER TABLE`s. On MySQL/MariaDB every one of them commits on its own, so a
    /// guard placed after them would leave a half-added column group behind, which is exactly the
    /// state `RefusePartialPermissionSchema` then has to talk an operator out of.
    #[test]
    fn the_migration_refuses_without_the_record_and_adds_no_column() {
        let mut connection = connect(&[SCHEMA_BEFORE_0716, MEMBERSHIPS]);

        assert!(connection.batch_execute(ADD_COLLECTION_PERMISSIONS).is_err());

        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
                 WHERE name IN ('create_new_collections', 'edit_any_collection', 'delete_any_collection')"
            ),
            0,
            "the guard has to run before the ALTER TABLE statements, or MySQL keeps the partial column group"
        );
    }

    /// `2026-08-09-120000` repeats the materialization for databases that already recorded
    /// `2026-07-23-120000`, and it is driven by the same record for the same reason.
    #[test]
    fn the_repeat_materialization_is_also_bound_to_the_record() {
        let mut connection = connect_after_0716(MEMBERSHIPS, &["m_recorded", "m_no_group"]);
        connection.batch_execute(HISTORY_VERIFIED).unwrap();

        connection.batch_execute(MATERIALIZE_GROUP_AUTHORITY).unwrap();

        assert_eq!(collection_permissions(&mut connection, "m_recorded"), (false, true, true));
        assert_eq!(collection_permissions(&mut connection, "m_unrecorded"), (false, false, false));
        assert_eq!(collection_permissions(&mut connection, "m_no_group"), (false, false, false));
    }

    /// Without the record the file cannot tell a converted legacy Manager from an ordinary Custom
    /// member, and without the history marker nobody has said the unrecorded ones are unrecorded on
    /// purpose. Granting would be a silent escalation, skipping would silently drop a capability, so
    /// it stops -- and the marker itself never grants anything.
    #[test]
    fn the_repeat_materialization_refuses_an_unaudited_history() {
        let mut refuses = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        assert!(refuses.batch_execute(MATERIALIZE_GROUP_AUTHORITY).is_err());

        let mut audited = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        audited.batch_execute(HISTORY_VERIFIED).unwrap();
        audited.batch_execute(MATERIALIZE_GROUP_AUTHORITY).unwrap();
        assert_eq!(
            collection_permissions(&mut audited, "m_unrecorded"),
            (false, false, false),
            "the marker settles who is undecidable, it never grants"
        );
    }

    /// The one question the chain asks. `m_recorded` is the conversion it is about: its authority came
    /// from the group and is about to outlive it.
    ///
    /// The two halves deliberately use separate connections. Every guard in this chain aborts by
    /// leaving its `CREATE TEMPORARY TABLE` un-dropped, so a *retry on the same session* trips over
    /// the leftover instead of the real condition. That is not reachable from Vaultwarden -- a failed
    /// migration ends the process, and Diesel wraps each migration in a transaction on SQLite and
    /// PostgreSQL, where temporary DDL rolls back with it -- but a test that reused the connection
    /// would be asserting on the wrong error.
    #[test]
    fn permanent_collection_authority_needs_an_acknowledgement() {
        let mut refuses = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        assert_eq!(collection_permissions(&mut refuses, "m_recorded"), (false, true, true));
        assert!(refuses.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err());

        // The answer lifts it, and is consumed so the next upgrade has to ask again.
        let mut acknowledged = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        acknowledged.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        acknowledged.batch_execute(CONFIRM_PERMANENT_AUTHORITY).unwrap();
        assert!(!table_exists(&mut acknowledged, super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE));

        // It grants nothing and revokes nothing on the way through.
        assert_eq!(collection_permissions(&mut acknowledged, "m_recorded"), (false, true, true));
    }

    /// `create_new_collections` is independently mutable. An owner can set it after an earlier
    /// revision materialized a group-derived 0/1/1 grant, so the resulting 1/1/1 shape must not be
    /// mistaken for immutable evidence that membership `access_all` supplied all three permissions.
    #[test]
    fn mutable_create_permission_does_not_hide_group_derived_authority() {
        let mut connection = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        connection
            .batch_execute("UPDATE users_organizations SET create_new_collections = TRUE WHERE uuid = 'm_recorded';")
            .unwrap();
        assert_eq!(collection_permissions(&mut connection, "m_recorded"), (true, true, true));

        assert!(
            connection.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err(),
            "a current permission value is not historical provenance"
        );
    }

    /// An unrecorded Custom member holding the permissions is *not* excluded: on a database first
    /// upgraded by an earlier revision those may be the bulk grant its `20260809120000` wrote, and
    /// nothing can tell them from a deliberate grant any more.
    #[test]
    fn an_unrecorded_grant_is_still_worth_asking_about() {
        let mut connection = connect_after_0716(MEMBERSHIPS, &[]);
        connection
            .batch_execute(
                "UPDATE users_organizations \
                 SET create_new_collections = TRUE, edit_any_collection = TRUE, delete_any_collection = TRUE \
                 WHERE uuid = 'm_unrecorded'",
            )
            .unwrap();

        assert!(connection.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err());
    }

    /// The record is still a chain invariant used by repair and rollback even though the final
    /// materialized-authority predicate no longer uses it to exclude rows. Refuse a damaged chain
    /// explicitly rather than letting a later statement fail as `no such table`.
    #[test]
    fn the_confirmation_refuses_without_the_record() {
        let mut connection = connect(&[SCHEMA_BEFORE_0716, LEGACY_MANAGER_RECORD, MEMBERSHIPS]);
        connection.batch_execute(ADD_COLLECTION_PERMISSIONS).unwrap();
        connection.batch_execute("DROP TABLE __vw_custom_role_legacy_manager").unwrap();

        assert!(connection.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err());
    }

    /// A refusal is only a decision if "no" can be carried out on the schema it is printed for, and
    /// this one is printed from two of them. The migrated shape was always answerable; the legacy
    /// shape -- the ordinary upgrade, and the common case -- was told to clear columns that do not
    /// exist there yet, so the only statement an operator could actually run was the acknowledgement.
    ///
    /// Both halves are checked against the recovery text itself, so a future edit that drops one of
    /// the two statements fails here rather than in an operator's terminal.
    #[test]
    fn the_recovery_can_be_declined_on_both_schema_shapes() {
        let legacy_query = super::permanent_authority_lookahead_query(false, true, false, false, false, "\"groups\"")
            .expect("membership access_all is still present in the legacy fixture");

        // 1. Legacy shape. The migrated shape's statement cannot run here at all.
        let mut connection = connect(&[LEGACY_SCHEMA, LEGACY_GROUP_DERIVED_MANAGER]);
        assert_eq!(count(&mut connection, &legacy_query), 1, "the fixture has to raise the question");
        assert!(
            connection
                .batch_execute(
                    "UPDATE users_organizations \
                     SET edit_any_collection = FALSE, delete_any_collection = FALSE \
                     WHERE uuid = 'm_mgr'"
                )
                .is_err(),
            "the permission columns do not exist before the upgrade -- this is why the text needs two answers"
        );

        // What the text offers instead: end the group relationship, for one membership...
        let mut connection = connect(&[LEGACY_SCHEMA, LEGACY_GROUP_DERIVED_MANAGER]);
        connection
            .batch_execute(
                "DELETE FROM groups_users \
                 WHERE users_organizations_uuid = 'm_mgr' AND groups_uuid = 'g_all'",
            )
            .unwrap();
        assert_eq!(count(&mut connection, &legacy_query), 0, "declining has to answer the question");

        // ...or for the whole group at once.
        let mut connection = connect(&[LEGACY_SCHEMA, LEGACY_GROUP_DERIVED_MANAGER]);
        connection.batch_execute("UPDATE \"groups\" SET access_all = FALSE WHERE uuid = 'g_all'").unwrap();
        assert_eq!(count(&mut connection, &legacy_query), 0, "declining has to answer the question");

        // 2. Migrated shape: the statement the text prints for it runs, and answers the question.
        let mut connection = connect_after_0716(MEMBERSHIPS, &["m_recorded"]);
        assert_eq!(lookahead_count(&mut connection), 1);
        connection
            .batch_execute(
                "UPDATE users_organizations \
                 SET edit_any_collection = FALSE, delete_any_collection = FALSE \
                 WHERE uuid = 'm_recorded'",
            )
            .unwrap();
        assert_eq!(lookahead_count(&mut connection), 0);

        for statement in [
            "DELETE FROM groups_users",
            "UPDATE \"groups\" SET access_all = FALSE",
            "SET edit_any_collection = FALSE, delete_any_collection = FALSE",
        ] {
            assert!(
                super::PERMANENT_COLLECTION_AUTHORITY_RECOVERY.contains(statement),
                "the refusal has to print `{statement}`"
            );
        }
    }

    /// The reason the preflight exists: it has to reach the *same* verdict as the migration, or it
    /// either refuses a database the migration would have let through, or lets one through that then
    /// aborts with nothing but a duplicate-key error. Checked against the real files.
    #[test]
    fn the_preflight_lookahead_agrees_with_the_migration() {
        // (name, record contents, extra setup) -> the migration decides, the lookahead has to match.
        let cases: [(&str, &[&str], &str); 5] = [
            ("group-derived conversion", &["m_recorded"], ""),
            ("nothing qualifies", &["m_no_group"], ""),
            (
                "membership access_all, never group-bound",
                &["m_recorded"],
                "UPDATE users_organizations SET create_new_collections = TRUE WHERE uuid = 'm_recorded'",
            ),
            (
                "bulk grant to a membership that is not on the record",
                &[],
                "UPDATE users_organizations SET edit_any_collection = TRUE WHERE uuid = 'm_unrecorded'",
            ),
            (
                "revoked membership: no authority today, but it would come back with one",
                &["m_recorded"],
                "UPDATE users_organizations SET status = -1 WHERE uuid = 'm_recorded'",
            ),
        ];

        for (name, record, extra) in cases {
            let mut connection = connect_after_0716(MEMBERSHIPS, record);
            if !extra.is_empty() {
                connection.batch_execute(extra).unwrap();
            }

            let predicted = lookahead_count(&mut connection) != 0;
            let refused = connection.batch_execute(CONFIRM_PERMANENT_AUTHORITY).is_err();
            assert_eq!(predicted, refused, "preflight and migration disagree for: {name}");
        }
    }
}

/// Runs the whole Custom-role chain, then `tools/custom_role_rollback/sqlite.sql`, then the chain
/// again — against a throwaway SQLite database, with the real files on both legs.
///
/// The round trip is the claim the rollback tooling rests on: an operator who downgrades and later
/// upgrades again has to arrive at the same permissions, or the escape hatch quietly rewrites
/// authorization. It was only ever verified by hand.
#[cfg(all(test, sqlite))]
mod custom_role_rollback_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, sql_types::Text, sqlite::SqliteConnection};

    /// The nine files, in the order Diesel applies them.
    const CHAIN: [&str; 9] = [
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-15-120000_mark_pending_custom_collection_migration/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-16-120000_add_custom_collection_permissions/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-23-120000_reconcile_legacy_custom_roles/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-24-120000_drop_membership_access_all/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-24-130000_add_custom_access_permissions/up.sql"),
        include_str!("../../migrations/sqlite/2026-07-24-140000_guard_custom_role_downgrade/up.sql"),
        include_str!("../../migrations/sqlite/2026-08-09-120000_materialize_legacy_group_collection_authority/up.sql"),
        include_str!("../../migrations/sqlite/2026-08-10-120000_confirm_permanent_collection_authority/up.sql"),
    ];
    const CHAIN_VERSIONS: [&str; 9] = [
        "20260630120000",
        "20260715120000",
        "20260716120000",
        "20260723120000",
        "20260724120000",
        "20260724130000",
        "20260724140000",
        "20260809120000",
        "20260810120000",
    ];

    const ROLLBACK: &str = include_str!("../../tools/custom_role_rollback/sqlite.sql");

    const PERMANENT_AUTHORITY_ACK: &str =
        "CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY)";

    /// `users_organizations` exactly as the release before this feature leaves it — the rollback
    /// script checks for *precisely* eighteen columns afterwards, so a reduced fixture would not
    /// exercise the check it exists for.
    const UPSTREAM_SCHEMA: &str = "
        CREATE TABLE __diesel_schema_migrations (
            version VARCHAR(50) NOT NULL PRIMARY KEY,
            run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE users_organizations (
            uuid       TEXT    NOT NULL PRIMARY KEY,
            user_uuid  TEXT    NOT NULL,
            org_uuid   TEXT    NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE,
            akey       TEXT    NOT NULL DEFAULT '',
            status     INTEGER NOT NULL DEFAULT 2,
            atype      INTEGER NOT NULL,
            reset_password_key TEXT,
            external_id TEXT,
            invited_by_email TEXT DEFAULT NULL,
            UNIQUE (user_uuid, org_uuid)
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY,
            organizations_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups_users (
            groups_uuid TEXT NOT NULL,
            users_organizations_uuid TEXT NOT NULL,
            PRIMARY KEY (groups_uuid, users_organizations_uuid)
        );
        INSERT INTO __diesel_schema_migrations (version) VALUES ('20250109172300');
    ";

    /// One membership per legacy shape that the mapping treats differently.
    const LEGACY_MEMBERSHIPS: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES
            ('g_all', 'org', TRUE),
            ('g_plain', 'org', FALSE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype) VALUES
            ('m_owner',     'u1', 'org', FALSE,  2, 0),
            ('m_admin',     'u2', 'org', FALSE,  2, 1),
            ('m_user',      'u3', 'org', FALSE,  2, 2),
            ('m_mgr_bare',  'u4', 'org', FALSE,  2, 3),
            ('m_mgr_all',   'u5', 'org', TRUE,   2, 3),
            ('m_mgr_group', 'u6', 'org', FALSE,  2, 3),
            ('m_mgr_gone',  'u7', 'org', FALSE, -1, 3);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all', 'm_mgr_group'),
            ('g_all', 'm_mgr_gone'),
            ('g_plain', 'm_mgr_bare');
    ";

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        value: String,
    }

    fn rows(connection: &mut SqliteConnection, query: &str) -> Vec<String> {
        diesel::sql_query(query).load::<Row>(connection).unwrap().into_iter().map(|row| row.value).collect()
    }

    /// Every membership's role plus its nine permissions, as one comparable line each.
    fn permission_state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype || ' status=' || status \
                 || ' ' || manage_users || manage_groups || manage_policies \
                 || create_new_collections || edit_any_collection || delete_any_collection \
                 || access_event_logs || access_import_export || access_reports AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    fn legacy_state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype || ' access_all=' || access_all AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    /// Applies the chain, recording each version the way Diesel would.
    fn upgrade(connection: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        for (sql, version) in CHAIN.iter().zip(CHAIN_VERSIONS) {
            connection.batch_execute(sql)?;
            connection
                .batch_execute(&format!("INSERT INTO __diesel_schema_migrations (version) VALUES ('{version}')"))?;
        }
        Ok(())
    }

    /// `.bail on` is a sqlite3 shell command, not SQL. Dropping it is safe here — a failing statement
    /// fails the whole `batch_execute` anyway — but the assertion keeps the test honest if another
    /// dot-command is ever added, because those the shell would act on and this runner would not.
    fn rollback_sql() -> String {
        let (dot, sql): (Vec<&str>, Vec<&str>) = ROLLBACK.lines().partition(|line| line.starts_with('.'));
        assert_eq!(dot, [".bail on"], "unexpected sqlite3 shell command in the rollback script");
        sql.join("\n")
    }

    fn connect() -> SqliteConnection {
        connect_with(LEGACY_MEMBERSHIPS)
    }

    fn connect_with(memberships: &str) -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        connection.batch_execute("PRAGMA foreign_keys = OFF").unwrap();
        connection.batch_execute(UPSTREAM_SCHEMA).unwrap();
        connection.batch_execute(memberships).unwrap();
        connection
    }

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        rows(connection, &format!("SELECT ({query}) || '' AS value"))[0].parse().unwrap()
    }

    /// The nine `down.sql` files, in the order `diesel migration revert` applies them.
    const REVERT_CHAIN: [&str; 9] = [
        include_str!("../../migrations/sqlite/2026-08-10-120000_confirm_permanent_collection_authority/down.sql"),
        include_str!(
            "../../migrations/sqlite/2026-08-09-120000_materialize_legacy_group_collection_authority/down.sql"
        ),
        include_str!("../../migrations/sqlite/2026-07-24-140000_guard_custom_role_downgrade/down.sql"),
        include_str!("../../migrations/sqlite/2026-07-24-130000_add_custom_access_permissions/down.sql"),
        include_str!("../../migrations/sqlite/2026-07-24-120000_drop_membership_access_all/down.sql"),
        include_str!("../../migrations/sqlite/2026-07-23-120000_reconcile_legacy_custom_roles/down.sql"),
        include_str!("../../migrations/sqlite/2026-07-16-120000_add_custom_collection_permissions/down.sql"),
        include_str!("../../migrations/sqlite/2026-07-15-120000_mark_pending_custom_collection_migration/down.sql"),
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/down.sql"),
    ];

    const DOWNGRADE_ACK: &str =
        "CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY)";

    /// The revert chain the rollback README offers as the Diesel alternative to `sqlite.sql`, run
    /// end to end. It was only ever verified by hand, and it is where the acknowledgement's lifetime
    /// lives: consuming it at the guard instead of at the oldest lossy step leaves every following
    /// destructive revert unguarded and strands the chain halfway.
    #[test]
    fn the_diesel_revert_chain_runs_with_one_acknowledgement() {
        let mut connection = connect();
        let before = legacy_state(&mut connection);

        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        upgrade(&mut connection).unwrap();

        // One decision, plus the historical provenance as the allowlist -- what the README suggests.
        connection.batch_execute(DOWNGRADE_ACK).unwrap();
        connection
            .batch_execute(
                "CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
                 INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid)
                 SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager;",
            )
            .unwrap();

        for (step, down) in REVERT_CHAIN.iter().enumerate() {
            connection.batch_execute(down).unwrap_or_else(|e| panic!("revert step {step} failed: {e}"));
        }

        assert_eq!(
            legacy_state(&mut connection),
            before
                .iter()
                .map(|row| {
                    // Same documented exception as the standalone script: the upgrade dropped the
                    // column because the role already reaches every collection, so the original
                    // value no longer exists.
                    if row.starts_with("m_owner") || row.starts_with("m_admin") {
                        row.replace("access_all=0", "access_all=1")
                    } else {
                        row.clone()
                    }
                })
                .collect::<Vec<_>>(),
            "the revert chain has to land on the same legacy shape as tools/custom_role_rollback/"
        );
    }

    /// Without the acknowledgement the chain stops at the guard, before the first destructive step,
    /// and changes nothing.
    #[test]
    fn the_revert_chain_stops_at_the_guard_and_mutates_nothing() {
        let mut connection = connect();
        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        upgrade(&mut connection).unwrap();
        let upgraded = permission_state(&mut connection);

        // 2026-08-10 and 2026-08-09 revert cleanly; they are no-ops by design.
        connection.batch_execute(REVERT_CHAIN[0]).unwrap();
        connection.batch_execute(REVERT_CHAIN[1]).unwrap();
        assert!(connection.batch_execute(REVERT_CHAIN[2]).is_err(), "the downgrade guard has to refuse");

        assert_eq!(permission_state(&mut connection), upgraded, "a refused revert must not mutate");
    }

    /// The migrated-schema half of this is covered in `custom_role_migration_sql_tests`. This is the
    /// other half, and the one an ordinary upgrade actually meets: the preflight has to predict from
    /// the *legacy* schema exactly whether the chain will stop for the permanent-authority decision.
    #[test]
    fn the_legacy_shape_lookahead_agrees_with_the_whole_chain() {
        let query = super::permanent_authority_lookahead_query(false, true, false, false, false, "\"groups\"")
            .expect("membership access_all is still present before the upgrade");

        let cases: [(&str, &str); 5] = [
            ("group-derived Manager: the question", LEGACY_MEMBERSHIPS),
            (
                "membership access_all too: conservatively ask without immutable provenance",
                "INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
                 INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype)
                 VALUES ('m', 'u', 'org', TRUE, 2, 3);
                 INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm');",
            ),
            (
                "the access_all group belongs to another organization",
                "INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'other', TRUE);
                 INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype)
                 VALUES ('m', 'u', 'org', FALSE, 2, 3);
                 INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm');",
            ),
            (
                "a plain User in the group is not converted and not asked about",
                "INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
                 INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype)
                 VALUES ('m', 'u', 'org', FALSE, 2, 2);
                 INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm');",
            ),
            (
                "an invited Manager holds nothing today, but would come back with it",
                "INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org', TRUE);
                 INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype)
                 VALUES ('m', 'u', 'org', FALSE, 0, 3);
                 INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm');",
            ),
        ];

        for (name, memberships) in cases {
            let mut connection = connect_with(memberships);
            let predicted = count(&mut connection, &query) != 0;
            let refused = upgrade(&mut connection).is_err();
            assert_eq!(predicted, refused, "preflight and chain disagree on the legacy schema for: {name}");
        }
    }

    #[test]
    fn upgrade_rollback_and_upgrade_again_converge() {
        let mut connection = connect();
        let before = legacy_state(&mut connection);

        // `m_mgr_group` and `m_mgr_gone` reach every collection through an access_all group, so the
        // chain stops for the decision 2026-08-10-120000 exists to ask.
        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        upgrade(&mut connection).unwrap();
        let upgraded = permission_state(&mut connection);

        // The legacy Manager whose authority came from the group carries it in the columns now; the
        // one whose membership held access_all gets all three; a bare Manager gets nothing.
        assert!(upgraded.contains(&"m_mgr_group atype=4 status=2 000011000".to_owned()), "{upgraded:?}");
        assert!(upgraded.contains(&"m_mgr_all atype=4 status=2 000111000".to_owned()), "{upgraded:?}");
        assert!(upgraded.contains(&"m_mgr_bare atype=4 status=2 000000000".to_owned()), "{upgraded:?}");
        assert!(upgraded.contains(&"m_user atype=2 status=2 000000000".to_owned()), "{upgraded:?}");

        // Roll back with the historical provenance as the allowlist, which is what the README offers
        // as the starting point.
        connection
            .batch_execute(
                "CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
                 INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid)
                 SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager;",
            )
            .unwrap();
        connection.batch_execute(&rollback_sql()).unwrap();

        assert_eq!(
            legacy_state(&mut connection),
            before
                .iter()
                .map(|row| {
                    // Owner and Admin always come back with access_all set: the upgrade dropped the
                    // column precisely because their role already reaches every collection, so the
                    // original value no longer exists. Documented in the rollback README.
                    if row.starts_with("m_owner") || row.starts_with("m_admin") {
                        row.replace("access_all=0", "access_all=1")
                    } else {
                        row.clone()
                    }
                })
                .collect::<Vec<_>>(),
            "the rollback has to restore the legacy roles it was given an allowlist for"
        );
        assert_eq!(
            rows(
                &mut connection,
                "SELECT version AS value FROM __diesel_schema_migrations WHERE version >= '20260630120000'"
            ),
            Vec::<String>::new(),
            "the older binary must not see a ledger from the future"
        );

        // A re-upgrade has to ask again -- the acknowledgement is consumed, and a revert is not
        // consent -- and then land on exactly the state it produced the first time.
        assert!(upgrade(&mut connect_from(&mut connection)).is_err(), "the question has to be asked again");
        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        upgrade(&mut connection).unwrap();

        assert_eq!(permission_state(&mut connection), upgraded, "the round trip has to converge");
    }

    /// A second connection onto the same rolled-back content, so the "asks again" probe can fail
    /// without leaving its aborted guard behind on the connection the test continues with.
    fn connect_from(source: &mut SqliteConnection) -> SqliteConnection {
        let mut copy = SqliteConnection::establish(":memory:").unwrap();
        copy.batch_execute("PRAGMA foreign_keys = OFF").unwrap();
        copy.batch_execute(UPSTREAM_SCHEMA).unwrap();
        copy.batch_execute("DELETE FROM __diesel_schema_migrations").unwrap();
        for statement in rows(
            source,
            "SELECT 'INSERT INTO users_organizations (uuid,user_uuid,org_uuid,access_all,akey,status,atype) VALUES (''' \
                 || uuid || ''',''' || user_uuid || ''',''' || org_uuid || ''',' || access_all || ',''' || akey \
                 || ''',' || status || ',' || atype || ')' AS value FROM users_organizations",
        ) {
            copy.batch_execute(&statement).unwrap();
        }
        copy.batch_execute(LEGACY_GROUPS_ONLY).unwrap();
        copy
    }

    const LEGACY_GROUPS_ONLY: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES
            ('g_all', 'org', TRUE),
            ('g_plain', 'org', FALSE);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all', 'm_mgr_group'),
            ('g_all', 'm_mgr_gone'),
            ('g_plain', 'm_mgr_bare');
    ";

    /// The precondition is the only thing standing between a mismatched database and an irreversible
    /// rewrite, so it has to refuse before touching anything.
    #[test]
    fn the_rollback_refuses_without_an_allowlist_and_changes_nothing() {
        let mut connection = connect();
        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
        upgrade(&mut connection).unwrap();
        let upgraded = permission_state(&mut connection);

        assert!(connection.batch_execute(&rollback_sql()).is_err());

        assert_eq!(permission_state(&mut connection), upgraded, "a refused rollback must not mutate");
        assert_eq!(
            rows(
                &mut connection,
                "SELECT COUNT(*) || '' AS value FROM __diesel_schema_migrations WHERE version >= '20260630120000'"
            ),
            vec!["9".to_owned()],
            "and it must not touch the ledger either"
        );
    }
}

/// MySQL/MariaDB use numeric comparison when one side of an equality is numeric. A malformed
/// rollback allowlist with an INT column can consequently select UUIDs that were never placed on
/// the list. These source-level contract tests complement the backend rollback tests: both entry
/// points must validate the documented CHAR(36) shape before their first role-mapping query.
#[cfg(test)]
mod mysql_custom_role_rollback_sql_tests {
    const STANDALONE_ROLLBACK: &str = include_str!("../../tools/custom_role_rollback/mysql.sql");
    const DIESEL_DOWN_MIGRATION: &str =
        include_str!("../../migrations/mysql/2026-06-30-120000_add_custom_role_permissions/down.sql");
    const ROLE_MAPPING: &str = "uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)";
    const STANDALONE_FIRST_MUTATION: &str = "ALTER TABLE users_organizations ADD COLUMN access_all";
    const DIESEL_FIRST_AUTHORIZATION_MUTATION: &str = "UPDATE users_organizations SET atype = 3";

    fn assert_char_36_guard_precedes_mutation(sql: &str, mutation: &str, expected_guard_copies: usize) {
        let role_mapping = sql.find(ROLE_MAPPING).expect("rollback must contain the allowlist role mapping");
        let mutation = sql.find(mutation).expect("rollback must contain the guarded mutation");
        assert!(mutation <= role_mapping, "the selected boundary must precede the role mapping");
        let preconditions = &sql[..mutation];

        assert_eq!(
            preconditions.matches("data_type = 'char'").count(),
            expected_guard_copies,
            "every allowlist shape check must require a character column"
        );
        assert_eq!(
            preconditions.matches("character_maximum_length = 36").count(),
            expected_guard_copies,
            "every allowlist shape check must require the complete UUID length"
        );
    }

    #[test]
    fn non_char_36_allowlists_are_rejected_before_mysql_role_mapping() {
        // The standalone script duplicates each predicate: once for its readable diagnostic and
        // once for the duplicate-key guard that actually stops execution.
        assert_char_36_guard_precedes_mutation(STANDALONE_ROLLBACK, STANDALONE_FIRST_MUTATION, 2);
        assert_char_36_guard_precedes_mutation(DIESEL_DOWN_MIGRATION, DIESEL_FIRST_AUTHORIZATION_MUTATION, 1);
    }
}

#[cfg(test)]
mod custom_role_migration_preflight_tests {
    use std::error::Error as _;

    use super::{
        CustomRoleMigrationFacts as Facts, CustomRolePreflightDecision as Decision, custom_role_preflight_decision,
        custom_role_preflight_error, mysql_partial_unexpected_values_query, permanent_authority_lookahead_query,
    };

    fn pending_repair() -> Facts {
        Facts {
            memberships_table_exists: true,
            migration_table_exists: true,
            access_all_column_exists: true,
            // Any database on which the chain has started under the code that ships today carries
            // both of these, because its first migration writes them. Where it has not started,
            // `manage_permissions_migration_applied` is false and neither is read.
            legacy_manager_record_exists: true,
            history_verified: true,
            ..Facts::default()
        }
    }

    #[test]
    fn empty_database_can_run_normal_migrations() {
        assert_eq!(custom_role_preflight_decision(Facts::default(), false), Decision::Proceed);
    }

    #[test]
    fn existing_schema_without_a_ledger_is_not_guessed() {
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    memberships_table_exists: true,
                    access_all_column_exists: true,
                    ..Facts::default()
                },
                false,
            ),
            Decision::RefuseMissingMigrationLedger
        );
    }

    /// A database on which the whole chain has already run.
    fn fully_migrated() -> Facts {
        Facts {
            memberships_table_exists: true,
            migration_table_exists: true,
            access_all_column_exists: false,
            manage_permission_columns: 3,
            manage_permissions_migration_applied: true,
            collection_permission_columns: 3,
            collection_permissions_migration_applied: true,
            access_permission_columns: 3,
            access_permissions_migration_applied: true,
            repair_migration_applied: true,
            access_all_drop_migration_applied: true,
            legacy_user_access_all_count: 0,
            same_run_0716_marker: false,
            legacy_manager_record_exists: true,
            history_verified: true,
            confirm_permanent_authority_migration_applied: true,
            permanent_collection_authority_ack: false,
            unconfirmed_permanent_authority_count: 0,
        }
    }

    /// A database ready for `20260810120000`, i.e. one memberships still awaiting the decision.
    fn awaiting_permanent_authority_decision() -> Facts {
        Facts {
            confirm_permanent_authority_migration_applied: false,
            permanent_collection_authority_ack: false,
            unconfirmed_permanent_authority_count: 2,
            ..fully_migrated()
        }
    }

    /// The refusal `20260810120000` exists for has to be reached *here*, with the review query and
    /// the acknowledgement attached. Left to the migration's own guard it arrives as nothing but
    /// `UNIQUE constraint failed: __vw_permanent_authority_guard.blocked`, on an upgrade that is
    /// otherwise perfectly healthy.
    #[test]
    fn unconfirmed_permanent_collection_authority_is_refused_with_a_recovery_path() {
        let facts = awaiting_permanent_authority_decision();
        let decision = custom_role_preflight_decision(facts, false);
        assert_eq!(decision, Decision::RefuseUnconfirmedPermanentCollectionAuthority);
        assert_eq!(custom_role_preflight_decision(facts, true), decision, "MySQL must not auto-complete this");

        let error = custom_role_preflight_error(decision, facts);
        let message = error.source().expect("preflight error should retain its I/O error source").to_string();
        assert!(message.contains("__vw_ack_permanent_collection_authority"), "{message}");
        assert!(message.contains("was_legacy_manager"), "{message}");
        assert!(message.contains("Nothing has been changed."), "{message}");
        // The count belongs in the message: it is what tells an operator whether the review query is
        // expected to return one row or a hundred.
        assert!(message.contains('2'), "{message}");
    }

    /// Three separate ways out, and each of them has to actually let the upgrade through.
    #[test]
    fn the_permanent_authority_question_is_asked_exactly_once() {
        // The owner answered it.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    permanent_collection_authority_ack: true,
                    ..awaiting_permanent_authority_decision()
                },
                false,
            ),
            Decision::Proceed
        );
        // Already answered on an earlier start: the migration is recorded, so it never runs again and
        // the acknowledgement it consumed is gone. Asking a second time would deadlock the upgrade.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    confirm_permanent_authority_migration_applied: true,
                    ..awaiting_permanent_authority_decision()
                },
                false,
            ),
            Decision::Proceed
        );
        // Nothing to decide -- the common case.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    unconfirmed_permanent_authority_count: 0,
                    ..awaiting_permanent_authority_decision()
                },
                false,
            ),
            Decision::Proceed
        );
    }

    /// A damaged schema is the more urgent problem and its recovery is a different one, so it has to
    /// be reported first. The question is only worth asking about a database that can actually run
    /// the migration.
    #[test]
    fn a_damaged_schema_outranks_the_permanent_authority_question() {
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    access_permission_columns: 1,
                    access_permissions_migration_applied: false,
                    ..awaiting_permanent_authority_decision()
                },
                false,
            ),
            Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Access)
        );
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    history_verified: false,
                    ..awaiting_permanent_authority_decision()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );
    }

    /// The lookahead has to answer the same question before and after the columns it would rather
    /// read exist, because the preflight runs before any migration does.
    #[test]
    fn the_permanent_authority_lookahead_reads_whichever_schema_is_present() {
        let materialized = permanent_authority_lookahead_query(true, false, true, true, true, "\"groups\"").unwrap();
        assert!(materialized.contains("uo.atype = 4"));
        assert!(materialized.contains("edit_any_collection = TRUE OR uo.delete_any_collection = TRUE"));
        assert!(!materialized.contains("create_new_collections"));
        assert!(!materialized.contains(super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE));

        // The materialized predicate does not change with provenance availability: a mutable current
        // permission is never treated as historical evidence.
        let no_record = permanent_authority_lookahead_query(true, false, false, true, true, "\"groups\"").unwrap();
        assert_eq!(no_record, materialized);

        // The ordinary upgrade: nothing is materialized yet, so the answer comes from the retired
        // Manager role plus the legacy bit that the first migration turns into all three permissions.
        let legacy = permanent_authority_lookahead_query(false, true, false, false, false, "\"groups\"").unwrap();
        assert!(legacy.contains("uo.atype = 3"));
        assert!(!legacy.contains("uo.access_all = FALSE"));

        // Both shapes bind the group to the membership's own organization.
        for query in [&materialized, &no_record, &legacy] {
            assert!(query.contains("g.organizations_uuid = uo.org_uuid"), "{query}");
            assert!(query.contains("g.access_all = TRUE"), "{query}");
        }

        // Neither column group is readable: the migration cannot run either, so there is nothing to
        // look ahead to.
        assert!(permanent_authority_lookahead_query(false, false, true, false, false, "\"groups\"").is_none());

        // The reserved identifier is the caller's to quote.
        assert!(
            permanent_authority_lookahead_query(true, false, true, true, true, "`groups`")
                .unwrap()
                .contains("`groups`")
        );
    }

    #[test]
    fn repair_marker_makes_completed_state_idempotent() {
        assert_eq!(custom_role_preflight_decision(fully_migrated(), false), Decision::Proceed);
    }

    /// A database upgraded by an earlier revision of this feature branch carries the Custom-role
    /// versions without the effects the current files have, and Diesel will not run them again. The
    /// two tables the first migration creates today are the only durable evidence of that, so their
    /// absence has to stop the upgrade -- before every check that assumes the chain did what it does
    /// today.
    #[test]
    fn a_history_written_by_an_earlier_revision_is_refused() {
        // Neither table: an untouched earlier-revision database.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    legacy_manager_record_exists: false,
                    history_verified: false,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );

        // Recording provenance is data recovery, not an audit: writing the record table must not by
        // itself pass as a review of the history that made it necessary.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    legacy_manager_record_exists: true,
                    history_verified: false,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );

        // And the marker alone leaves the later migrations and the rollback scripts without the data
        // they read.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    legacy_manager_record_exists: false,
                    history_verified: true,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );

        // It is checked from the *first* Custom-role migration, not only from the repair one: the
        // divergence starts where `atype = 3` is reused, which is before the repair runs.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    repair_migration_applied: false,
                    access_all_drop_migration_applied: false,
                    access_all_column_exists: true,
                    legacy_manager_record_exists: false,
                    history_verified: false,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );

        // It outranks the schema/ledger checks: those describe an interrupted migration whose replay
        // is safe, which is not what this database needs.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    legacy_manager_record_exists: false,
                    history_verified: false,
                    access_all_column_exists: true,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::RefuseUnverifiedCustomRoleHistory
        );

        // A database that has not started the chain at all is untouched by any of this.
        assert_eq!(custom_role_preflight_decision(pending_repair(), false), Decision::Proceed);
    }

    /// The repair migration runs *before* the access_all drop and the third permission column group,
    /// so a partial state of either always carries `repair_migration_applied`. Skipping the schema
    /// checks for repaired databases would make them unreachable in exactly the situation they were
    /// written for.
    #[test]
    fn interrupted_migrations_after_the_repair_are_still_detected() {
        // Crash after `DROP COLUMN access_all`, before the ledger insert. MySQL/MariaDB commit DDL
        // implicitly, so the column is gone for good; a retry would fail with 1091.
        let interrupted_drop = Facts {
            access_all_drop_migration_applied: false,
            access_permission_columns: 0,
            access_permissions_migration_applied: false,
            ..fully_migrated()
        };
        assert_eq!(
            custom_role_preflight_decision(interrupted_drop, true),
            Decision::CompleteInterruptedAccessAllDrop,
            "MySQL/MariaDB can complete this in place"
        );
        assert_eq!(
            custom_role_preflight_decision(interrupted_drop, false),
            Decision::RefuseInterruptedAccessAllDrop,
            "backends with transactional DDL cannot reach this state by themselves"
        );

        // Crash after one of the three `ADD COLUMN` statements of the access group, before the
        // ledger insert. A retry would fail with 1060.
        for present in [1, 2] {
            assert_eq!(
                custom_role_preflight_decision(
                    Facts {
                        access_permission_columns: present,
                        access_permissions_migration_applied: false,
                        ..fully_migrated()
                    },
                    true,
                ),
                Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Access)
            );
        }

        // Ledger recorded, columns missing.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    access_permission_columns: 2,
                    ..fully_migrated()
                },
                true
            ),
            Decision::RefusePermissionLedgerMismatch(super::PermissionColumnGroup::Access)
        );

        // Drop recorded, but the column is back: schema and ledger disagree.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    access_all_column_exists: true,
                    ..fully_migrated()
                },
                true
            ),
            Decision::RefuseAccessAllDropLedgerMismatch
        );
    }

    #[test]
    fn a_pending_drop_after_the_repair_proceeds() {
        // The repair ran, the drop is simply next in line: column present, migration not recorded.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    access_all_column_exists: true,
                    access_all_drop_migration_applied: false,
                    access_permission_columns: 0,
                    access_permissions_migration_applied: false,
                    ..fully_migrated()
                },
                false,
            ),
            Decision::Proceed
        );
    }

    #[test]
    fn a_later_access_migration_before_the_pending_drop_is_refused() {
        // This exact non-prefix history was deployable from the feature's former side branch:
        // 20260724130000 and its columns exist, while 20260724120000 is still pending. SQLite's
        // pending fixed-list rebuild would otherwise discard all three columns and their values.
        for repair_migration_applied in [false, true] {
            let facts = Facts {
                repair_migration_applied,
                access_all_column_exists: true,
                access_all_drop_migration_applied: false,
                access_permission_columns: 3,
                access_permissions_migration_applied: true,
                ..fully_migrated()
            };
            let expected = Decision::RefuseOutOfOrderAccessPermissionsMigration;

            assert_eq!(custom_role_preflight_decision(facts, false), expected);
            assert_eq!(custom_role_preflight_decision(facts, true), expected);

            let message = custom_role_preflight_error(expected, facts)
                .source()
                .expect("preflight error should retain its I/O error source")
                .to_string();
            assert!(message.contains(super::CUSTOM_ACCESS_PERMISSIONS_MIGRATION), "{message}");
            assert!(message.contains(super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION), "{message}");
            assert!(message.contains("would drop access_event_logs"), "{message}");
            assert!(message.contains("Nothing has been changed"), "{message}");
        }
    }

    /// A repair is selected only after the same snapshot has passed every refusal. This pins the two
    /// mutation-before-refusal orders that previously existed: 0716 completion before discovering a
    /// damaged later column group, and interrupted-drop ledger repair before asking the owner.
    #[test]
    fn automatic_mysql_repairs_are_deferred_behind_all_refusals() {
        let partial_0716_with_damaged_access_group = Facts {
            collection_permission_columns: 3,
            collection_permissions_migration_applied: false,
            access_permission_columns: 1,
            access_permissions_migration_applied: false,
            ..pending_repair()
        };
        assert_eq!(
            custom_role_preflight_decision(partial_0716_with_damaged_access_group, true),
            Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Access),
            "0716 must not be completed before a later schema refusal"
        );

        let interrupted_drop_with_unanswered_authority = Facts {
            access_all_drop_migration_applied: false,
            access_permission_columns: 0,
            access_permissions_migration_applied: false,
            ..awaiting_permanent_authority_decision()
        };
        let decision = custom_role_preflight_decision(interrupted_drop_with_unanswered_authority, true);
        assert_eq!(decision, Decision::RefuseUnconfirmedPermanentCollectionAuthority);
        let message = custom_role_preflight_error(decision, interrupted_drop_with_unanswered_authority)
            .source()
            .expect("preflight error should retain its I/O error source")
            .to_string();
        assert!(message.contains("Nothing has been changed."), "{message}");

        // The historical partial-completion query reads access_all. Once 0723 and its following drop
        // are recorded, three columns without the earlier 0716 ledger are a non-prefix mismatch, not
        // the repairable pre-0723 crash state.
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: false,
                    ..fully_migrated()
                },
                true,
            ),
            Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Collection)
        );
    }

    #[test]
    fn interrupted_access_all_drop_error_names_the_ledger_fix() {
        let facts = Facts {
            access_all_drop_migration_applied: false,
            access_permission_columns: 0,
            access_permissions_migration_applied: false,
            ..fully_migrated()
        };
        let decision = custom_role_preflight_decision(facts, false);
        let error = custom_role_preflight_error(decision, facts);
        let message = error.source().expect("preflight error should retain its I/O error source").to_string();
        assert!(message.contains(super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION));
        assert!(message.contains("INSERT INTO __diesel_schema_migrations"));
    }

    #[test]
    fn a_historical_drop_without_the_repair_is_refused() {
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    access_all_drop_migration_applied: true,
                    access_all_column_exists: false,
                    ..pending_repair()
                },
                false,
            ),
            Decision::RefuseAlreadyDropped
        );
    }

    #[test]
    fn legacy_user_access_all_error_carries_a_recovery_path() {
        let facts = Facts {
            legacy_user_access_all_count: 2,
            ..pending_repair()
        };
        let decision = custom_role_preflight_decision(facts, false);
        assert_eq!(decision, Decision::RefuseLegacyUserAccessAll);

        let error = custom_role_preflight_error(decision, facts);
        let message = error.source().expect("preflight error should retain its I/O error source").to_string();
        assert!(message.contains("2 membership(s)"));
        // The operator needs the affected memberships ...
        assert!(message.contains("WHERE atype = 2\n  AND access_all = TRUE;"));
        // ... and both decisions: drop the reach, or write it out explicitly first.
        assert!(message.contains("SET access_all = FALSE"));
        assert!(message.contains("INSERT INTO users_collections"));
        // Nothing here may present the snapshot as equivalent to the old dynamic reach.
        assert!(message.contains("collections created after"));
    }

    #[test]
    fn already_dropped_error_points_at_the_backup() {
        let facts = Facts {
            access_all_drop_migration_applied: true,
            ..pending_repair()
        };
        let decision = custom_role_preflight_decision(facts, false);
        assert_eq!(decision, Decision::RefuseAlreadyDropped);

        let error = custom_role_preflight_error(decision, facts);
        let message = error.source().expect("preflight error should retain its I/O error source").to_string();
        assert!(message.contains("Restore the database backup"));
    }

    /// A legacy `User` membership carrying the historical access_all bit stops the upgrade before any
    /// migration runs, whatever its status is. Converting the bit into direct per-collection
    /// assignments would turn a dynamic, status-bound reach into a durable snapshot -- and those rows
    /// would still be there for an older binary after a rollback, which never checked the membership
    /// status on that path.
    #[test]
    fn legacy_user_access_all_blocks_the_upgrade_before_any_migration() {
        assert_eq!(custom_role_preflight_decision(pending_repair(), false), Decision::Proceed);

        let untouched_schema = Facts {
            legacy_user_access_all_count: 1,
            ..pending_repair()
        };
        assert_eq!(
            custom_role_preflight_decision(untouched_schema, false),
            Decision::RefuseLegacyUserAccessAll,
            "nothing may have been migrated yet when this is refused"
        );
        // MySQL/MariaDB gets no exception: no partial state may be completed past this either.
        assert_eq!(custom_role_preflight_decision(untouched_schema, true), Decision::RefuseLegacyUserAccessAll);
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    manage_permission_columns: 3,
                    manage_permissions_migration_applied: true,
                    legacy_user_access_all_count: 1,
                    ..pending_repair()
                },
                false,
            ),
            Decision::RefuseLegacyUserAccessAll
        );
    }

    #[test]
    fn a_partial_permission_column_group_is_refused_with_an_actionable_message() {
        // Every group is checked, not just the collection one: an interrupted MySQL migration can
        // leave `manage_*` or `access_*` columns behind, and re-running it would fail forever with
        // `Duplicate column name`.
        for (facts, group, expected) in [
            (
                Facts {
                    manage_permission_columns: 2,
                    ..pending_repair()
                },
                "manage_users",
                Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Manage),
            ),
            (
                Facts {
                    manage_permission_columns: 3,
                    manage_permissions_migration_applied: true,
                    access_permission_columns: 3,
                    ..pending_repair()
                },
                "access_event_logs",
                Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Access),
            ),
            (
                Facts {
                    manage_permission_columns: 1,
                    manage_permissions_migration_applied: true,
                    ..pending_repair()
                },
                "manage_users",
                Decision::RefusePermissionLedgerMismatch(super::PermissionColumnGroup::Manage),
            ),
        ] {
            // `true` = MySQL: only the historical collection-group state is auto-completed, never these.
            assert_eq!(custom_role_preflight_decision(facts, true), expected);
            assert_eq!(custom_role_preflight_decision(facts, false), expected);

            let error = custom_role_preflight_error(expected, facts);
            let message = error.source().expect("preflight error should retain its I/O error source").to_string();
            assert!(message.contains(group), "message should name the affected columns: {message}");
            assert!(message.contains("ALTER TABLE users_organizations DROP COLUMN"));
        }
    }

    /// A group-derived legacy Manager is no longer a special case for the preflight: the repair
    /// migration writes the authority into the permission columns, and nothing reads the 0/1/1 shape
    /// afterwards, so no state of those columns has to be attributed or refused.
    #[test]
    fn a_group_derived_legacy_manager_needs_no_preflight_decision() {
        assert_eq!(custom_role_preflight_decision(pending_repair(), false), Decision::Proceed);
        for same_run_0716_marker in [false, true] {
            assert_eq!(
                custom_role_preflight_decision(
                    Facts {
                        collection_permission_columns: 3,
                        collection_permissions_migration_applied: true,
                        same_run_0716_marker,
                        ..pending_repair()
                    },
                    false,
                ),
                Decision::Proceed
            );
        }
    }

    /// The two partial-column states need opposite advice. Without the ledger entry the migration
    /// never completed, so the leftovers are untouched defaults and dropping them is free. With the
    /// ledger entry the migration *did* run, so the remaining columns can hold granted permissions --
    /// and dropping them alone would not even clear the refusal, because the ledger row stays.
    #[test]
    fn the_two_partial_column_states_get_opposite_recovery_advice() {
        let interrupted = Facts {
            access_permission_columns: 1,
            access_permissions_migration_applied: false,
            ..fully_migrated()
        };
        let vanished = Facts {
            access_permission_columns: 1,
            access_permissions_migration_applied: true,
            ..fully_migrated()
        };

        let interrupted_decision = custom_role_preflight_decision(interrupted, false);
        let vanished_decision = custom_role_preflight_decision(vanished, false);
        assert_eq!(interrupted_decision, Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Access));
        assert_eq!(vanished_decision, Decision::RefusePermissionLedgerMismatch(super::PermissionColumnGroup::Access));

        let message_of = |decision| {
            custom_role_preflight_error(decision, interrupted)
                .source()
                .expect("preflight error should retain its I/O error source")
                .to_string()
        };
        let interrupted_message = message_of(interrupted_decision);
        let vanished_message = message_of(vanished_decision);

        assert!(interrupted_message.contains("dropping them"), "{interrupted_message}");
        assert!(!interrupted_message.contains("DELETE FROM __diesel_schema_migrations"));

        // The dangerous claim must not be repeated where it is false, and the operator has to be told
        // to remove the ledger row as well if they accept the loss.
        assert!(!vanished_message.contains("loses nothing"), "{vanished_message}");
        assert!(vanished_message.contains("Do not drop them"), "{vanished_message}");
        assert!(vanished_message.contains("Restoring the database backup"), "{vanished_message}");
        assert!(vanished_message.contains("DELETE FROM __diesel_schema_migrations"), "{vanished_message}");
    }

    /// Both generic texts end in the migration running again. For the collection group after the
    /// access_all drop that is impossible -- 2026-07-16-120000 reads the dropped column -- so the advice
    /// has to change to "reach the finished shape without executing it".
    #[test]
    fn the_collection_group_gets_replay_free_advice_once_access_all_is_gone() {
        for (columns, applied, expected) in [
            (1, false, Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Collection)),
            (1, true, Decision::RefusePermissionLedgerMismatch(super::PermissionColumnGroup::Collection)),
        ] {
            let facts = Facts {
                collection_permission_columns: columns,
                collection_permissions_migration_applied: applied,
                ..fully_migrated()
            };
            let decision = custom_role_preflight_decision(facts, false);
            assert_eq!(decision, expected);

            let message = custom_role_preflight_error(decision, facts)
                .source()
                .expect("preflight error should retain its I/O error source")
                .to_string();
            assert!(message.contains("cannot be migrated again on this database"), "{message}");
            assert!(message.contains("ADD COLUMN create_new_collections"), "{message}");
            assert!(message.contains("VALUES ('20260716120000')"), "{message}");
            // The replay-based advice must not leak through for this state.
            assert!(!message.contains("DELETE FROM __diesel_schema_migrations"), "{message}");
            assert!(!message.contains("lets the migration run again"), "{message}");
        }

        // While access_all still exists a replay is fine, so the generic texts stay in place.
        let before_drop = Facts {
            access_all_column_exists: true,
            access_all_drop_migration_applied: false,
            access_permission_columns: 0,
            access_permissions_migration_applied: false,
            collection_permission_columns: 1,
            collection_permissions_migration_applied: false,
            ..fully_migrated()
        };
        let decision = custom_role_preflight_decision(before_drop, false);
        assert_eq!(decision, Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Collection));
        let message = custom_role_preflight_error(decision, before_drop)
            .source()
            .expect("preflight error should retain its I/O error source")
            .to_string();
        assert!(message.contains("lets the migration run again"), "{message}");
    }

    #[test]
    fn exact_mysql_partial_schema_uses_only_the_mysql_completion_path() {
        let facts = Facts {
            collection_permission_columns: 3,
            collection_permissions_migration_applied: false,
            ..pending_repair()
        };
        assert_eq!(custom_role_preflight_decision(facts, true), Decision::CompleteMysqlCollectionMigration);
        assert_eq!(
            custom_role_preflight_decision(facts, false),
            Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Collection)
        );
    }

    #[test]
    fn mysql_partial_0716_projects_the_pending_group_authority_before_completion() {
        let projected = permanent_authority_lookahead_query(true, true, true, false, false, "`groups`")
            .expect("the partial schema still has access_all");

        assert!(!projected.contains("uo.access_all = FALSE"), "{projected}");
        assert!(projected.contains(super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE), "{projected}");
        assert!(projected.contains("g.organizations_uuid = uo.org_uuid"), "{projected}");
        assert!(
            projected.contains("uo.edit_any_collection = TRUE"),
            "the projection must retain both pending and already-materialized grants: {projected}"
        );

        let facts = Facts {
            collection_permission_columns: 3,
            collection_permissions_migration_applied: false,
            unconfirmed_permanent_authority_count: 1,
            ..pending_repair()
        };
        assert_eq!(
            custom_role_preflight_decision(facts, true),
            Decision::RefuseUnconfirmedPermanentCollectionAuthority,
            "the owner decision must precede complete_partial_collection_migration()"
        );

        let acknowledged = Facts {
            permanent_collection_authority_ack: true,
            ..facts
        };
        assert_eq!(
            custom_role_preflight_decision(acknowledged, true),
            Decision::CompleteMysqlCollectionMigration,
            "the validated partial state is repairable after the owner answers"
        );
    }

    /// Some earlier feature-branch snapshots recorded 0716 after adding its columns but before the
    /// group-derived UPDATE was part of that migration. The later 0723 repair is what will write
    /// 0/1/1 for those recorded Managers, so a recorded 0716 must not make the preflight trust the
    /// temporary 0/0/0 values while that repair is still pending.
    #[test]
    fn recorded_old_0716_projects_the_pending_repair_before_migrations_run() {
        let projected = permanent_authority_lookahead_query(true, true, true, true, false, "\"groups\"")
            .expect("the pending repair can be projected from access_all and the Manager record");

        assert!(projected.contains(super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE), "{projected}");
        assert!(projected.contains("uo.atype = 3 OR"), "{projected}");
        assert!(projected.contains("uo.edit_any_collection = TRUE"), "{projected}");

        let facts = Facts {
            manage_permission_columns: 3,
            manage_permissions_migration_applied: true,
            collection_permission_columns: 3,
            collection_permissions_migration_applied: true,
            repair_migration_applied: false,
            unconfirmed_permanent_authority_count: 1,
            ..pending_repair()
        };
        for mysql in [false, true] {
            assert_eq!(
                custom_role_preflight_decision(facts, mysql),
                Decision::RefuseUnconfirmedPermanentCollectionAuthority,
                "backend flag {mysql}: the owner must decide before the pending repair writes 0/1/1"
            );
        }
    }

    #[test]
    fn interrupted_mysql_drop_repair_has_an_explicit_transaction_boundary() {
        let source = include_str!("mod.rs");
        let function = source
            .split_once("fn complete_interrupted_access_all_drop(")
            .expect("repair function must exist")
            .1
            .split_once("/// Read everything")
            .expect("repair function boundary must remain recognizable")
            .0;

        assert!(function.contains("connection.transaction"), "the ledger repair must commit with autocommit=0");
        assert!(function.contains("super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION"));
    }

    #[test]
    fn postgresql_preflight_requires_one_migration_namespace() {
        let query = super::postgresql_migration_namespace_query();
        for relation in [
            "users_organizations",
            "__diesel_schema_migrations",
            "groups",
            "groups_users",
            super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE,
            super::CUSTOM_ROLE_HISTORY_VERIFIED_TABLE,
        ] {
            assert!(query.contains(relation), "namespace guard does not bind {relation}: {query}");
        }
        assert!(query.contains("current_schema()"));
        assert!(query.contains("resolved.relnamespace <> memberships.relnamespace"));
    }

    /// A repair is not an answer to the permanent-authority question. Both automatic repairs are
    /// deferred behind that refusal, and re-inspection after a permitted repair must reach the same
    /// refusal if the database changes between the decision and the next pass.
    #[test]
    fn a_repair_does_not_answer_the_permanent_authority_question() {
        // The interrupted drop is reachable only after the repair migration, and 20260724130000
        // cannot have run yet, so its columns are still absent on both sides of that repair.
        let interrupted_drop = Facts {
            access_permission_columns: 0,
            access_permissions_migration_applied: false,
            ..awaiting_permanent_authority_decision()
        };

        for (name, before_repair, after_repair) in [
            (
                "the historical MySQL partial collection-permission schema",
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: false,
                    unconfirmed_permanent_authority_count: 2,
                    ..pending_repair()
                },
                // complete_partial_collection_migration() records 20260716120000, nothing else.
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    unconfirmed_permanent_authority_count: 2,
                    ..pending_repair()
                },
            ),
            (
                "an access_all drop that committed without its ledger entry",
                Facts {
                    access_all_drop_migration_applied: false,
                    ..interrupted_drop
                },
                // complete_interrupted_access_all_drop() records 20260724120000, nothing else.
                interrupted_drop,
            ),
        ] {
            assert_eq!(
                custom_role_preflight_decision(before_repair, true),
                Decision::RefuseUnconfirmedPermanentCollectionAuthority,
                "{name}: no repair may mutate the database before the owner decides"
            );
            assert_eq!(
                custom_role_preflight_decision(after_repair, true),
                Decision::RefuseUnconfirmedPermanentCollectionAuthority,
                "{name}: re-inspection must preserve the refusal"
            );
        }
    }

    #[test]
    fn historical_mysql_partial_query_does_not_require_the_new_marker_table() {
        let query = mysql_partial_unexpected_values_query(false);
        assert!(!query.contains(super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE));
        assert!(!query.contains("groups_users"));
        // Without the allowance the query reads users_organizations only, so it stays answerable on
        // a database that has no provenance record at all.
        assert!(!query.contains(super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE));
    }

    #[test]
    fn same_run_mysql_partial_query_requires_the_current_group_source() {
        let query = mysql_partial_unexpected_values_query(true);
        assert!(query.contains("access_all = FALSE"));
        assert!(query.contains("edit_any_collection = TRUE"));
        assert!(query.contains("delete_any_collection = TRUE"));
        assert!(query.contains("INNER JOIN `groups` AS g"));
        assert!(query.contains("g.organizations_uuid = users_organizations.org_uuid"));
        assert!(query.contains("g.access_all = TRUE"));
    }

    /// The allowance describes what 2026-07-16-120000 can produce, and that statement is driven by
    /// the legacy-Manager record. A 0/1/1 row for a membership that is not on the record therefore
    /// has no legitimate source, and must not be counted as an expected shape -- otherwise the
    /// automatic MySQL recovery would adopt a grant nothing can account for.
    #[test]
    fn the_same_run_allowance_is_bound_to_the_legacy_manager_record() {
        let query = mysql_partial_unexpected_values_query(true);
        assert!(
            query.contains(&format!(
                "uuid IN (SELECT users_organizations_uuid FROM {})",
                super::CUSTOM_ROLE_LEGACY_MANAGER_TABLE
            )),
            "{query}"
        );
    }

    #[test]
    fn incomplete_columns_and_ledger_mismatch_are_refused() {
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 2,
                    ..pending_repair()
                },
                true,
            ),
            Decision::RefusePartialPermissionSchema(super::PermissionColumnGroup::Collection)
        );
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 2,
                    collection_permissions_migration_applied: true,
                    ..pending_repair()
                },
                true,
            ),
            Decision::RefusePermissionLedgerMismatch(super::PermissionColumnGroup::Collection)
        );
    }
}
