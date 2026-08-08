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
const CUSTOM_ROLE_SAME_RUN_MARKER_TABLE: &str = "__vw_custom_role_same_run_0716";

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
}

const PARTIAL_PERMISSION_COLUMNS_RECOVERY: &str = concat!(
    "\n\nThis happens when a migration was interrupted between its ALTER TABLE statements (on ",
    "MySQL/MariaDB every DDL statement commits on its own, so columns can exist without the ledger ",
    "entry). The leftover columns only ever hold their FALSE default at this point, so dropping them ",
    "loses nothing and lets the migration run again from a clean state.\n\n",
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

const AMBIGUOUS_DIRECT_PERMISSIONS_RECOVERY_SQL: &str = concat!(
    "\n\nList every affected membership with this SQLite/MySQL/PostgreSQL-compatible query:\n",
    "SELECT uuid, user_uuid, org_uuid, atype, status\n",
    "FROM users_organizations\n",
    "WHERE atype IN (3, 4)\n",
    "  AND access_all = FALSE\n",
    "  AND create_new_collections = FALSE\n",
    "  AND edit_any_collection = TRUE\n",
    "  AND delete_any_collection = TRUE;\n\n",
    "To see which of them still have an organization-local full-access group as a plausible source of the pattern, ",
    "run the query below. On MySQL/MariaDB the reserved word `groups` has to be quoted with backticks:\n",
    "SELECT uo.uuid, uo.org_uuid, g.uuid AS group_uuid, g.name AS group_name\n",
    "FROM users_organizations uo\n",
    "INNER JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid\n",
    "INNER JOIN groups g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid\n",
    "WHERE g.access_all = TRUE\n",
    "  AND uo.atype IN (3, 4)\n",
    "  AND uo.access_all = FALSE\n",
    "  AND uo.create_new_collections = FALSE\n",
    "  AND uo.edit_any_collection = TRUE\n",
    "  AND uo.delete_any_collection = TRUE;\n\n",
    "An organization owner has to decide per membership which of the two meanings applies. Replace ",
    "<MEMBERSHIP_UUID> and run exactly one guarded statement for that membership while every Vaultwarden instance is ",
    "stopped. Do not bulk-apply either statement.\n\n",
    "The pattern was a group-derived copy, or the authority is no longer wanted: drop it and let the group (if any) ",
    "remain the only source of access.\n",
    "UPDATE users_organizations\n",
    "SET edit_any_collection = FALSE,\n",
    "    delete_any_collection = FALSE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>' AND access_all = FALSE AND create_new_collections = FALSE;\n\n",
    "The pattern was an intentional direct grant that has to survive: make it unambiguous so the migration can pass.\n",
    "UPDATE users_organizations\n",
    "SET create_new_collections = TRUE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>' AND access_all = FALSE AND edit_any_collection = TRUE;\n\n",
    "Note that the second statement also grants Create-any-collection, because a 0/1/1 pattern is exactly the state ",
    "the migration cannot attribute. If that member must not be able to create collections, start the server once so ",
    "the migration completes, then set create_new_collections back to FALSE for that membership."
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
    ambiguous_direct_permission_count: i64,
    same_run_0716_marker: bool,
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
    RefuseAmbiguousDirectPermissions,
    RefuseInterruptedAccessAllDrop,
    RefuseAccessAllDropLedgerMismatch,
    RefusePartialPermissionSchema(PermissionColumnGroup),
    RefusePermissionLedgerMismatch(PermissionColumnGroup),
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
    if facts.repair_migration_applied {
        // The drop is a single statement with no data component, so it is all-or-nothing: either the
        // column is still there and the migration is pending, or the column is gone and the
        // migration is recorded.
        if facts.access_all_column_exists == facts.access_all_drop_migration_applied {
            return if facts.access_all_drop_migration_applied {
                CustomRolePreflightDecision::RefuseAccessAllDropLedgerMismatch
            } else if can_complete_mysql_partial_migration {
                // Only reachable on MySQL/MariaDB, and the schema is already in its intended final
                // state -- just record the migration instead of stopping the operator.
                CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop
            } else {
                CustomRolePreflightDecision::RefuseInterruptedAccessAllDrop
            };
        }
    } else {
        // Once access_all has been dropped, its former value and the provenance of 0/1/1
        // collection permissions can no longer be reconstructed. Never guess at either.
        if facts.access_all_drop_migration_applied {
            return CustomRolePreflightDecision::RefuseAlreadyDropped;
        }
        if !facts.access_all_column_exists {
            return CustomRolePreflightDecision::RefuseMissingAccessAll;
        }

        if facts.ambiguous_direct_permission_count != 0 && !facts.same_run_0716_marker {
            return CustomRolePreflightDecision::RefuseAmbiguousDirectPermissions;
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
            (3, false) if group == PermissionColumnGroup::Collection && can_complete_mysql_partial_migration => {
                return CustomRolePreflightDecision::CompleteMysqlCollectionMigration;
            }
            (_, true) => return CustomRolePreflightDecision::RefusePermissionLedgerMismatch(group),
            _ => return CustomRolePreflightDecision::RefusePartialPermissionSchema(group),
        }
    }

    CustomRolePreflightDecision::Proceed
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
        CustomRolePreflightDecision::RefuseAmbiguousDirectPermissions => format!(
            "Found {} membership(s) with an ambiguous 0/1/1 collection-permission pattern. It is \
             not possible to distinguish an older group-derived backfill from an intentional \
             direct Edit+Delete assignment.",
            facts.ambiguous_direct_permission_count
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
        CustomRolePreflightDecision::Proceed
        | CustomRolePreflightDecision::CompleteMysqlCollectionMigration
        | CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop => {
            unreachable!("successful preflight decisions do not produce errors")
        }
    };
    let recovery = match decision {
        CustomRolePreflightDecision::RefuseAmbiguousDirectPermissions => AMBIGUOUS_DIRECT_PERMISSIONS_RECOVERY_SQL,
        CustomRolePreflightDecision::RefusePartialPermissionSchema(_)
        | CustomRolePreflightDecision::RefusePermissionLedgerMismatch(_) => PARTIAL_PERMISSION_COLUMNS_RECOVERY,
        CustomRolePreflightDecision::RefuseAlreadyDropped => ALREADY_DROPPED_RECOVERY,
        CustomRolePreflightDecision::RefuseInterruptedAccessAllDrop => INTERRUPTED_ACCESS_ALL_DROP_RECOVERY,
        CustomRolePreflightDecision::RefuseAccessAllDropLedgerMismatch => ACCESS_ALL_DROP_MISMATCH_RECOVERY,
        _ => "",
    };

    std::io::Error::other(format!(
        "Custom-role migration preflight stopped startup: {detail} Back up the database and resolve \
         the legacy membership state manually before restarting.{recovery}"
    ))
    .into()
}

#[cfg(any(mysql, test))]
fn mysql_partial_unexpected_values_query(allow_same_run_group_derived: bool) -> String {
    let same_run_group_derived = if allow_same_run_group_derived {
        " OR \
         (atype = 4 \
          AND access_all = FALSE \
          AND create_new_collections = FALSE \
          AND edit_any_collection = TRUE \
          AND delete_any_collection = TRUE \
          AND EXISTS ( \
              SELECT 1 \
              FROM groups_users AS gu \
              INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid \
              WHERE gu.users_organizations_uuid = users_organizations.uuid \
                AND g.organizations_uuid = users_organizations.org_uuid \
                AND g.access_all = TRUE \
          ))"
    } else {
        ""
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
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        let ambiguous_direct_permission_count = if access_all_column_exists && collection_permission_columns == 3 {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype IN (3, 4) \
                       AND access_all = FALSE \
                       AND create_new_collections = FALSE \
                       AND edit_any_collection = TRUE \
                       AND delete_any_collection = TRUE",
            )?
        } else {
            0
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
            ambiguous_direct_permission_count,
            same_run_0716_marker,
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
            // exact, same-run group-derived 0/1/1 row to 0/0/0; that authority remains dynamically
            // derived from the group, and the separate 07-23 repair then reconciles the role.
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
        diesel::sql_query(format!(
            "INSERT INTO __diesel_schema_migrations (version) VALUES ('{}')",
            super::DROP_MEMBERSHIP_ACCESS_ALL_MIGRATION
        ))
        .execute(connection)?;

        Ok(())
    }

    fn preflight(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
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
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        let ambiguous_direct_permission_count = if access_all_column_exists && collection_permission_columns == 3 {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype IN (3, 4) \
                       AND access_all = FALSE \
                       AND create_new_collections = FALSE \
                       AND edit_any_collection = TRUE \
                       AND delete_any_collection = TRUE",
            )?
        } else {
            0
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
            ambiguous_direct_permission_count,
            same_run_0716_marker,
        };

        match super::custom_role_preflight_decision(facts, true) {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::CompleteMysqlCollectionMigration => {
                complete_partial_collection_migration(connection, same_run_0716_marker)
            }
            super::CustomRolePreflightDecision::CompleteInterruptedAccessAllDrop => {
                complete_interrupted_access_all_drop(connection)
            }
            decision => Err(super::custom_role_preflight_error(decision, facts)),
        }
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

    fn table_exists(connection: &mut diesel::pg::PgConnection, table: &str) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.tables \
                 WHERE table_schema = current_schema() AND table_name = '{table}'"
            ),
        )
        .map(|value| value != 0)
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
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'users_organizations' \
               AND column_name = 'access_all'",
        )? != 0;
        let permission_columns = |connection: &mut diesel::pg::PgConnection,
                                  group: super::PermissionColumnGroup|
         -> Result<i64, diesel::result::Error> {
            count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM information_schema.columns                      WHERE table_schema = current_schema()                        AND table_name = 'users_organizations'                        AND column_name IN ({})",
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
        let same_run_0716_marker = same_run_marker_table_exists
            && count(
                connection,
                format!("SELECT COUNT(*) AS count FROM {} WHERE marker = 1", super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE),
            )? != 0;

        let ambiguous_direct_permission_count = if access_all_column_exists && collection_permission_columns == 3 {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                     WHERE atype IN (3, 4) \
                       AND access_all = FALSE \
                       AND create_new_collections = FALSE \
                       AND edit_any_collection = TRUE \
                       AND delete_any_collection = TRUE",
            )?
        } else {
            0
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
            ambiguous_direct_permission_count,
            same_run_0716_marker,
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

#[cfg(test)]
mod custom_role_migration_preflight_tests {
    use std::error::Error as _;

    use super::{
        CustomRoleMigrationFacts as Facts, CustomRolePreflightDecision as Decision, custom_role_preflight_decision,
        custom_role_preflight_error, mysql_partial_unexpected_values_query,
    };

    fn pending_repair() -> Facts {
        Facts {
            memberships_table_exists: true,
            migration_table_exists: true,
            access_all_column_exists: true,
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
            ambiguous_direct_permission_count: 0,
            same_run_0716_marker: false,
        }
    }

    #[test]
    fn repair_marker_makes_completed_state_idempotent() {
        assert_eq!(custom_role_preflight_decision(fully_migrated(), false), Decision::Proceed);
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
    fn ambiguous_direct_permissions_error_carries_a_recovery_path() {
        let facts = Facts {
            ambiguous_direct_permission_count: 2,
            ..pending_repair()
        };
        let decision = custom_role_preflight_decision(facts, false);
        assert_eq!(decision, Decision::RefuseAmbiguousDirectPermissions);

        let error = custom_role_preflight_error(decision, facts);
        let message = error.source().expect("preflight error should retain its I/O error source").to_string();
        assert!(message.contains("2 membership(s)"));
        // The operator needs the affected memberships and their possible group source ...
        assert!(message.contains("SELECT uuid, user_uuid, org_uuid, atype, status"));
        assert!(message.contains("WHERE g.access_all = TRUE"));
        // ... plus both decisions, and the note that keeping the grant also grants Create.
        assert!(message.contains("SET edit_any_collection = FALSE,\n    delete_any_collection = FALSE"));
        assert!(message.contains("SET create_new_collections = TRUE"));
        assert!(message.contains("also grants Create-any-collection"));
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

    // REGRESSION: a legacy `User` membership with the historical access_all bit must NOT stop the
    // upgrade. The 2026-07-23 migration materializes that reach as explicit per-collection
    // assignments, so the preflight has nothing left to decide and every other fact stays untouched.
    #[test]
    fn legacy_user_access_all_no_longer_blocks_the_upgrade() {
        assert_eq!(custom_role_preflight_decision(pending_repair(), false), Decision::Proceed);
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    manage_permission_columns: 3,
                    manage_permissions_migration_applied: true,
                    ..pending_repair()
                },
                false,
            ),
            Decision::Proceed
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

    #[test]
    fn group_derived_zero_permissions_are_safe_but_ambiguous_direct_permissions_are_refused() {
        assert_eq!(custom_role_preflight_decision(pending_repair(), false), Decision::Proceed);
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    ..pending_repair()
                },
                false,
            ),
            Decision::Proceed
        );
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    ambiguous_direct_permission_count: 1,
                    ..pending_repair()
                },
                false,
            ),
            Decision::RefuseAmbiguousDirectPermissions
        );
        assert_eq!(
            custom_role_preflight_decision(
                Facts {
                    collection_permission_columns: 3,
                    collection_permissions_migration_applied: true,
                    ambiguous_direct_permission_count: 1,
                    same_run_0716_marker: true,
                    ..pending_repair()
                },
                false,
            ),
            Decision::Proceed
        );
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
    fn historical_mysql_partial_query_does_not_require_the_new_marker_table() {
        let query = mysql_partial_unexpected_values_query(false);
        assert!(!query.contains(super::CUSTOM_ROLE_SAME_RUN_MARKER_TABLE));
        assert!(!query.contains("groups_users"));
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
