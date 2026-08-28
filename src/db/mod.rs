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

/// The single migration this feature adds.
///
/// This section exists because some database states cannot be converted without a decision that
/// belongs to an owner. The migration file refuses them itself as a backstop, but Diesel surfaces
/// only the driver-level duplicate-key error that refusal produces; the preflight evaluates the same
/// predicates first, so the operator gets the question and the way out instead.
const CUSTOM_ROLE_PERMISSIONS_MIGRATION: &str = "20260630120000";

/// The nine permission columns the migration adds.
const CUSTOM_ROLE_PERMISSION_COLUMNS: [&str; 9] = [
    "manage_users",
    "manage_groups",
    "manage_policies",
    "create_new_collections",
    "edit_any_collection",
    "delete_any_collection",
    "access_event_logs",
    "access_import_export",
    "access_reports",
];

/// Every column `users_organizations` has once the migration has run, and nothing else.
///
/// A fingerprint, not a schema definition: a table carrying exactly these eighteen names is the one
/// this migration produces. One column more or fewer and nothing may be inferred about it.
const EXPECTED_MEMBERSHIP_COLUMNS: [&str; 18] = [
    "uuid",
    "user_uuid",
    "org_uuid",
    "akey",
    "status",
    "atype",
    "reset_password_key",
    "external_id",
    "invited_by_email",
    "manage_users",
    "manage_groups",
    "manage_policies",
    "create_new_collections",
    "edit_any_collection",
    "delete_any_collection",
    "access_event_logs",
    "access_import_export",
    "access_reports",
];

/// The one-line reason the Custom-role preflight refused to start, once it has.
///
/// The refusal is deterministic -- it reads schema and ledger state no retry can change -- so
/// `create_db_pool` stops immediately instead of retrying it as a connection problem and repeating
/// the whole recovery procedure each time. It also gives the startup path a plain sentence to print:
/// `Error`'s `Display` renders the JSON API body and its `Debug` escapes newlines.
static CUSTOM_ROLE_PREFLIGHT_REFUSAL: OnceLock<String> = OnceLock::new();

/// Why startup was stopped by the Custom-role preflight, if it was. `None` means the database was
/// simply not reachable (yet), which is worth retrying.
pub fn custom_role_preflight_refusal() -> Option<&'static str> {
    CUSTOM_ROLE_PREFLIGHT_REFUSAL.get().map(String::as_str)
}

/// What to do with a legacy `User + access_all` membership, from `LEGACY_USER_ACCESS_ALL_MIGRATION`.
///
/// The bit is a state official Vaultwarden wrote: until upstream commit `0d16da44` both the invite
/// and the edit endpoint stored a client-supplied `access_all` regardless of the role requested. It
/// has no representation in the new model -- it granted dynamic read/write reach over every
/// collection, present and future, and nothing else -- so which meaning to keep is a decision about
/// that member's access, not something the upgrade can infer.
///
/// Refusing stays the default; the other two let an owner take that decision once for the instance
/// instead of hand-writing SQL per membership.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LegacyUserAccessAllPolicy {
    /// Stop and print the recovery procedure.
    #[default]
    Refuse,
    /// The reach is no longer wanted: clear the bit. Explicit assignments are kept.
    Drop,
    /// The reach has to survive: write it out as explicit assignments, then clear the bit.
    Materialize,
}

impl LegacyUserAccessAllPolicy {
    pub fn from_config(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "refuse" => Some(Self::Refuse),
            "drop" => Some(Self::Drop),
            "materialize" => Some(Self::Materialize),
            _ => None,
        }
    }

    /// An unparsable value cannot reach here -- `validate_config` rejects it at startup -- but
    /// falling back to the refusal keeps the failure mode closed rather than silently permissive.
    fn configured() -> Self {
        Self::from_config(&CONFIG.legacy_user_access_all_migration()).unwrap_or_default()
    }
}

/// The migration's own last statement.
///
/// `RecordCompletedMigration` has to run it too. That path records a migration whose schema changes
/// all committed but whose ledger entry did not, and Diesel then skips the file entirely -- so
/// nothing else would ever execute the statements after the last `ALTER TABLE`. An acknowledgement
/// surviving a repaired upgrade would let a later revert run without fresh consent, which is exactly
/// what the migration drops it to prevent.
const DROP_DOWNGRADE_ACK_SQL: &str = "DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade";

/// Whether this backend commits a migration's schema statements one at a time, so an interrupted
/// upgrade can leave the migration half-applied.
///
/// MySQL and MariaDB do: every `ALTER TABLE` implicitly commits. SQLite and PostgreSQL run the whole
/// migration in one transaction, so a half-applied schema there was not produced by an interruption
/// and nothing may be resumed on the assumption this migration was the only writer.
type InterruptibleSchemaChanges = bool;

/// The migration's Manager -> Custom conversion, replayed when an interrupted upgrade is resumed.
///
/// Character for character the `UPDATE` in
/// `migrations/mysql/2026-06-30-120000_add_custom_role_permissions/up.sql`. Idempotent for the same
/// reason it is safe there -- it matches only `atype = 3` and leaves none behind -- which is what
/// lets one recovery path cover *both* interruption points without telling them apart. It reads
/// `access_all`, so it must run before that column is dropped.
#[cfg(mysql)]
const CUSTOM_ROLE_MANAGER_CONVERSION_SQL: &str = "\
UPDATE users_organizations \
SET create_new_collections = access_all, \
    edit_any_collection = access_all \
        OR EXISTS ( \
            SELECT 1 \
            FROM groups_users AS gu \
            INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid \
            WHERE gu.users_organizations_uuid = users_organizations.uuid \
              AND g.organizations_uuid = users_organizations.org_uuid \
              AND g.access_all = TRUE \
        ), \
    delete_any_collection = access_all \
        OR EXISTS ( \
            SELECT 1 \
            FROM groups_users AS gu \
            INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid \
            WHERE gu.users_organizations_uuid = users_organizations.uuid \
              AND g.organizations_uuid = users_organizations.org_uuid \
              AND g.access_all = TRUE \
        ), \
    atype = 4 \
WHERE atype = 3";

/// The migration's final schema statement.
#[cfg(mysql)]
const DROP_ACCESS_ALL_SQL: &str = "ALTER TABLE users_organizations DROP COLUMN access_all";

/// What an interrupted upgrade still owes, in order -- exactly what the migration file does from its
/// `UPDATE` onwards. The caller records the ledger entry afterwards. Gated on MySQL, the only backend
/// a resume is reachable on.
#[cfg(mysql)]
const CUSTOM_ROLE_RESUME_STATEMENTS: [&str; 3] =
    [CUSTOM_ROLE_MANAGER_CONVERSION_SQL, DROP_ACCESS_ALL_SQL, DROP_DOWNGRADE_ACK_SQL];

/// Relax the direct assignments of an affected membership before the bit goes away.
///
/// `access_all` *overrode* `read_only` and `hide_passwords`: a member carrying it reached every
/// collection read/write with passwords visible even where an explicit row said otherwise. Inserting
/// only the missing rows would therefore quietly downgrade every collection the member was also
/// explicitly assigned to. `manage` is deliberately untouched -- `access_all` never conferred it,
/// and an existing grant is an independent decision.
const LEGACY_USER_ACCESS_ALL_RELAX_SQL: &str = "\
UPDATE users_collections \
SET read_only = FALSE, hide_passwords = FALSE \
WHERE EXISTS ( \
    SELECT 1 \
    FROM users_organizations uo \
    INNER JOIN collections c ON c.org_uuid = uo.org_uuid \
    WHERE uo.user_uuid = users_collections.user_uuid \
      AND c.uuid = users_collections.collection_uuid \
      AND uo.atype = 2 \
      AND uo.access_all = TRUE \
      AND uo.status = 2 \
)";

/// Write the reach out as explicit assignments.
///
/// Confirmed memberships only: a `users_collections` row is not bound to the membership status the
/// way `access_all` was, so materialising an invited, accepted or revoked membership would hand it
/// durable assignments it does not have today. Those only lose the bit.
const LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL: &str = "\
INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage) \
SELECT uo.user_uuid, c.uuid, FALSE, FALSE, FALSE \
FROM users_organizations uo \
INNER JOIN collections c ON c.org_uuid = uo.org_uuid \
WHERE uo.atype = 2 \
  AND uo.access_all = TRUE \
  AND uo.status = 2 \
  AND NOT EXISTS ( \
      SELECT 1 FROM users_collections uc \
      WHERE uc.user_uuid = uo.user_uuid \
        AND uc.collection_uuid = c.uuid \
  )";

/// Clear the bit on every affected membership, whatever its status. Always the last statement: the
/// two above select on it.
const LEGACY_USER_ACCESS_ALL_CLEAR_SQL: &str =
    "UPDATE users_organizations SET access_all = FALSE WHERE atype = 2 AND access_all = TRUE";

const LEGACY_USER_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nThe same decision applies to every affected membership on this instance, so it can also be ",
    "taken once, without any SQL, by setting LEGACY_USER_ACCESS_ALL_MIGRATION before the next start:\n",
    "  drop         clear the bit. Each member keeps the collections they are explicitly assigned\n",
    "               to and loses the organization-wide reach.\n",
    "  materialize  write the reach out as explicit assignments first, then clear the bit. Confirmed\n",
    "               memberships only; the others are treated as 'drop'.\n",
    "Both are applied before the migration touches anything, and the setting is inert afterwards.\n\n",
    "To decide per membership instead, list them:\n",
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
    "access_all overrode read_only and hide_passwords, so the collections the member is *already* ",
    "assigned to have to be relaxed as well -- otherwise they come out of the upgrade with less access ",
    "than they have now. Run both statements, in this order:\n",
    "UPDATE users_collections\n",
    "SET read_only = FALSE, hide_passwords = FALSE\n",
    "WHERE user_uuid = (SELECT user_uuid FROM users_organizations WHERE uuid = '<MEMBERSHIP_UUID>')\n",
    "  AND collection_uuid IN (\n",
    "    SELECT c.uuid FROM collections c\n",
    "    INNER JOIN users_organizations uo ON uo.org_uuid = c.org_uuid\n",
    "    WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  );\n",
    "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)\n",
    "SELECT uo.user_uuid, c.uuid, FALSE, FALSE, FALSE\n",
    "FROM users_organizations uo\n",
    "INNER JOIN collections c ON c.org_uuid = uo.org_uuid\n",
    "WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND NOT EXISTS (\n",
    "    SELECT 1 FROM users_collections uc\n",
    "    WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = c.uuid\n",
    "  );\n\n",
    "If the member genuinely needs organization-wide reach afterwards, give them the Custom role with ",
    "the 'Edit any collection' permission from the web vault once the upgrade has completed. That is ",
    "the supported, visible and revocable equivalent."
);

const AMBIGUOUS_PARTIAL_MIGRATION_RECOVERY: &str = concat!(
    "\n\nSome of the columns this migration adds already exist, so a previous attempt changed the ",
    "table -- but the result is not the schema an interrupted run leaves behind, so how far it got ",
    "cannot be established and finishing it would run the conversion against a table this build does ",
    "not recognise.\n\n",
    "An interruption is resumed automatically, and only on MySQL and MariaDB, where each ALTER TABLE ",
    "commits on its own. It requires all of:\n",
    "  * all nine Custom-role permission columns present and NOT NULL\n",
    "  * users_organizations carrying exactly the eighteen expected columns plus access_all\n",
    "  * a migration ledger that exists and records nothing newer than this migration\n",
    "  * no plain User membership still carrying access_all\n\n",
    "On SQLite and PostgreSQL the whole migration runs inside one transaction, so it cannot stop ",
    "half-way: this schema was produced by something else and is never resumed.\n\n",
    "Restore the backup taken before the schema was changed and start the upgrade again. If the ",
    "database was rolled back with tools/custom_role_rollback/, run that script to completion first -- ",
    "it restores the column set and the ledger together."
);

const MISSING_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nThe upgrade derives every Custom collection permission from that column, so it cannot run ",
    "without it, and neither of the two questions above it can be answered.\n\n",
    "One way to reach this state *is* recoverable and is repaired automatically: on MySQL and ",
    "MariaDB every ALTER TABLE commits on its own, so a process that dies after the migration's ",
    "final DROP COLUMN and before Diesel records the migration leaves a database that is already ",
    "fully converted and only missing its ledger row. That is not this database -- the checks below ",
    "did not all pass, so the schema is not the one the completed migration produces and nothing may ",
    "be assumed about how far it got:\n",
    "  * all nine Custom-role permission columns present and NOT NULL\n",
    "  * users_organizations carrying exactly the eighteen expected columns\n",
    "  * no membership left on the legacy Manager role (atype = 3)\n",
    "  * a migration ledger that exists and records nothing newer than this migration\n\n",
    "If the database was rolled back with tools/custom_role_rollback/, run that script to completion ",
    "-- it restores the column and the ledger together. Otherwise restore the backup taken before the ",
    "schema was changed and start again from there."
);

/// What the preflight reads. All of it comes from the schema and the migration ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
// Each field is an independent observation about the database, not a mode: they are combined by
// `custom_role_preflight_decision` and `custom_role_migration_is_complete`, which is exactly what
// the lint would have them replaced by.
#[allow(clippy::struct_excessive_bools)]
struct CustomRoleMigrationFacts {
    memberships_table_exists: bool,
    /// {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`} is recorded, i.e. this database is already upgraded.
    migration_applied: bool,
    access_all_column_exists: bool,
    legacy_user_access_all_count: i64,
    /// The migration ledger table exists, so a missing entry means "not recorded" rather than
    /// "nowhere to look".
    migration_ledger_exists: bool,
    /// How many of [`CUSTOM_ROLE_PERMISSION_COLUMNS`] exist, and how many of those are NOT NULL.
    permission_columns_present: i64,
    permission_columns_not_null: i64,
    /// Total number of columns on `users_organizations`, and how many of them are names from
    /// [`EXPECTED_MEMBERSHIP_COLUMNS`]. Both have to equal the expected count: the first rules out a
    /// column this build knows nothing about, the second rules out a missing one.
    membership_column_count: i64,
    expected_membership_columns_present: i64,
    /// Memberships still carrying the legacy persisted Manager role.
    legacy_manager_rows: i64,
    /// A migration newer than the Custom-role one is recorded. Diesel applies migrations in order,
    /// so this can only mean the ledger was edited or the binary is older than the database.
    newer_migration_recorded: bool,
}

/// Whether the facts prove that the Custom-role migration ran to completion and only its ledger
/// entry is missing.
///
/// A conjunction rather than "the legacy column is gone": dropping `access_all` is the migration's
/// *last* schema statement, so its absence alone is also what a hand-edited or half-rolled-back
/// database looks like, and recording the migration there would start the server against a schema
/// the code does not match. Each condition rules out one way of arriving here with the column gone:
///
/// * a column dropped by hand fails the permission-column checks;
/// * a partially applied later schema change fails the exact-column-count check;
/// * a half-finished conversion still has `atype = 3` rows;
/// * a tampered ledger fails the newer-migration check.
fn custom_role_migration_is_complete(facts: CustomRoleMigrationFacts) -> bool {
    let counted = |count: i64, expected: usize| usize::try_from(count).is_ok_and(|found| found == expected);

    facts.memberships_table_exists
        && !facts.migration_applied
        && !facts.access_all_column_exists
        && facts.migration_ledger_exists
        && !facts.newer_migration_recorded
        && counted(facts.permission_columns_present, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        && counted(facts.permission_columns_not_null, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        && counted(facts.membership_column_count, EXPECTED_MEMBERSHIP_COLUMNS.len())
        && counted(facts.expected_membership_columns_present, EXPECTED_MEMBERSHIP_COLUMNS.len())
        && facts.legacy_manager_rows == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustomRolePreflightDecision {
    Proceed,
    /// The migration finished but its ledger entry never committed. Record it and continue.
    RecordCompletedMigration,
    /// The migration got as far as adding its columns -- and possibly as far as converting the
    /// legacy Managers -- but not to the end. Finish it, then record it.
    ResumeInterruptedMigration,
    /// Clear the legacy `User + access_all` bit, then continue.
    DropLegacyUserAccessAll,
    /// Write the reach of a confirmed legacy `User + access_all` membership out as explicit
    /// assignments, clear the bit, then continue.
    MaterializeLegacyUserAccessAll,
    RefuseMissingAccessAll,
    RefuseLegacyUserAccessAll,
    /// Some of the migration's columns exist while it is still unrecorded, but the schema is not the
    /// one an interrupted run leaves behind. Nothing may be assumed about how far it got.
    RefuseAmbiguousPartialMigration,
}

/// Whether the facts prove the migration was interrupted after it added its columns, leaving a
/// schema that can be finished rather than restored from a backup.
///
/// An exact fingerprint of the one state an interrupted run produces, not "some of the columns are
/// there": any other shape means something other than this migration changed the table, and resuming
/// would run the conversion against a schema this build does not know.
///
/// `legacy_manager_rows` is deliberately *not* constrained — it is non-zero at the earlier
/// interruption point and zero at the later one, and the conversion is idempotent, so one resume
/// covers both. `legacy_user_access_all_count` must be zero, which the caller establishes first.
fn custom_role_migration_is_resumable(facts: CustomRoleMigrationFacts) -> bool {
    let counted = |count: i64, expected: usize| usize::try_from(count).is_ok_and(|found| found == expected);

    facts.memberships_table_exists
        && !facts.migration_applied
        && facts.access_all_column_exists
        && facts.legacy_user_access_all_count == 0
        && facts.migration_ledger_exists
        && !facts.newer_migration_recorded
        && counted(facts.permission_columns_present, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        && counted(facts.permission_columns_not_null, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        // Exactly the finished table, plus the legacy column the migration has not dropped yet.
        && counted(facts.membership_column_count, EXPECTED_MEMBERSHIP_COLUMNS.len() + 1)
        && counted(facts.expected_membership_columns_present, EXPECTED_MEMBERSHIP_COLUMNS.len())
}

/// The decision to act on once any legacy `User + access_all` rows have been resolved.
///
/// Resolving them changes one fact, so the answer is recomputed: a database that is *both*
/// half-applied and carries such a row must still be resumed, not handed to Diesel.
fn custom_role_decision_after_legacy_resolution(
    facts: CustomRoleMigrationFacts,
    legacy_user_access_all: LegacyUserAccessAllPolicy,
    interruptible_schema_changes: InterruptibleSchemaChanges,
) -> CustomRolePreflightDecision {
    let mut resolved = facts;
    resolved.legacy_user_access_all_count = 0;
    custom_role_preflight_decision(resolved, legacy_user_access_all, interruptible_schema_changes)
}

fn custom_role_preflight_decision(
    facts: CustomRoleMigrationFacts,
    legacy_user_access_all: LegacyUserAccessAllPolicy,
    interruptible_schema_changes: InterruptibleSchemaChanges,
) -> CustomRolePreflightDecision {
    // A fresh installation: Diesel creates the schema from scratch and there is nothing to convert.
    if !facts.memberships_table_exists {
        return CustomRolePreflightDecision::Proceed;
    }

    // Already upgraded. Every question below is about the legacy schema, which no longer exists, and
    // Diesel never runs a recorded migration again.
    if facts.migration_applied {
        return CustomRolePreflightDecision::Proceed;
    }

    // The migration is pending, so the legacy column has to be there -- both questions below read it,
    // and the conversion derives all three collection permissions from it.
    //
    // Unless the migration already ran and only its ledger entry is missing. MySQL and MariaDB
    // commit every ALTER TABLE on their own, so a process killed between the migration's final
    // `DROP COLUMN access_all` and Diesel's ledger insert leaves exactly that: a fully converted
    // database that looks pending. Record the entry instead of sending the operator to a backup.
    if !facts.access_all_column_exists {
        if custom_role_migration_is_complete(facts) {
            return CustomRolePreflightDecision::RecordCompletedMigration;
        }
        return CustomRolePreflightDecision::RefuseMissingAccessAll;
    }

    // A plain User carrying membership `access_all` has no representation in the new model: unlimited
    // reach over every collection, present and future, with no management authority. Materialising it as
    // direct assignments turns a dynamic guarantee into a snapshot and -- since a `users_collections` row
    // is not bound to the membership status -- would hand a revoked or never-confirmed member durable
    // assignments. Refuse, unless the owner has already decided once (`LegacyUserAccessAllPolicy`).
    if facts.legacy_user_access_all_count != 0 {
        return match legacy_user_access_all {
            LegacyUserAccessAllPolicy::Refuse => CustomRolePreflightDecision::RefuseLegacyUserAccessAll,
            LegacyUserAccessAllPolicy::Drop => CustomRolePreflightDecision::DropLegacyUserAccessAll,
            LegacyUserAccessAllPolicy::Materialize => CustomRolePreflightDecision::MaterializeLegacyUserAccessAll,
        };
    }

    // Nothing left to resolve and the legacy column still there. If the migration's own columns are
    // *also* present, a previous run stopped part-way: on MySQL/MariaDB each `ALTER TABLE` commits on
    // its own. Handing the file back to Diesel would re-run the `ADD COLUMN` and abort with a bare
    // duplicate-column error, which is what this branch replaces.
    if facts.permission_columns_present != 0 {
        if interruptible_schema_changes && custom_role_migration_is_resumable(facts) {
            return CustomRolePreflightDecision::ResumeInterruptedMigration;
        }
        return CustomRolePreflightDecision::RefuseAmbiguousPartialMigration;
    }

    // A legacy Manager whose organization-wide management comes from an org-local `access_all` group is
    // deliberately not a question: an ordinary state that the migration maps onto `edit_any_collection` /
    // `delete_any_collection`. Refusing it would block a normal upgrade; see the migration file.
    CustomRolePreflightDecision::Proceed
}

/// The full operator-facing text for a refusal: what was found, and what to do about it.
///
/// Kept separate from the `Error` so it can be logged with `Display` (the only formatting that
/// preserves the newlines the SQL below depends on) and asserted on in tests.
fn custom_role_preflight_report(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> String {
    let detail = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => format!(
            "The membership access_all column is missing while migration \
             {CUSTOM_ROLE_PERMISSIONS_MIGRATION} is still pending."
        ),
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => format!(
            "Found {} membership(s) of the plain User type carrying the legacy access_all bit. That \
             combination has no representation in the Custom role model: it grants dynamic reach over \
             every collection without any management authority.",
            facts.legacy_user_access_all_count
        ),
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => format!(
            "Migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION} is still pending, but {} of its {} \
             permission columns already exist on users_organizations ({} of them NOT NULL) and the \
             table currently has {} columns.",
            facts.permission_columns_present,
            CUSTOM_ROLE_PERMISSION_COLUMNS.len(),
            facts.permission_columns_not_null,
            facts.membership_column_count
        ),
        _ => unreachable!("only a refusal is an error"),
    };

    let recovery = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => MISSING_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => LEGACY_USER_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => AMBIGUOUS_PARTIAL_MIGRATION_RECOVERY,
        _ => "",
    };

    format!("Custom-role migration preflight stopped startup. Nothing has been changed.\n\n{detail}{recovery}")
}

/// `'a', 'b', 'c'` — a literal list for an `IN (...)` predicate. The names are compile-time
/// constants from this file, never request data.
fn sql_name_list(names: &[&str]) -> String {
    names.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ")
}

/// Report a refusal and produce the error that stops startup.
///
/// Printed here through `Display`, and only here: the startup path logs a failed pool with `{e:?}`,
/// whose `Debug` formatting escapes the newlines the recovery SQL depends on, and pool creation is
/// retried. Log it once readably, flag the refusal so the retry loop stops, and let a one-line error
/// travel back.
fn custom_role_preflight_error(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> Error {
    error!("{}", custom_role_preflight_report(decision, facts));

    let detail = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => {
            "the membership access_all column is missing while the Custom-role migration is still pending"
        }
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => {
            "a plain User membership still carries the legacy access_all bit"
        }
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => {
            "the Custom-role migration is partially applied and the schema is not one it can finish"
        }
        _ => unreachable!("only a refusal is an error"),
    };

    let summary = format!(
        "The Custom-role migration preflight refused to start: {detail}. \
         Nothing has been changed; the recovery procedure is printed above."
    );
    // First refusal wins; a second would say the same thing about the same database.
    drop(CUSTOM_ROLE_PREFLIGHT_REFUSAL.set(summary.clone()));

    std::io::Error::other(summary).into()
}

/// Record a migration that finished but whose ledger entry never committed.
///
/// `sql` is the backend's idempotent insert, so a second startup that races or repeats this is a
/// no-op rather than a duplicate-key failure.
/// The statements that resolve the legacy flag, in the order they have to run.
///
/// The last one is always the clear, so its row count is the number of memberships resolved.
fn legacy_user_access_all_statements(decision: CustomRolePreflightDecision) -> &'static [&'static str] {
    match decision {
        CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => &[
            LEGACY_USER_ACCESS_ALL_RELAX_SQL,
            LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL,
            LEGACY_USER_ACCESS_ALL_CLEAR_SQL,
        ],
        CustomRolePreflightDecision::DropLegacyUserAccessAll => &[LEGACY_USER_ACCESS_ALL_CLEAR_SQL],
        _ => &[],
    }
}

fn log_resolved_legacy_user_access_all(decision: CustomRolePreflightDecision, memberships: usize) {
    let action = match decision {
        CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
            "their organization-wide reach was written out as explicit collection assignments \
             (confirmed memberships only) and the flag was cleared"
        }
        CustomRolePreflightDecision::DropLegacyUserAccessAll => {
            "the flag was cleared; each member keeps the collections they are explicitly assigned to"
        }
        _ => unreachable!("no other decision resolves the legacy flag"),
    };
    warn!(
        "LEGACY_USER_ACCESS_ALL_MIGRATION resolved {memberships} plain User membership(s) carrying the \
         legacy access_all flag before migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: {action}. This ran \
         once, on the configured policy; the setting has no effect on an upgraded database."
    );
}

fn log_recorded_completed_migration() {
    warn!(
        "Custom-role migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: the schema is fully converted but the \
         migration was not recorded. This is what an interrupted migration leaves behind on MySQL and \
         MariaDB, where every ALTER TABLE commits on its own. Every completed-schema check passed, so the \
         missing ledger entry has been recorded and startup continues; no data was changed."
    );
}

#[cfg(mysql)]
fn log_resumed_interrupted_migration(converted: usize) {
    warn!(
        "Custom-role migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: its permission columns were already \
         present while the migration was still unrecorded, which is what an interrupted upgrade leaves \
         behind on MySQL and MariaDB, where every ALTER TABLE commits on its own. The schema matched the \
         expected fingerprint exactly, so the migration was finished: {converted} legacy Manager \
         membership(s) converted, the access_all column dropped and the migration recorded. The \
         conversion is the migration's own statement and matches only atype = 3, so a run that had \
         already converted them changed nothing here."
    );
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    /// Diesel runs each SQLite migration inside a transaction, so a failure rolls the whole file
    /// back and no half-applied schema can be left behind.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = false;

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

    /// Read-only, with exactly one exception: the idempotent ledger insert that records a migration
    /// which provably already ran (see `custom_role_migration_is_complete`).
    ///
    /// `pragma_table_xinfo` rather than `table_info`: the latter omits generated columns, so one would
    /// pass the exact-column-count fingerprint unseen.
    fn preflight(connection: &mut diesel::sqlite::SqliteConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
             WHERE name = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({}) AND \"notnull\" = 1",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count =
            count(connection, "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations')")?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

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
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                // Diesel will not run the file, so the migration's own statements after its last
                // schema change have to happen here.
                diesel::sql_query(super::DROP_DOWNGRADE_ACK_SQL).execute(connection)?;
                diesel::sql_query(format!(
                    "INSERT OR IGNORE INTO __diesel_schema_migrations (version, run_on) \
                     VALUES ('{}', CURRENT_TIMESTAMP)",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ))
                .execute(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag changes one fact, so the answer has to be recomputed before the
                // file goes back to Diesel.
                //
                // Data integrity (audit F-2): recomputed *before* the statements run. They commit
                // immediately and cannot be undone -- `materialize` even relaxes `read_only` and
                // `hide_passwords` on existing assignments -- so a database that would be refused
                // afterwards anyway has to be refused now, while the refusal's "Nothing has been
                // changed" is still true.
                match super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES) {
                    super::CustomRolePreflightDecision::Proceed => {}
                    followup => return Err(super::custom_role_preflight_error(followup, facts)),
                }
                let mut resolved = 0;
                for statement in super::legacy_user_access_all_statements(decision) {
                    resolved = diesel::sql_query(*statement).execute(connection)?;
                }
                super::log_resolved_legacy_user_access_all(decision, resolved);
                Ok(())
            }
            // SQLite runs the whole migration inside one transaction, so it cannot stop half-way and
            // `custom_role_preflight_decision` never resumes for it. Fail closed rather than rely on
            // that from a distance.
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => Err(super::custom_role_preflight_error(
                super::CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                facts,
            )),
            decision => Err(super::custom_role_preflight_error(decision, facts)),
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

    /// MySQL and MariaDB commit every `ALTER TABLE` on their own, so a process killed part-way
    /// through a migration leaves it half-applied. This is the only backend an interrupted upgrade
    /// can be resumed on.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = true;

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

    /// Read-only apart from the idempotent ledger insert and the resume below. This is the backend that
    /// produces both states: MySQL and MariaDB commit every ALTER TABLE on their own, so a process killed
    /// part-way through leaves a database that looks pending but is not.
    fn preflight(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
               AND table_name = 'users_organizations' \
               AND column_name = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({}) \
                   AND is_nullable = 'NO'",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'users_organizations'",
        )?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

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
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                // Diesel will not run the file, so the migration's own statements after its last
                // schema change have to happen here.
                diesel::sql_query(super::DROP_DOWNGRADE_ACK_SQL).execute(connection)?;
                record_migration(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => resume_migration(connection),
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag changes one fact, so the answer has to be recomputed: this
                // database may *also* be a half-applied upgrade, which must never be handed back to
                // Diesel -- it would re-run `ALTER TABLE ... ADD COLUMN` and abort.
                //
                // Data integrity (audit F-2): recomputed *before* the statements run. They commit
                // immediately and cannot be undone -- `materialize` even relaxes `read_only` and
                // `hide_passwords` on existing assignments -- so a database that would be refused
                // afterwards anyway has to be refused now, while the refusal's "Nothing has been
                // changed" is still true. Resuming is not a refusal: those statements do run, and the
                // interrupted migration is finished afterwards.
                let followup =
                    super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
                if !matches!(
                    followup,
                    super::CustomRolePreflightDecision::Proceed
                        | super::CustomRolePreflightDecision::ResumeInterruptedMigration
                ) {
                    return Err(super::custom_role_preflight_error(followup, facts));
                }
                let mut resolved = 0;
                for statement in super::legacy_user_access_all_statements(decision) {
                    resolved = diesel::sql_query(*statement).execute(connection)?;
                }
                super::log_resolved_legacy_user_access_all(decision, resolved);
                match followup {
                    super::CustomRolePreflightDecision::ResumeInterruptedMigration => resume_migration(connection),
                    _ => Ok(()),
                }
            }
            decision => Err(super::custom_role_preflight_error(decision, facts)),
        }
    }

    /// Idempotent ledger insert, so a repeated or racing startup is a no-op rather than a
    /// duplicate-key failure.
    fn record_migration(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), diesel::result::Error> {
        diesel::sql_query(format!(
            "INSERT IGNORE INTO __diesel_schema_migrations (version, run_on) \
             VALUES ('{}', CURRENT_TIMESTAMP)",
            super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
        ))
        .execute(connection)
        .map(|_| ())
    }

    /// Finish a migration that stopped between its first `ALTER TABLE` and its last.
    ///
    /// Only reached once `custom_role_migration_is_resumable` has confirmed the schema, so these are the
    /// statements that run has not executed -- or, for the conversion, one it may already have executed,
    /// which matches nothing the second time. Diesel then finds the migration recorded and never opens
    /// the file, so the `ADD COLUMN` that would abort startup is never reached.
    fn resume_migration(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let mut converted = 0;
        for statement in super::CUSTOM_ROLE_RESUME_STATEMENTS {
            let affected = diesel::sql_query(statement).execute(connection)?;
            if statement == super::CUSTOM_ROLE_MANAGER_CONVERSION_SQL {
                converted = affected;
            }
        }
        record_migration(connection)?;
        super::log_resumed_interrupted_migration(converted);
        Ok(())
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

    /// Diesel runs each PostgreSQL migration inside a transaction, and PostgreSQL DDL is
    /// transactional, so a failure rolls the whole file back.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = false;

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
    /// `current_schema()` is where new objects are created, not necessarily where an existing table is
    /// found: with `search_path = decoy, real` and the tables in `real` it answers `decoy`, the lookup
    /// finds nothing, `preflight` returns early on `!memberships_table_exists`, and Diesel then runs the
    /// migration against `real` with both checks silently skipped. `to_regclass` walks the same path the
    /// migration does, so the two cannot disagree about which table they mean. (The migration and
    /// `tools/custom_role_rollback/postgresql.sql` resolve it the same way.)
    fn table_exists(connection: &mut diesel::pg::PgConnection, table: &str) -> Result<bool, diesel::result::Error> {
        count(connection, format!("SELECT COUNT(*) AS count FROM pg_class WHERE oid = to_regclass('{table}')"))
            .map(|value| value != 0)
    }

    /// Read-only, with exactly one exception: the idempotent ledger insert that records a migration
    /// which provably already ran (see `custom_role_migration_is_complete`). PostgreSQL has
    /// transactional DDL, so it never produces that state itself -- the repair is here so a database
    /// restored or copied from a MySQL-side incident is handled identically on every backend.
    fn preflight(connection: &mut diesel::pg::PgConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        // Columns are resolved through the same `to_regclass` lookup as [`table_exists`], so a
        // `search_path` split cannot make the schema and the column check describe two different
        // tables.
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pg_attribute \
             WHERE attrelid = to_regclass('users_organizations') \
               AND attnum > 0 \
               AND NOT attisdropped \
               AND attname = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped \
                   AND attname IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped AND attnotnull \
                   AND attname IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count = count(
            connection,
            "SELECT COUNT(*) AS count FROM pg_attribute \
             WHERE attrelid = to_regclass('users_organizations') \
               AND attnum > 0 AND NOT attisdropped",
        )?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped \
                   AND attname IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

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
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                // Diesel will not run the file, so the migration's own statements after its last
                // schema change have to happen here.
                diesel::sql_query(super::DROP_DOWNGRADE_ACK_SQL).execute(connection)?;
                diesel::sql_query(format!(
                    "INSERT INTO __diesel_schema_migrations (version, run_on) \
                     VALUES ('{}', CURRENT_TIMESTAMP) ON CONFLICT (version) DO NOTHING",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ))
                .execute(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag changes one fact, so the answer has to be recomputed before the
                // file goes back to Diesel.
                //
                // Data integrity (audit F-2): recomputed *before* the statements run. They commit
                // immediately and cannot be undone -- `materialize` even relaxes `read_only` and
                // `hide_passwords` on existing assignments -- so a database that would be refused
                // afterwards anyway has to be refused now, while the refusal's "Nothing has been
                // changed" is still true.
                match super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES) {
                    super::CustomRolePreflightDecision::Proceed => {}
                    followup => return Err(super::custom_role_preflight_error(followup, facts)),
                }
                let mut resolved = 0;
                for statement in super::legacy_user_access_all_statements(decision) {
                    resolved = diesel::sql_query(*statement).execute(connection)?;
                }
                super::log_resolved_legacy_user_access_all(decision, resolved);
                Ok(())
            }
            // PostgreSQL runs the whole migration inside one transaction, so it cannot stop half-way
            // and `custom_role_preflight_decision` never resumes for it. Fail closed rather than rely
            // on that from a distance.
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => Err(super::custom_role_preflight_error(
                super::CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                facts,
            )),
            decision => Err(super::custom_role_preflight_error(decision, facts)),
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

/// Executes the real migration file against a throwaway SQLite database.
///
/// Everything else here tests the *decision* the preflight makes; this tests the SQL it protects.
/// The rules the migration encodes -- authority materialized from what a membership held then, and
/// only from its own organization -- are invisible to a Rust test unless the statements run.
#[cfg(all(test, sqlite))]
mod custom_role_migration_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{
        Connection, RunQueryDsl,
        sql_types::{BigInt, Text},
        sqlite::SqliteConnection,
    };

    const ADD_CUSTOM_ROLE_PERMISSIONS: &str =
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/up.sql");

    /// `users_organizations` exactly as current upstream main leaves it: membership `access_all`, the
    /// retired Manager role, and none of the nine permission columns.
    const LEGACY_SCHEMA: &str = "
        CREATE TABLE users_organizations (
            uuid       TEXT    NOT NULL PRIMARY KEY,
            user_uuid  TEXT    NOT NULL,
            org_uuid   TEXT    NOT NULL,
            access_all BOOLEAN NOT NULL,
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
        CREATE TABLE collections (
            uuid     TEXT NOT NULL PRIMARY KEY,
            org_uuid TEXT NOT NULL
        );
        CREATE TABLE users_collections (
            user_uuid       TEXT    NOT NULL,
            collection_uuid TEXT    NOT NULL,
            read_only       BOOLEAN NOT NULL DEFAULT FALSE,
            hide_passwords  BOOLEAN NOT NULL DEFAULT FALSE,
            manage          BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (user_uuid, collection_uuid)
        );
    ";

    /// One membership per legacy shape the conversion treats differently, in two organizations.
    ///
    /// `m_mgr_foreign` is the tenancy probe: an org-1 Manager carrying a `groups_users` row pointing at
    /// org 2's `accessAll` group. No HTTP path creates that row, which is why the migration's
    /// organization predicate has to be tested rather than assumed.
    const LEGACY_MEMBERSHIPS: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES
            ('g_all',    'org1', TRUE),
            ('g_plain',  'org1', FALSE),
            ('g2_all',   'org2', TRUE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype) VALUES
            ('m_owner',       'u1',  'org1', TRUE,   2,  0),
            ('m_admin',       'u2',  'org1', TRUE,   2,  1),
            ('m_user',        'u3',  'org1', FALSE,  2,  2),
            ('m_mgr_all',     'u4',  'org1', TRUE,   2,  3),
            ('m_mgr_bare',    'u5',  'org1', FALSE,  2,  3),
            ('m_mgr_plain_g', 'u6',  'org1', FALSE,  2,  3),
            ('m_mgr_group',   'u7',  'org1', FALSE,  2,  3),
            ('m_user_group',  'u8',  'org1', FALSE,  2,  2),
            ('m_mgr_invited', 'u9',  'org1', FALSE,  0,  3),
            ('m_mgr_revoked', 'u10', 'org1', FALSE, -1,  3),
            ('m_mgr_foreign', 'u11', 'org1', FALSE,  2,  3),
            ('m2_mgr_group',  'u12', 'org2', FALSE,  2,  3),
            ('m2_user',       'u7',  'org2', FALSE,  2,  2);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all',   'm_mgr_group'),
            ('g_all',   'm_user_group'),
            ('g_all',   'm_mgr_revoked'),
            ('g_plain', 'm_mgr_plain_g'),
            ('g2_all',  'm2_mgr_group'),
            ('g2_all',  'm_mgr_foreign');
    ";

    /// The one state the upgrade refuses by default: a plain User still carrying `access_all`.
    ///
    /// `access_all` overrode `read_only` and `hide_passwords` but never conferred `manage`, so `u20`'s
    /// two existing assignments must be relaxed and its `manage` grant left alone. The row on `c3` is a
    /// different organization's and unbacked by any membership: nothing may touch it. `u21` and `u22` are
    /// revoked and invited, so they must come out with no assignments at all.
    const LEGACY_USER_ACCESS_ALL: &str = "
        INSERT INTO collections (uuid, org_uuid) VALUES
            ('c1', 'org1'), ('c2', 'org1'), ('c4', 'org1'), ('c3', 'org2');
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype) VALUES
            ('m_uaa',     'u20', 'org1', TRUE,  2, 2),
            ('m_uaa_rev', 'u21', 'org1', TRUE, -1, 2),
            ('m_uaa_inv', 'u22', 'org1', TRUE,  0, 2);
        INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage) VALUES
            ('u20', 'c1', TRUE, TRUE,  FALSE),
            ('u20', 'c2', TRUE, FALSE, TRUE),
            ('u20', 'c3', TRUE, FALSE, TRUE);
    ";

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        value: String,
    }

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count).unwrap()
    }

    fn rows(connection: &mut SqliteConnection, query: &str) -> Vec<String> {
        diesel::sql_query(query).load::<Row>(connection).unwrap().into_iter().map(|row| row.value).collect()
    }

    fn connect(memberships: &str) -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        connection.batch_execute("PRAGMA foreign_keys = OFF").unwrap();
        connection.batch_execute(LEGACY_SCHEMA).unwrap();
        connection.batch_execute(memberships).unwrap();
        connection
    }

    /// Applies the migration the way Diesel's harness does: inside a transaction, so a refusal rolls
    /// back the temporary guard tables as well and a retry starts from the same state a restart would.
    fn migrate(connection: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        connection.transaction(|connection| connection.batch_execute(ADD_CUSTOM_ROLE_PERMISSIONS))
    }

    /// Runs what the preflight runs for the configured policy, in the same order.
    fn resolve(connection: &mut SqliteConnection, decision: super::CustomRolePreflightDecision) {
        for statement in super::legacy_user_access_all_statements(decision) {
            diesel::sql_query(*statement).execute(connection).unwrap();
        }
    }

    /// Every collection assignment, as one line each.
    fn assignments(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT user_uuid || ' ' || collection_uuid \
                 || ' ro=' || read_only || ' hide=' || hide_passwords || ' manage=' || manage AS value \
             FROM users_collections ORDER BY user_uuid, collection_uuid",
        )
    }

    /// Resuming replays the migration's own conversion, so it has to land on exactly what the migration
    /// produces and stay there when replayed -- that idempotence is what covers both interruption points.
    /// Run on SQLite because that is the backend with an in-process harness; the `DROP COLUMN` companion
    /// is left out because SQLite before 3.35 cannot run it.
    #[cfg(mysql)]
    #[test]
    fn the_resume_conversion_matches_the_migration_and_is_idempotent() {
        // What the migration produces when it runs to completion.
        let mut finished = connect(LEGACY_MEMBERSHIPS);
        migrate(&mut finished).unwrap();
        let expected = state(&mut finished);

        // The same database, interrupted straight after `ALTER TABLE ... ADD COLUMN`: the nine
        // columns exist at their defaults, nothing is converted, `access_all` is still there.
        let mut interrupted = connect(LEGACY_MEMBERSHIPS);
        for column in super::CUSTOM_ROLE_PERMISSION_COLUMNS {
            diesel::sql_query(format!(
                "ALTER TABLE users_organizations ADD COLUMN {column} BOOLEAN NOT NULL DEFAULT FALSE"
            ))
            .execute(&mut interrupted)
            .unwrap();
        }
        assert_ne!(state(&mut interrupted), expected, "the interrupted database must not already match");

        let converted = diesel::sql_query(super::CUSTOM_ROLE_MANAGER_CONVERSION_SQL).execute(&mut interrupted).unwrap();
        assert!(converted > 0, "the first replay has legacy Managers to convert");
        assert_eq!(state(&mut interrupted), expected, "resuming must land on the migration's own result");

        // The later interruption point: the conversion already ran, so replaying it matches nothing.
        let replayed = diesel::sql_query(super::CUSTOM_ROLE_MANAGER_CONVERSION_SQL).execute(&mut interrupted).unwrap();
        assert_eq!(replayed, 0, "the conversion must match nothing the second time");
        assert_eq!(state(&mut interrupted), expected, "replaying the conversion must change nothing");
    }

    /// Every membership's role plus the six permissions the conversion can set, as one line each.
    fn state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype \
                 || ' ' || create_new_collections || edit_any_collection || delete_any_collection \
                 || ' ' || manage_users || manage_groups || manage_policies \
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

    fn table_exists(connection: &mut SqliteConnection, table: &str) -> bool {
        count(
            connection,
            &format!("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
        ) != 0
    }

    /// The whole conversion, in one comparison. Written out per membership on purpose: every line is
    /// a rule, and a regression in any of them is a silent authorization change.
    #[test]
    fn the_conversion_maps_every_legacy_shape_exactly_once() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        migrate(&mut connection).unwrap();

        assert_eq!(
            state(&mut connection),
            [
                // The second organization is converted on its own terms...
                "m2_mgr_group atype=4 011 000000",
                // ...and the same *user* holding a plain User membership there gains nothing from
                // being a Manager in the first organization.
                "m2_user atype=2 000 000000",
                // Admin keeps its role; the new model grants it everything implicitly, so no
                // permission column is set.
                "m_admin atype=1 000 000000",
                // Membership access_all was the "Manage all collections" checkbox: all three.
                "m_mgr_all atype=4 111 000000",
                // Manager with nothing: Custom with nothing.
                "m_mgr_bare atype=4 000 000000",
                // A groups_users row pointing at another organization's accessAll group grants
                // nothing -- the migration requires the group to belong to the membership's own org.
                "m_mgr_foreign atype=4 000 000000",
                // Group-derived authority: edit and delete, never create.
                "m_mgr_group atype=4 011 000000",
                // Invited is converted like any other membership.
                "m_mgr_invited atype=4 000 000000",
                // A group without accessAll conveys nothing.
                "m_mgr_plain_g atype=4 000 000000",
                // Revoked is converted like any other membership: status is not part of the rule.
                "m_mgr_revoked atype=4 011 000000",
                "m_owner atype=0 000 000000",
                // A plain User is never converted, not even inside an accessAll group.
                "m_user atype=2 000 000000",
                "m_user_group atype=2 000 000000",
            ]
        );
    }

    /// The nine columns exist, `access_all` does not, and nothing else about the table changed.
    #[test]
    fn the_rebuilt_table_has_the_final_shape() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        migrate(&mut connection).unwrap();

        assert_eq!(
            rows(&mut connection, "SELECT name AS value FROM pragma_table_xinfo('users_organizations')"),
            [
                "uuid",
                "user_uuid",
                "org_uuid",
                "akey",
                "status",
                "atype",
                "reset_password_key",
                "external_id",
                "invited_by_email",
                "manage_users",
                "manage_groups",
                "manage_policies",
                "create_new_collections",
                "edit_any_collection",
                "delete_any_collection",
                "access_event_logs",
                "access_import_export",
                "access_reports",
            ]
        );
        // The primary key and the UNIQUE pair, and nothing else: the rollback script checks for
        // exactly these two and would refuse a database the rebuild had changed.
        assert_eq!(count(&mut connection, "SELECT COUNT(*) AS count FROM pragma_index_list('users_organizations')"), 2);
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM users_organizations WHERE uuid = 'm_owner' AND user_uuid = 'u1'"
            ),
            1
        );
    }

    /// The one shape the upgrade refuses outright, checked in the SQL rather than only in the Rust
    /// preflight: `diesel migration run` and a bare `MigrationHarness` never consult the preflight,
    /// and the column that carries the reach is gone a few statements later.
    #[test]
    fn a_plain_user_carrying_access_all_is_refused_and_nothing_changes() {
        let memberships = "
            INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                ('m_user_all', 'u1', 'org1', TRUE, 2);
        ";
        let mut connection = connect(memberships);
        let before = legacy_state(&mut connection);

        assert!(migrate(&mut connection).is_err());

        assert_eq!(legacy_state(&mut connection), before);
        assert!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') WHERE name = 'access_all'"
            ) == 1,
            "the refusal must leave the legacy column in place"
        );
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
                 WHERE name IN ('manage_users', 'create_new_collections', 'access_reports')"
            ),
            0,
            "the refusal must not leave a half-applied schema behind"
        );
    }

    /// The whole point of this revision: a legacy Manager whose organization-wide collection
    /// management comes from an organization-local `access_all` group is an ordinary, valid
    /// current-main state. It must migrate straight through -- no acknowledgement table, no failed
    /// first startup -- and land on edit + delete without collection creation.
    #[test]
    fn group_derived_authority_migrates_without_any_acknowledgement() {
        let memberships = "
            INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org1', TRUE);
            INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                ('m_mgr_group', 'u1', 'org1', FALSE, 3);
            INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm_mgr_group');
        ";
        let mut connection = connect(memberships);

        migrate(&mut connection).expect("a valid current-main database must migrate on the first try");

        assert_eq!(state(&mut connection), ["m_mgr_group atype=4 011 000000"]);
        // The group and its flag are what they were: only the membership row changed.
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM \"groups\" WHERE uuid = 'g_all' AND access_all = TRUE"
            ),
            1
        );
        assert_eq!(count(&mut connection, "SELECT COUNT(*) AS count FROM groups_users WHERE groups_uuid = 'g_all'"), 1);
    }

    /// Nothing about the upgrade is conditional on operator state any more, so running it twice from
    /// the same legacy database has to produce the same row both times.
    /// LEGACY_USER_ACCESS_ALL_MIGRATION=materialize: the reach becomes explicit assignments that
    /// reproduce it exactly, and the upgrade then runs.
    #[test]
    fn materializing_the_legacy_flag_reproduces_the_reach_and_unblocks_the_upgrade() {
        let mut connection = connect(LEGACY_USER_ACCESS_ALL);
        assert!(migrate(&mut connection).is_err(), "the guard must refuse this database untouched");

        let mut connection = connect(LEGACY_USER_ACCESS_ALL);
        resolve(&mut connection, super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll);

        assert_eq!(
            assignments(&mut connection),
            [
                // relaxed: access_all overrode read_only and hide_passwords ...
                "u20 c1 ro=0 hide=0 manage=0",
                // ... but never conferred manage, so an explicit grant survives
                "u20 c2 ro=0 hide=0 manage=1",
                // a row whose collection belongs to another organization is not this membership\'s
                "u20 c3 ro=1 hide=0 manage=1",
                // the third collection of the organization, written out
                "u20 c4 ro=0 hide=0 manage=0",
            ],
            "a revoked or invited membership must not receive any assignment"
        );
        assert_eq!(
            count(&mut connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE access_all = TRUE"),
            0
        );

        migrate(&mut connection).expect("the upgrade runs once the flag is resolved");
        assert!(!table_exists(&mut connection, "users_organizations_new"));
    }

    /// LEGACY_USER_ACCESS_ALL_MIGRATION=drop: only the flag goes; explicit assignments are kept
    /// exactly as they are, including their restrictions.
    #[test]
    fn dropping_the_legacy_flag_keeps_every_explicit_assignment_untouched() {
        let mut connection = connect(LEGACY_USER_ACCESS_ALL);
        let before = assignments(&mut connection);
        resolve(&mut connection, super::CustomRolePreflightDecision::DropLegacyUserAccessAll);

        assert_eq!(assignments(&mut connection), before, "drop must not write a single assignment");
        assert_eq!(
            count(&mut connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE access_all = TRUE"),
            0
        );

        migrate(&mut connection).expect("the upgrade runs once the flag is resolved");
        assert_eq!(count(&mut connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 2"), 3);
    }

    #[test]
    fn the_conversion_is_deterministic() {
        let first = {
            let mut connection = connect(LEGACY_MEMBERSHIPS);
            migrate(&mut connection).unwrap();
            state(&mut connection)
        };
        let second = {
            let mut connection = connect(LEGACY_MEMBERSHIPS);
            migrate(&mut connection).unwrap();
            state(&mut connection)
        };
        assert_eq!(first, second);
    }

    /// A Manager whose own `access_all` bit is set    /// A Manager whose own `access_all` bit is set is not part of the question: that bit is already a
    /// durable membership-level grant, so converting it changes no meaning and must not stop an
    /// upgrade that has nothing else to decide.
    #[test]
    fn a_manager_with_its_own_access_all_bit_is_not_asked_about() {
        let memberships = "
            INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org1', TRUE);
            INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                ('m_mgr_both', 'u1', 'org1', TRUE, 3);
            INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm_mgr_both');
        ";
        let mut connection = connect(memberships);

        migrate(&mut connection).unwrap();

        assert_eq!(state(&mut connection), ["m_mgr_both atype=4 111 000000"]);
    }

    /// A leftover downgrade acknowledgement is cleared by the upgrade, so consent from an earlier
    /// revert is never inherited by a later one.
    #[test]
    fn a_leftover_downgrade_acknowledgement_is_cleared() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        connection
            .batch_execute("CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY)")
            .unwrap();

        migrate(&mut connection).unwrap();

        assert!(!table_exists(&mut connection, "__vw_allow_custom_role_downgrade"));
    }

    /// The upgrade must not depend on, or leave behind, any bookkeeping table of its own.
    #[test]
    fn the_upgrade_creates_no_bookkeeping_table() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        migrate(&mut connection).unwrap();

        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name LIKE '__vw_%'"
            ),
            0
        );
    }

    /// Every shape a valid current-main database can hold has to migrate on the first try. Only the
    /// one legacy state that cannot be represented at all may abort -- and it is the last case here.
    #[test]
    fn every_valid_current_main_shape_migrates_on_the_first_try() {
        let cases: [(&str, &str, bool); 7] = [
            (
                "Manager, nothing else",
                "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) \
              VALUES ('m', 'u', 'org1', FALSE, 3);",
                true,
            ),
            (
                "Manager in a group without accessAll",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', FALSE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
                true,
            ),
            (
                "Manager in an accessAll group",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
                true,
            ),
            (
                "Manager with membership access_all as well",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', TRUE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
                true,
            ),
            (
                "plain User in an accessAll group",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 2);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
                true,
            ),
            (
                "Manager in another organization's accessAll group",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org2', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
                true,
            ),
            (
                "plain User carrying membership access_all",
                "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) \
              VALUES ('m', 'u', 'org1', TRUE, 2);",
                false,
            ),
        ];

        for (name, memberships, should_migrate) in cases {
            let mut connection = connect(memberships);
            assert_eq!(migrate(&mut connection).is_ok(), should_migrate, "unexpected outcome for: {name}");
        }
    }
}

/// Runs the real migration, then `tools/custom_role_rollback/sqlite.sql`}

/// Runs the real migration, then `tools/custom_role_rollback/sqlite.sql`, then the migration again --
/// against a throwaway SQLite database, with the real files on both legs.
///
/// The claim the rollback tooling rests on: downgrade then upgrade again has to arrive at the same
/// permissions, or the escape hatch quietly rewrites authorization.
#[cfg(all(test, sqlite))]
mod custom_role_rollback_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, sql_types::Text, sqlite::SqliteConnection};

    const MIGRATION: &str =
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/up.sql");
    const REVERT: &str = include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/down.sql");
    const ROLLBACK: &str = include_str!("../../tools/custom_role_rollback/sqlite.sql");

    const VERSION: &str = "20260630120000";

    const DOWNGRADE_ACK: &str =
        "CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY)";
    const ALLOWLIST: &str =
        "CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY)";

    /// `users_organizations` exactly as current upstream main leaves it -- the rollback script checks
    /// for *precisely* eighteen columns and two indexes afterwards, so a reduced fixture would not
    /// exercise the checks it exists for.
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
            ('m_owner',     'u1', 'org', TRUE,   2, 0),
            ('m_admin',     'u2', 'org', TRUE,   2, 1),
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

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        rows(connection, &format!("SELECT ({query}) || '' AS value"))[0].parse().unwrap()
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

    /// Applies the migration, recording its version the way Diesel would.
    fn upgrade(connection: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        connection.batch_execute(MIGRATION)?;
        connection.batch_execute(&format!("INSERT INTO __diesel_schema_migrations (version) VALUES ('{VERSION}')"))
    }

    /// `.bail on` is a sqlite3 shell command, not SQL. Dropping it is safe here -- a failing statement
    /// fails the whole `batch_execute` anyway -- but the assertion keeps the test honest if another
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

    /// The whole point of the tooling: upgrade, roll back, upgrade again, and land on the same
    /// permissions. The allowlist is what makes it converge -- it names exactly the memberships that
    /// were Managers, which is what the second upgrade then reads.
    #[test]
    fn upgrade_rollback_and_upgrade_again_converge() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let after_first_upgrade = permission_state(&mut connection);

        connection.batch_execute(ALLOWLIST).unwrap();
        connection
            .batch_execute(
                "INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES \
                 ('m_mgr_bare'), ('m_mgr_all'), ('m_mgr_group'), ('m_mgr_gone')",
            )
            .unwrap();
        connection.batch_execute(&rollback_sql()).unwrap();

        assert_eq!(
            legacy_state(&mut connection),
            [
                "m_admin atype=1 access_all=1",
                "m_mgr_all atype=3 access_all=1",
                "m_mgr_bare atype=3 access_all=0",
                // Group-derived authority came back as 0/1/1, which is not all three, so the legacy
                // "manage all collections" bit stays off -- the old binary derives the same authority
                // from `groups.access_all` again anyway.
                "m_mgr_gone atype=3 access_all=0",
                "m_mgr_group atype=3 access_all=0",
                "m_owner atype=0 access_all=1",
                "m_user atype=2 access_all=0",
            ]
        );
        assert_eq!(count(&mut connection, "SELECT COUNT(*) FROM __diesel_schema_migrations"), 1);

        upgrade(&mut connection).unwrap();
        assert_eq!(permission_state(&mut connection), after_first_upgrade, "the round trip must converge");
    }

    /// The role mapping is a decision, not a conversion, so the script refuses to make it up.
    #[test]
    fn the_rollback_refuses_without_an_allowlist_and_changes_nothing() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(&rollback_sql()).is_err());

        assert_eq!(permission_state(&mut connection), before);
        assert_eq!(count(&mut connection, "SELECT COUNT(*) FROM __diesel_schema_migrations"), 2);
    }

    /// A migration this script has never seen may have changed anything, including the table it
    /// rebuilds from a fixed column list.
    #[test]
    fn the_rollback_refuses_a_ledger_from_the_future() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        connection.batch_execute(ALLOWLIST).unwrap();
        connection.batch_execute("INSERT INTO __diesel_schema_migrations (version) VALUES ('20270101000000')").unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(&rollback_sql()).is_err());
        assert_eq!(permission_state(&mut connection), before);
    }

    /// The Diesel alternative the README documents, end to end. Both decisions are required, and both
    /// are consumed by the revert they authorize.
    #[test]
    fn the_diesel_revert_runs_with_both_acknowledgements() {
        let mut connection = connect();
        let before = legacy_state(&mut connection);
        upgrade(&mut connection).unwrap();

        connection.batch_execute(DOWNGRADE_ACK).unwrap();
        connection.batch_execute(ALLOWLIST).unwrap();
        connection
            .batch_execute(
                "INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES \
                 ('m_mgr_bare'), ('m_mgr_all'), ('m_mgr_group'), ('m_mgr_gone')",
            )
            .unwrap();
        connection.batch_execute(REVERT).unwrap();

        // The fixture's Owner and Admin already carry the bit, which is what current main writes for
        // them, so this database round-trips byte-identically. (A database where an Owner somehow had
        // it cleared would come back with it set: the upgrade dropped the column precisely because
        // their role already implies it, so the original value is gone.)
        assert_eq!(legacy_state(&mut connection), before);
        assert!(
            count(
                &mut connection,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
                 AND name IN ('__vw_allow_custom_role_downgrade', '__vw_rollback_manager_allowlist')"
            ) == 0,
            "both decisions authorized exactly this downgrade"
        );
    }

    /// Without the acknowledgement the revert stops before its first mutation.
    #[test]
    fn the_revert_stops_at_the_guard_and_mutates_nothing() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(REVERT).is_err());
        assert_eq!(permission_state(&mut connection), before);

        // The acknowledgement alone is not enough either: the role mapping is a separate decision.
        connection.batch_execute(DOWNGRADE_ACK).unwrap();
        assert!(connection.batch_execute(REVERT).is_err());
        assert_eq!(permission_state(&mut connection), before);
    }
}

#[cfg(test)]
mod custom_role_migration_preflight_tests {
    use super::{
        CUSTOM_ROLE_PERMISSION_COLUMNS, CustomRoleMigrationFacts, CustomRolePreflightDecision,
        EXPECTED_MEMBERSHIP_COLUMNS, LEGACY_USER_ACCESS_ALL_CLEAR_SQL, LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL,
        LEGACY_USER_ACCESS_ALL_RELAX_SQL, LegacyUserAccessAllPolicy, custom_role_decision_after_legacy_resolution,
        custom_role_preflight_decision, custom_role_preflight_report, legacy_user_access_all_statements,
    };

    /// The operator-facing refusal text.
    fn message(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> String {
        custom_role_preflight_report(decision, facts)
    }

    /// Refusing is the default policy; the tests that care about the other two pass them explicitly.
    /// MySQL/MariaDB is the backend an interrupted upgrade can be resumed on, so it is the default
    /// here too; `decide_atomic` covers SQLite and PostgreSQL.
    fn decide(facts: CustomRoleMigrationFacts) -> CustomRolePreflightDecision {
        custom_role_preflight_decision(facts, LegacyUserAccessAllPolicy::Refuse, true)
    }

    /// The same question on a backend that runs the whole migration in one transaction.
    fn decide_atomic(facts: CustomRoleMigrationFacts) -> CustomRolePreflightDecision {
        custom_role_preflight_decision(facts, LegacyUserAccessAllPolicy::Refuse, false)
    }

    /// A database that has not been upgraded yet and has nothing to decide.
    fn ready() -> CustomRoleMigrationFacts {
        CustomRoleMigrationFacts {
            memberships_table_exists: true,
            migration_applied: false,
            access_all_column_exists: true,
            legacy_user_access_all_count: 0,
            migration_ledger_exists: true,
            // The legacy schema: no permission columns yet, `access_all` instead of the nine.
            permission_columns_present: 0,
            permission_columns_not_null: 0,
            membership_column_count: 10,
            expected_membership_columns_present: 9,
            legacy_manager_rows: 0,
            newer_migration_recorded: false,
        }
    }

    /// A database on which the migration ran to completion but whose ledger entry never committed --
    /// what an interrupted migration leaves behind on MySQL and MariaDB.
    fn completed_but_unrecorded() -> CustomRoleMigrationFacts {
        CustomRoleMigrationFacts {
            memberships_table_exists: true,
            migration_applied: false,
            access_all_column_exists: false,
            legacy_user_access_all_count: 0,
            migration_ledger_exists: true,
            permission_columns_present: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            permission_columns_not_null: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            membership_column_count: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap(),
            expected_membership_columns_present: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap(),
            legacy_manager_rows: 0,
            newer_migration_recorded: false,
        }
    }

    /// What an interrupted MySQL/MariaDB upgrade leaves behind: the nine permission columns are
    /// there, `access_all` has not been dropped yet, and the ledger entry never committed.
    fn interrupted() -> CustomRoleMigrationFacts {
        CustomRoleMigrationFacts {
            permission_columns_present: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            permission_columns_not_null: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            // the finished table plus the legacy column that still has to go
            membership_column_count: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len() + 1).unwrap(),
            expected_membership_columns_present: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap(),
            ..ready()
        }
    }

    /// Audit M-2: the state that used to reach Diesel and abort with a bare duplicate-column error.
    #[test]
    fn an_interrupted_migration_is_resumed_instead_of_reaching_diesel() {
        assert_eq!(decide(interrupted()), CustomRolePreflightDecision::ResumeInterruptedMigration);
    }

    /// SQLite and PostgreSQL run the whole migration in one transaction, so a half-applied schema
    /// there was not produced by an interruption and must never be finished on that assumption.
    #[test]
    fn a_transactional_backend_never_resumes() {
        assert_eq!(decide_atomic(interrupted()), CustomRolePreflightDecision::RefuseAmbiguousPartialMigration);
    }

    /// Every single deviation from the expected schema falls back to the controlled refusal.
    #[test]
    fn only_the_exact_interrupted_fingerprint_is_resumed() {
        let mut partial_columns = interrupted();
        partial_columns.permission_columns_present = 4;
        let mut nullable_column = interrupted();
        nullable_column.permission_columns_not_null -= 1;
        let mut extra_column = interrupted();
        extra_column.membership_column_count += 1;
        let mut renamed_column = interrupted();
        renamed_column.expected_membership_columns_present -= 1;
        let mut tampered_ledger = interrupted();
        tampered_ledger.newer_migration_recorded = true;
        let mut no_ledger = interrupted();
        no_ledger.migration_ledger_exists = false;

        for (what, facts) in [
            ("only some permission columns", partial_columns),
            ("a nullable permission column", nullable_column),
            ("an unknown extra column", extra_column),
            ("a missing expected column", renamed_column),
            ("a newer migration recorded", tampered_ledger),
            ("no migration ledger", no_ledger),
        ] {
            assert_eq!(decide(facts), CustomRolePreflightDecision::RefuseAmbiguousPartialMigration, "{what}");
        }
    }

    /// An untouched database still has none of the columns, so it is never mistaken for an
    /// interrupted one on either kind of backend.
    #[test]
    fn an_untouched_pending_database_is_not_mistaken_for_an_interrupted_one() {
        assert_eq!(decide(ready()), CustomRolePreflightDecision::Proceed);
        assert_eq!(decide_atomic(ready()), CustomRolePreflightDecision::Proceed);
    }

    /// A completed-but-unrecorded database keeps its own answer: `access_all` is already gone there,
    /// so it is recorded rather than resumed.
    #[test]
    fn a_completed_migration_is_recorded_not_resumed() {
        assert_eq!(decide(completed_but_unrecorded()), CustomRolePreflightDecision::RecordCompletedMigration);
    }

    /// The legacy `User + access_all` question still comes first on an interrupted database — and
    /// once it is resolved the resume must still happen, rather than the file going back to Diesel.
    #[test]
    fn the_legacy_flag_is_answered_before_an_interrupted_migration_is_resumed() {
        let mut facts = interrupted();
        facts.legacy_user_access_all_count = 2;

        assert_eq!(decide(facts), CustomRolePreflightDecision::RefuseLegacyUserAccessAll);
        for (policy, expected) in [
            (LegacyUserAccessAllPolicy::Drop, CustomRolePreflightDecision::DropLegacyUserAccessAll),
            (LegacyUserAccessAllPolicy::Materialize, CustomRolePreflightDecision::MaterializeLegacyUserAccessAll),
        ] {
            assert_eq!(custom_role_preflight_decision(facts, policy, true), expected, "{policy:?}");
            assert_eq!(
                custom_role_decision_after_legacy_resolution(facts, policy, true),
                CustomRolePreflightDecision::ResumeInterruptedMigration,
                "{policy:?} must still finish the interrupted migration"
            );
        }
    }

    /// Audit F-2. Resolving the legacy flag writes -- and `materialize` also relaxes `read_only` and
    /// `hide_passwords` on assignments that already exist. Those statements commit immediately, so
    /// the preflight asks what the *resolved* database would answer before running any of them: a
    /// schema no backend can finish has to be refused while "Nothing has been changed" is still true.
    ///
    /// The two cases that must not be confused: on a backend whose schema changes are interruptible
    /// the exact fingerprint still resumes (the statements do run), while every other partial schema,
    /// and every partial schema at all on a transactional backend, refuses without writing.
    #[test]
    fn a_partial_schema_is_refused_before_the_legacy_flag_is_resolved() {
        let resolving = [LegacyUserAccessAllPolicy::Drop, LegacyUserAccessAllPolicy::Materialize];

        let mut half_applied = interrupted();
        half_applied.legacy_user_access_all_count = 3;
        half_applied.permission_columns_present = 4;
        half_applied.permission_columns_not_null = 4;
        for policy in resolving {
            for interruptible in [true, false] {
                assert_eq!(
                    custom_role_decision_after_legacy_resolution(half_applied, policy, interruptible),
                    CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                    "{policy:?} interruptible={interruptible}: a 4-of-9 schema must refuse, not write first"
                );
            }
        }

        let mut fingerprinted = interrupted();
        fingerprinted.legacy_user_access_all_count = 3;
        for policy in resolving {
            assert_eq!(
                custom_role_decision_after_legacy_resolution(fingerprinted, policy, false),
                CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                "{policy:?}: a transactional backend never resumes, so it must refuse before writing"
            );
            assert_eq!(
                custom_role_decision_after_legacy_resolution(fingerprinted, policy, true),
                CustomRolePreflightDecision::ResumeInterruptedMigration,
                "{policy:?}: the exact fingerprint still resumes, and the statements do run"
            );
        }

        // The control: with a schema that is not partial at all, resolving is all there is to do.
        let mut ordinary = ready();
        ordinary.legacy_user_access_all_count = 3;
        for policy in resolving {
            for interruptible in [true, false] {
                assert_eq!(
                    custom_role_decision_after_legacy_resolution(ordinary, policy, interruptible),
                    CustomRolePreflightDecision::Proceed,
                    "{policy:?} interruptible={interruptible}"
                );
            }
        }
    }

    /// The refusal has to say what was found and what to do about it, and must not claim the
    /// database was changed.
    #[test]
    fn the_ambiguous_refusal_reports_the_schema_and_a_way_out() {
        let mut facts = interrupted();
        facts.permission_columns_present = 4;
        let text = message(CustomRolePreflightDecision::RefuseAmbiguousPartialMigration, facts);

        assert!(text.contains("Nothing has been changed"), "{text}");
        assert!(text.contains("4 of its 9 permission columns"), "{text}");
        assert!(text.contains("Restore the backup"), "{text}");
        assert!(text.contains("SQLite and PostgreSQL"), "{text}");
    }

    #[test]
    fn an_empty_database_proceeds() {
        assert_eq!(decide(CustomRoleMigrationFacts::default()), CustomRolePreflightDecision::Proceed);
    }

    #[test]
    fn an_ordinary_upgrade_proceeds() {
        assert_eq!(decide(ready()), CustomRolePreflightDecision::Proceed);
    }

    /// The checks below all read the legacy schema, so an already-upgraded database must not be
    /// asked about them again -- and a re-run of the question would have no data to answer it from.
    #[test]
    fn an_already_upgraded_database_is_not_asked_anything() {
        let facts = CustomRoleMigrationFacts {
            migration_applied: true,
            access_all_column_exists: false,
            ..ready()
        };
        assert_eq!(decide(facts), CustomRolePreflightDecision::Proceed);
    }

    #[test]
    fn a_pending_migration_without_the_legacy_column_is_refused() {
        let facts = CustomRoleMigrationFacts {
            access_all_column_exists: false,
            ..ready()
        };
        assert_eq!(decide(facts), CustomRolePreflightDecision::RefuseMissingAccessAll);
    }

    /// The state an interrupted migration leaves on MySQL/MariaDB: every ALTER TABLE committed on
    /// its own, so the schema is final, but the process died before Diesel recorded the migration.
    /// The database is already correct; only the ledger entry is missing.
    #[test]
    fn a_completed_migration_with_no_ledger_entry_is_recorded_instead_of_refused() {
        assert_eq!(decide(completed_but_unrecorded()), CustomRolePreflightDecision::RecordCompletedMigration);
    }

    /// Every individual condition has to hold. Each mutation below is a different way of arriving at
    /// "the legacy column is gone" without the migration having finished, and each one must fall
    /// back to refusing rather than recording a migration that did not happen.
    #[test]
    fn an_incomplete_schema_is_never_mistaken_for_a_completed_migration() {
        let complete = completed_but_unrecorded();
        let permission_columns = i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap();
        let membership_columns = i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap();

        let broken = [
            (
                "one permission column missing",
                CustomRoleMigrationFacts {
                    permission_columns_present: permission_columns - 1,
                    permission_columns_not_null: permission_columns - 1,
                    membership_column_count: membership_columns - 1,
                    expected_membership_columns_present: membership_columns - 1,
                    ..complete
                },
            ),
            (
                "a permission column is nullable",
                CustomRoleMigrationFacts {
                    permission_columns_not_null: permission_columns - 1,
                    ..complete
                },
            ),
            (
                "an unexpected extra column",
                CustomRoleMigrationFacts {
                    membership_column_count: membership_columns + 1,
                    ..complete
                },
            ),
            (
                "an expected column is missing but the count matches",
                CustomRoleMigrationFacts {
                    expected_membership_columns_present: membership_columns - 1,
                    ..complete
                },
            ),
            (
                "memberships still on the legacy Manager role",
                CustomRoleMigrationFacts {
                    legacy_manager_rows: 1,
                    ..complete
                },
            ),
            (
                "the ledger records something newer",
                CustomRoleMigrationFacts {
                    newer_migration_recorded: true,
                    ..complete
                },
            ),
            (
                "there is no ledger to record into",
                CustomRoleMigrationFacts {
                    migration_ledger_exists: false,
                    ..complete
                },
            ),
        ];

        for (label, facts) in broken {
            assert_eq!(
                decide(facts),
                CustomRolePreflightDecision::RefuseMissingAccessAll,
                "{label} must not be treated as a completed migration"
            );
        }
    }

    /// Audit M-2: the two earlier MySQL/MariaDB interruption points still have `access_all`, so they
    /// never reach the completed-schema check. They used to fall through as an ordinary pending
    /// migration, which handed the file back to Diesel and aborted startup on the duplicate column.
    /// Both are now recognised and finished instead.
    #[test]
    fn both_earlier_interruption_points_are_resumed() {
        let after_add_column = CustomRoleMigrationFacts {
            permission_columns_present: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            permission_columns_not_null: i64::try_from(CUSTOM_ROLE_PERMISSION_COLUMNS.len()).unwrap(),
            membership_column_count: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap() + 1,
            expected_membership_columns_present: i64::try_from(EXPECTED_MEMBERSHIP_COLUMNS.len()).unwrap(),
            legacy_manager_rows: 3,
            ..ready()
        };
        assert_eq!(decide(after_add_column), CustomRolePreflightDecision::ResumeInterruptedMigration);

        let after_update = CustomRoleMigrationFacts {
            legacy_manager_rows: 0,
            ..after_add_column
        };
        assert_eq!(decide(after_update), CustomRolePreflightDecision::ResumeInterruptedMigration);
    }

    /// An already-recorded migration is never re-examined, so the repair cannot fire twice.
    #[test]
    fn recording_the_migration_is_idempotent() {
        let recorded = CustomRoleMigrationFacts {
            migration_applied: true,
            ..completed_but_unrecorded()
        };
        assert_eq!(decide(recorded), CustomRolePreflightDecision::Proceed);
    }

    /// The refusal text used to claim this state could not occur, and sent the operator to a backup.
    #[test]
    fn the_missing_column_recovery_text_no_longer_denies_the_state_can_occur() {
        let message = message(
            CustomRolePreflightDecision::RefuseMissingAccessAll,
            CustomRoleMigrationFacts {
                access_all_column_exists: false,
                ..ready()
            },
        );
        assert!(!message.contains("does not arise from any Vaultwarden version"), "{message}");
        assert!(message.contains("repaired automatically"), "{message}");
    }

    /// The three documented values, and nothing else. An unparsable value never reaches the
    /// preflight -- `validate_config` rejects it at startup -- but it still has to fail closed.
    #[test]
    fn the_legacy_user_access_all_policy_parses_only_the_documented_values() {
        assert_eq!(LegacyUserAccessAllPolicy::from_config("refuse"), Some(LegacyUserAccessAllPolicy::Refuse));
        assert_eq!(LegacyUserAccessAllPolicy::from_config("drop"), Some(LegacyUserAccessAllPolicy::Drop));
        assert_eq!(LegacyUserAccessAllPolicy::from_config("materialize"), Some(LegacyUserAccessAllPolicy::Materialize));
        assert_eq!(
            LegacyUserAccessAllPolicy::from_config("  MATERIALIZE "),
            Some(LegacyUserAccessAllPolicy::Materialize)
        );

        for value in ["", " ", "yes", "true", "1", "keep", "refuse-all", "dropall"] {
            assert_eq!(LegacyUserAccessAllPolicy::from_config(value), None, "{value} must not parse");
        }
        assert_eq!(LegacyUserAccessAllPolicy::default(), LegacyUserAccessAllPolicy::Refuse);
    }

    /// The policy selects what happens to an affected membership, and does nothing at all when
    /// there is none -- a database without the legacy flag must upgrade identically whatever it is
    /// set to.
    #[test]
    fn the_configured_policy_only_decides_what_happens_to_an_affected_membership() {
        let mut affected = ready();
        affected.legacy_user_access_all_count = 2;

        for (policy, expected) in [
            (LegacyUserAccessAllPolicy::Refuse, CustomRolePreflightDecision::RefuseLegacyUserAccessAll),
            (LegacyUserAccessAllPolicy::Drop, CustomRolePreflightDecision::DropLegacyUserAccessAll),
            (LegacyUserAccessAllPolicy::Materialize, CustomRolePreflightDecision::MaterializeLegacyUserAccessAll),
        ] {
            assert_eq!(custom_role_preflight_decision(affected, policy, true), expected, "{policy:?}");
            // nothing to resolve -> the policy is inert
            assert_eq!(
                custom_role_preflight_decision(ready(), policy, true),
                CustomRolePreflightDecision::Proceed,
                "{policy:?} must not change an unaffected database"
            );
        }
    }

    /// A damaged schema still outranks the flag, whatever the policy says: the resolution statements
    /// read `access_all`, so they cannot run once the column is gone.
    #[test]
    fn the_policy_never_overrides_a_refusal_about_the_schema() {
        let mut broken = ready();
        broken.access_all_column_exists = false;
        broken.legacy_user_access_all_count = 3;

        for policy in
            [LegacyUserAccessAllPolicy::Refuse, LegacyUserAccessAllPolicy::Drop, LegacyUserAccessAllPolicy::Materialize]
        {
            assert_eq!(
                custom_role_preflight_decision(broken, policy, true),
                CustomRolePreflightDecision::RefuseMissingAccessAll,
                "{policy:?}"
            );
        }
    }

    /// `materialize` writes, then clears; `drop` only clears. The clear is always last, because the
    /// statements before it select on the flag -- and its row count is what gets logged.
    #[test]
    fn the_resolution_statements_end_with_the_clear() {
        let materialize =
            legacy_user_access_all_statements(CustomRolePreflightDecision::MaterializeLegacyUserAccessAll);
        assert_eq!(materialize.len(), 3);
        assert_eq!(materialize[0], LEGACY_USER_ACCESS_ALL_RELAX_SQL);
        assert_eq!(materialize[1], LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL);
        assert_eq!(materialize[2], LEGACY_USER_ACCESS_ALL_CLEAR_SQL);

        let drop = legacy_user_access_all_statements(CustomRolePreflightDecision::DropLegacyUserAccessAll);
        assert_eq!(drop, [LEGACY_USER_ACCESS_ALL_CLEAR_SQL]);

        for decision in [
            CustomRolePreflightDecision::Proceed,
            CustomRolePreflightDecision::RecordCompletedMigration,
            CustomRolePreflightDecision::RefuseMissingAccessAll,
            CustomRolePreflightDecision::RefuseLegacyUserAccessAll,
        ] {
            assert!(legacy_user_access_all_statements(decision).is_empty(), "{decision:?}");
        }
    }

    /// The refusal has to point at the setting that resolves it, and keep both manual procedures.
    #[test]
    fn the_recovery_text_offers_the_automatic_resolution() {
        let mut facts = ready();
        facts.legacy_user_access_all_count = 1;
        let text = message(CustomRolePreflightDecision::RefuseLegacyUserAccessAll, facts);

        assert!(text.contains("LEGACY_USER_ACCESS_ALL_MIGRATION"));
        assert!(text.contains("materialize"));
        assert!(text.contains("drop"));
        // access_all overrode both flags, so the manual path has to relax existing rows too
        assert!(text.contains("SET read_only = FALSE, hide_passwords = FALSE"));
        assert!(text.contains("INSERT INTO users_collections"));
    }

    #[test]
    fn legacy_user_access_all_is_refused_with_a_recovery_path() {
        let facts = CustomRoleMigrationFacts {
            legacy_user_access_all_count: 2,
            ..ready()
        };
        let decision = decide(facts);
        assert_eq!(decision, CustomRolePreflightDecision::RefuseLegacyUserAccessAll);

        let message = message(decision, facts);
        assert!(message.contains("Nothing has been changed."), "{message}");
        assert!(message.contains("Found 2 membership(s)"), "{message}");
        assert!(message.contains("SET access_all = FALSE"), "{message}");
        assert!(message.contains("INSERT INTO users_collections"), "{message}");
    }

    /// The state this revision stopped refusing: a legacy Manager reaching every collection through
    /// an organization-local `access_all` group. The preflight has no fact for it any more, so there
    /// is nothing left that could stop an ordinary upgrade.
    #[test]
    fn group_derived_collection_authority_never_stops_startup() {
        assert_eq!(decide(ready()), CustomRolePreflightDecision::Proceed);
    }

    /// A damaged legacy schema outranks the unrepresentable-state check: its answer would be
    /// unreadable, and the migration cannot run either way.
    #[test]
    fn a_damaged_schema_outranks_the_legacy_user_check() {
        let facts = CustomRoleMigrationFacts {
            access_all_column_exists: false,
            legacy_user_access_all_count: 1,
            ..ready()
        };
        assert_eq!(decide(facts), CustomRolePreflightDecision::RefuseMissingAccessAll);
    }

    /// Every refusal promises the operator that startup stopped before anything was touched. The
    /// preflight only ever reads, so that promise holds by construction -- this pins the wording that
    /// carries it.
    #[test]
    fn every_refusal_says_nothing_has_been_changed() {
        for decision in [
            CustomRolePreflightDecision::RefuseMissingAccessAll,
            CustomRolePreflightDecision::RefuseLegacyUserAccessAll,
        ] {
            let message = message(decision, ready());
            assert!(message.contains("Nothing has been changed."), "{decision:?}: {message}");
        }
    }
}
