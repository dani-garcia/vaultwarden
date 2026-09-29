// Native credential/keyset contract informed by Vaultwarden PR 7297 (AGPL-3.0),
// branch snapshot at 727fead3a06eabf477ae9abed2ff0328acba7a6f.
// Transactional lifecycle guards keep vault key rotation and passkey keys consistent.
use super::{TwoFactor, User, UserId};
use crate::{
    api::{ApiResult, EmptyResult},
    crypto,
    db::{
        DbConn, DbConnInner,
        schema::{twofactor, users, web_authn_credentials, web_authn_login_challenges},
    },
    error::Error,
    util::get_uuid,
};
use diesel::prelude::*;

// Opaque encrypted fields and challenge data intentionally have no Debug implementation.
#[derive(Clone, Queryable, Insertable)]
#[diesel(table_name = web_authn_credentials)]
pub struct WebAuthnCredential {
    pub uuid: String,
    pub user_uuid: UserId,
    pub name: String,
    pub credential: String,
    pub credential_id_hash: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

#[derive(Clone)]
pub struct PasskeyAccount {
    pub uuid: UserId,
    stamp: String,
    private_key: String,
}
impl PasskeyAccount {
    pub fn from_user(user: &User) -> ApiResult<Self> {
        let private_key = user
            .private_key
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::new_msg("Account keys are not initialized"))?;
        Ok(Self {
            uuid: user.uuid.clone(),
            stamp: user.security_stamp.clone(),
            private_key: private_key.clone(),
        })
    }
    pub fn binding(&self) -> String {
        crypto::sha256_hex(self.private_key.as_bytes())
    }
    // No-op write serializes per-account credential changes on every backend.
    // Read the condition back instead of relying on MySQL's changed-row count.
    fn lock(&self, conn: &mut DbConnInner) -> EmptyResult {
        diesel::update(users::table.filter(users::uuid.eq(&self.uuid)))
            .set(users::uuid.eq(&self.uuid))
            .execute(conn)
            .map_err(|_| unavailable())?;
        let count = users::table
            .filter(users::uuid.eq(&self.uuid))
            .filter(users::enabled.eq(true))
            .filter(users::security_stamp.eq(&self.stamp))
            .filter(users::private_key.eq(&self.private_key))
            .count()
            .get_result::<i64>(conn)
            .map_err(|_| unavailable())?;
        if count != 1 {
            return Err(Error::new_msg("Account changed. Sync and try again."));
        }
        Ok(())
    }
    pub async fn lock_for_rotation(&self, conn: &DbConn) -> EmptyResult {
        let account = self.clone();
        conn.run(move |conn| account.lock(conn)).await
    }
    pub async fn replace_challenge(&self, row: TwoFactor, conn: &DbConn) -> EmptyResult {
        let account = self.clone();
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                account.lock(conn)?;
                diesel::delete(
                    twofactor::table
                        .filter(twofactor::user_uuid.eq(&account.uuid))
                        .filter(twofactor::atype.eq(row.atype)),
                )
                .execute(conn)
                .map_err(|_| unavailable())?;
                diesel::insert_into(twofactor::table).values(row).execute(conn).map_err(|_| unavailable())?;
                Ok(())
            })
        })
        .await
    }
}
fn unavailable() -> Error {
    Error::new_msg("Passkey storage unavailable")
}
fn concurrent() -> Error {
    Error::new_msg("Passkey changed. Sync and try again.")
}

impl WebAuthnCredential {
    pub fn same_login_epoch(expected_credential: &Self, expected_user: &User, credential: &Self, user: &User) -> bool {
        expected_credential.uuid == credential.uuid
            && expected_credential.user_uuid == credential.user_uuid
            && expected_credential.credential == credential.credential
            && expected_credential.supports_prf == credential.supports_prf
            && expected_credential.encrypted_user_key == credential.encrypted_user_key
            && expected_credential.encrypted_public_key == credential.encrypted_public_key
            && expected_credential.encrypted_private_key == credential.encrypted_private_key
            && expected_user.uuid == user.uuid
            && expected_user.enabled == user.enabled
            && expected_user.security_stamp == user.security_stamp
            && expected_user.email == user.email
            && expected_user.akey == user.akey
            && expected_user.private_key == user.private_key
            && expected_user.public_key == user.public_key
            && expected_user.password_hash == user.password_hash
            && expected_user.client_kdf_type == user.client_kdf_type
            && expected_user.client_kdf_iter == user.client_kdf_iter
            && expected_user.client_kdf_memory == user.client_kdf_memory
            && expected_user.client_kdf_parallelism == user.client_kdf_parallelism
    }

    pub fn has_prf_keyset(&self) -> bool {
        self.supports_prf
            && [&self.encrypted_user_key, &self.encrypted_public_key, &self.encrypted_private_key]
                .iter()
                .all(|v| v.as_ref().is_some_and(|v| !v.is_empty()))
    }
    pub fn prf_status(&self) -> i32 {
        if self.supports_prf {
            i32::from(!self.has_prf_keyset())
        } else {
            2
        }
    }
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> ApiResult<Vec<Self>> {
        conn.run(move |conn| {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .order(web_authn_credentials::uuid.asc())
                .load(conn)
                .map_err(|_| unavailable())
        })
        .await
    }
    // A single statement gives the credential wrappers and account keys one
    // database snapshot, including while key rotation is committing.
    fn load_login_account(hash: &str, conn: &mut DbConnInner) -> ApiResult<Option<(Self, User)>> {
        web_authn_credentials::table
            .inner_join(users::table.on(users::uuid.eq(web_authn_credentials::user_uuid)))
            .filter(web_authn_credentials::credential_id_hash.eq(hash))
            .select((web_authn_credentials::all_columns, users::all_columns))
            .first(conn)
            .optional()
            .map_err(|_| unavailable())
    }
    pub async fn find_login_account(hash: &str, conn: &DbConn) -> ApiResult<Option<(Self, User)>> {
        conn.run(move |conn| Self::load_login_account(hash, conn)).await
    }
    pub async fn update_authentication(&self, previous_credential: &str, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        let previous = previous_credential.to_owned();
        conn.run(move |conn| {
            let changed = diesel::update(
                web_authn_credentials::table
                    .filter(web_authn_credentials::uuid.eq(&row.uuid))
                    .filter(web_authn_credentials::user_uuid.eq(&row.user_uuid))
                    .filter(web_authn_credentials::credential.eq(previous)),
            )
            .set(web_authn_credentials::credential.eq(row.credential))
            .execute(conn)
            .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(concurrent());
            }
            Ok(())
        })
        .await
    }
    pub async fn find_by_user_and_credential_id_hash(
        user_uuid: &UserId,
        hash: &str,
        conn: &DbConn,
    ) -> ApiResult<Option<Self>> {
        conn.run(move |conn| {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .filter(web_authn_credentials::credential_id_hash.eq(hash))
                .first(conn)
                .optional()
                .map_err(|_| unavailable())
        })
        .await
    }
    pub async fn insert(&self, account: &PasskeyAccount, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        let account = account.clone();
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                account.lock(conn)?;
                let count = web_authn_credentials::table
                    .filter(web_authn_credentials::user_uuid.eq(&account.uuid))
                    .count()
                    .get_result::<i64>(conn)
                    .map_err(|_| unavailable())?;
                if count >= 5 {
                    return Err(Error::new_msg("Maximum number of passkeys reached"));
                }
                diesel::insert_into(web_authn_credentials::table).values(row).execute(conn).map_err(
                    |error| match error {
                        diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _) => {
                            Error::new_msg("Passkey is already registered")
                        }
                        _ => unavailable(),
                    },
                )?;
                Ok(())
            })
        })
        .await
    }
    pub async fn update_prf(&self, account: &PasskeyAccount, previous_credential: &str, conn: &DbConn) -> EmptyResult {
        let row = self.clone();
        let account = account.clone();
        let previous = previous_credential.to_owned();
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                account.lock(conn)?;
                let target = || {
                    web_authn_credentials::table
                        .filter(web_authn_credentials::uuid.eq(&row.uuid))
                        .filter(web_authn_credentials::user_uuid.eq(&account.uuid))
                        .filter(web_authn_credentials::credential.eq(&previous))
                };
                if target().count().get_result::<i64>(conn).map_err(|_| unavailable())? != 1 {
                    return Err(concurrent());
                }
                diesel::update(target())
                    .set((
                        web_authn_credentials::credential.eq(row.credential),
                        web_authn_credentials::encrypted_user_key.eq(row.encrypted_user_key),
                        web_authn_credentials::encrypted_public_key.eq(row.encrypted_public_key),
                        web_authn_credentials::encrypted_private_key.eq(row.encrypted_private_key),
                    ))
                    .execute(conn)
                    .map_err(|_| unavailable())?;
                Ok(())
            })
        })
        .await
    }
    pub async fn rewrap_all(account: &PasskeyAccount, rows: Vec<(Self, String, String)>, conn: &DbConn) -> EmptyResult {
        if rows.is_empty() {
            return Ok(());
        }
        let account = account.clone();
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                account.lock(conn)?;
                for (old, encrypted_user_key, encrypted_public_key) in rows {
                    let target = || {
                        web_authn_credentials::table
                            .filter(web_authn_credentials::uuid.eq(&old.uuid))
                            .filter(web_authn_credentials::user_uuid.eq(&account.uuid))
                            .filter(web_authn_credentials::credential.eq(&old.credential))
                            .filter(web_authn_credentials::encrypted_private_key.eq(&old.encrypted_private_key))
                    };
                    if target().count().get_result::<i64>(conn).map_err(|_| unavailable())? != 1 {
                        return Err(concurrent());
                    }
                    diesel::update(target())
                        .set((
                            web_authn_credentials::encrypted_user_key.eq(encrypted_user_key),
                            web_authn_credentials::encrypted_public_key.eq(encrypted_public_key),
                        ))
                        .execute(conn)
                        .map_err(|_| unavailable())?;
                }
                Ok(())
            })
        })
        .await
    }

    pub async fn delete_by_uuid_and_user(uuid: &str, user_uuid: &UserId, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                diesel::update(users::table.filter(users::uuid.eq(user_uuid)))
                    .set(users::uuid.eq(user_uuid))
                    .execute(conn)
                    .map_err(|_| unavailable())?;
                diesel::delete(
                    web_authn_credentials::table
                        .filter(web_authn_credentials::uuid.eq(uuid))
                        .filter(web_authn_credentials::user_uuid.eq(user_uuid)),
                )
                .execute(conn)
                .map(|n| n == 1)
                .map_err(|_| unavailable())
            })
        })
        .await
    }
    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                diesel::update(users::table.filter(users::uuid.eq(user_uuid)))
                    .set(users::uuid.eq(user_uuid))
                    .execute(conn)
                    .map_err(|_| unavailable())?;
                diesel::delete(web_authn_credentials::table.filter(web_authn_credentials::user_uuid.eq(user_uuid)))
                    .execute(conn)
                    .map(|_| ())
                    .map_err(|_| unavailable())
            })
        })
        .await
    }
    pub async fn consume_challenge(row: TwoFactor, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::delete(
                twofactor::table
                    .filter(twofactor::uuid.eq(row.uuid))
                    .filter(twofactor::user_uuid.eq(row.user_uuid))
                    .filter(twofactor::data.eq(row.data)),
            )
            .execute(conn)
            .map(|n| n == 1)
            .map_err(|_| unavailable())
        })
        .await
    }
    pub fn id() -> String {
        get_uuid()
    }
}

// Anonymous WebAuthn state is stored server-side so every assertion consumes one challenge.
// This is required for synced authenticators whose signature counter stays at zero.
pub struct WebAuthnLoginChallenge;
impl WebAuthnLoginChallenge {
    pub async fn create(token: &str, state: String, created_at: i64, conn: &DbConn) -> EmptyResult {
        let token_hash = crypto::sha256_hex(token.as_bytes());
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                diesel::delete(
                    web_authn_login_challenges::table
                        .filter(web_authn_login_challenges::created_at.lt(created_at.saturating_sub(300))),
                )
                .execute(conn)
                .map_err(|_| unavailable())?;
                diesel::insert_into(web_authn_login_challenges::table)
                    .values((
                        web_authn_login_challenges::token_hash.eq(token_hash),
                        web_authn_login_challenges::state.eq(state),
                        web_authn_login_challenges::created_at.eq(created_at),
                    ))
                    .execute(conn)
                    .map(|_| ())
                    .map_err(|_| unavailable())
            })
        })
        .await
    }
    pub async fn consume(token: &str, now: i64, conn: &DbConn) -> ApiResult<Option<String>> {
        let token_hash = crypto::sha256_hex(token.as_bytes());
        conn.run(move |conn| {
            conn.transaction::<_, Error, _>(|conn| {
                let row: Option<(String, i64)> = web_authn_login_challenges::table
                    .filter(web_authn_login_challenges::token_hash.eq(&token_hash))
                    .select((web_authn_login_challenges::state, web_authn_login_challenges::created_at))
                    .first(conn)
                    .optional()
                    .map_err(|_| unavailable())?;
                let deleted = diesel::delete(
                    web_authn_login_challenges::table.filter(web_authn_login_challenges::token_hash.eq(token_hash)),
                )
                .execute(conn)
                .map_err(|_| unavailable())?;
                match row {
                    Some((state, created)) if deleted == 1 && created <= now + 30 && created >= now - 300 => {
                        Ok(Some(state))
                    }
                    _ => Ok(None),
                }
            })
        })
        .await
    }
}

#[cfg(all(test, sqlite))]
mod login_snapshot_tests {
    use super::*;
    use diesel::{Connection, connection::SimpleConnection, sqlite::SqliteConnection};
    use diesel_migrations::MigrationHarness;

    #[test]
    fn login_snapshot_never_mixes_key_rotation_epochs_and_observes_deletion() {
        let path = std::env::temp_dir().join(format!("vw-passkey-login-snapshot-{}.sqlite3", get_uuid()));
        let db_url = path.to_str().unwrap();
        let mut migration_conn = SqliteConnection::establish(db_url).unwrap();
        migration_conn.run_pending_migrations(crate::db::sqlite_migrations::MIGRATIONS).unwrap();
        migration_conn.batch_execute("PRAGMA journal_mode=WAL;").unwrap();
        drop(migration_conn);
        let mut reader = DbConnInner::Sqlite(SqliteConnection::establish(db_url).unwrap());
        let mut writer = DbConnInner::Sqlite(SqliteConnection::establish(db_url).unwrap());
        let user = get_uuid();
        reader.batch_execute(&format!(
            "INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,private_key,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter) VALUES ('{user}',1,datetime('now'),datetime('now'),0,'user@example.test','Synthetic user',X'00',zeroblob(64),1000,'old-account-wrapper','old-private-wrapper','old-stamp','[]','[]',0,600000); INSERT INTO web_authn_credentials (uuid,user_uuid,name,credential,credential_id_hash,supports_prf,encrypted_user_key,encrypted_public_key,encrypted_private_key) VALUES ('{}','{user}','Synthetic passkey','old-credential','fingerprint',1,'old-user-wrapper','old-public-wrapper','old-passkey-private-wrapper');",
            get_uuid()
        )).unwrap();
        let (before_credential, before_user) =
            WebAuthnCredential::load_login_account("fingerprint", &mut reader).unwrap().unwrap();
        assert_eq!(before_credential.encrypted_user_key.as_deref(), Some("old-user-wrapper"));
        assert_eq!(before_user.akey, "old-account-wrapper");

        writer.transaction::<_, diesel::result::Error, _>(|db| {
            db.batch_execute("UPDATE users SET akey='new-account-wrapper', private_key='new-private-wrapper', security_stamp='new-stamp' WHERE email='user@example.test'; UPDATE web_authn_credentials SET encrypted_user_key='new-user-wrapper', encrypted_public_key='new-public-wrapper' WHERE credential_id_hash='fingerprint';")?;
            // The writer has changed both rows but has not committed. A login
            // statement sees one committed epoch, never one row from each.
            let (credential, user) = WebAuthnCredential::load_login_account("fingerprint", &mut reader).unwrap().unwrap();
            assert_eq!(credential.encrypted_user_key.as_deref(), Some("old-user-wrapper"));
            assert_eq!(user.akey, "old-account-wrapper");
            Ok(())
        }).unwrap();

        let (after_credential, after_user) =
            WebAuthnCredential::load_login_account("fingerprint", &mut reader).unwrap().unwrap();
        assert_eq!(after_credential.encrypted_user_key.as_deref(), Some("new-user-wrapper"));
        assert_eq!(after_user.akey, "new-account-wrapper");
        assert!(!WebAuthnCredential::same_login_epoch(
            &before_credential,
            &before_user,
            &after_credential,
            &after_user
        ));
        writer.batch_execute("DELETE FROM web_authn_credentials WHERE credential_id_hash='fingerprint';").unwrap();
        assert!(WebAuthnCredential::load_login_account("fingerprint", &mut reader).unwrap().is_none());
        drop(reader);
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }
}
