use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use macros::UuidFromParam;

use crate::api::EmptyResult;
use crate::db::schema::{web_authn_credentials, web_authn_login_challenges};
use crate::db::{DbConn, DbPool};
use crate::error::{Error, MapResult};
use crate::util::get_uuid;

use super::UserId;

/// How long a pending passkey-login challenge stays valid before it is rejected.
const WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS: i64 = 300;
const WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Clone, Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = web_authn_credentials)]
#[diesel(primary_key(uuid))]
pub struct WebAuthnCredential {
    pub uuid: WebAuthnCredentialId,
    pub user_uuid: UserId,
    pub name: String,
    pub credential: String,
    pub credential_id_hash: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

impl WebAuthnCredential {
    #[expect(
        clippy::too_many_arguments,
        reason = "Matches positional-arg constructor pattern used by all other model `new` functions"
    )]
    pub fn new(
        user_uuid: UserId,
        name: String,
        credential: String,
        credential_id_hash: String,
        supports_prf: bool,
        encrypted_user_key: Option<String>,
        encrypted_public_key: Option<String>,
        encrypted_private_key: Option<String>,
    ) -> Self {
        Self {
            uuid: WebAuthnCredentialId(get_uuid()),
            user_uuid,
            name,
            credential,
            credential_id_hash,
            supports_prf,
            encrypted_user_key,
            encrypted_public_key,
            encrypted_private_key,
        }
    }

    /// Whether this credential carries a complete PRF "rotateable key set",
    /// i.e. passwordless vault decryption is fully enabled for it.
    pub fn has_prf_keyset(&self) -> bool {
        self.supports_prf
            && self.encrypted_user_key.is_some()
            && self.encrypted_public_key.is_some()
            && self.encrypted_private_key.is_some()
    }

    /// Bitwarden `WebAuthnPrfStatus`: 0 = Enabled, 1 = Supported, 2 = Unsupported.
    /// Mirrors `WebAuthnCredential.GetPrfStatus()` in the upstream Bitwarden server.
    pub fn prf_status(&self) -> i32 {
        match (self.supports_prf, self.has_prf_keyset()) {
            (false, _) => 2,    // Unsupported
            (true, true) => 0,  // Enabled
            (true, false) => 1, // Supported
        }
    }

    pub async fn save_with_user_limit(&self, limit: usize, conn: &DbConn) -> EmptyResult {
        let credential = self.clone();
        let limit = i64::try_from(limit).map_err(|_| Error::new("Invalid passkey limit", "Passkey limit overflow"))?;

        db_run! { conn: {
            conn.transaction::<(), Error, _>(|conn| {
                let count = web_authn_credentials::table
                    .filter(web_authn_credentials::user_uuid.eq(&credential.user_uuid))
                    .count()
                    .get_result::<i64>(conn)
                    .map_res("Error counting web_authn_credentials")?;
                if count >= limit {
                    return Err(Error::new("Maximum number of passkeys reached", "WebAuthn credential limit reached"));
                }

                let result = diesel::insert_into(web_authn_credentials::table)
                    .values(&credential)
                    .execute(conn);
                match result {
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {
                        Err(Error::new("Passkey is already registered", "Duplicate WebAuthn credential ID"))
                    }
                    result => result.map_res("Error saving web_authn_credential"),
                }
            })
        }}
    }

    pub async fn count_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<usize, Error> {
        let user_uuid = user_uuid.clone();
        let count = db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .count()
                .get_result::<i64>(conn)
                .map_res("Error counting web_authn_credentials")
        }}?;

        usize::try_from(count)
            .map_err(|_| Error::new("Error counting web_authn_credentials", "Credential count overflow"))
    }

    /// Guard the rowcount returned by an UPDATE against a concurrent
    /// credential delete. A 0-row result means a `post_api_webauthn_delete`
    /// (or `User::delete` cascade) removed the row inside our window — a
    /// concurrent-state outcome that deserves a clean refusal.
    ///
    /// Returns a Simple error so the routine concurrent-delete race does NOT
    /// emit an `error!()` log line from the Rocket responder. The message
    /// itself describes an expected concurrent-state outcome, not a server
    /// bug, and a multi-replica deployment would otherwise spam operator logs.
    /// Visible to sibling modules so credential rewrap paths can share the
    /// same rowcount-zero handling rather than re-implementing it for every
    /// update statement.
    pub(crate) fn ensure_credential_present(rows: usize) -> EmptyResult {
        if rows == 0 {
            return Err(Error::new_msg("Webauthn credential modified concurrently"));
        }
        Ok(())
    }

    /// Persist the serialized passkey blob after a successful assertion advances
    /// its signature counter. Touches only the `credential` column so a concurrent
    /// key rotation cannot clobber it (see [`Self::update_keys`]).
    pub async fn update_credential(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            let rows: usize = diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set(web_authn_credentials::credential.eq(&self.credential))
                .execute(conn)
                .map_res("Error updating web_authn_credential signature counter")?;
            Self::ensure_credential_present(rows)
        }}
    }

    /// Persist the PRF unlock blobs the rotation flow re-encrypts under the new
    /// account key. Touches only the two account-key-wrapped columns, so it
    /// cannot clobber a concurrent counter advance (see [`Self::update_credential`])
    /// nor the enrollment-time `encrypted_private_key`. The
    /// `ensure_credential_present` guard reports a 0-row UPDATE (row deleted
    /// inside our window) so callers can treat the rewrap as a degraded no-op.
    pub async fn update_keys(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            let rows: usize = diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set((
                    web_authn_credentials::encrypted_user_key.eq(&self.encrypted_user_key),
                    web_authn_credentials::encrypted_public_key.eq(&self.encrypted_public_key),
                ))
                .execute(conn)
                .map_res("Error updating web_authn_credential keys")?;
            Self::ensure_credential_present(rows)
        }}
    }

    /// Drop all PRF unlock blobs so clients stop advertising unlock-with-passkey
    /// for a credential whose key material could not be rewrapped after account
    /// key rotation.
    pub async fn clear_prf_keyset(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            let rows: usize = diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set((
                    web_authn_credentials::encrypted_user_key.eq::<Option<String>>(None),
                    web_authn_credentials::encrypted_public_key.eq::<Option<String>>(None),
                    web_authn_credentials::encrypted_private_key.eq::<Option<String>>(None),
                ))
                .execute(conn)
                .map_res("Error clearing web_authn_credential PRF keyset")?;
            Self::ensure_credential_present(rows)
        }}
    }

    /// Persist a complete PRF unlock keyset after a user enables vault
    /// encryption for an existing passkey-login credential, optionally
    /// folding the signature-counter advance from the assertion that
    /// authorised the enrolment into the same UPDATE — both the keyset
    /// and the counter are written in one statement so a half-applied
    /// state is impossible without involving a separate transaction.
    ///
    /// `advanced_counter` gates the `credential` blob write. The caller
    /// passes `true` only when `Passkey::update_credential` reported a real
    /// counter advance; otherwise the column is left untouched so a
    /// concurrent counter advance committed by another instance (e.g. a
    /// parallel `webauthn_login` in a multi-replica deployment) is not
    /// silently overwritten with the stale blob loaded here.
    ///
    /// A 0-rows result is surfaced as a `Simple` error (NOT `Db(NotFound)`)
    /// via [`Self::ensure_credential_present`] so the renderer at
    /// `error.rs` does not log a routine concurrent-delete race at ERROR
    /// level.
    pub async fn update_credential_and_prf_keyset(&self, advanced_counter: bool, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            let target = web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid));
            let rows: usize = if advanced_counter {
                diesel::update(target)
                    .set((
                        web_authn_credentials::credential.eq(&self.credential),
                        web_authn_credentials::encrypted_user_key.eq(&self.encrypted_user_key),
                        web_authn_credentials::encrypted_public_key.eq(&self.encrypted_public_key),
                        web_authn_credentials::encrypted_private_key.eq(&self.encrypted_private_key),
                    ))
                    .execute(conn)
                    .map_res("Error updating web_authn_credential PRF keyset")?
            } else {
                diesel::update(target)
                    .set((
                        web_authn_credentials::encrypted_user_key.eq(&self.encrypted_user_key),
                        web_authn_credentials::encrypted_public_key.eq(&self.encrypted_public_key),
                        web_authn_credentials::encrypted_private_key.eq(&self.encrypted_private_key),
                    ))
                    .execute(conn)
                    .map_res("Error updating web_authn_credential PRF keyset")?
            };
            Self::ensure_credential_present(rows)
        }}
    }

    /// Surface DB errors so callers can convert them into proper failure
    /// responses instead of panicking inside `conn.run`'s blocking closure.
    /// In particular, this is reachable from the unauthenticated
    /// `webauthn_login` grant in `src/api/identity.rs`, where a transient
    /// DB error must not crash the worker.
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<Vec<Self>, Error> {
        db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .map_res("Error loading web_authn_credentials")
        }}
    }

    /// Look up a single credential by `(user_uuid, credential_id_hash)`,
    /// using the UNIQUE index of the same name. Used by `put_api_webauthn`
    /// to locate the row matching a verified assertion without loading the
    /// user's entire passkey set.
    pub async fn find_by_user_and_credential_id_hash(
        user_uuid: &UserId,
        credential_id_hash: &str,
        conn: &DbConn,
    ) -> Result<Option<Self>, Error> {
        db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .filter(web_authn_credentials::credential_id_hash.eq(credential_id_hash))
                .first::<Self>(conn)
                .optional()
                .map_res("Error loading web_authn_credential by credential_id_hash")
        }}
    }

    /// Re-check that the credential row still exists without changing it.
    /// This protects successful assertions whose authenticators do not
    /// advance a signature counter: there is no UPDATE rowcount to observe in
    /// that case, so callers need an explicit existence probe before they
    /// mint a login response.
    pub async fn ensure_still_registered(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            let rows: i64 = web_authn_credentials::table
                .filter(web_authn_credentials::uuid.eq(&self.uuid))
                .filter(web_authn_credentials::user_uuid.eq(&self.user_uuid))
                .count()
                .get_result(conn)
                .map_res("Error checking web_authn_credential presence")?;
            Self::ensure_credential_present(usize::from(rows > 0))
        }}
    }

    pub async fn delete_by_uuid_and_user(
        uuid: &WebAuthnCredentialId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            let rows = diesel::delete(
                web_authn_credentials::table
                    .filter(web_authn_credentials::uuid.eq(uuid))
                    .filter(web_authn_credentials::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map_res("Error removing web_authn_credential")?;
            Self::ensure_credential_present(rows)
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(web_authn_credentials::table.filter(web_authn_credentials::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting all web_authn_credentials for user")
        }}
    }
}

/// A pending passkey-login (discoverable credential) authentication challenge.
///
/// The login ceremony begins before the user is known, so the challenge state
/// cannot be tied to a `twofactor` row. It is persisted here keyed by a random
/// single-use token and consumed exactly once by [`WebAuthnLoginChallenge::take`].
#[derive(Debug, Queryable, Insertable)]
#[diesel(table_name = web_authn_login_challenges)]
pub struct WebAuthnLoginChallenge {
    pub id: WebAuthnLoginChallengeId,
    pub challenge: String,
    pub created_at: NaiveDateTime,
}

impl WebAuthnLoginChallenge {
    pub fn new(challenge: String) -> Self {
        Self {
            id: WebAuthnLoginChallengeId(get_uuid()),
            challenge,
            created_at: Utc::now().naive_utc(),
        }
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::insert_into(web_authn_login_challenges::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving web_authn_login_challenge")
        }}
    }

    fn is_fresh(created_at: NaiveDateTime) -> bool {
        Self::is_fresh_at(created_at, Utc::now().naive_utc())
    }

    /// Pure freshness predicate. The `now` parameter exists so tests can
    /// assert the inclusive `>=` / `<=` boundaries deterministically without
    /// racing the `Utc::now()` call inside the production wrapper above.
    fn is_fresh_at(created_at: NaiveDateTime, now: NaiveDateTime) -> bool {
        crate::util::is_within_freshness_window(
            created_at,
            now,
            TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS),
            TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS),
        )
    }

    #[cfg(test)]
    fn is_purgeable_at(created_at: NaiveDateTime, now: NaiveDateTime) -> bool {
        !Self::is_fresh_at(created_at, now)
    }

    /// Fetch and delete a pending challenge (single-use). Three outcomes:
    /// - `Ok(Some(_))` — winner of the SELECT+DELETE race; the row has been
    ///   removed and the caller may verify the assertion against the state.
    /// - `Ok(None)` — token unknown, already consumed by a concurrent caller,
    ///   or the row was current but past the TTL cutoff (post-transaction
    ///   filter). All three collapse to a single "stale or invalid challenge"
    ///   path so the caller can't distinguish them — a small AUTH_FAILED
    ///   information-leak hardening for the unauthenticated login endpoint.
    /// - `Err(_)` — DB degradation (deadlock, conn drop, lock timeout). The
    ///   surrounding transaction rolled back atomically, so the row is intact
    ///   rather than silently consumed; propagating via `?` lets the caller
    ///   surface a 5xx instead of an indistinguishable 4xx stale-token
    ///   response.
    pub async fn take(id: &WebAuthnLoginChallengeId, conn: &DbConn) -> Result<Option<Self>, Error> {
        db_run! { conn: {
            // Single-use rests on the `deleted == 1` row-count guard, not on
            // isolation: concurrent callers may all SELECT the row, but only
            // the one whose DELETE returns 1 may use it; the rest get `None`.
            // The transaction rolls the SELECT+DELETE back atomically on a DB
            // error, leaving the row intact rather than silently consumed.
            //
            // `is_fresh` runs INSIDE the transaction closure, AFTER the DELETE,
            // reading the wall clock at consume time, so a stale row is still
            // purged on a consumption attempt rather than lingering until the
            // background sweeper runs.
            conn
                .transaction::<Option<WebAuthnLoginChallenge>, diesel::result::Error, _>(|conn| {
                    let challenge = web_authn_login_challenges::table
                        .filter(web_authn_login_challenges::id.eq(id))
                        .first::<WebAuthnLoginChallenge>(conn)
                        .optional()?;
                    let deleted = diesel::delete(
                        web_authn_login_challenges::table.filter(web_authn_login_challenges::id.eq(id)),
                    )
                    .execute(conn)?;
                    Ok(challenge.filter(|c| deleted == 1 && Self::is_fresh(c.created_at)))
                })
                .map_res("Error taking web_authn_login_challenge")
        }}
    }

    /// Scheduled cleanup of challenges that were started but never consumed.
    pub async fn delete_expired(pool: DbPool) -> EmptyResult {
        debug!("Purging expired web_authn_login_challenges");
        if let Ok(conn) = pool.get().await {
            let now = Utc::now().naive_utc();
            let oldest = now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS);
            let newest = now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS);
            db_run! { conn: {
                diesel::delete(web_authn_login_challenges::table.filter(
                    web_authn_login_challenges::created_at
                        .lt(oldest)
                        .or(web_authn_login_challenges::created_at.gt(newest)),
                ))
                    .execute(conn)
                    .map_res("Error deleting expired web_authn_login_challenges")
            }}
        } else {
            err!("Failed to get DB connection while purging expired web_authn_login_challenges")
        }
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct WebAuthnCredentialId(String);

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct WebAuthnLoginChallengeId(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(
        supports_prf: bool,
        user_key: Option<&str>,
        pub_key: Option<&str>,
        priv_key: Option<&str>,
    ) -> WebAuthnCredential {
        WebAuthnCredential::new(
            UserId::from(String::from("00000000-0000-0000-0000-000000000000")),
            String::from("test"),
            String::from("{}"),
            String::from("credential-id-hash"),
            supports_prf,
            user_key.map(String::from),
            pub_key.map(String::from),
            priv_key.map(String::from),
        )
    }

    // Bitwarden WebAuthnPrfStatus: Enabled = 0, Supported = 1, Unsupported = 2.
    #[test]
    fn prf_status_unsupported_when_authenticator_has_no_prf() {
        assert_eq!(cred(false, None, None, None).prf_status(), 2);
        // No PRF support means Unsupported even if blobs are somehow present.
        assert_eq!(cred(false, Some("u"), Some("p"), Some("k")).prf_status(), 2);
    }

    #[test]
    fn prf_status_supported_when_prf_capable_but_keyset_incomplete() {
        assert_eq!(cred(true, None, None, None).prf_status(), 1);
        assert_eq!(cred(true, Some("u"), Some("p"), None).prf_status(), 1);
    }

    #[test]
    fn prf_status_enabled_only_with_a_complete_keyset() {
        let c = cred(true, Some("u"), Some("p"), Some("k"));
        assert!(c.has_prf_keyset());
        assert_eq!(c.prf_status(), 0);
    }

    /// Each `WebAuthnCredential::new` argument must land in the field that
    /// shares its name. Without this, two adjacent `Option<String>` args
    /// could be swapped at a call site without the compiler noticing.
    #[test]
    fn new_assigns_each_argument_to_its_named_field() {
        let cred = WebAuthnCredential::new(
            UserId::from(String::from("user-uuid")),
            String::from("display-name"),
            String::from("credential-json"),
            String::from("hash-value"),
            true,
            Some(String::from("user-key")),
            Some(String::from("public-key")),
            Some(String::from("private-key")),
        );
        assert_eq!(cred.user_uuid.as_ref(), "user-uuid");
        assert_eq!(cred.name, "display-name");
        assert_eq!(cred.credential, "credential-json");
        assert_eq!(cred.credential_id_hash, "hash-value");
        assert!(cred.supports_prf);
        assert_eq!(cred.encrypted_user_key.as_deref(), Some("user-key"));
        assert_eq!(cred.encrypted_public_key.as_deref(), Some("public-key"));
        assert_eq!(cred.encrypted_private_key.as_deref(), Some("private-key"));
    }

    #[test]
    fn credential_rowcount_guard_rejects_missing_rows() {
        assert!(WebAuthnCredential::ensure_credential_present(1).is_ok());
        assert!(WebAuthnCredential::ensure_credential_present(0).is_err());
    }

    /// Exhaust the 2^4 truth table for `has_prf_keyset` and `prf_status`:
    /// only `(supports_prf=true, all three blobs Some)` reports
    /// `has_prf_keyset() == true` / `prf_status() == 0` (Enabled). Any
    /// `supports_prf=false` row is Unsupported (2). Any `supports_prf=true`
    /// row with at least one blob missing is Supported (1). The login
    /// response's `WebAuthnPrfOption` gating depends on this enum, so the
    /// full matrix is enforced to prevent a refactor accidentally
    /// advertising PRF capability on a credential with an incomplete
    /// keyset (which would leak partial state to the client).
    #[test]
    fn prf_status_full_truth_table() {
        for supports_prf in [false, true] {
            for user in [None, Some("u")] {
                for pub_ in [None, Some("p")] {
                    for priv_ in [None, Some("k")] {
                        let c = cred(supports_prf, user, pub_, priv_);
                        let all_keys_present = user.is_some() && pub_.is_some() && priv_.is_some();
                        let expected_has_keyset = supports_prf && all_keys_present;
                        let expected_status = match (supports_prf, expected_has_keyset) {
                            (false, _) => 2,    // Unsupported
                            (true, false) => 1, // Supported (capable but incomplete)
                            (true, true) => 0,  // Enabled
                        };
                        assert_eq!(
                            c.has_prf_keyset(),
                            expected_has_keyset,
                            "has_prf_keyset(supports_prf={supports_prf}, user={user:?}, pub={pub_:?}, priv={priv_:?})",
                        );
                        assert_eq!(
                            c.prf_status(),
                            expected_status,
                            "prf_status(supports_prf={supports_prf}, user={user:?}, pub={pub_:?}, priv={priv_:?})",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn login_challenge_freshness_allows_current_window() {
        let now = Utc::now().naive_utc();

        assert!(WebAuthnLoginChallenge::is_fresh(now));
        assert!(WebAuthnLoginChallenge::is_fresh(now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS - 5)));
        assert!(WebAuthnLoginChallenge::is_fresh(
            now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS - 5)
        ));
    }

    #[test]
    fn login_challenge_freshness_rejects_old_or_far_future_rows() {
        let now = Utc::now().naive_utc();

        assert!(!WebAuthnLoginChallenge::is_fresh(now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS + 1)));
        assert!(!WebAuthnLoginChallenge::is_fresh(
            now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS + 1)
        ));
    }

    /// Exact-boundary coverage. The production `is_fresh` reads `Utc::now()`
    /// inside the function, so a test against `now - TTL` would race the
    /// internal clock read by microseconds and assert FALSE for the boundary
    /// row that should be inclusive. `is_fresh_at` takes `now` as a parameter
    /// so the comparison is deterministic.
    #[test]
    fn login_challenge_freshness_inclusive_at_both_boundaries() {
        let now = Utc::now().naive_utc();

        assert!(
            WebAuthnLoginChallenge::is_fresh_at(now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS), now),
            "created_at exactly TTL old must remain fresh (`>=` is inclusive)"
        );
        assert!(
            WebAuthnLoginChallenge::is_fresh_at(
                now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS),
                now
            ),
            "created_at exactly skew seconds ahead must remain fresh (`<=` is inclusive)"
        );
        assert!(
            !WebAuthnLoginChallenge::is_fresh_at(
                now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS) - TimeDelta::nanoseconds(1),
                now
            ),
            "one nanosecond past the TTL boundary must reject"
        );
        assert!(
            !WebAuthnLoginChallenge::is_fresh_at(
                now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS) + TimeDelta::nanoseconds(1),
                now
            ),
            "one nanosecond past the skew boundary must reject"
        );
    }

    #[test]
    fn login_challenge_cleanup_purges_only_outside_fresh_window() {
        let now = Utc::now().naive_utc();

        assert!(!WebAuthnLoginChallenge::is_purgeable_at(now, now));
        assert!(!WebAuthnLoginChallenge::is_purgeable_at(
            now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS),
            now,
        ));
        assert!(!WebAuthnLoginChallenge::is_purgeable_at(
            now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS),
            now,
        ));
        assert!(WebAuthnLoginChallenge::is_purgeable_at(
            now - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS) - TimeDelta::nanoseconds(1),
            now,
        ));
        assert!(WebAuthnLoginChallenge::is_purgeable_at(
            now + TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_CLOCK_SKEW_SECONDS) + TimeDelta::nanoseconds(1),
            now,
        ));
    }
}
