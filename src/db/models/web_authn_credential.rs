use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use macros::UuidFromParam;

use crate::api::EmptyResult;
use crate::db::schema::{web_authn_credentials, web_authn_login_challenges};
use crate::db::{DbConn, DbPool};
use crate::error::MapResult;
use crate::util::get_uuid;

use super::UserId;

/// How long a pending passkey-login challenge stays valid before it is rejected.
const WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Identifiable, Queryable, Insertable)]
#[diesel(table_name = web_authn_credentials)]
#[diesel(primary_key(uuid))]
pub struct WebAuthnCredential {
    pub uuid: WebAuthnCredentialId,
    pub user_uuid: UserId,
    pub name: String,
    pub credential: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

impl WebAuthnCredential {
    pub fn new(
        user_uuid: UserId,
        name: String,
        credential: String,
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

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::insert_into(web_authn_credentials::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving web_authn_credential")
        }}
    }

    /// Persist the serialized passkey blob after a successful assertion advances
    /// its signature counter. Touches only the `credential` column so a concurrent
    /// key rotation cannot clobber it (see [`Self::update_keys`]).
    pub async fn update_credential(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set(web_authn_credentials::credential.eq(&self.credential))
                .execute(conn)
                .map_res("Error updating web_authn_credential signature counter")
        }}
    }

    /// Persist the PRF unlock blobs that the rotation flow re-encrypts under the
    /// new account key. Touches only the two columns that key rotation actually
    /// changes, so it cannot clobber a concurrent signature-counter advance (see
    /// [`Self::update_credential`]) nor the enrollment-time `encrypted_private_key`.
    pub async fn update_keys(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set((
                    web_authn_credentials::encrypted_user_key.eq(&self.encrypted_user_key),
                    web_authn_credentials::encrypted_public_key.eq(&self.encrypted_public_key),
                ))
                .execute(conn)
                .map_res("Error updating web_authn_credential keys")
        }}
    }

    /// Persist a complete PRF unlock keyset after a user enables vault
    /// encryption for an existing passkey-login credential.
    pub async fn update_prf_keyset(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::update(web_authn_credentials::table.filter(web_authn_credentials::uuid.eq(&self.uuid)))
                .set((
                    web_authn_credentials::encrypted_user_key.eq(&self.encrypted_user_key),
                    web_authn_credentials::encrypted_public_key.eq(&self.encrypted_public_key),
                    web_authn_credentials::encrypted_private_key.eq(&self.encrypted_private_key),
                ))
                .execute(conn)
                .map_res("Error updating web_authn_credential PRF keyset")
        }}
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading web_authn_credentials")
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &WebAuthnCredentialId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::uuid.eq(uuid))
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn delete_by_uuid_and_user(
        uuid: &WebAuthnCredentialId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                web_authn_credentials::table
                    .filter(web_authn_credentials::uuid.eq(uuid))
                    .filter(web_authn_credentials::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map_res("Error removing web_authn_credential")
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

    /// Fetch and delete a pending challenge (single-use). Returns `None` when the
    /// token is unknown, has already been consumed, or the challenge has expired.
    pub async fn take(id: &WebAuthnLoginChallengeId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            // Single-use: the SELECT and DELETE run in one transaction so the row
            // is read and removed atomically. Only the request whose DELETE
            // removes the row (deleted == 1) may use the challenge; a concurrent
            // request deletes 0 rows and gets `None`. A DB error aborts the
            // transaction, leaving the challenge intact rather than silently
            // treating it as consumed.
            let taken = conn
                .transaction::<Option<WebAuthnLoginChallenge>, diesel::result::Error, _>(|conn| {
                    let challenge = web_authn_login_challenges::table
                        .filter(web_authn_login_challenges::id.eq(id))
                        .first::<WebAuthnLoginChallenge>(conn)
                        .optional()?;
                    let deleted = diesel::delete(
                        web_authn_login_challenges::table.filter(web_authn_login_challenges::id.eq(id)),
                    )
                    .execute(conn)?;
                    Ok(challenge.filter(|_| deleted == 1))
                })
                .unwrap_or(None);

            let cutoff = Utc::now().naive_utc() - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS);
            taken.filter(|c| c.created_at >= cutoff)
        }}
    }

    /// Scheduled cleanup of challenges that were started but never consumed.
    pub async fn delete_expired(pool: DbPool) -> EmptyResult {
        debug!("Purging expired web_authn_login_challenges");
        if let Ok(conn) = pool.get().await {
            let cutoff = Utc::now().naive_utc() - TimeDelta::seconds(WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS);
            db_run! { conn: {
                diesel::delete(web_authn_login_challenges::table.filter(web_authn_login_challenges::created_at.lt(cutoff)))
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
}
