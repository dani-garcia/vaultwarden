use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;
use webauthn_rs::prelude::Passkey;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, schema::webauthn_credentials},
    error::MapResult,
    util::get_uuid,
};
use macros::UuidFromParam;

use super::UserId;

#[derive(Identifiable, Queryable, Insertable, Selectable)]
#[diesel(table_name = webauthn_credentials)]
#[diesel(primary_key(uuid))]
pub struct WebauthnCredential {
    pub uuid: WebauthnCredentialId,
    pub user_uuid: UserId,
    pub name: String,
    /// Base64url without padding, as the clients send it
    pub credential_id: String,
    /// The webauthn-rs `Passkey`, as JSON
    pub credential: String,
    pub supports_prf: bool,
    /// The user key, wrapped by the public key of the PRF key pair
    pub encrypted_user_key: Option<String>,
    /// The public key of the PRF key pair, wrapped by the user key, so that a key rotation can re-wrap the user key
    pub encrypted_public_key: Option<String>,
    /// The private key of the PRF key pair, wrapped by the key the authenticator's PRF output derives
    pub encrypted_private_key: Option<String>,
    /// When the newest challenge this credential answered was issued, in milliseconds since the Unix epoch. An assertion
    /// must answer a newer one, which makes it single use. A server clock that goes backwards (or another instance's
    /// clock running behind) refuses the passkey's logins until it catches up.
    pub last_challenge_issued_at: Option<i64>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Enums/WebAuthnPrfStatus.cs#L3-L8>
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebauthnPrfStatus {
    Enabled = 0,
    Supported = 1,
    Unsupported = 2,
}

/// Local methods
impl WebauthnCredential {
    pub fn new(
        user_uuid: UserId,
        name: String,
        passkey: &Passkey,
        supports_prf: bool,
        encrypted_user_key: Option<String>,
        encrypted_public_key: Option<String>,
        encrypted_private_key: Option<String>,
    ) -> ApiResult<Self> {
        let now = Utc::now().naive_utc();
        Ok(Self {
            uuid: WebauthnCredentialId(get_uuid()),
            user_uuid,
            name,
            credential_id: data_encoding::BASE64URL_NOPAD.encode(passkey.cred_id()),
            credential: serde_json::to_string(passkey)?,
            supports_prf,
            encrypted_user_key,
            encrypted_public_key,
            encrypted_private_key,
            last_challenge_issued_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn passkey(&self) -> ApiResult<Passkey> {
        Ok(serde_json::from_str(&self.credential)?)
    }

    pub fn prf_status(&self) -> WebauthnPrfStatus {
        if !self.supports_prf {
            WebauthnPrfStatus::Unsupported
        } else if self.encrypted_user_key.is_some()
            && self.encrypted_private_key.is_some()
            && self.encrypted_public_key.is_some()
        {
            WebauthnPrfStatus::Enabled
        } else {
            WebauthnPrfStatus::Supported
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "prfStatus": self.prf_status() as i32,
            "encryptedUserKey": self.encrypted_user_key,
            "encryptedPublicKey": self.encrypted_public_key,
            "object": "webauthnCredential",
        })
    }

    /// The transports are empty, since they aren't stored.
    ///
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/Vault/Models/Response/SyncResponseModel.cs#L69-L77>
    pub fn to_sync_prf_option(&self) -> Option<Value> {
        (self.prf_status() == WebauthnPrfStatus::Enabled).then(|| {
            json!({
                "encryptedPrivateKey": self.encrypted_private_key,
                "encryptedUserKey": self.encrypted_user_key,
                "credentialId": self.credential_id,
                "transports": [],
            })
        })
    }

    /// The same option in the login response, which uses PascalCase.
    ///
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Identity/IdentityServer/UserDecryptionOptionsBuilder.cs#L63-L76>
    pub fn to_login_prf_option(&self) -> Option<Value> {
        (self.prf_status() == WebauthnPrfStatus::Enabled).then(|| {
            json!({
                "EncryptedPrivateKey": self.encrypted_private_key,
                "EncryptedUserKey": self.encrypted_user_key,
                "CredentialId": self.credential_id,
                "Transports": [],
            })
        })
    }
}

/// Database methods
impl WebauthnCredential {
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(webauthn_credentials::table).values(self).execute(conn).map_res("Error saving passkey")
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            webauthn_credentials::table
                .filter(webauthn_credentials::user_uuid.eq(user_uuid))
                .order(webauthn_credentials::created_at)
                .load::<Self>(conn)
                .expect("Error loading passkeys")
        })
        .await
    }

    pub async fn find_by_user_and_credential_id(
        user_uuid: &UserId,
        credential_id: &str,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            webauthn_credentials::table
                .filter(webauthn_credentials::user_uuid.eq(user_uuid))
                .filter(webauthn_credentials::credential_id.eq(credential_id))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// `false` when the credential is gone or already answered a challenge issued at the same time or later. A single
    /// statement, so that two concurrent uses of one assertion can't both pass.
    pub async fn use_challenge(&self, issued_at: i64, passkey: &Passkey, conn: &DbConn) -> ApiResult<bool> {
        let credential = serde_json::to_string(passkey)?;
        let now = Utc::now().naive_utc();
        let updated: usize = conn
            .run(move |conn| {
                diesel::update(
                    webauthn_credentials::table.filter(webauthn_credentials::uuid.eq(&self.uuid)).filter(
                        webauthn_credentials::last_challenge_issued_at
                            .is_null()
                            .or(webauthn_credentials::last_challenge_issued_at.lt(issued_at)),
                    ),
                )
                .set((
                    webauthn_credentials::credential.eq(credential),
                    webauthn_credentials::last_challenge_issued_at.eq(Some(issued_at)),
                    webauthn_credentials::updated_at.eq(now),
                ))
                .execute(conn)
                .map_res("Error saving passkey")
            })
            .await?;
        Ok(updated == 1)
    }

    pub async fn set_prf_keys(
        &self,
        encrypted_user_key: String,
        encrypted_public_key: String,
        encrypted_private_key: String,
        conn: &DbConn,
    ) -> EmptyResult {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(webauthn_credentials::table.filter(webauthn_credentials::uuid.eq(&self.uuid)))
                .set((
                    webauthn_credentials::encrypted_user_key.eq(Some(encrypted_user_key)),
                    webauthn_credentials::encrypted_public_key.eq(Some(encrypted_public_key)),
                    webauthn_credentials::encrypted_private_key.eq(Some(encrypted_private_key)),
                    webauthn_credentials::updated_at.eq(now),
                ))
                .execute(conn)
                .map_res("Error saving passkey")
        })
        .await
    }

    /// The private key stays: the PRF key wraps it, not the user key.
    pub async fn rotate_keys(
        &self,
        encrypted_user_key: String,
        encrypted_public_key: String,
        conn: &DbConn,
    ) -> EmptyResult {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(webauthn_credentials::table.filter(webauthn_credentials::uuid.eq(&self.uuid)))
                .set((
                    webauthn_credentials::encrypted_user_key.eq(Some(encrypted_user_key)),
                    webauthn_credentials::encrypted_public_key.eq(Some(encrypted_public_key)),
                    webauthn_credentials::updated_at.eq(now),
                ))
                .execute(conn)
                .map_res("Error saving passkey")
        })
        .await
    }

    /// `false` when the user has no credential with that id.
    pub async fn delete_by_uuid_and_user(
        uuid: &WebauthnCredentialId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> ApiResult<bool> {
        let deleted: usize = conn
            .run(move |conn| {
                diesel::delete(
                    webauthn_credentials::table
                        .filter(webauthn_credentials::uuid.eq(uuid))
                        .filter(webauthn_credentials::user_uuid.eq(user_uuid)),
                )
                .execute(conn)
                .map_res("Error deleting passkey")
            })
            .await?;
        Ok(deleted == 1)
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(webauthn_credentials::table.filter(webauthn_credentials::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting passkeys")
        })
        .await
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
pub struct WebauthnCredentialId(String);

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;
    use crate::db::{models::User, test_db};

    /// A passkey as webauthn-rs stores it, with the key from its own test data
    const PASSKEY: &str = r#"{"cred":{"cred_id":"dmF1bHR3YXJkZW4gdGVzdCBwYXNza2V5","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":[194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],"y":[143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]}}},"counter":2,"user_verified":true,"backup_eligible":false,"backup_state":false,"registration_policy":"required","extensions":{"cred_protect":"NotRequested","hmac_create_secret":"NotRequested"},"attestation":{"data":"None","metadata":"None"},"attestation_format":"None"}}"#;

    #[test]
    fn assertions_are_single_use_and_key_writes_leave_the_rest() {
        test_db::run(async |db| {
            let conn = db.conn();
            let mut user = User::new("passkey@example.com", None);
            user.save(&conn).await.unwrap();
            let passkey: Passkey = serde_json::from_str(PASSKEY).unwrap();
            let credential = WebauthnCredential::new(
                user.uuid.clone(),
                "Key".into(),
                &passkey,
                true,
                Some("4.user".into()),
                Some("2.public".into()),
                Some("2.private".into()),
            )
            .unwrap();
            credential.insert(&conn).await.unwrap();
            let stored = async || {
                WebauthnCredential::find_by_user_and_credential_id(&user.uuid, &credential.credential_id, &conn)
                    .await
                    .unwrap()
            };

            // A challenge is answered once, and an older one can't follow a newer one
            assert!(credential.use_challenge(1_000, &passkey, &conn).await.unwrap());
            assert!(!credential.use_challenge(1_000, &passkey, &conn).await.unwrap());
            assert!(credential.use_challenge(2_000, &passkey, &conn).await.unwrap());
            assert!(!credential.use_challenge(1_500, &passkey, &conn).await.unwrap());

            // A rotation keeps the private key, which the PRF key wraps, and the challenge
            credential.rotate_keys("4.user2".into(), "2.public2".into(), &conn).await.unwrap();
            let rotated = stored().await;
            assert_eq!(rotated.encrypted_user_key.as_deref(), Some("4.user2"));
            assert_eq!(rotated.encrypted_public_key.as_deref(), Some("2.public2"));
            assert_eq!(rotated.encrypted_private_key.as_deref(), Some("2.private"));
            assert_eq!(rotated.last_challenge_issued_at, Some(2_000));
            assert_eq!(rotated.credential, credential.credential);

            // Deleted, it can't answer any challenge
            assert!(WebauthnCredential::delete_by_uuid_and_user(&credential.uuid, &user.uuid, &conn).await.unwrap());
            assert!(!credential.use_challenge(3_000, &passkey, &conn).await.unwrap());
        });
    }
}
