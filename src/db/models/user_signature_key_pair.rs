use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    db::{DbConn, schema::user_signature_key_pairs},
    error::MapResult,
    util::get_uuid,
};
use macros::UuidFromParam;

use super::UserId;

/// A user's signature key pair, part of the "v2" account cryptographic state.
///
/// Upstream keeps this in its own table rather than as columns on the user, with a unique index on
/// the user id. The stated intent is to eventually keep superseded key pairs around (an `active`
/// flag was sketched but not shipped), which is why this is modelled as a row with its own identity
/// instead of a set of user attributes.
///
/// Ref: <https://github.com/bitwarden/server/blob/main/src/Sql/dbo/KeyManagement/Tables/UserSignatureKeyPair.sql>
#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = user_signature_key_pairs)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct UserSignatureKeyPair {
    pub uuid: UserSignatureKeyPairId,
    pub user_uuid: UserId,

    pub signature_algorithm: i32,
    /// The signing (private) key, wrapped by the user key.
    pub signing_key: String,
    /// The COSE-encoded public verifying key.
    pub verifying_key: String,

    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// https://github.com/bitwarden/server/blob/main/src/Core/KeyManagement/Enums/SignatureAlgorithm.cs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519 = 0,
    MlDsa44 = 1,
}

impl SignatureAlgorithm {
    pub fn from_str(algorithm: &str) -> Option<Self> {
        match algorithm {
            "ed25519" => Some(Self::Ed25519),
            "mldsa44" => Some(Self::MlDsa44),
            _ => None,
        }
    }

    pub fn from_i32(algorithm: i32) -> Option<Self> {
        match algorithm {
            0 => Some(Self::Ed25519),
            1 => Some(Self::MlDsa44),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "mldsa44",
        }
    }
}

/// Local methods
impl UserSignatureKeyPair {
    pub fn new(
        user_uuid: UserId,
        signature_algorithm: SignatureAlgorithm,
        signing_key: String,
        verifying_key: String,
    ) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: UserSignatureKeyPairId(get_uuid()),
            user_uuid,
            signature_algorithm: signature_algorithm as i32,
            signing_key,
            verifying_key,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "wrappedSigningKey": self.signing_key,
            "verifyingKey": self.verifying_key,
            "object": "signatureKeyPair",
        })
    }
}

/// Database methods
impl UserSignatureKeyPair {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            mysql {
                diesel::insert_into(user_signature_key_pairs::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving user signature key pair")
            }
            postgresql, sqlite {
                diesel::insert_into(user_signature_key_pairs::table)
                    .values(&*self)
                    .on_conflict(user_signature_key_pairs::user_uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving user signature key pair")
            }
        }
    }

    /// The key pair currently in use by the user. There is at most one today, enforced by a unique
    /// index on `user_uuid`.
    pub async fn find_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            user_signature_key_pairs::table
                .filter(user_signature_key_pairs::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(user_signature_key_pairs::table.filter(user_signature_key_pairs::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting user signature key pairs")
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
pub struct UserSignatureKeyPairId(String);
