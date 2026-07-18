use chrono::{NaiveDateTime, Utc};
use derive_more::Display;
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    crypto,
    db::{DbConn, models::OrganizationId, schema::scim_api_key},
    error::MapResult,
};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = scim_api_key)]
#[diesel(primary_key(uuid))]
pub struct ScimApiKey {
    pub uuid: ScimApiKeyId,
    pub org_uuid: OrganizationId,
    // sha256 hex digest of the token secret. The plaintext secret is shown once
    // at generation time and never stored or logged.
    pub key_hash: String,
    pub enabled: bool,
    pub created_at: NaiveDateTime,
    pub revision_date: NaiveDateTime,
}

#[derive(Clone, Debug, DieselNewType, Display, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimApiKeyId(String);

impl ScimApiKey {
    pub fn new(org_uuid: OrganizationId, key_hash: String) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: ScimApiKeyId(crate::util::get_uuid()),
            org_uuid,
            key_hash,
            enabled: true,
            created_at: now,
            revision_date: now,
        }
    }

    // Constant-time comparison against a plaintext secret's digest. A dummy
    // digest is compared when no key row exists so the caller can keep the
    // verification cost independent of row presence.
    pub fn check_valid_secret(&self, secret: &str) -> bool {
        crypto::ct_eq(&self.key_hash, crypto::sha256_hex(secret.as_bytes()))
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        // Rotation replaces the row wholesale (delete + insert), so a plain
        // insert with an update fallback covers every backend identically.
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(scim_api_key::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(scim_api_key::table)
                            .filter(scim_api_key::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving SCIM api key")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving SCIM api key")
            }
            postgresql {
                diesel::insert_into(scim_api_key::table)
                    .values(self)
                    .on_conflict(scim_api_key::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving SCIM api key")
            }
        }
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| scim_api_key::table.filter(scim_api_key::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_active_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            scim_api_key::table
                .filter(scim_api_key::org_uuid.eq(org_uuid))
                .filter(scim_api_key::enabled.eq(true))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(scim_api_key::table.filter(scim_api_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing SCIM api key from organization")
        })
        .await
    }
}
