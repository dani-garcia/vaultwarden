use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use macros::UuidFromParam;

use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::db::schema::webauthn_credentials;
use crate::error::MapResult;

use super::UserId;

#[derive(num_derive::FromPrimitive, Serialize)]
pub enum WebauthnCredentialPrfStatus {
    Enabled = 0,
    Disabled = 1,
    NotSupported = 2,
}

#[derive(Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = webauthn_credentials)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct WebauthnCredential {
    pub uuid: WebauthnCredentialId,
    pub user_uuid: UserId,
    pub name: String,
    pub credential: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

/// Local methods
impl WebauthnCredential {
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
            uuid: WebauthnCredentialId(crate::util::get_uuid()),
            user_uuid,
            name,
            credential,
            supports_prf,
            encrypted_user_key,
            encrypted_public_key,
            encrypted_private_key,
        }
    }

    pub fn get_prf_status(&self) -> WebauthnCredentialPrfStatus {
        if self.supports_prf {
            if self.encrypted_user_key.is_some()
                && self.encrypted_public_key.is_some()
                && self.encrypted_private_key.is_some()
            {
                WebauthnCredentialPrfStatus::Enabled
            } else {
                WebauthnCredentialPrfStatus::Disabled
            }
        } else {
            WebauthnCredentialPrfStatus::NotSupported
        }
    }
}

/// Database methods
impl WebauthnCredential {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::insert_into(webauthn_credentials::table)
                .values(self)
                .execute(conn)
                .map_res("Error saving webauthn_credential")
        }}
    }

    pub async fn find_all_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            webauthn_credentials::table
                .filter(webauthn_credentials::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        }}
    }

    pub async fn delete_by_uuid_and_user(
        uuid: &WebauthnCredentialId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                webauthn_credentials::table
                    .filter(webauthn_credentials::uuid.eq(uuid))
                    .filter(webauthn_credentials::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map_res("Error removing webauthn_credential")
        }}
    }

    pub async fn update_credential_by_uuid(
        uuid: &WebauthnCredentialId,
        credential: String,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            diesel::update(
                webauthn_credentials::table
                    .filter(webauthn_credentials::uuid.eq(uuid)),
            )
            .set(webauthn_credentials::credential.eq(credential))
            .execute(conn)
            .map_res("Error updating credential for webauthn_credential")
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                webauthn_credentials::table
                    .filter(webauthn_credentials::user_uuid.eq(user_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting all webauthn_credentials for user")
        }}
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
