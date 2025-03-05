use std::time::Duration;

use bigdecimal::{BigDecimal, ToPrimitive};
use derive_more::{AsRef, Deref, Display};
use serde_json::Value;

use super::{CipherId, OrganizationId, UserId};
use crate::{config::PathType, CONFIG};
use macros::IdFromParam;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = attachments)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(id))]
    pub struct Attachment {
        pub id: AttachmentId,
        pub cipher_uuid: CipherId,
        pub file_name: String, // encrypted
        pub file_size: i64,
        pub akey: Option<String>,
    }
}

/// Local methods
impl Attachment {
    pub const fn new(
        id: AttachmentId,
        cipher_uuid: CipherId,
        file_name: String,
        file_size: i64,
        akey: Option<String>,
    ) -> Self {
        Self {
            id,
            cipher_uuid,
            file_name,
            file_size,
            akey,
        }
    }

    pub fn get_file_path(&self) -> String {
        format!("{}/{}", self.cipher_uuid, self.id)
    }

    pub async fn get_url(&self, host: &str) -> Result<String, crate::Error> {
        let operator = CONFIG.opendal_operator_for_path_type(PathType::Attachments)?;

        if operator.info().scheme() == opendal::Scheme::Fs {
            let token = encode_jwt(&generate_file_download_claims(self.cipher_uuid.clone(), self.id.clone()));
            Ok(format!("{host}/attachments/{}/{}?token={token}", self.cipher_uuid, self.id))
        } else {
            Ok(operator
                .presign_read(&self.get_file_path(), Duration::from_secs(5 * 60))
                .await
                .map_err(Into::<crate::Error>::into)?
                .uri()
                .to_string())
        }
    }

    pub async fn to_json(&self, host: &str) -> Result<Value, crate::Error> {
        Ok(json!({
            "id": self.id,
            "url": self.get_url(host).await?,
            "fileName": self.file_name,
            "size": self.file_size.to_string(),
            "sizeName": crate::util::get_display_size(self.file_size),
            "key": self.akey,
            "object": "attachment"
        }))
    }
}

use crate::auth::{encode_jwt, generate_file_download_claims};
use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Attachment {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(attachments::table)
                    .values(AttachmentDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(attachments::table)
                            .filter(attachments::id.eq(&self.id))
                            .set(AttachmentDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving attachment")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving attachment")
            }
            postgresql {
                let value = AttachmentDb::to_db(self);
                diesel::insert_into(attachments::table)
                    .values(&value)
                    .on_conflict(attachments::id)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving attachment")
            }
        }
    }

    pub async fn delete(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            crate::util::retry(
                || diesel::delete(attachments::table.filter(attachments::id.eq(&self.id))).execute(conn),
                10,
            )
            .map(|_| ())
            .map_res("Error deleting attachment")
        }}?;

        let operator = CONFIG.opendal_operator_for_path_type(PathType::Attachments)?;
        let file_path = self.get_file_path();

        if let Err(e) = operator.delete_iter([file_path.clone()]).await {
            if e.kind() == opendal::ErrorKind::NotFound {
                debug!("File '{file_path}' already deleted.");
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &mut DbConn) -> EmptyResult {
        for attachment in Attachment::find_by_cipher(cipher_uuid, conn).await {
            attachment.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_id(id: &AttachmentId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            attachments::table
                .filter(attachments::id.eq(id.to_lowercase()))
                .first::<AttachmentDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_cipher(cipher_uuid: &CipherId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            attachments::table
                .filter(attachments::cipher_uuid.eq(cipher_uuid))
                .load::<AttachmentDb>(conn)
                .expect("Error loading attachments")
                .from_db()
        }}
    }

    pub async fn size_by_user(user_uuid: &UserId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            let result: Option<BigDecimal> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");

            match result.map(|r| r.to_i64()) {
                Some(Some(r)) => r,
                Some(None) => i64::MAX,
                None => 0
            }
        }}
    }

    pub async fn count_by_user(user_uuid: &UserId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        }}
    }

    pub async fn size_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            let result: Option<BigDecimal> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");

            match result.map(|r| r.to_i64()) {
                Some(Some(r)) => r,
                Some(None) => i64::MAX,
                None => 0
            }
        }}
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        }}
    }

    // This will return all attachments linked to the user or org
    // There is no filtering done here if the user actually has access!
    // It is used to speed up the sync process, and the matching is done in a different part.
    pub async fn find_all_by_user_and_orgs(
        user_uuid: &UserId,
        org_uuids: &Vec<OrganizationId>,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .or_filter(ciphers::organization_uuid.eq_any(org_uuids))
                .select(attachments::all_columns)
                .load::<AttachmentDb>(conn)
                .expect("Error loading attachments")
                .from_db()
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
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    IdFromParam,
)]
pub struct AttachmentId(pub String);
