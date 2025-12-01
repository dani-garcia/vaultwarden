use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use serde_json::Value;

use super::{CipherId, User, UserId};
use crate::db::schema::{folders, folders_ciphers};
use diesel::prelude::*;
use macros::UuidFromParam;

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = folders)]
#[diesel(primary_key(uuid))]
pub struct Folder {
    pub uuid: FolderId,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub user_uuid: UserId,
    pub name: String,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = folders_ciphers)]
#[diesel(primary_key(cipher_uuid, folder_uuid))]
pub struct FolderCipher {
    pub cipher_uuid: CipherId,
    pub folder_uuid: FolderId,
}

/// Local methods
impl Folder {
    pub fn new(user_uuid: UserId, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: FolderId(crate::util::get_uuid()),
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "id": self.uuid,
            "revisionDate": format_date(&self.updated_at),
            "name": self.name,
            "object": "folder",
        })
    }
}

impl FolderCipher {
    pub fn new(folder_uuid: FolderId, cipher_uuid: CipherId) -> Self {
        Self {
            folder_uuid,
            cipher_uuid,
        }
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Folder {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(folders::table)
                    .values(&*self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(folders::table)
                            .filter(folders::uuid.eq(&self.uuid))
                            .set(&*self)
                            .execute(conn)
                            .map_res("Error saving folder")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving folder")
            }
            postgresql {
                diesel::insert_into(folders::table)
                    .values(&*self)
                    .on_conflict(folders::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving folder")
            }
        }
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;
        FolderCipher::delete_all_by_folder(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(folders::table.filter(folders::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting folder")
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        for folder in Self::find_by_user(user_uuid, conn).await {
            folder.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_uuid_and_user(uuid: &FolderId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            folders::table
                .filter(folders::uuid.eq(uuid))
                .filter(folders::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            folders::table
                .filter(folders::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading folders")
        }}
    }
}

impl FolderCipher {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                // Not checking for ForeignKey Constraints here.
                // Table folders_ciphers does not have ForeignKey Constraints which would cause conflicts.
                // This table has no constraints pointing to itself, but only to others.
                diesel::replace_into(folders_ciphers::table)
                    .values(self)
                    .execute(conn)
                    .map_res("Error adding cipher to folder")
            }
            postgresql {
                diesel::insert_into(folders_ciphers::table)
                    .values(self)
                    .on_conflict((folders_ciphers::cipher_uuid, folders_ciphers::folder_uuid))
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to folder")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                folders_ciphers::table
                    .filter(folders_ciphers::cipher_uuid.eq(self.cipher_uuid))
                    .filter(folders_ciphers::folder_uuid.eq(self.folder_uuid)),
            )
            .execute(conn)
            .map_res("Error removing cipher from folder")
        }}
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(folders_ciphers::table.filter(folders_ciphers::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from folders")
        }}
    }

    pub async fn delete_all_by_folder(folder_uuid: &FolderId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(folders_ciphers::table.filter(folders_ciphers::folder_uuid.eq(folder_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from folder")
        }}
    }

    pub async fn find_by_folder_and_cipher(
        folder_uuid: &FolderId,
        cipher_uuid: &CipherId,
        conn: &DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            folders_ciphers::table
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .filter(folders_ciphers::cipher_uuid.eq(cipher_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_folder(folder_uuid: &FolderId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            folders_ciphers::table
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .load::<Self>(conn)
                .expect("Error loading folders")
        }}
    }

    /// Return a vec with (cipher_uuid, folder_uuid)
    /// This is used during a full sync so we only need one query for all folder matches.
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<(CipherId, FolderId)> {
        db_run! { conn: {
            folders_ciphers::table
                .inner_join(folders::table)
                .filter(folders::user_uuid.eq(user_uuid))
                .select(folders_ciphers::all_columns)
                .load::<(CipherId, FolderId)>(conn)
                .unwrap_or_default()
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
pub struct FolderId(String);
