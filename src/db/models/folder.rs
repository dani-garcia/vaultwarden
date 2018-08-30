use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::{User, Cipher};

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "folders"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[primary_key(uuid)]
pub struct Folder {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub user_uuid: String,
    pub name: String,
}

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "folders_ciphers"]
#[belongs_to(Cipher, foreign_key = "cipher_uuid")]
#[belongs_to(Folder, foreign_key = "folder_uuid")]
#[primary_key(cipher_uuid, folder_uuid)]
pub struct FolderCipher {
    pub cipher_uuid: String,
    pub folder_uuid: String,
}

/// Local methods
impl Folder {
    pub fn new(user_uuid: String, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        use util::format_date;

        json!({
            "Id": self.uuid,
            "RevisionDate": format_date(&self.updated_at),
            "Name": self.name,
            "Object": "folder",
        })
    }
}

impl FolderCipher {
    pub fn new(folder_uuid: &str, cipher_uuid: &str) -> Self {
        Self {
            folder_uuid: folder_uuid.to_string(),
            cipher_uuid: cipher_uuid.to_string(),
        }
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::{folders, folders_ciphers};

/// Database methods
impl Folder {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        User::update_uuid_revision(&self.user_uuid, conn);
        self.updated_at = Utc::now().naive_utc();

        match diesel::replace_into(folders::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(&self, conn: &DbConn) -> QueryResult<()> {
        User::update_uuid_revision(&self.user_uuid, conn);
        FolderCipher::delete_all_by_folder(&self.uuid, &conn)?;

        diesel::delete(
            folders::table.filter(
                folders::uuid.eq(&self.uuid)
            )
        ).execute(&**conn).and(Ok(()))
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        folders::table
            .filter(folders::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        folders::table
            .filter(folders::user_uuid.eq(user_uuid))
            .load::<Self>(&**conn).expect("Error loading folders")
    }
}

impl FolderCipher {
    pub fn save(&self, conn: &DbConn) -> QueryResult<()> {
        diesel::replace_into(folders_ciphers::table)
        .values(&*self)
        .execute(&**conn).and(Ok(()))
    }

    pub fn delete(self, conn: &DbConn) -> QueryResult<()> {
        diesel::delete(folders_ciphers::table
            .filter(folders_ciphers::cipher_uuid.eq(self.cipher_uuid))
            .filter(folders_ciphers::folder_uuid.eq(self.folder_uuid))
        ).execute(&**conn).and(Ok(()))
    }

    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> QueryResult<()> {
        diesel::delete(folders_ciphers::table
            .filter(folders_ciphers::cipher_uuid.eq(cipher_uuid))
        ).execute(&**conn).and(Ok(()))
    }

    pub fn delete_all_by_folder(folder_uuid: &str, conn: &DbConn) -> QueryResult<()> {
        diesel::delete(folders_ciphers::table
            .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
        ).execute(&**conn).and(Ok(()))
    }

    pub fn find_by_folder_and_cipher(folder_uuid: &str, cipher_uuid: &str, conn: &DbConn) -> Option<Self> {
        folders_ciphers::table
            .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
            .filter(folders_ciphers::cipher_uuid.eq(cipher_uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_folder(folder_uuid: &str, conn: &DbConn) -> Vec<Self> {
        folders_ciphers::table
            .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
            .load::<Self>(&**conn).expect("Error loading folders")
    }
}
