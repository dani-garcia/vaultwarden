use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use super::{Cipher, User};

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
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
}

/// Local methods
impl Folder {
    pub fn new(user_uuid: String, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

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

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Folder {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn: 
            sqlite, mysql {   
                diesel::replace_into(folders::table)
                    .values(FolderDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving folder")
            }
            postgresql {
                let value = FolderDb::to_db(self);
                diesel::insert_into(folders::table)
                    .values(&value)
                    .on_conflict(folders::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving folder")
            }
        }
    }

    pub fn delete(&self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);
        FolderCipher::delete_all_by_folder(&self.uuid, &conn)?;

        
        db_run! { conn: {
            diesel::delete(folders::table.filter(folders::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting folder")
        }}
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for folder in Self::find_by_user(user_uuid, &conn) {
            folder.delete(&conn)?;
        }
        Ok(())
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            folders::table
                .filter(folders::uuid.eq(uuid))
                .first::<FolderDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            folders::table
                .filter(folders::user_uuid.eq(user_uuid))
                .load::<FolderDb>(conn)
                .expect("Error loading folders")
                .from_db()
        }}
    }
}

impl FolderCipher {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: 
            sqlite, mysql {
                diesel::replace_into(folders_ciphers::table)
                    .values(FolderCipherDb::to_db(self))
                    .execute(conn)
                    .map_res("Error adding cipher to folder")
            }
            postgresql {
                diesel::insert_into(folders_ciphers::table)
                    .values(FolderCipherDb::to_db(self))
                    .on_conflict((folders_ciphers::cipher_uuid, folders_ciphers::folder_uuid))
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to folder") 
            }
        }  
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
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

    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(folders_ciphers::table.filter(folders_ciphers::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from folders")
        }}
    }

    pub fn delete_all_by_folder(folder_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(folders_ciphers::table.filter(folders_ciphers::folder_uuid.eq(folder_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from folder")
        }}
    }

    pub fn find_by_folder_and_cipher(folder_uuid: &str, cipher_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            folders_ciphers::table
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .filter(folders_ciphers::cipher_uuid.eq(cipher_uuid))
                .first::<FolderCipherDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_folder(folder_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            folders_ciphers::table
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .load::<FolderCipherDb>(conn)
                .expect("Error loading folders")
                .from_db()
        }}
    }
}
