use serde_json::Value;

use super::Cipher;
use crate::CONFIG;

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "attachments"]
    #[changeset_options(treat_none_as_null="true")]
    #[belongs_to(super::Cipher, foreign_key = "cipher_uuid")]
    #[primary_key(id)]
    pub struct Attachment {
        pub id: String,
        pub cipher_uuid: String,
        pub file_name: String,
        pub file_size: i32,
        pub akey: Option<String>,
    }
}

/// Local methods
impl Attachment {
    pub const fn new(id: String, cipher_uuid: String, file_name: String, file_size: i32) -> Self {
        Self {
            id,
            cipher_uuid,
            file_name,
            file_size,
            akey: None,
        }
    }

    pub fn get_file_path(&self) -> String {
        format!("{}/{}/{}", CONFIG.attachments_folder(), self.cipher_uuid, self.id)
    }

    pub fn to_json(&self, host: &str) -> Value {
        use crate::util::get_display_size;

        let web_path = format!("{}/attachments/{}/{}", host, self.cipher_uuid, self.id);
        let display_size = get_display_size(self.file_size);

        json!({
            "Id": self.id,
            "Url": web_path,
            "FileName": self.file_name,
            "Size": self.file_size.to_string(),
            "SizeName": display_size,
            "Key": self.akey,
            "Object": "attachment"
        })
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Attachment {

    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(attachments::table)
                    .values(AttachmentDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving attachment")
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

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            crate::util::retry(
                || diesel::delete(attachments::table.filter(attachments::id.eq(&self.id))).execute(conn),
                10,
            )
            .map_res("Error deleting attachment")?;

            crate::util::delete_file(&self.get_file_path())?;
            Ok(())
        }}
    }

    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        for attachment in Attachment::find_by_cipher(&cipher_uuid, &conn) {
            attachment.delete(&conn)?;
        }
        Ok(())
    }

    pub fn find_by_id(id: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            attachments::table
                .filter(attachments::id.eq(id.to_lowercase()))
                .first::<AttachmentDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_cipher(cipher_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            attachments::table
                .filter(attachments::cipher_uuid.eq(cipher_uuid))
                .load::<AttachmentDb>(conn)
                .expect("Error loading attachments")
                .from_db()
        }}
    }

    pub fn find_by_ciphers(cipher_uuids: Vec<String>, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            attachments::table
                .filter(attachments::cipher_uuid.eq_any(cipher_uuids))
                .load::<AttachmentDb>(conn)
                .expect("Error loading attachments")
                .from_db()
        }}
    }

    pub fn size_by_user(user_uuid: &str, conn: &DbConn) -> i64 {
        db_run! { conn: {
            let result: Option<i64> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");
            result.unwrap_or(0)
        }}
    }

    pub fn count_by_user(user_uuid: &str, conn: &DbConn) -> i64 {
        db_run! { conn: {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::user_uuid.eq(user_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        }}
    }

    pub fn size_by_org(org_uuid: &str, conn: &DbConn) -> i64 {
        db_run! { conn: {
            let result: Option<i64> = attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .select(diesel::dsl::sum(attachments::file_size))
                .first(conn)
                .expect("Error loading user attachment total size");
            result.unwrap_or(0)
        }}
    }

    pub fn count_by_org(org_uuid: &str, conn: &DbConn) -> i64 {
        db_run! { conn: {
            attachments::table
                .left_join(ciphers::table.on(ciphers::uuid.eq(attachments::cipher_uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .count()
                .first(conn)
                .unwrap_or(0)
        }}
    }
}
