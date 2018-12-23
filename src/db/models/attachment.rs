use serde_json::Value;

use super::Cipher;
use crate::CONFIG;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "attachments"]
#[belongs_to(Cipher, foreign_key = "cipher_uuid")]
#[primary_key(id)]
pub struct Attachment {
    pub id: String,
    pub cipher_uuid: String,
    pub file_name: String,
    pub file_size: i32,
    pub key: Option<String>,
}

/// Local methods
impl Attachment {
    pub fn new(id: String, cipher_uuid: String, file_name: String, file_size: i32) -> Self {
        Self {
            id,
            cipher_uuid,
            file_name,
            file_size,
            key: None,
        }
    }

    pub fn get_file_path(&self) -> String {
        format!("{}/{}/{}", CONFIG.attachments_folder, self.cipher_uuid, self.id)
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
            "Key": self.key,
            "Object": "attachment"
        })
    }
}

use diesel;
use diesel::prelude::*;
use crate::db::DbConn;
use crate::db::schema::attachments;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Attachment {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        diesel::replace_into(attachments::table)
            .values(self)
            .execute(&**conn)
            .map_res("Error saving attachment")
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        crate::util::retry(
            || diesel::delete(attachments::table.filter(attachments::id.eq(&self.id)))
                .execute(&**conn),
            10,
        )
        .map_res("Error deleting attachment")?;
        
        crate::util::delete_file(&self.get_file_path())?;
        Ok(())
    }

    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        for attachment in Attachment::find_by_cipher(&cipher_uuid, &conn) {
            attachment.delete(&conn)?;
        }
        Ok(())
    }

    pub fn find_by_id(id: &str, conn: &DbConn) -> Option<Self> {
        attachments::table.filter(attachments::id.eq(id)).first::<Self>(&**conn).ok()
    }

    pub fn find_by_cipher(cipher_uuid: &str, conn: &DbConn) -> Vec<Self> {
        attachments::table
            .filter(attachments::cipher_uuid.eq(cipher_uuid))
            .load::<Self>(&**conn)
            .expect("Error loading attachments")
    }

    pub fn find_by_ciphers(cipher_uuids: Vec<String>, conn: &DbConn) -> Vec<Self> {
        attachments::table
            .filter(attachments::cipher_uuid.eq_any(cipher_uuids))
            .load::<Self>(&**conn)
            .expect("Error loading attachments")
    }
}
