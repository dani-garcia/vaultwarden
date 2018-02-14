use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::User;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "ciphers"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[primary_key(uuid)]
pub struct Cipher {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: String,
    pub folder_uuid: Option<String>,
    pub organization_uuid: Option<String>,

    // Login = 1,
    // SecureNote = 2,
    // Card = 3,
    // Identity = 4
    pub type_: i32,

    pub data: String,
    pub favorite: bool,
}

/// Local methods
impl Cipher {
    pub fn new(user_uuid: String, type_: i32, favorite: bool) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,

            user_uuid,
            folder_uuid: None,
            organization_uuid: None,

            type_,
            favorite,

            data: String::new(),
        }
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::ciphers;

/// Database methods
impl Cipher {
    pub fn to_json(&self, conn: &DbConn) -> JsonValue {
        use serde_json;
        use util::format_date;
        use super::Attachment;

        let data_json: JsonValue = serde_json::from_str(&self.data).unwrap();

        let attachments = Attachment::find_by_cipher(&self.uuid, conn);
        let attachments_json: Vec<JsonValue> = attachments.iter().map(|c| c.to_json()).collect();

        json!({
            "Id": self.uuid,
            "Type": self.type_,
            "RevisionDate": format_date(&self.updated_at),
            "FolderId": self.folder_uuid,
            "Favorite": self.favorite,
            "OrganizationId": "",
            "Attachments": attachments_json,
            "OrganizationUseTotp": false,
            "Data": data_json,
            "Object": "cipher",
            "Edit": true,
        })
    }

    pub fn save(&self, conn: &DbConn) -> bool {
        // TODO: Update modified date

        match diesel::replace_into(ciphers::table)
            .values(self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(ciphers::table.filter(
            ciphers::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        ciphers::table
            .filter(ciphers::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
            .filter(ciphers::user_uuid.eq(user_uuid))
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }
}
