use chrono::{NaiveDate, NaiveDateTime, Utc};
use time::Duration;
use serde_json::Value as JsonValue;

use uuid::Uuid;

#[derive(Queryable, Insertable, Identifiable)]
#[table_name = "ciphers"]
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
    pub attachments: Option<Vec<u8>>,
}

/// Local methods
impl Cipher {
    pub fn new(user_uuid: String, type_: i32, favorite: bool) -> Cipher {
        let now = Utc::now().naive_utc();

        Cipher {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,

            user_uuid,
            folder_uuid: None,
            organization_uuid: None,

            type_,
            favorite,

            data: String::new(),
            attachments: None,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        use serde_json;
        use util::format_date;

        let data: JsonValue = serde_json::from_str(&self.data).unwrap();

        json!({
            "Id": self.uuid,
            "Type": self.type_,
            "RevisionDate": format_date(&self.updated_at),
            "FolderId": self.folder_uuid,
            "Favorite": self.favorite,
            "OrganizationId": "",
            "Attachments": self.attachments,
            "OrganizationUseTotp": false,
            "Data": data,
            "Object": "cipher",
            "Edit": true,
        })
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::ciphers;

/// Database methods
impl Cipher {
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

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Cipher> {
        ciphers::table
            .filter(ciphers::uuid.eq(uuid))
            .first::<Cipher>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Cipher> {
        ciphers::table
            .filter(ciphers::user_uuid.eq(user_uuid))
            .load::<Cipher>(&**conn).expect("Error loading ciphers")
    }
}
