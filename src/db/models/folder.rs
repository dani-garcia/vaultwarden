use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::User;

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

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::folders;

/// Database methods
impl Folder {
    pub fn save(&self, conn: &DbConn) -> bool {
        // TODO: Update modified date

        match diesel::replace_into(folders::table)
            .values(self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(folders::table.filter(
            folders::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
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
