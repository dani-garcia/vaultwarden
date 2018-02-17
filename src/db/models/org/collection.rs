use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::Organization;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "collections"]
#[belongs_to(Organization, foreign_key = "org_uuid")]
#[primary_key(uuid)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: String, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: Uuid::new_v4().to_string(),

            org_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Name": self.name,
            "Object": "collection",
        })
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::collections;

/// Database methods
impl Collection {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        self.updated_at = Utc::now().naive_utc();

        match diesel::replace_into(collections::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(collections::table.filter(
            collections::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        collections::table
            .filter(collections::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }
}
