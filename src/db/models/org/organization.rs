use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

#[derive(Debug, Identifiable, Queryable, Insertable)]
#[table_name = "organizations"]
#[primary_key(uuid)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,

    pub key: String,
}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: String, key: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: Uuid::new_v4().to_string(),

            name,
            billing_email,
            key,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "Name": self.name,

            "BusinessName": null,
            "BusinessAddress1":	null,
            "BusinessAddress2":	null,
            "BusinessAddress3":	null,
            "BusinessCountry": null,
            "BusinessTaxNumber": null,
            "BillingEmail":self.billing_email,
            "Plan": "Free",
            "PlanType": 0, // Free plan

            "Seats": 10,
            "MaxCollections": 10,

            "UseGroups": false,
            "UseDirectory": false,
            "UseEvents": false,
            "UseTotp": false,

            "Object": "organization",
        })
    }

    pub fn to_json_profile(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "Name": self.name,

            "Seats": 10,
            "MaxCollections": 10,

            "UseGroups": false,
            "UseDirectory": false,
            "UseEvents": false,
            "UseTotp": false,

            "MaxStorageGb": null,

            // These are probably per user
            "Key": self.key,
            "Status": 2, // Confirmed
            "Type": 0, // Owner
            "Enabled": true,

            "Object": "profileOrganization",
        })
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::organizations;

/// Database methods
impl Organization {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        self.updated_at = Utc::now().naive_utc();

        match diesel::replace_into(organizations::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(organizations::table.filter(
            organizations::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        organizations::table
            .filter(organizations::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }
}
