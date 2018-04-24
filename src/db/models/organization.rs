use serde_json::Value as JsonValue;

use uuid::Uuid;

#[derive(Debug, Identifiable, Queryable, Insertable)]
#[table_name = "organizations"]
#[primary_key(uuid)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
}

#[derive(Debug, Identifiable, Queryable, Insertable)]
#[table_name = "users_organizations"]
#[primary_key(uuid)]
pub struct UserOrganization {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,

    pub access_all: bool,
    pub key: String,
    pub status: i32,
    pub type_: i32,
}

pub enum UserOrgStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

pub enum UserOrgType {
    Owner = 0,
    Admin = 1,
    User = 2,
}

impl UserOrgType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "Owner" => Some(UserOrgType::Owner),
            "1" | "Admin" => Some(UserOrgType::Admin),
            "2" | "User" => Some(UserOrgType::User),
            _ => None,
        }
    }
}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),

            name,
            billing_email,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "Name": self.name,
            "Seats": 10,
            "MaxCollections": 10,

            "Use2fa": false,
            "UseDirectory": false,
            "UseEvents": false,
            "UseGroups": false,
            "UseTotp": false,

            "BusinessName": null,
            "BusinessAddress1":	null,
            "BusinessAddress2":	null,
            "BusinessAddress3":	null,
            "BusinessCountry": null,
            "BusinessTaxNumber": null,

            "BillingEmail": self.billing_email,
            "Plan": "Free",
            "PlanType": 0, // Free plan

            "Object": "organization",
        })
    }
}

impl UserOrganization {
    pub fn new(user_uuid: String, org_uuid: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),

            user_uuid,
            org_uuid,

            access_all: false,
            key: String::new(),
            status: UserOrgStatus::Accepted as i32,
            type_: UserOrgType::User as i32,
        }
    }
}


use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::organizations;
use db::schema::users_organizations;

/// Database methods
impl Organization {
    pub fn save(&mut self, conn: &DbConn) -> bool {
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

impl UserOrganization {
    pub fn to_json(&self, conn: &DbConn) -> JsonValue {
        let org = Organization::find_by_uuid(&self.org_uuid, conn).unwrap();

        json!({
            "Id": self.org_uuid,
            "Name": org.name,
            "Seats": 10,
            "MaxCollections": 10,

            "Use2fa": false,
            "UseDirectory": false,
            "UseEvents": false,
            "UseGroups": false,
            "UseTotp": false,

            "MaxStorageGb": null,

            // These are per user
            "Key": self.key,
            "Status": self.status,
            "Type": self.type_,
            "Enabled": true,

            "Object": "profileOrganization",
        })
    }

    pub fn to_json_user_details(&self, conn: &DbConn) -> JsonValue {
        use super::User;
        let user = User::find_by_uuid(&self.user_uuid, conn).unwrap();

        json!({
            "Id": self.uuid,
            "UserId": self.user_uuid,
            "Name": user.name,
            "Email": user.email,

            "Status": self.status,
            "Type": self.type_,
            "AccessAll": true,

            "Object": "organizationUserUserDetails",
        })
    }

    pub fn to_json_details(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "UserId": self.user_uuid,

            "Status": self.status,
            "Type": self.type_,
            "AccessAll": true,
            "Collections": [],

            "Object": "organizationUserDetails",
        })
    }

    pub fn save(&mut self, conn: &DbConn) -> bool {
        match diesel::replace_into(users_organizations::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(users_organizations::table.filter(
            users_organizations::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        users_organizations::table
            .filter(users_organizations::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .load::<Self>(&**conn).expect("Error loading user organizations")
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .load::<Self>(&**conn).expect("Error loading user organizations")
    }

    pub fn find_by_org_and_type(org_uuid: &str, type_: i32, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .filter(users_organizations::type_.eq(type_))
            .load::<Self>(&**conn).expect("Error loading user organizations")
    }

    pub fn find_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .first::<Self>(&**conn).ok()
    }
}


