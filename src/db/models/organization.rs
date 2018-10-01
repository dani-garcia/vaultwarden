use serde_json::Value as JsonValue;

use uuid::Uuid;
use super::{User, CollectionUser};

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
            "MaxStorageGb": 10, // The value doesn't matter, we don't check server-side
            "Use2fa": true,
            "UseDirectory": false,
            "UseEvents": false,
            "UseGroups": false,
            "UseTotp": true,

            "BusinessName": null,
            "BusinessAddress1":	null,
            "BusinessAddress2":	null,
            "BusinessAddress3":	null,
            "BusinessCountry": null,
            "BusinessTaxNumber": null,

            "BillingEmail": self.billing_email,
            "Plan": "TeamsAnnually",
            "PlanType": 5, // TeamsAnnually plan
            "UsersGetPremium": true,
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
use db::schema::{organizations, users_organizations, users_collections, ciphers_collections};

/// Database methods
impl Organization {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        UserOrganization::find_by_org(&self.uuid, conn)
        .iter()
        .for_each(|user_org| {
            User::update_uuid_revision(&user_org.user_uuid, conn);
        });

        match diesel::replace_into(organizations::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> QueryResult<()> {
        use super::{Cipher, Collection};

        Cipher::delete_all_by_organization(&self.uuid, &conn)?;
        Collection::delete_all_by_organization(&self.uuid, &conn)?;
        UserOrganization::delete_all_by_organization(&self.uuid, &conn)?;

        diesel::delete(
            organizations::table.filter(
                organizations::uuid.eq(self.uuid)
            )
        ).execute(&**conn).and(Ok(()))
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
            "UsersGetPremium": true,

            "Use2fa": true,
            "UseDirectory": false,
            "UseEvents": false,
            "UseGroups": false,
            "UseTotp": true,

            "MaxStorageGb": 10, // The value doesn't matter, we don't check server-side

            // These are per user
            "Key": self.key,
            "Status": self.status,
            "Type": self.type_,
            "Enabled": true,

            "Object": "profileOrganization",
        })
    }

    pub fn to_json_user_details(&self, conn: &DbConn) -> JsonValue {
        let user = User::find_by_uuid(&self.user_uuid, conn).unwrap();

        json!({
            "Id": self.uuid,
            "UserId": self.user_uuid,
            "Name": user.name,
            "Email": user.email,

            "Status": self.status,
            "Type": self.type_,
            "AccessAll": self.access_all,

            "Object": "organizationUserUserDetails",
        })
    }

    pub fn to_json_collection_user_details(&self, read_only: bool, conn: &DbConn) -> JsonValue {
        let user = User::find_by_uuid(&self.user_uuid, conn).unwrap();

        json!({
            "OrganizationUserId": self.uuid,
            "AccessAll": self.access_all,
            "Name": user.name,
            "Email": user.email,
            "Type": self.type_,
            "Status": self.status,
            "ReadOnly": read_only,
            "Object": "collectionUser",
        })
    }

    pub fn to_json_details(&self, conn: &DbConn) -> JsonValue {        
        let coll_uuids = if self.access_all { 
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections = CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn);
            collections.iter().map(|c| json!({"Id": c.collection_uuid, "ReadOnly": c.read_only})).collect()
        };

        json!({
            "Id": self.uuid,
            "UserId": self.user_uuid,

            "Status": self.status,
            "Type": self.type_,
            "AccessAll": self.access_all,
            "Collections": coll_uuids,

            "Object": "organizationUserDetails",
        })
    }

    pub fn save(&mut self, conn: &DbConn) -> bool {
        User::update_uuid_revision(&self.user_uuid, conn);

        match diesel::replace_into(users_organizations::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> QueryResult<()> {
        User::update_uuid_revision(&self.user_uuid, conn);

        CollectionUser::delete_all_by_user(&self.user_uuid, &conn)?;

        diesel::delete(
            users_organizations::table.filter(
                users_organizations::uuid.eq(self.uuid)
            )
        ).execute(&**conn).and(Ok(()))
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> QueryResult<()> {
        for user_org in Self::find_by_org(&org_uuid, &conn) {
            user_org.delete(&conn)?;
        }
        Ok(())
    }

    pub fn has_full_access(self) -> bool {
        self.access_all || self.type_ < UserOrgType::User as i32
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        users_organizations::table
            .filter(users_organizations::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
        users_organizations::table
            .filter(users_organizations::uuid.eq(uuid))
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .filter(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
            .load::<Self>(&**conn).unwrap_or_default()
    }

    pub fn find_invited_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .filter(users_organizations::status.eq(UserOrgStatus::Invited as i32))
            .load::<Self>(&**conn).unwrap_or_default()
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

    pub fn find_by_cipher_and_org(cipher_uuid: &str, org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
        .filter(users_organizations::org_uuid.eq(org_uuid))
        .left_join(users_collections::table.on(
            users_collections::user_uuid.eq(users_organizations::user_uuid)
        ))
        .left_join(ciphers_collections::table.on(
            ciphers_collections::collection_uuid.eq(users_collections::collection_uuid).and(
                ciphers_collections::cipher_uuid.eq(&cipher_uuid)
            )
        ))
        .filter(
            users_organizations::access_all.eq(true).or( // AccessAll..
                ciphers_collections::cipher_uuid.eq(&cipher_uuid) // ..or access to collection with cipher
            )
        )
        .select(users_organizations::all_columns)
        .load::<Self>(&**conn).expect("Error loading user organizations")
    }

    pub fn find_by_collection_and_org(collection_uuid: &str, org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
        .filter(users_organizations::org_uuid.eq(org_uuid))
        .left_join(users_collections::table.on(
            users_collections::user_uuid.eq(users_organizations::user_uuid)
        ))
        .filter(
            users_organizations::access_all.eq(true).or( // AccessAll..
                users_collections::collection_uuid.eq(&collection_uuid) // ..or access to collection with cipher
            )
        )
        .select(users_organizations::all_columns)
        .load::<Self>(&**conn).expect("Error loading user organizations")
    }

}


