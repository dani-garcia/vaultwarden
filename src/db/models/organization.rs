use std::cmp::Ordering;
use serde_json::Value;

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

#[derive(Copy, Clone)]
#[derive(PartialEq)]
#[derive(Eq)]
pub enum UserOrgType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
}

impl Ord for UserOrgType {
    fn cmp(&self, other: &UserOrgType) -> Ordering {
        if self == other {
            Ordering::Equal
        } else {
            match self {
                UserOrgType::Owner => Ordering::Greater,
                UserOrgType::Admin => match other {
                    UserOrgType::Owner => Ordering::Less,
                    _ => Ordering::Greater
                },
                UserOrgType::Manager => match other {
                    UserOrgType::Owner | UserOrgType::Admin => Ordering::Less,
                    _ => Ordering::Greater
                },
                UserOrgType::User => Ordering::Less
            }
        }
    }
}

impl PartialOrd for UserOrgType {
    fn partial_cmp(&self, other: &UserOrgType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<i32> for UserOrgType {
    fn eq(&self, other: &i32) -> bool {
        *other == *self as i32
    }
}

impl PartialOrd<i32> for UserOrgType {
    fn partial_cmp(&self, other: &i32) -> Option<Ordering> {
        if let Some(other) = Self::from_i32(*other) {
            return Some(self.cmp(&other))
        }
        None
    }

    fn gt(&self, other: &i32) -> bool {
        match self.partial_cmp(other) {
            Some(Ordering::Less) | Some(Ordering::Equal) => false,
            _ => true,
        }
    }

    fn ge(&self, other: &i32) -> bool {
        match self.partial_cmp(other) {
            Some(Ordering::Less) => false,
            _ => true,
        }
    }

}

impl PartialEq<UserOrgType> for i32 {
    fn eq(&self, other: &UserOrgType) -> bool {
        *self == *other as i32
    }
}

impl PartialOrd<UserOrgType> for i32 {
    fn partial_cmp(&self, other: &UserOrgType) -> Option<Ordering> {
        if let Some(self_type) = UserOrgType::from_i32(*self) {
            return Some(self_type.cmp(other))
        }
        None
    }

    fn lt(&self, other: &UserOrgType) -> bool {
        match self.partial_cmp(other) {
            Some(Ordering::Less) | None => true,
            _ => false,
        }
    }

    fn le(&self, other: &UserOrgType) -> bool {
        match self.partial_cmp(other) {
            Some(Ordering::Less) | Some(Ordering::Equal) | None => true,
            _ => false,
        }
    }

}

impl UserOrgType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "Owner" => Some(UserOrgType::Owner),
            "1" | "Admin" => Some(UserOrgType::Admin),
            "2" | "User" => Some(UserOrgType::User),
            "3" | "Manager" => Some(UserOrgType::Manager),
            _ => None,
        }
    }

    pub fn from_i32(i: i32) -> Option<Self> {
        match i {
            0 => Some(UserOrgType::Owner),
            1 => Some(UserOrgType::Admin),
            2 => Some(UserOrgType::User),
            3 => Some(UserOrgType::Manager),
            _ => None,
        }
    }

}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),

            name,
            billing_email,
        }
    }

    pub fn to_json(&self) -> Value {
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
            uuid: crate::util::get_uuid(),

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
use crate::db::DbConn;
use crate::db::schema::{organizations, users_organizations, users_collections, ciphers_collections};

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Organization {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        UserOrganization::find_by_org(&self.uuid, conn)
        .iter()
        .for_each(|user_org| {
            User::update_uuid_revision(&user_org.user_uuid, conn);
        });

        diesel::replace_into(organizations::table)
            .values(&*self).execute(&**conn)
            .map_res("Error saving organization")
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        use super::{Cipher, Collection};

        Cipher::delete_all_by_organization(&self.uuid, &conn)?;
        Collection::delete_all_by_organization(&self.uuid, &conn)?;
        UserOrganization::delete_all_by_organization(&self.uuid, &conn)?;

        diesel::delete(
            organizations::table.filter(
                organizations::uuid.eq(self.uuid)
            )
        ).execute(&**conn)
        .map_res("Error saving organization")
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        organizations::table
            .filter(organizations::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }
}

impl UserOrganization {
    pub fn to_json(&self, conn: &DbConn) -> Value {
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

    pub fn to_json_user_details(&self, conn: &DbConn) -> Value {
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

    pub fn to_json_collection_user_details(&self, read_only: bool, conn: &DbConn) -> Value {
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

    pub fn to_json_details(&self, conn: &DbConn) -> Value {        
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

    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);

        diesel::replace_into(users_organizations::table)
            .values(&*self).execute(&**conn)  
        .map_res("Error adding user to organization")
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);

        CollectionUser::delete_all_by_user(&self.user_uuid, &conn)?;

        diesel::delete(
            users_organizations::table.filter(
                users_organizations::uuid.eq(self.uuid)
            )
        ).execute(&**conn)
        .map_res("Error removing user from organization")
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for user_org in Self::find_by_org(&org_uuid, &conn) {
            user_org.delete(&conn)?;
        }
        Ok(())
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for user_org in Self::find_any_state_by_user(&user_uuid, &conn) {
            user_org.delete(&conn)?;
        }
        Ok(())
    }

    pub fn has_full_access(self) -> bool {
        self.access_all || self.type_ >= UserOrgType::Admin
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

    pub fn find_any_state_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_organizations::table
            .filter(users_organizations::user_uuid.eq(user_uuid))
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


