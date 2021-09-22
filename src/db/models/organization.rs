use num_traits::FromPrimitive;
use serde_json::Value;
use std::cmp::Ordering;

use super::{CollectionUser, OrgPolicy, OrgPolicyType, User};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[table_name = "organizations"]
    #[primary_key(uuid)]
    pub struct Organization {
        pub uuid: String,
        pub name: String,
        pub billing_email: String,
        pub identifier: Option<String>,
        pub private_key: Option<String>,
        pub public_key: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[table_name = "users_organizations"]
    #[primary_key(uuid)]
    pub struct UserOrganization {
        pub uuid: String,
        pub user_uuid: String,
        pub org_uuid: String,

        pub access_all: bool,
        pub akey: String,
        pub status: i32,
        pub atype: i32,
    }
}

pub enum UserOrgStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

#[derive(Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum UserOrgType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
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
}

impl Ord for UserOrgType {
    fn cmp(&self, other: &UserOrgType) -> Ordering {
        // For easy comparison, map each variant to an access level (where 0 is lowest).
        static ACCESS_LEVEL: [i32; 4] = [
            3, // Owner
            2, // Admin
            0, // User
            1, // Manager
        ];
        ACCESS_LEVEL[*self as usize].cmp(&ACCESS_LEVEL[*other as usize])
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
            return Some(self.cmp(&other));
        }
        None
    }

    fn gt(&self, other: &i32) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Greater))
    }

    fn ge(&self, other: &i32) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Greater) | Some(Ordering::Equal))
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
            return Some(self_type.cmp(other));
        }
        None
    }

    fn lt(&self, other: &UserOrgType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less) | None)
    }

    fn le(&self, other: &UserOrgType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less) | Some(Ordering::Equal) | None)
    }
}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: String, private_key: Option<String>, public_key: Option<String>) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            name,
            billing_email,
            private_key,
            public_key,
            identifier: None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "Identifier": self.identifier,
            "Name": self.name,
            "Seats": 10, // The value doesn't matter, we don't check server-side
            "MaxCollections": 10, // The value doesn't matter, we don't check server-side
            "MaxStorageGb": 10, // The value doesn't matter, we don't check server-side
            "Use2fa": true,
            "UseDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "UseEvents": false, // not supported by us
            "UseGroups": false, // not supported by us
            "UseTotp": true,
            "UsePolicies": true,
            "SelfHost": true,
            "UseApi": false, // not supported by us
            "HasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "ResetPasswordEnrolled": false, // not supported by us

            "BusinessName": null,
            "BusinessAddress1": null,
            "BusinessAddress2": null,
            "BusinessAddress3": null,
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
            akey: String::new(),
            status: UserOrgStatus::Accepted as i32,
            atype: UserOrgType::User as i32,
        }
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Organization {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        UserOrganization::find_by_org(&self.uuid, conn).iter().for_each(|user_org| {
            User::update_uuid_revision(&user_org.user_uuid, conn);
        });

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(organizations::table)
                    .values(OrganizationDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(organizations::table)
                            .filter(organizations::uuid.eq(&self.uuid))
                            .set(OrganizationDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving organization")

            }
            postgresql {
                let value = OrganizationDb::to_db(self);
                diesel::insert_into(organizations::table)
                    .values(&value)
                    .on_conflict(organizations::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        use super::{Cipher, Collection};

        Cipher::delete_all_by_organization(&self.uuid, conn)?;
        Collection::delete_all_by_organization(&self.uuid, conn)?;
        UserOrganization::delete_all_by_organization(&self.uuid, conn)?;
        OrgPolicy::delete_all_by_organization(&self.uuid, conn)?;

        db_run! { conn: {
            diesel::delete(organizations::table.filter(organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error saving organization")
        }}
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            organizations::table
                .filter(organizations::uuid.eq(uuid))
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_by_identifier(identifier: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            organizations::table
                .filter(organizations::identifier.eq(identifier))
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn get_all(conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            organizations::table.load::<OrganizationDb>(conn).expect("Error loading organizations").from_db()
        }}
    }
}

impl UserOrganization {
    pub fn to_json(&self, conn: &DbConn) -> Value {
        let org = Organization::find_by_uuid(&self.org_uuid, conn).unwrap();

        json!({
            "Id": self.org_uuid,
            "Identifier": null, // not supported by us
            "Name": org.name,
            "Seats": 10, // The value doesn't matter, we don't check server-side
            "MaxCollections": 10, // The value doesn't matter, we don't check server-side
            "UsersGetPremium": true,

            "Use2fa": true,
            "UseDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "UseEvents": false, // not supported by us
            "UseGroups": false, // not supported by us
            "UseTotp": true,
            "UsePolicies": true,
            "UseApi": false, // not supported by us
            "SelfHost": true,
            "HasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
            "ResetPasswordEnrolled": false, // not supported by us
            "SsoBound": true,
            "UseSso": true,
            // TODO: Add support for Business Portal
            // Upstream is moving Policies and SSO management outside of the web-vault to /portal
            // For now they still have that code also in the web-vault, but they will remove it at some point.
            // https://github.com/bitwarden/server/tree/master/bitwarden_license/src/
            "UseBusinessPortal": false, // Disable BusinessPortal Button

            // TODO: Add support for Custom User Roles
            // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
            // "Permissions": {
            //     "AccessBusinessPortal": false,
            //     "AccessEventLogs": false,
            //     "AccessImportExport": false,
            //     "AccessReports": false,
            //     "ManageAllCollections": false,
            //     "ManageAssignedCollections": false,
            //     "ManageCiphers": false,
            //     "ManageGroups": false,
            //     "ManagePolicies": false,
            //     "ManageResetPassword": false,
            //     "ManageSso": false,
            //     "ManageUsers": false,
            // },

            "MaxStorageGb": 10, // The value doesn't matter, we don't check server-side

            // These are per user
            "Key": self.akey,
            "Status": self.status,
            "Type": self.atype,
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
            "Type": self.atype,
            "AccessAll": self.access_all,

            "Object": "organizationUserUserDetails",
        })
    }

    pub fn to_json_user_access_restrictions(&self, col_user: &CollectionUser) -> Value {
        json!({
            "Id": self.uuid,
            "ReadOnly": col_user.read_only,
            "HidePasswords": col_user.hide_passwords,
        })
    }

    pub fn to_json_details(&self, conn: &DbConn) -> Value {
        let coll_uuids = if self.access_all {
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections = CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn);
            collections
                .iter()
                .map(|c| {
                    json!({
                        "Id": c.collection_uuid,
                        "ReadOnly": c.read_only,
                        "HidePasswords": c.hide_passwords,
                    })
                })
                .collect()
        };

        json!({
            "Id": self.uuid,
            "UserId": self.user_uuid,

            "Status": self.status,
            "Type": self.atype,
            "AccessAll": self.access_all,
            "Collections": coll_uuids,

            "Object": "organizationUserDetails",
        })
    }
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(users_organizations::table)
                    .values(UserOrganizationDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(users_organizations::table)
                            .filter(users_organizations::uuid.eq(&self.uuid))
                            .set(UserOrganizationDb::to_db(self))
                            .execute(conn)
                            .map_res("Error adding user to organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding user to organization")
            }
            postgresql {
                let value = UserOrganizationDb::to_db(self);
                diesel::insert_into(users_organizations::table)
                    .values(&value)
                    .on_conflict(users_organizations::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error adding user to organization")
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);

        CollectionUser::delete_all_by_user_and_org(&self.user_uuid, &self.org_uuid, conn)?;

        db_run! { conn: {
            diesel::delete(users_organizations::table.filter(users_organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from organization")
        }}
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for user_org in Self::find_by_org(org_uuid, conn) {
            user_org.delete(conn)?;
        }
        Ok(())
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for user_org in Self::find_any_state_by_user(user_uuid, conn) {
            user_org.delete(conn)?;
        }
        Ok(())
    }

    pub fn find_by_email_and_org(email: &str, org_id: &str, conn: &DbConn) -> Option<UserOrganization> {
        if let Some(user) = super::User::find_by_mail(email, conn) {
            if let Some(user_org) = UserOrganization::find_by_user_and_org(&user.uuid, org_id, conn) {
                return Some(user_org);
            }
        }

        None
    }

    pub fn has_status(&self, status: UserOrgStatus) -> bool {
        self.status == status as i32
    }

    pub fn has_type(&self, user_type: UserOrgType) -> bool {
        self.atype == user_type as i32
    }

    pub fn has_full_access(&self) -> bool {
        (self.access_all || self.atype >= UserOrgType::Admin) && self.has_status(UserOrgStatus::Confirmed)
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub fn find_invited_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Invited as i32))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub fn find_any_state_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .load::<UserOrganizationDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub fn count_by_org(org_uuid: &str, conn: &DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub fn find_by_org_and_type(org_uuid: &str, atype: i32, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype))
                .load::<UserOrganizationDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub fn find_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_by_user_and_policy(user_uuid: &str, policy_type: OrgPolicyType, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .inner_join(
                    org_policies::table.on(
                        org_policies::org_uuid.eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))
                            .and(org_policies::atype.eq(policy_type as i32))
                            .and(org_policies::enabled.eq(true)))
                )
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .select(users_organizations::all_columns)
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub fn find_by_cipher_and_org(cipher_uuid: &str, org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
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
            .load::<UserOrganizationDb>(conn).expect("Error loading user organizations").from_db()
        }}
    }

    pub fn find_by_collection_and_org(collection_uuid: &str, org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
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
            .load::<UserOrganizationDb>(conn).expect("Error loading user organizations").from_db()
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn partial_cmp_UserOrgType() {
        assert!(UserOrgType::Owner > UserOrgType::Admin);
        assert!(UserOrgType::Admin > UserOrgType::Manager);
        assert!(UserOrgType::Manager > UserOrgType::User);
    }
}
