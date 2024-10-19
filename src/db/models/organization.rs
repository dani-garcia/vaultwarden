use chrono::{NaiveDateTime, Utc};
use num_traits::FromPrimitive;
use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use super::{CollectionUser, Group, GroupUser, OrgPolicy, OrgPolicyType, TwoFactor, User};
use crate::db::models::{Collection, CollectionGroup};
use crate::CONFIG;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = organizations)]
    #[diesel(primary_key(uuid))]
    pub struct Organization {
        pub uuid: String,
        pub name: String,
        pub billing_email: String,
        pub private_key: Option<String>,
        pub public_key: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = users_organizations)]
    #[diesel(primary_key(uuid))]
    pub struct UserOrganization {
        pub uuid: String,
        pub user_uuid: String,
        pub org_uuid: String,

        pub access_all: bool,
        pub akey: String,
        pub status: i32,
        pub atype: i32,
        pub reset_password_key: Option<String>,
        pub external_id: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = organization_api_key)]
    #[diesel(primary_key(uuid, org_uuid))]
    pub struct OrganizationApiKey {
        pub uuid: String,
        pub org_uuid: String,
        pub atype: i32,
        pub api_key: String,
        pub revision_date: NaiveDateTime,
    }
}

// https://github.com/bitwarden/server/blob/b86a04cef9f1e1b82cf18e49fc94e017c641130c/src/Core/Enums/OrganizationUserStatusType.cs
pub enum UserOrgStatus {
    Revoked = -1,
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
        matches!(self.partial_cmp(other), Some(Ordering::Greater | Ordering::Equal))
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
        matches!(self.partial_cmp(other), Some(Ordering::Less | Ordering::Equal) | None)
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
        }
    }
    // https://github.com/bitwarden/server/blob/13d1e74d6960cf0d042620b72d85bf583a4236f7/src/Api/Models/Response/Organizations/OrganizationResponseModel.cs
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "identifier": null, // not supported by us
            "name": self.name,
            "seats": null,
            "maxCollections": null,
            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side
            "use2fa": true,
            "useCustomPermissions": false,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.org_events_enabled(),
            "useGroups": CONFIG.org_groups_enabled(),
            "useTotp": true,
            "usePolicies": true,
            // "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "useSso": false, // Not supported
            // "useKeyConnector": false, // Not supported
            "selfHost": true,
            "useApi": true,
            "hasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),

            "businessName": null,
            "businessAddress1": null,
            "businessAddress2": null,
            "businessAddress3": null,
            "businessCountry": null,
            "businessTaxNumber": null,

            "billingEmail": self.billing_email,
            "planType": 6, // Custom plan
            "usersGetPremium": true,
            "object": "organization",
        })
    }
}

// Used to either subtract or add to the current status
// The number 128 should be fine, it is well within the range of an i32
// The same goes for the database where we only use INTEGER (the same as an i32)
// It should also provide enough room for 100+ types, which i doubt will ever happen.
static ACTIVATE_REVOKE_DIFF: i32 = 128;

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
            reset_password_key: None,
            external_id: None,
        }
    }

    pub fn restore(&mut self) -> bool {
        if self.status < UserOrgStatus::Invited as i32 {
            self.status += ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    pub fn revoke(&mut self) -> bool {
        if self.status > UserOrgStatus::Revoked as i32 {
            self.status -= ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    /// Return the status of the user in an unrevoked state
    pub fn get_unrevoked_status(&self) -> i32 {
        if self.status <= UserOrgStatus::Revoked as i32 {
            return self.status + ACTIVATE_REVOKE_DIFF;
        }
        self.status
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) -> bool {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        if self.external_id != external_id {
            self.external_id = match external_id {
                Some(external_id) if !external_id.is_empty() => Some(external_id),
                _ => None,
            };
            return true;
        }
        false
    }
}

impl OrganizationApiKey {
    pub fn new(org_uuid: String, api_key: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),

            org_uuid,
            atype: 0, // Type 0 is the default and only type we support currently
            api_key,
            revision_date: Utc::now().naive_utc(),
        }
    }

    pub fn check_valid_api_key(&self, api_key: &str) -> bool {
        crate::crypto::ct_eq(&self.api_key, api_key)
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Organization {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        if !email_address::EmailAddress::is_valid(self.billing_email.trim()) {
            err!(format!("BillingEmail {} is not a valid email address", self.billing_email.trim()))
        }

        for user_org in UserOrganization::find_by_org(&self.uuid, conn).await.iter() {
            User::update_uuid_revision(&user_org.user_uuid, conn).await;
        }

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

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        use super::{Cipher, Collection};

        Cipher::delete_all_by_organization(&self.uuid, conn).await?;
        Collection::delete_all_by_organization(&self.uuid, conn).await?;
        UserOrganization::delete_all_by_organization(&self.uuid, conn).await?;
        OrgPolicy::delete_all_by_organization(&self.uuid, conn).await?;
        Group::delete_all_by_organization(&self.uuid, conn).await?;
        OrganizationApiKey::delete_all_by_organization(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(organizations::table.filter(organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error saving organization")
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            organizations::table
                .filter(organizations::uuid.eq(uuid))
                .first::<OrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn get_all(conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            organizations::table.load::<OrganizationDb>(conn).expect("Error loading organizations").from_db()
        }}
    }
}

impl UserOrganization {
    pub async fn to_json(&self, conn: &mut DbConn) -> Value {
        let org = Organization::find_by_uuid(&self.org_uuid, conn).await.unwrap();

        let permissions = json!({
                // TODO: Add support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                "createNewCollections": false,
                "editAnyCollection": false,
                "deleteAnyCollection": false,
                "editAssignedCollections": false,
                "deleteAssignedCollections": false,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
        });

        // https://github.com/bitwarden/server/blob/13d1e74d6960cf0d042620b72d85bf583a4236f7/src/Api/Models/Response/ProfileOrganizationResponseModel.cs
        json!({
            "id": self.org_uuid,
            "identifier": null, // Not supported
            "name": org.name,
            "seats": null,
            "maxCollections": null,
            "usersGetPremium": true,
            "use2fa": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.org_events_enabled(),
            "useGroups": CONFIG.org_groups_enabled(),
            "useTotp": true,
            "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "usePolicies": true,
            "useApi": true,
            "selfHost": true,
            "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),
            "ssoBound": false, // Not supported
            "useSso": false, // Not supported
            "useKeyConnector": false,
            "useSecretsManager": false,
            "usePasswordManager": true,
            "useCustomPermissions": false,
            "useActivateAutofillPolicy": false,

            "organizationUserId": self.uuid,
            "providerId": null,
            "providerName": null,
            "providerType": null,
            "familySponsorshipFriendlyName": null,
            "familySponsorshipAvailable": false,
            "planProductType": 3,
            "productTierType": 3, // Enterprise tier
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "familySponsorshipLastSyncDate": null,
            "familySponsorshipValidUntil": null,
            "familySponsorshipToDelete": null,
            "accessSecretsManager": false,
            "limitCollectionCreationDeletion": false, // This should be set to true only when we can handle roles like createNewCollections
            "allowAdminAccessToAllCollectionItems": true,
            "flexibleCollections": false,

            "permissions": permissions,

            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side

            // These are per user
            "userId": self.user_uuid,
            "key": self.akey,
            "status": self.status,
            "type": self.atype,
            "enabled": true,

            "object": "profileOrganization",
        })
    }

    pub async fn to_json_user_details(
        &self,
        include_collections: bool,
        include_groups: bool,
        conn: &mut DbConn,
    ) -> Value {
        let user = User::find_by_uuid(&self.user_uuid, conn).await.unwrap();

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < UserOrgStatus::Revoked as i32 {
            UserOrgStatus::Revoked as i32
        } else {
            self.status
        };

        let twofactor_enabled = !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty();

        let groups: Vec<String> = if include_groups && CONFIG.org_groups_enabled() {
            GroupUser::find_by_user(&self.uuid, conn).await.iter().map(|gu| gu.groups_uuid.clone()).collect()
        } else {
            // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
            // so just act as if there are no groups.
            Vec::with_capacity(0)
        };

        let collections: Vec<Value> = if include_collections {
            // Get all collections for the user here already to prevent more queries
            let cu: HashMap<String, CollectionUser> =
                CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                    .await
                    .into_iter()
                    .map(|cu| (cu.collection_uuid.clone(), cu))
                    .collect();

            // Get all collection groups for this user to prevent there inclusion
            let cg: HashSet<String> = CollectionGroup::find_by_user(&self.user_uuid, conn)
                .await
                .into_iter()
                .map(|cg| cg.collections_uuid)
                .collect();

            Collection::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                .await
                .into_iter()
                .filter_map(|c| {
                    let (read_only, hide_passwords, can_manage) = if self.has_full_access() {
                        (false, false, self.atype >= UserOrgType::Manager)
                    } else if let Some(cu) = cu.get(&c.uuid) {
                        (
                            cu.read_only,
                            cu.hide_passwords,
                            self.atype == UserOrgType::Manager && !cu.read_only && !cu.hide_passwords,
                        )
                    // If previous checks failed it might be that this user has access via a group, but we should not return those elements here
                    // Those are returned via a special group endpoint
                    } else if cg.contains(&c.uuid) {
                        return None;
                    } else {
                        (true, true, false)
                    };

                    Some(json!({
                        "id": c.uuid,
                        "readOnly": read_only,
                        "hidePasswords": hide_passwords,
                        "manage": can_manage,
                    }))
                })
                .collect()
        } else {
            Vec::with_capacity(0)
        };

        let permissions = json!({
            // TODO: Add support for Custom User Roles
            // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
            "accessEventLogs": false,
            "accessImportExport": false,
            "accessReports": false,
            "createNewCollections": false,
            "editAnyCollection": false,
            "deleteAnyCollection": false,
            "editAssignedCollections": false,
            "deleteAssignedCollections": false,
            "manageGroups": false,
            "managePolicies": false,
            "manageSso": false, // Not supported
            "manageUsers": false,
            "manageResetPassword": false,
            "manageScim": false // Not supported (Not AGPLv3 Licensed)
        });

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "name": if self.get_unrevoked_status() >= UserOrgStatus::Accepted as i32 { Some(user.name) } else { None },
            "email": user.email,
            "externalId": self.external_id,
            "avatarColor": user.avatar_color,
            "groups": groups,
            "collections": collections,

            "status": status,
            "type": self.atype,
            "accessAll": self.access_all,
            "twoFactorEnabled": twofactor_enabled,
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "hasMasterPassword": !user.password_hash.is_empty(),

            "permissions": permissions,

            "ssoBound": false, // Not supported
            "usesKeyConnector": false, // Not supported
            "accessSecretsManager": false, // Not supported (Not AGPLv3 Licensed)

            "object": "organizationUserUserDetails",
        })
    }

    pub fn to_json_user_access_restrictions(&self, col_user: &CollectionUser) -> Value {
        json!({
            "id": self.uuid,
            "readOnly": col_user.read_only,
            "hidePasswords": col_user.hide_passwords,
        })
    }

    pub async fn to_json_details(&self, conn: &mut DbConn) -> Value {
        let coll_uuids = if self.access_all {
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections =
                CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn).await;
            collections
                .iter()
                .map(|c| {
                    json!({
                        "id": c.collection_uuid,
                        "readOnly": c.read_only,
                        "hidePasswords": c.hide_passwords,
                    })
                })
                .collect()
        };

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < UserOrgStatus::Revoked as i32 {
            UserOrgStatus::Revoked as i32
        } else {
            self.status
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,

            "status": status,
            "type": self.atype,
            "accessAll": self.access_all,
            "collections": coll_uuids,

            "object": "organizationUserDetails",
        })
    }
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

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
                    },
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

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        CollectionUser::delete_all_by_user_and_org(&self.user_uuid, &self.org_uuid, conn).await?;
        GroupUser::delete_all_by_user(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(users_organizations::table.filter(users_organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from organization")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for user_org in Self::find_by_org(org_uuid, conn).await {
            user_org.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for user_org in Self::find_any_state_by_user(user_uuid, conn).await {
            user_org.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_email_and_org(email: &str, org_id: &str, conn: &mut DbConn) -> Option<UserOrganization> {
        if let Some(user) = User::find_by_mail(email, conn).await {
            if let Some(user_org) = UserOrganization::find_by_user_and_org(&user.uuid, org_id, conn).await {
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

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_confirmed_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn find_invited_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Invited as i32))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn find_any_state_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn count_accepted_and_confirmed_by_user(user_uuid: &str, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Accepted as i32).or(users_organizations::status.eq(UserOrgStatus::Confirmed as i32)))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_org(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .load::<UserOrganizationDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn find_confirmed_by_org(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
                .load::<UserOrganizationDb>(conn)
                .unwrap_or_default().from_db()
        }}
    }

    pub async fn count_by_org(org_uuid: &str, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_org_and_type(org_uuid: &str, atype: UserOrgType, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .load::<UserOrganizationDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn count_confirmed_by_org_and_type(org_uuid: &str, atype: UserOrgType, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .filter(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_confirmed_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .first::<UserOrganizationDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<UserOrganizationDb>(conn)
                .expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn get_org_uuid_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<String> {
        db_run! { conn: {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .select(users_organizations::org_uuid)
                .load::<String>(conn)
                .unwrap_or_default()
        }}
    }

    pub async fn find_by_user_and_policy(user_uuid: &str, policy_type: OrgPolicyType, conn: &mut DbConn) -> Vec<Self> {
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

    pub async fn find_by_cipher_and_org(cipher_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
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
            .distinct()
            .load::<UserOrganizationDb>(conn).expect("Error loading user organizations").from_db()
        }}
    }

    pub async fn find_by_cipher_and_org_with_group(cipher_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_organizations::table
            .filter(users_organizations::org_uuid.eq(org_uuid))
            .inner_join(groups_users::table.on(
                groups_users::users_organizations_uuid.eq(users_organizations::uuid)
            ))
            .left_join(collections_groups::table.on(
                collections_groups::groups_uuid.eq(groups_users::groups_uuid)
            ))
            .left_join(groups::table.on(groups::uuid.eq(groups_users::groups_uuid)))
            .left_join(ciphers_collections::table.on(
                    ciphers_collections::collection_uuid.eq(collections_groups::collections_uuid).and(ciphers_collections::cipher_uuid.eq(&cipher_uuid))

                ))
            .filter(
                    groups::access_all.eq(true).or( // AccessAll via groups
                        ciphers_collections::cipher_uuid.eq(&cipher_uuid) // ..or access to collection via group
                    )
                )
                .select(users_organizations::all_columns)
                .distinct()
            .load::<UserOrganizationDb>(conn).expect("Error loading user organizations with groups").from_db()
        }}
    }

    pub async fn user_has_ge_admin_access_to_cipher(user_uuid: &str, cipher_uuid: &str, conn: &mut DbConn) -> bool {
        db_run! { conn: {
            users_organizations::table
            .inner_join(ciphers::table.on(ciphers::uuid.eq(cipher_uuid).and(ciphers::organization_uuid.eq(users_organizations::org_uuid.nullable()))))
            .filter(users_organizations::user_uuid.eq(user_uuid))
            .filter(users_organizations::atype.eq_any(vec![UserOrgType::Owner as i32, UserOrgType::Admin as i32]))
            .count()
            .first::<i64>(conn)
            .ok().unwrap_or(0) != 0
        }}
    }

    pub async fn find_by_collection_and_org(collection_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
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

    pub async fn find_by_external_id_and_org(ext_id: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! {conn: {
            users_organizations::table
            .filter(
                users_organizations::external_id.eq(ext_id)
                .and(users_organizations::org_uuid.eq(org_uuid))
            )
            .first::<UserOrganizationDb>(conn).ok().from_db()
        }}
    }
}

impl OrganizationApiKey {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(organization_api_key::table)
                    .values(OrganizationApiKeyDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(organization_api_key::table)
                            .filter(organization_api_key::uuid.eq(&self.uuid))
                            .set(OrganizationApiKeyDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving organization")

            }
            postgresql {
                let value = OrganizationApiKeyDb::to_db(self);
                diesel::insert_into(organization_api_key::table)
                    .values(&value)
                    .on_conflict((organization_api_key::uuid, organization_api_key::org_uuid))
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub async fn find_by_org_uuid(org_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            organization_api_key::table
                .filter(organization_api_key::org_uuid.eq(org_uuid))
                .first::<OrganizationApiKeyDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(organization_api_key::table.filter(organization_api_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing organization api key from organization")
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
