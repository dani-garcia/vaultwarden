use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use num_traits::FromPrimitive;
use serde_json::Value;

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        schema::{
            ciphers, ciphers_collections, collections_groups, groups, groups_users, org_policies, organization_api_key,
            organizations, users, users_collections, users_organizations,
        },
    },
    error::MapResult,
};
use macros::UuidFromParam;

use super::{
    Cipher, CipherId, Collection, CollectionGroup, CollectionId, CollectionUser, Group, GroupId, GroupUser, OrgPolicy,
    OrgPolicyType, TwoFactor, User, UserId,
};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = organizations)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Organization {
    pub uuid: OrganizationId,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users_organizations)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
#[expect(clippy::struct_excessive_bools, reason = "Each Custom role permission is a column of its own")]
pub struct Membership {
    pub uuid: MembershipId,
    pub user_uuid: UserId,
    pub org_uuid: OrganizationId,

    pub invited_by_email: Option<String>,

    pub access_all: bool,
    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,

    // The permissions of a Custom role, only accessed through `CustomPermission`.
    manage_users: bool,
    manage_groups: bool,
    manage_policies: bool,
    create_new_collections: bool,
    edit_any_collection: bool,
    delete_any_collection: bool,
    access_event_logs: bool,
    access_import_export: bool,
    access_reports: bool,
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = organization_api_key)]
#[diesel(primary_key(uuid, org_uuid))]
pub struct OrganizationApiKey {
    pub uuid: OrgApiKeyId,
    pub org_uuid: OrganizationId,
    pub atype: i32,
    pub api_key: String,
    pub revision_date: NaiveDateTime,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Enums/OrganizationUserStatusType.cs
#[derive(PartialEq)]
pub enum MembershipStatus {
    Revoked = -1,
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
}

impl MembershipStatus {
    pub fn from_i32(status: i32) -> Option<Self> {
        match status {
            0 => Some(Self::Invited),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            // NOTE: we don't care about revoked members where this is used
            // if this ever changes also adapt the OrgHeaders check.
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum MembershipType {
    Owner = 0,
    Admin = 1,
    User = 2,
    // The legacy Manager role. The Bitwarden clients no longer know it and are shown a Custom role instead.
    Manager = 3,
    // Only granted while EXPERIMENTAL_CUSTOM_ROLES is enabled.
    Custom = 4,
}

impl MembershipType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "Owner" => Some(MembershipType::Owner),
            "1" | "Admin" => Some(MembershipType::Admin),
            "2" | "User" => Some(MembershipType::User),
            "3" | "Manager" => Some(MembershipType::Manager),
            "4" | "Custom" => Some(MembershipType::Custom),
            _ => None,
        }
    }

    /// The role a member invite or edit from the Bitwarden clients asks for, given the member's current
    /// role (`None` for an invite).
    ///
    /// The clients no longer know the legacy Manager role and are shown a Custom role in its place, so a
    /// requested Custom role is the legacy Manager unless EXPERIMENTAL_CUSTOM_ROLES is enabled. An existing
    /// Manager or Custom member keeps their role when the request repeats it, so an unrelated edit never
    /// turns one into the other.
    pub fn requested(
        requested: MembershipType,
        current: Option<&Membership>,
        custom_roles_enabled: bool,
    ) -> MembershipType {
        if requested != MembershipType::Custom {
            return requested;
        }
        match current {
            Some(member) if member.has_type(MembershipType::Custom) => MembershipType::Custom,
            Some(member) if member.has_type(MembershipType::Manager) => MembershipType::Manager,
            _ if custom_roles_enabled => MembershipType::Custom,
            _ => MembershipType::Manager,
        }
    }

    /// The authority of a role, which is what roles are compared by. A Custom member gets its authority from
    /// its permissions, never from its role, so the role itself ranks right above User and below Manager.
    const fn rank(self) -> u8 {
        match self {
            MembershipType::User => 0,
            MembershipType::Custom => 1,
            MembershipType::Manager => 2,
            MembershipType::Admin => 3,
            MembershipType::Owner => 4,
        }
    }
}

impl Ord for MembershipType {
    fn cmp(&self, other: &MembershipType) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for MembershipType {
    fn partial_cmp(&self, other: &MembershipType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<i32> for MembershipType {
    fn eq(&self, other: &i32) -> bool {
        *other == *self as i32
    }
}

impl PartialOrd<i32> for MembershipType {
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

impl PartialEq<MembershipType> for i32 {
    fn eq(&self, other: &MembershipType) -> bool {
        *self == *other as i32
    }
}

impl PartialOrd<MembershipType> for i32 {
    fn partial_cmp(&self, other: &MembershipType) -> Option<Ordering> {
        if let Some(self_type) = MembershipType::from_i32(*self) {
            return Some(self_type.cmp(other));
        }
        None
    }

    fn lt(&self, other: &MembershipType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less) | None)
    }

    fn le(&self, other: &MembershipType) -> bool {
        matches!(self.partial_cmp(other), Some(Ordering::Less | Ordering::Equal) | None)
    }
}

/// The granular permissions of the Custom role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustomPermission {
    ManageUsers,
    ManageGroups,
    ManagePolicies,
    CreateNewCollections,
    EditAnyCollection,
    DeleteAnyCollection,
    AccessEventLogs,
    AccessImportExport,
    AccessReports,
}

/// The permissions this version enforces on every endpoint they open. Only these can be granted, a stored
/// grant of any other one grants nothing. They are implemented one at a time, so this grows with them.
const SUPPORTED_CUSTOM_PERMISSIONS: &[CustomPermission] = &[];

impl CustomPermission {
    pub const ALL: [CustomPermission; 9] = [
        CustomPermission::ManageUsers,
        CustomPermission::ManageGroups,
        CustomPermission::ManagePolicies,
        CustomPermission::CreateNewCollections,
        CustomPermission::EditAnyCollection,
        CustomPermission::DeleteAnyCollection,
        CustomPermission::AccessEventLogs,
        CustomPermission::AccessImportExport,
        CustomPermission::AccessReports,
    ];

    /// The key of the permission in the `permissions` object of the Bitwarden clients.
    pub const fn json_key(self) -> &'static str {
        match self {
            CustomPermission::ManageUsers => "manageUsers",
            CustomPermission::ManageGroups => "manageGroups",
            CustomPermission::ManagePolicies => "managePolicies",
            CustomPermission::CreateNewCollections => "createNewCollections",
            CustomPermission::EditAnyCollection => "editAnyCollection",
            CustomPermission::DeleteAnyCollection => "deleteAnyCollection",
            CustomPermission::AccessEventLogs => "accessEventLogs",
            CustomPermission::AccessImportExport => "accessImportExport",
            CustomPermission::AccessReports => "accessReports",
        }
    }

    pub fn is_supported(self) -> bool {
        SUPPORTED_CUSTOM_PERMISSIONS.contains(&self)
    }

    /// The permissions a member invite or edit grants a Custom role.
    ///
    /// A permission is only granted when it is set to `true`, and anything but a boolean is rejected: this
    /// replaces the member's permissions, so a malformed value must not silently remove one. Granting a
    /// permission this version does not enforce is rejected as well. The clients also send permissions
    /// Vaultwarden does not know at all, like `manageSso`, those are ignored.
    pub fn requested(permissions: &HashMap<String, Value>) -> Result<HashSet<CustomPermission>, crate::Error> {
        let mut granted = HashSet::new();
        for permission in CustomPermission::ALL {
            match permissions.get(permission.json_key()) {
                None | Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) if permission.is_supported() => {
                    granted.insert(permission);
                }
                Some(Value::Bool(true)) => {
                    err!(format!("The Custom role permission '{}' is not supported yet", permission.json_key()))
                }
                Some(_) => {
                    err!(format!("The Custom role permission '{}' must be true or false", permission.json_key()))
                }
            }
        }
        Ok(granted)
    }
}

/// The stored roles with authority over the whole organization. Queries match them by value, comparing
/// `atype <= Admin` would also match any unknown value below it.
pub(super) const ORG_ADMIN_ATYPES: [i32; 2] = [MembershipType::Owner as i32, MembershipType::Admin as i32];

/// Whether the experimental Custom role is enabled. Nothing is ever granted through a Custom role otherwise.
pub fn custom_roles_enabled() -> bool {
    CONFIG.experimental_custom_roles()
}

/// Local methods
impl Organization {
    pub fn new(name: String, billing_email: &str, private_key: Option<String>, public_key: Option<String>) -> Self {
        let billing_email = billing_email.to_lowercase();
        Self {
            uuid: OrganizationId(crate::util::get_uuid()),
            name,
            billing_email,
            private_key,
            public_key,
        }
    }
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/Organizations/OrganizationResponseModel.cs
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "seats": null,
            "maxCollections": null,
            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side
            "use2fa": true,
            "useCustomPermissions": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.org_events_enabled(),
            "useGroups": CONFIG.org_groups_enabled(),
            "useTotp": true,
            "usePolicies": true,
            "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "useSso": false, // Not supported
            "useKeyConnector": false, // Not supported
            "usePasswordManager": true,
            "useSecretsManager": false, // Not supported (Not AGPLv3 Licensed)
            "selfHost": true,
            "useApi": true,
            "useDisableSMAdsForUsers": true, // Hide Secrets Manager ads
            "useInviteLinks": false, // Not (yet) supported
            "useMyItems": false, // Not (yet) supported
            "useOrganizationDomains": false, // Not supported (Linked to SSO)
            "usePam": false, // Not supported
            "usePhishingBlocker": false,
            "hasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),
            "allowAdminAccessToAllCollectionItems": true,
            "limitCollectionCreation": true,
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,

            "businessName": self.name,
            "businessAddress1": null,
            "businessAddress2": null,
            "businessAddress3": null,
            "businessCountry": null,
            "businessTaxNumber": null,

            "maxAutoscaleSeats": null,
            "maxAutoscaleSmSeats": null,
            "maxAutoscaleSmServiceAccounts": null,

            "secretsManagerPlan": null,
            "smSeats": null,
            "smServiceAccounts": null,

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
const ACTIVATE_REVOKE_DIFF: i32 = 128;

impl Membership {
    pub fn new(user_uuid: UserId, org_uuid: OrganizationId, invited_by_email: Option<String>) -> Self {
        Self {
            uuid: MembershipId(crate::util::get_uuid()),

            user_uuid,
            org_uuid,
            invited_by_email,

            access_all: false,
            akey: String::new(),
            status: MembershipStatus::Accepted as i32,
            atype: MembershipType::User as i32,
            reset_password_key: None,
            external_id: None,

            manage_users: false,
            manage_groups: false,
            manage_policies: false,
            create_new_collections: false,
            edit_any_collection: false,
            delete_any_collection: false,
            access_event_logs: false,
            access_import_export: false,
            access_reports: false,
        }
    }

    fn custom_permission_mut(&mut self, permission: CustomPermission) -> &mut bool {
        match permission {
            CustomPermission::ManageUsers => &mut self.manage_users,
            CustomPermission::ManageGroups => &mut self.manage_groups,
            CustomPermission::ManagePolicies => &mut self.manage_policies,
            CustomPermission::CreateNewCollections => &mut self.create_new_collections,
            CustomPermission::EditAnyCollection => &mut self.edit_any_collection,
            CustomPermission::DeleteAnyCollection => &mut self.delete_any_collection,
            CustomPermission::AccessEventLogs => &mut self.access_event_logs,
            CustomPermission::AccessImportExport => &mut self.access_import_export,
            CustomPermission::AccessReports => &mut self.access_reports,
        }
    }

    /// Change the role. Nothing the old role carried survives a role change: the Custom role permissions are
    /// dropped, so changing the role back later starts from none. A Custom role never keeps the legacy
    /// `access_all` flag, its reach only comes from its permissions.
    pub fn set_type(&mut self, new_type: MembershipType) {
        if self.atype != new_type as i32 {
            for permission in CustomPermission::ALL {
                *self.custom_permission_mut(permission) = false;
            }
        }
        if new_type == MembershipType::Custom {
            self.access_all = false;
        }
        self.atype = new_type as i32;
    }

    /// Grant this Custom member exactly `permissions` out of those this version enforces. A stored grant of a
    /// permission this version does not enforce is kept as it is: it grants nothing here.
    pub fn set_custom_permissions(&mut self, permissions: &HashSet<CustomPermission>) {
        for permission in CustomPermission::ALL.into_iter().filter(|p| p.is_supported()) {
            *self.custom_permission_mut(permission) = permissions.contains(&permission);
        }
    }

    /// Why this legacy Manager can't become a Custom member without losing what they may do now, if they can't. A
    /// conversion must not silently change their access, and a Custom role can't keep access to all collections
    /// (which also puts every collection in the Manager's own vault), nor manage any collection yet.
    pub async fn custom_role_conversion_loss(&self, conn: &DbConn) -> Option<&'static str> {
        if !self.has_type(MembershipType::Manager) {
            return None;
        }
        if self.access_all {
            return Some(
                "This Manager has access to all collections, which a Custom member can't have: the collections they \
                 aren't assigned to would disappear from their vault. Uncheck Manage all collections for them first, \
                 or keep the Manager role.",
            );
        }
        // Whatever their status, the collections they manage directly, through a group or through a group with
        // access to all collections
        let mut manages = GroupUser::has_full_access_by_member(&self.org_uuid, &self.uuid, conn).await
            || CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                .await
                .iter()
                .any(|assignment| assignment.manage);
        for group_user in GroupUser::find_by_member(&self.uuid, conn).await {
            if manages {
                break;
            }
            manages = CollectionGroup::find_by_group(&group_user.groups_uuid, &self.org_uuid, conn)
                .await
                .iter()
                .any(|assignment| assignment.manage);
        }
        manages.then_some(
            "This Manager manages collections, with the manage permission or through a group with access to all \
             collections, which a Custom member can't do yet. Remove that first, or keep the Manager role.",
        )
    }

    pub fn restore(&mut self) -> bool {
        if self.status < MembershipStatus::Invited as i32 {
            self.status += ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    pub fn revoke(&mut self) -> bool {
        if self.status > MembershipStatus::Revoked as i32 {
            self.status -= ACTIVATE_REVOKE_DIFF;
            return true;
        }
        false
    }

    /// Return the status of the user in an unrevoked state
    pub fn get_unrevoked_status(&self) -> i32 {
        if self.status <= MembershipStatus::Revoked as i32 {
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

    /// HACK: Convert the manager type to a custom type
    /// It will be converted back on other locations
    pub fn type_manager_as_custom(&self) -> i32 {
        match self.atype {
            3 => 4,
            _ => self.atype,
        }
    }
}

impl OrganizationApiKey {
    pub fn new(org_uuid: OrganizationId, api_key: String) -> Self {
        Self {
            uuid: OrgApiKeyId(crate::util::get_uuid()),

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

/// Database methods
impl Organization {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        if !crate::util::is_valid_email(&self.billing_email) {
            err!(format!("BillingEmail {} is not a valid email address", self.billing_email.escape_debug()))
        }

        for member in &Membership::find_by_org(&self.uuid, conn).await {
            User::update_uuid_revision(&member.user_uuid, conn).await;
        }

        db_run! { conn:
            mysql {
                diesel::insert_into(organizations::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
            postgresql, sqlite {
                diesel::insert_into(organizations::table)
                    .values(self)
                    .on_conflict(organizations::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        Cipher::delete_all_by_organization(&self.uuid, conn).await?;
        Collection::delete_all_by_organization(&self.uuid, conn).await?;
        Membership::delete_all_by_organization(&self.uuid, conn).await?;
        OrgPolicy::delete_all_by_organization(&self.uuid, conn).await?;
        Group::delete_all_by_organization(&self.uuid, conn).await?;
        OrganizationApiKey::delete_all_by_organization(&self.uuid, conn).await?;

        conn.run(move |conn| {
            diesel::delete(organizations::table.filter(organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error saving organization")
        })
        .await
    }

    pub async fn find_by_uuid(uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| organizations::table.filter(organizations::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_name(name: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| organizations::table.filter(organizations::name.eq(name)).first::<Self>(conn).ok()).await
    }

    pub async fn get_all(conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| organizations::table.load::<Self>(conn).expect("Error loading organizations")).await
    }

    pub async fn find_main_org_user_email(user_email: &str, conn: &DbConn) -> Option<Self> {
        let lower_mail = user_email.to_lowercase();

        conn.run(move |conn| {
            organizations::table
                .inner_join(users_organizations::table.on(users_organizations::org_uuid.eq(organizations::uuid)))
                .inner_join(users::table.on(users::uuid.eq(users_organizations::user_uuid)))
                .filter(users::email.eq(lower_mail))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .select(organizations::all_columns)
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_org_user_email(user_email: &str, conn: &DbConn) -> Vec<Self> {
        let lower_mail = user_email.to_lowercase();

        conn.run(move |conn| {
            organizations::table
                .inner_join(users_organizations::table.on(users_organizations::org_uuid.eq(organizations::uuid)))
                .inner_join(users::table.on(users::uuid.eq(users_organizations::user_uuid)))
                .filter(users::email.eq(lower_mail))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .select(organizations::all_columns)
                .load::<Self>(conn)
                .expect("Error loading user orgs")
        })
        .await
    }
}

impl Membership {
    pub async fn to_json(&self, conn: &DbConn) -> Value {
        let org = Organization::find_by_uuid(&self.org_uuid, conn).await.unwrap();

        // HACK: Convert the manager type to a custom type
        // It will be converted back on other locations
        let membership_type = self.type_manager_as_custom();

        let permissions = json!({
                // TODO: Add full support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                // Currently we use the custom role as a manager role and link the 3 Collection roles to mimic the access_all permission
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                // If the following 3 Collection roles are set to true a custom user has access all permission
                "createNewCollections": membership_type == 4 && self.access_all,
                "editAnyCollection": membership_type == 4 && self.access_all,
                "deleteAnyCollection": membership_type == 4 && self.access_all,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
        });

        // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/ProfileOrganizationResponseModel.cs
        json!({
            "id": self.org_uuid,
            "identifier": null, // Not supported
            "name": org.name,
            "seats": 20, // hardcoded maxEmailsCount in the web-vault
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
            "useSecretsManager": false, // Not supported (Not AGPLv3 Licensed)
            "usePasswordManager": true,
            "useCustomPermissions": true,
            "useActivateAutofillPolicy": false,
            "useAdminSponsoredFamilies": false,
            "useRiskInsights": false, // Not supported (Not AGPLv3 Licensed)
            "useDisableSMAdsForUsers": true, // Hide Secrets Manager ads
            "useInviteLinks": false, // Not (yet) supported
            "useMyItems": false, // Not (yet) supported
            "useOrganizationDomains": false, // Not supported (Linked to SSO)
            "usePam": false, // Not supported
            "usePhishingBlocker": false,

            "organizationUserId": self.uuid,
            "providerId": null,
            "providerName": null,
            "providerType": null,
            "familySponsorshipFriendlyName": null,
            "familySponsorshipAvailable": false,
            "productTierType": 3, // Enterprise tier
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "familySponsorshipLastSyncDate": null,
            "familySponsorshipValidUntil": null,
            "familySponsorshipToDelete": null,
            "accessSecretsManager": false,
            // limit collection creation to managers with access_all permission to prevent issues
            "limitCollectionCreation": self.atype < MembershipType::Manager || !self.access_all,
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,
            "allowAdminAccessToAllCollectionItems": true,
            "userIsClaimedByOrganization": false, // Means not managed via the Members UI, like SSO

            "permissions": permissions,

            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side

            // These are per user
            "userId": self.user_uuid,
            // Accepted (not yet confirmed) members have no key yet; send null like upstream, not ""
            "key": (!self.akey.is_empty()).then_some(&self.akey),
            "status": self.status,
            "type": membership_type,
            "enabled": true,

            "object": "profileOrganization",
        })
    }

    // Used by admins to view other members, so nothing here may depend on this member's status
    pub async fn to_json_details_for_admin(
        &self,
        include_collections: bool,
        include_groups: bool,
        conn: &DbConn,
    ) -> Value {
        let user = User::find_by_uuid(&self.user_uuid, conn).await.unwrap();

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        let twofactor_enabled = !TwoFactor::find_by_user(&user.uuid, conn).await.is_empty();

        let groups: Vec<GroupId> = if include_groups && CONFIG.org_groups_enabled() {
            GroupUser::find_by_member(&self.uuid, conn).await.iter().map(|gu| gu.groups_uuid.clone()).collect()
        } else {
            // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
            // so just act as if there are no groups.
            Vec::new()
        };

        // Check if a user is in a group which has access to all collections
        // If that is the case, we should not return individual collections!
        // This is used by admins to view other members, so it must not depend on the membership status
        let full_access_group =
            CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(&self.org_uuid, &self.uuid, conn).await;

        // If collections are to be included, only include them if the user does not have full access via a group or defined to the user it self
        // Only the collections assigned directly are returned, the ones assigned via a group are returned via a special group endpoint
        let collections: Vec<Value> = if include_collections && !(full_access_group || self.access_all) {
            CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                .await
                .into_iter()
                .map(|cu| {
                    json!({
                        "id": cu.collection_uuid,
                        "readOnly": cu.read_only,
                        "hidePasswords": cu.hide_passwords,
                        "manage": cu.manage || (self.atype == MembershipType::Manager && !cu.read_only && !cu.hide_passwords),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        // HACK: Convert the manager type to a custom type
        // It will be converted back on other locations
        let membership_type = self.type_manager_as_custom();

        // HACK: Only return permissions if the user is of type custom and has access_all
        // Else Bitwarden will assume the defaults of all false
        let permissions = if membership_type == 4 && self.access_all {
            json!({
                // TODO: Add full support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                // Currently we use the custom role as a manager role and link the 3 Collection roles to mimic the access_all permission
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                // If the following 3 Collection roles are set to true a custom user has access all permission
                "createNewCollections": true,
                "editAnyCollection": true,
                "deleteAnyCollection": true,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
            })
        } else {
            json!(null)
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "name": if self.get_unrevoked_status() >= MembershipStatus::Accepted as i32 { Some(user.name) } else { None },
            "email": user.email,
            "externalId": self.external_id,
            "avatarColor": user.avatar_color,
            "groups": groups,
            "collections": collections,

            "status": status,
            "type": membership_type,
            "twoFactorEnabled": twofactor_enabled,
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "hasMasterPassword": !user.password_hash.is_empty(),

            "permissions": permissions,

            "ssoBound": false, // Not supported
            "claimedByOrganization": false, // Means not managed via the Members UI, like SSO
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
            "manage": col_user.manage,
        })
    }

    pub async fn to_json_details(&self, conn: &DbConn) -> Value {
        let coll_uuids = if self.access_all {
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections =
                CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn).await;
            collections
                .iter()
                .map(|cu| {
                    json!({
                        "id": cu.collection_uuid,
                        "readOnly": cu.read_only,
                        "hidePasswords": cu.hide_passwords,
                        "manage": cu.manage,
                    })
                })
                .collect()
        };

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,

            "status": status,
            "type": self.atype,
            "collections": coll_uuids,

            "object": "organizationUserDetails",
        })
    }

    pub async fn to_json_mini_details(&self, conn: &DbConn) -> Value {
        let user = User::find_by_uuid(&self.user_uuid, conn).await.unwrap();

        // Because Bitwarden wants the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = if self.status < MembershipStatus::Revoked as i32 {
            MembershipStatus::Revoked as i32
        } else {
            self.status
        };

        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "type": self.type_manager_as_custom(), // HACK: Convert the manager type to a custom type
            "status": status,
            "name": user.name,
            "email": user.email,
            "object": "organizationUserUserMiniDetails",
        })
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        // The legacy `access_all` flag reaches every collection, which a Custom role may only do through its
        // permissions, so it must never be stored on one. `set_type` takes care of this.
        if self.has_type(MembershipType::Custom) && self.access_all {
            err!("A Custom role membership can't have access to all collections")
        }

        User::update_uuid_revision(&self.user_uuid, conn).await;

        db_run! { conn:
            mysql {
                diesel::insert_into(users_organizations::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error adding user to organization")
            }
            postgresql, sqlite {
                diesel::insert_into(users_organizations::table)
                    .values(self)
                    .on_conflict(users_organizations::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error adding user to organization")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        CollectionUser::delete_all_by_user_and_org(&self.user_uuid, &self.org_uuid, conn).await?;
        GroupUser::delete_all_by_member(&self.uuid, conn).await?;

        conn.run(move |conn| {
            diesel::delete(users_organizations::table.filter(users_organizations::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from organization")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for member in Self::find_by_org(org_uuid, conn).await {
            member.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        for member in Self::find_any_state_by_user(user_uuid, conn).await {
            member.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_email_and_org(email: &str, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Membership> {
        if let Some(user) = User::find_by_mail(email, conn).await
            && let Some(member) = Membership::find_by_user_and_org(&user.uuid, org_uuid, conn).await
        {
            return Some(member);
        }

        None
    }

    pub fn has_status(&self, status: MembershipStatus) -> bool {
        self.status == status as i32
    }

    pub fn has_type(&self, user_type: MembershipType) -> bool {
        self.atype == user_type as i32
    }

    pub fn has_full_access(&self) -> bool {
        (self.access_all || self.atype >= MembershipType::Admin) && self.has_status(MembershipStatus::Confirmed)
    }

    pub async fn find_by_uuid(uuid: &MembershipId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table.filter(users_organizations::uuid.eq(uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_uuid_and_org(uuid: &MembershipId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::uuid.eq(uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_confirmed_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_accepted_and_confirmed_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(
                    users_organizations::status
                        .eq(MembershipStatus::Accepted as i32)
                        .or(users_organizations::status.eq(MembershipStatus::Confirmed as i32)),
                )
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_invited_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Invited as i32))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    // Should be used only when email are disabled.
    // In Organizations::send_invite status is set to Accepted only if the user has a password.
    pub async fn accept_user_invitations(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(users_organizations::table)
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Invited as i32))
                .set(users_organizations::status.eq(MembershipStatus::Accepted as i32))
                .execute(conn)
                .map_res("Error confirming invitations")
        })
        .await
    }

    pub async fn find_any_state_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn count_accepted_and_confirmed_by_user(
        user_uuid: &UserId,
        excluded_org: &OrganizationId,
        conn: &DbConn,
    ) -> i64 {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.ne(excluded_org))
                .filter(
                    users_organizations::status
                        .eq(MembershipStatus::Accepted as i32)
                        .or(users_organizations::status.eq(MembershipStatus::Confirmed as i32)),
                )
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading user organizations")
        })
        .await
    }

    pub async fn find_confirmed_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    // Get all users which are either owner or admin, or a manager which can manage/access all
    pub async fn find_confirmed_and_manage_all_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_organizations::atype
                        .eq_any(vec![MembershipType::Owner as i32, MembershipType::Admin as i32])
                        .or(users_organizations::atype
                            .eq(MembershipType::Manager as i32)
                            .and(users_organizations::access_all.eq(true))),
                )
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_org_and_type(org_uuid: &OrganizationId, atype: MembershipType, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .load::<Self>(conn)
                .expect("Error loading user organizations")
        })
        .await
    }

    pub async fn count_confirmed_by_org_and_type(
        org_uuid: &OrganizationId,
        atype: MembershipType,
        conn: &DbConn,
    ) -> i64 {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::atype.eq(atype as i32))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_user_and_org(user_uuid: &UserId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_confirmed_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading user organizations")
        })
        .await
    }

    pub async fn find_by_user_and_policy(user_uuid: &UserId, policy_type: OrgPolicyType, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .inner_join(
                    org_policies::table.on(org_policies::org_uuid
                        .eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))
                        .and(org_policies::atype.eq(policy_type as i32))
                        .and(org_policies::enabled.eq(true))),
                )
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .select(users_organizations::all_columns)
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn find_by_cipher_and_org(cipher_uuid: &CipherId, org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .left_join(users_collections::table.on(users_collections::user_uuid.eq(users_organizations::user_uuid)))
                .left_join(
                    ciphers_collections::table.on(ciphers_collections::collection_uuid
                        .eq(users_collections::collection_uuid)
                        .and(ciphers_collections::cipher_uuid.eq(&cipher_uuid))),
                )
                .filter(users_organizations::access_all.eq(true).or(
                    // AccessAll..
                    ciphers_collections::cipher_uuid.eq(&cipher_uuid), // ..or access to collection with cipher
                ))
                .select(users_organizations::all_columns)
                .distinct()
                .load::<Self>(conn)
                .expect("Error loading user organizations")
        })
        .await
    }

    pub async fn find_by_cipher_and_org_with_group(
        cipher_uuid: &CipherId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .inner_join(
                    groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                )
                .left_join(collections_groups::table.on(collections_groups::groups_uuid.eq(groups_users::groups_uuid)))
                .left_join(
                    groups::table.on(groups::uuid
                        .eq(groups_users::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .left_join(
                    ciphers_collections::table.on(ciphers_collections::collection_uuid
                        .eq(collections_groups::collections_uuid)
                        .and(ciphers_collections::cipher_uuid.eq(&cipher_uuid))),
                )
                .filter(groups::access_all.eq(true).or(
                    // AccessAll via groups
                    ciphers_collections::cipher_uuid.eq(&cipher_uuid), // ..or access to collection via group
                ))
                .select(users_organizations::all_columns)
                .distinct()
                .load::<Self>(conn)
                .expect("Error loading user organizations with groups")
        })
        .await
    }

    pub async fn user_has_ge_admin_access_to_cipher(user_uuid: &UserId, cipher_uuid: &CipherId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            users_organizations::table
                .inner_join(
                    ciphers::table.on(ciphers::uuid
                        .eq(cipher_uuid)
                        .and(ciphers::organization_uuid.eq(users_organizations::org_uuid.nullable()))),
                )
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_organizations::atype.eq_any(vec![MembershipType::Owner as i32, MembershipType::Admin as i32]),
                )
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    pub async fn find_by_collection_and_org(
        collection_uuid: &CollectionId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .left_join(users_collections::table.on(users_collections::user_uuid.eq(users_organizations::user_uuid)))
                .filter(users_organizations::access_all.eq(true).or(
                    // AccessAll..
                    users_collections::collection_uuid.eq(&collection_uuid), // ..or access to collection with cipher
                ))
                .select(users_organizations::all_columns)
                .load::<Self>(conn)
                .expect("Error loading user organizations")
        })
        .await
    }

    pub async fn find_by_external_id_and_org(ext_id: &str, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::external_id.eq(ext_id).and(users_organizations::org_uuid.eq(org_uuid)))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_main_user_org(user_uuid: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.ne(MembershipStatus::Revoked as i32))
                .order(users_organizations::atype.asc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }
}

impl OrganizationApiKey {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(organization_api_key::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
            postgresql, sqlite {
                diesel::insert_into(organization_api_key::table)
                    .values(self)
                    .on_conflict((organization_api_key::uuid, organization_api_key::org_uuid))
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving organization")
            }
        }
    }

    pub async fn find_by_org_uuid(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            organization_api_key::table.filter(organization_api_key::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(organization_api_key::table.filter(organization_api_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing organization api key from organization")
        })
        .await
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
#[deref(forward)]
#[from(forward)]
pub struct OrganizationId(String);

#[derive(
    Clone,
    Debug,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct MembershipId(String);

#[derive(Clone, Debug, DieselNewType, Display, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgApiKeyId(String);

#[cfg(test)]
mod tests {
    use super::*;
    use MembershipType::{Admin, Custom, Manager, Owner, User};

    fn member(role: MembershipType) -> Membership {
        let mut member = Membership::new("user".into(), "org".into(), None);
        member.atype = role as i32;
        member.status = MembershipStatus::Confirmed as i32;
        member
    }

    #[test]
    fn membership_type_authority() {
        assert!(Owner > Admin && Admin > Manager && Manager > Custom && Custom > User);
        assert!((Custom as i32) >= User && (Custom as i32) < Manager && (Custom as i32) < Admin);
        for raw in [99, -1] {
            assert_eq!((raw >= User, raw >= Manager, raw >= Admin, raw < Admin), (false, false, false, true));
        }
        for (value, expected) in [
            ("3", Some(Manager)),
            ("Manager", Some(Manager)),
            ("4", Some(Custom)),
            ("Custom", Some(Custom)),
            ("5", None),
        ] {
            assert_eq!(MembershipType::from_str(value), expected);
        }
    }

    #[test]
    fn requested_membership_type() {
        for (current, disabled, enabled) in [
            (None, Manager, Custom),
            (Some(User), Manager, Custom),
            (Some(Manager), Manager, Manager),
            (Some(Custom), Custom, Custom),
        ] {
            let current = current.map(member);
            for (flag, expected) in [(false, disabled), (true, enabled)] {
                assert_eq!(MembershipType::requested(Custom, current.as_ref(), flag), expected);
            }
        }
        assert_eq!(MembershipType::requested(User, Some(&member(Custom)), true), User);
        assert_eq!(MembershipType::requested(User, Some(&member(Manager)), true), User);
        for requested in [Owner, Admin, Manager] {
            assert_eq!(MembershipType::requested(requested, Some(&member(Custom)), true), requested);
        }
    }

    #[test]
    fn custom_permission_requests() {
        let ignored = serde_json::from_value(json!({"manageUsers":false,"manageSso":true})).unwrap();
        assert!(CustomPermission::requested(&ignored).unwrap().is_empty());
        for permission in CustomPermission::ALL {
            for value in [json!(true), json!(null), json!("true"), json!(1), json!([true])] {
                let request = HashMap::from([(permission.json_key().to_owned(), value.clone())]);
                let result = CustomPermission::requested(&request);
                if value == json!(true) && SUPPORTED_CUSTOM_PERMISSIONS.contains(&permission) {
                    assert_eq!(result.unwrap(), HashSet::from([permission]));
                } else {
                    assert!(result.is_err(), "{permission:?}: {value}");
                }
            }
        }
        assert_eq!(SUPPORTED_CUSTOM_PERMISSIONS, []);
    }

    #[test]
    fn role_changes_drop_custom_permissions() {
        for (from, to) in [
            (Custom, Owner),
            (Custom, Admin),
            (Custom, Manager),
            (Custom, User),
            (User, Custom),
            (Manager, Custom),
            (Custom, Custom),
            (Admin, User),
        ] {
            let mut member = member(from);
            member.access_all = true;
            for permission in CustomPermission::ALL {
                *member.custom_permission_mut(permission) = true;
            }
            member.set_type(to);
            for permission in CustomPermission::ALL {
                assert_eq!(*member.custom_permission_mut(permission), from == to, "{from:?} -> {to:?}");
            }
            assert_eq!(member.access_all, to != Custom);
        }
    }
}
