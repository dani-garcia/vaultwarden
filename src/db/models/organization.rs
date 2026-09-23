use std::{cmp::Ordering, collections::HashSet};

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
            ciphers_collections, collections, collections_groups, groups, groups_users, org_policies,
            organization_api_key, organizations, users, users_collections, users_organizations,
        },
    },
    error::MapResult,
};
use macros::UuidFromParam;

use super::{
    Cipher, CipherId, Collection, CollectionId, CollectionUser, Group, GroupId, GroupUser, OrgPolicy, OrgPolicyType,
    TwoFactor, User, UserId, collection::stored_assignment_manage,
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
#[allow(clippy::struct_excessive_bools)]
pub struct Membership {
    pub uuid: MembershipId,
    pub user_uuid: UserId,
    pub org_uuid: OrganizationId,

    pub invited_by_email: Option<String>,

    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
    pub manage_users: bool,
    pub manage_groups: bool,
    pub manage_policies: bool,
    pub create_new_collections: bool,
    pub edit_any_collection: bool,
    pub delete_any_collection: bool,
    pub access_event_logs: bool,
    pub access_import_export: bool,
    pub access_reports: bool,
}

/// The nine Custom-role permissions in one place: struct field, Bitwarden JSON key, accessor name.
///
/// Everything that needs the complete set -- the `Membership` accessors, the permissions object the
/// clients receive, and the request parser in `api::core::organizations` -- expands this list instead
/// of repeating it, so the set cannot drift apart between them.
macro_rules! custom_role_permissions {
    ($consumer:path) => {
        $consumer! {
            manage_users, "manageUsers", has_manage_users;
            manage_groups, "manageGroups", has_manage_groups;
            manage_policies, "managePolicies", has_manage_policies;
            create_new_collections, "createNewCollections", has_create_new_collections;
            edit_any_collection, "editAnyCollection", has_edit_any_collection;
            delete_any_collection, "deleteAnyCollection", has_delete_any_collection;
            access_event_logs, "accessEventLogs", has_access_event_logs;
            access_import_export, "accessImportExport", has_access_import_export;
            access_reports, "accessReports", has_access_reports;
        }
    };
}
pub(crate) use custom_role_permissions;

macro_rules! impl_membership_custom_permissions {
    ($($field:ident, $json_key:literal, $accessor:ident);* $(;)?) => {
        impl Membership {
            // The granular custom permission flags are only meaningful while the membership is of
            // the Custom type. Gating them on the type here ensures that a stale flag left over from
            // a type change (e.g. via the admin panel) can never grant anything.
            $(
                pub fn $accessor(&self) -> bool {
                    self.has_type(MembershipType::Custom) && self.$field
                }
            )*

            pub fn clear_custom_permissions(&mut self) {
                $( self.$field = false; )*
            }

            /// The permissions object the Bitwarden clients receive.
            ///
            /// Type-gated through the accessors above, so a flag left behind on a non-Custom
            /// membership is reported as `false` rather than as a grant.
            pub fn custom_permissions_json(&self) -> Value {
                json!({
                    $( $json_key: self.$accessor(), )*
                    "manageSso": false, // Not supported
                    "manageResetPassword": false,
                    "manageScim": false // Not supported (Not AGPLv3 Licensed)
                })
            }
        }
    };
}
custom_role_permissions!(impl_membership_custom_permissions);

/// Diesel equivalent of [`Membership::has_edit_any_collection`].
///
/// Keep the role check in this shared predicate so a stale flag on any non-Custom membership
/// remains inert in every collection-access query.
pub(super) fn custom_membership_with_edit_any_collection() -> diesel::dsl::And<
    diesel::dsl::Eq<users_organizations::atype, i32>,
    diesel::dsl::Eq<users_organizations::edit_any_collection, bool>,
> {
    users_organizations::atype.eq(MembershipType::Custom as i32).and(users_organizations::edit_any_collection.eq(true))
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

#[derive(Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum MembershipType {
    Owner = 0,
    Admin = 1,
    User = 2,
    // NOTE: the legacy Manager role (wire value 3) has been folded into Custom. It is no longer a
    // distinct variant: it is never persisted or emitted, and an incoming value 3 is mapped onto
    // Custom for backward compatibility (see `from_str`). The Custom discriminant stays 4 because
    // that is the only role modern Bitwarden clients understand as carrying custom permissions.
    Custom = 4,
}

impl MembershipType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "Owner" => Some(MembershipType::Owner),
            "1" | "Admin" => Some(MembershipType::Admin),
            "2" | "User" => Some(MembershipType::User),
            // "3"/"Manager" is the legacy Manager role. Modern clients no longer offer it, but an old
            // client or stored request may still send value 3. Custom supersedes Manager, so accept
            // and fold it onto Custom.
            "3" | "Manager" | "4" | "Custom" => Some(MembershipType::Custom),
            _ => None,
        }
    }

    const fn access_rank(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Custom => 1,
            Self::Admin => 2,
            Self::Owner => 3,
        }
    }
}

/// The stored `users_organizations.atype` values that carry organization-wide authority by role.
///
/// Queries enumerate the two values instead of comparing `atype <= Admin`: `<=` also matches every value
/// *below* `Owner`, so a corrupt or negative `atype` would satisfy the SQL check while every Rust guard
/// rejects it. Enumerating keeps both layers on the same answer.
pub(crate) const ORG_ADMIN_ATYPES: &[i32] = &[MembershipType::Owner as i32, MembershipType::Admin as i32];

impl Ord for MembershipType {
    fn cmp(&self, other: &MembershipType) -> Ordering {
        // Roles are ordered by their authorization rank, not by their raw discriminant (Custom's
        // discriminant is 4 but it ranks between User and Admin). The discriminant is kept as a
        // stable tie-breaker so `Ord` never disagrees with `Eq`.
        self.access_rank().cmp(&other.access_rank()).then_with(|| (*self as i32).cmp(&(*other as i32)))
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
            err!(format!("BillingEmail {} is not a valid email address", self.billing_email))
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

        let membership_type = self.atype;

        let permissions = self.custom_permissions_json();

        // Edit any collection grants full read/edit access to every collection, but it must not
        // accidentally grant collection creation. The client treats limitCollectionCreation=false as
        // an independent create grant, so compute it from the actual role/permission.
        let limit_collection_creation = self.limit_collection_creation();

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
            "limitCollectionCreation": limit_collection_creation,
            "limitCollectionDeletion": true,
            "limitItemDeletion": false,
            "allowAdminAccessToAllCollectionItems": true,
            "userIsManagedByOrganization": false, // Means not managed via the Members UI, like SSO
            "userIsClaimedByOrganization": false, // The new key instead of the obsolete userIsManagedByOrganization

            "permissions": permissions,

            "maxStorageGb": i16::MAX, // The value doesn't matter, we don't check server-side

            // These are per user
            "userId": self.user_uuid,
            "key": self.akey,
            "status": self.status,
            "type": membership_type,
            "enabled": true,

            "object": "profileOrganization",
        })
    }

    pub async fn to_json_user_details(&self, include_collections: bool, include_groups: bool, conn: &DbConn) -> Value {
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

        let collections: Vec<Value> = if include_collections {
            CollectionUser::find_by_organization_and_user_uuid(&self.org_uuid, &self.user_uuid, conn)
                .await
                .into_iter()
                .map(|collection_user| {
                    json!({
                        "id": collection_user.collection_uuid,
                        "readOnly": collection_user.read_only,
                        "hidePasswords": collection_user.hide_passwords,
                        "manage": stored_assignment_manage(self.atype, collection_user.manage),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        let membership_type = self.atype;

        // Only return a permissions object for custom-type members. Otherwise Bitwarden assumes
        // all-false defaults and the role itself supplies any elevated capabilities.
        let permissions = if membership_type == MembershipType::Custom as i32 {
            self.custom_permissions_json()
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
            // `access_all` no longer exists as a stored flag; report the effective all-collection
            // access so clients that still read this obsolete field keep seeing a consistent value.
            "accessAll": self.grants_access_to_all_collections(),
            "twoFactorEnabled": twofactor_enabled,
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "hasMasterPassword": !user.password_hash.is_empty(),

            "permissions": permissions,

            "ssoBound": false, // Not supported
            "managedByOrganization": false, // This key is obsolete replaced by claimedByOrganization
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
        let coll_uuids = if self.grants_access_to_all_collections() {
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
            // Obsolete stored flag removed; report the effective all-collection access instead.
            "accessAll": self.grants_access_to_all_collections(),
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
            "type": self.atype,
            "status": status,
            "name": user.name,
            "email": user.email,
            "object": "organizationUserUserMiniDetails",
        })
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
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
        (self.has_edit_any_collection() || self.atype >= MembershipType::Admin)
            && self.has_status(MembershipStatus::Confirmed)
    }

    /// Whether this membership reaches every collection in the org regardless of per-collection
    /// assignments -- Admins/Owners implicitly, and Custom members holding `edit_any_collection`. The
    /// successor of the removed `access_all` flag: it backs the `accessAll` field the Bitwarden clients
    /// still read, and intentionally does not gate on status, matching the old column. Authorization
    /// decisions use the status-aware `has_full_access` instead.
    pub fn grants_access_to_all_collections(&self) -> bool {
        self.atype >= MembershipType::Admin || self.has_edit_any_collection()
    }

    /// Whether enabling an organization policy may revoke this membership as part of enforcing it.
    ///
    /// Two exclusions, both applying to every policy whose enforcement revokes non-compliant members
    /// (Two-Factor Authentication and Single Organization):
    ///
    /// * Admins and Owners are never revoked. `atype < Admin` is deliberately the *ceiling* comparison
    ///   used everywhere else, so an unknown stored role stays sweepable.
    /// * Nor is the member who made the change. Until the Custom role this was implied by the first rule;
    ///   `managePolicies` can now be held by a Custom member, who *is* sweepable and would otherwise
    ///   revoke themselves mid-request. Bitwarden excludes the acting user for the same reason.
    ///
    /// Peers are still revoked exactly as before.
    pub fn is_policy_enforcement_target(&self, acting_user: &UserId) -> bool {
        self.atype < MembershipType::Admin && &self.user_uuid != acting_user
    }

    /// Check for an explicit per-collection Manage grant without treating any `access_all` value as such
    /// a grant. Neither membership nor group `access_all` may manufacture one.
    ///
    /// There is deliberately no live exception for legacy Managers whose authority came from an
    /// organization-local `access_all` group. That legacy management authority is intentionally not
    /// materialized into Custom membership permissions during migration. The group continues to grant
    /// collection access dynamically, while any desired Custom collection-management permissions must
    /// be assigned explicitly after the upgrade.
    pub async fn has_explicit_collection_manage_access(&self, collection_uuid: &CollectionId, conn: &DbConn) -> bool {
        !self.explicit_collection_manage_grants(Some(collection_uuid.clone()), conn).await.is_empty()
    }

    /// Every collection of this organization carrying a real per-collection Manage grant for this
    /// membership, for callers that would otherwise ask the single-collection question once per
    /// collection.
    pub async fn explicitly_managed_collection_ids(&self, conn: &DbConn) -> HashSet<CollectionId> {
        self.explicit_collection_manage_grants(None, conn).await.into_iter().collect()
    }

    /// The single definition of "holds a real per-collection Manage grant" -- for one collection or for
    /// all of them, in one statement either way.
    ///
    /// Both grant paths are resolved in the same query: a direct `users_collections.manage` row, or a
    /// `collections_groups.manage` row reached through a group of *this* organization. The
    /// `collections_groups` join hangs off `groups::uuid` rather than off `groups_users::groups_uuid`,
    /// so a `groups_users` row pointing at another organization's group contributes nothing: the group
    /// fails the organization check, `groups::uuid` is then NULL and the join cannot match. Every
    /// collection considered is joined on the membership's own `org_uuid`, so no grant crosses
    /// organizations.
    ///
    /// `groups.access_all` is never read here. It grants collection *access* dynamically and is not a
    /// management grant; counting it would make an access-all group double as one.
    async fn explicit_collection_manage_grants(
        &self,
        collection_uuid: Option<CollectionId>,
        conn: &DbConn,
    ) -> Vec<CollectionId> {
        let membership_uuid = self.uuid.clone();
        let user_uuid = self.user_uuid.clone();
        let org_uuid = self.org_uuid.clone();

        conn.run(move |conn| {
            let grants = users_organizations::table
                .inner_join(collections::table.on(collections::org_uuid.eq(users_organizations::org_uuid)))
                .left_join(
                    users_collections::table.on(users_collections::collection_uuid
                        .eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(users_organizations::user_uuid))),
                )
                .left_join(groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)))
                .left_join(
                    groups::table.on(groups::uuid
                        .eq(groups_users::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .left_join(
                    collections_groups::table.on(collections_groups::groups_uuid
                        .nullable()
                        .eq(groups::uuid.nullable())
                        .and(collections_groups::collections_uuid.eq(collections::uuid))),
                )
                .filter(users_organizations::uuid.eq(membership_uuid))
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(users_organizations::atype.eq_any([MembershipType::User as i32, MembershipType::Custom as i32]))
                .filter(users_collections::manage.eq(true).or(collections_groups::manage.eq(true)))
                .select(collections::uuid)
                .distinct();

            match collection_uuid {
                Some(collection_uuid) => grants.filter(collections::uuid.eq(collection_uuid)).load(conn),
                None => grants.load(conn),
            }
            .unwrap_or_default()
        })
        .await
    }

    /// `manageAllCollections` is a client-side aggregate checkbox, not a separately persisted
    /// Bitwarden permission. It is selected exactly when all three child permissions are selected.
    pub fn has_manage_all_collections(&self) -> bool {
        self.has_create_new_collections() && self.has_edit_any_collection() && self.has_delete_any_collection()
    }

    /// Match Vaultwarden's existing collection-creation policy while keeping the Custom
    /// permission independent from edit/delete.
    pub fn can_create_new_collections(&self) -> bool {
        if !self.has_status(MembershipStatus::Confirmed) {
            return false;
        }

        match MembershipType::from_i32(self.atype) {
            Some(MembershipType::Owner | MembershipType::Admin) => true,
            Some(MembershipType::Custom) => self.create_new_collections,
            Some(MembershipType::User) | None => false,
        }
    }

    pub fn limit_collection_creation(&self) -> bool {
        match MembershipType::from_i32(self.atype) {
            Some(MembershipType::Owner | MembershipType::Admin) => false,
            Some(MembershipType::Custom) => !self.create_new_collections,
            Some(MembershipType::User) | None => true,
        }
    }

    pub fn can_delete_any_collection(&self) -> bool {
        self.has_status(MembershipStatus::Confirmed)
            && (self.atype >= MembershipType::Admin || self.has_delete_any_collection())
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

    // Get all users which are either owner or admin, or a Custom member which can access all collections
    pub async fn find_confirmed_and_manage_all_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_organizations::atype
                        .eq_any(ORG_ADMIN_ATYPES)
                        .or(custom_membership_with_edit_any_collection()),
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

    pub async fn get_orgs_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<OrganizationId> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .select(users_organizations::org_uuid)
                .load::<OrganizationId>(conn)
                .unwrap_or_default()
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
                .left_join(users_collections::table.on(users_collections::user_uuid.eq(users_organizations::user_uuid)))
                .left_join(
                    ciphers_collections::table.on(ciphers_collections::collection_uuid
                        .eq(users_collections::collection_uuid)
                        .and(ciphers_collections::cipher_uuid.eq(&cipher_uuid))),
                )
                .filter(
                    custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                        .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                        .or(ciphers_collections::cipher_uuid.eq(&cipher_uuid)), // ..or access to collection with cipher
                )
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

    pub async fn find_by_collection_and_org(
        collection_uuid: &CollectionId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid))
                .left_join(users_collections::table.on(users_collections::user_uuid.eq(users_organizations::user_uuid)))
                .filter(
                    custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                        .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                        .or(users_collections::collection_uuid.eq(&collection_uuid)), // ..or access to collection
                )
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

/// Fixtures for the tests that exercise the Custom role, here and in the modules using it.
#[cfg(test)]
impl Membership {
    /// An `atype` this build cannot interpret: a future build, a partial rollback or a hand-edited row.
    pub const UNKNOWN_ATYPE: i32 = 99;

    /// `atype` is a raw `i32` and `set` runs regardless of the role on purpose, so the tests can cover
    /// a role this build does not know and a permission flag left behind by a role change.
    pub fn for_test(atype: i32, status: MembershipStatus, set: impl FnOnce(&mut Self)) -> Self {
        let mut membership =
            Self::new(UserId::from(String::from("test-user")), OrganizationId::from(String::from("test-org")), None);
        membership.atype = atype;
        membership.status = status as i32;
        set(&mut membership);
        membership
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNKNOWN_ATYPE: i32 = Membership::UNKNOWN_ATYPE;

    fn membership(atype: i32) -> Membership {
        Membership::for_test(atype, MembershipStatus::Confirmed, |_| {})
    }

    /// How roles rank against each other, and how a stored `atype` is read.
    ///
    /// Every authorization guard in the tree asks `atype >= MembershipType::X` or
    /// `atype < MembershipType::X` against a value straight from the database, so those two answers --
    /// including the answers for a value this build does not know -- are the security semantics here.
    #[test]
    fn membership_type_ordering_and_parsing() {
        // Roles rank by authority, not by the stored discriminant: Custom is stored as 4 but sits
        // between User and Admin.
        assert!(MembershipType::Owner > MembershipType::Admin);
        assert!(MembershipType::Admin > MembershipType::Custom);
        assert!(MembershipType::Custom > MembershipType::User);

        // (stored atype, reaches Admin authority, is below Admin)
        let stored = [
            (MembershipType::Owner as i32, true, false),
            (MembershipType::Admin as i32, true, false),
            (MembershipType::Custom as i32, false, true),
            (MembershipType::User as i32, false, true),
            // An unknown role answers "no" to authority *and* "yes" to being below Admin. Both are
            // deliberate: it never reaches administrative authority, and it stays sweepable by policy
            // enforcement instead of becoming a row nothing can act on.
            (UNKNOWN_ATYPE, false, true),
            (-1, false, true),
        ];
        for (atype, reaches_admin, below_admin) in stored {
            assert_eq!(atype >= MembershipType::Admin, reaches_admin, "atype {atype} >= Admin");
            assert_eq!(atype < MembershipType::Admin, below_admin, "atype {atype} < Admin");
        }

        // Wire values. Modern clients no longer offer the Manager role, but an old client or a stored
        // request may still send 3; Custom supersedes it, so it is accepted and folded on.
        let accepted = [
            ("0", MembershipType::Owner),
            ("Owner", MembershipType::Owner),
            ("1", MembershipType::Admin),
            ("Admin", MembershipType::Admin),
            ("2", MembershipType::User),
            ("User", MembershipType::User),
            ("3", MembershipType::Custom),
            ("Manager", MembershipType::Custom),
            ("4", MembershipType::Custom),
            ("Custom", MembershipType::Custom),
        ];
        for (wire, expected) in accepted {
            assert!(
                MembershipType::from_str(wire) == Some(expected),
                "{wire:?} must parse as the role stored as {}",
                expected as i32
            );
        }
        for rejected in ["", " ", "3 ", "5", "-1", "manager", "custom", "Manager\n"] {
            assert!(MembershipType::from_str(rejected).is_none(), "{rejected:?} must not parse");
        }
    }

    /// The nine granular permissions are stored as plain columns, so they outlive a role change. Every
    /// reader gates them on the Custom type for that reason: a flag left behind on a User, an Admin or
    /// a role this build cannot read must grant nothing.
    #[test]
    fn custom_permission_flags_are_type_gated() {
        type Reader = fn(&Membership) -> bool;
        type Setter = fn(&mut Membership, bool);

        let permissions: [(&str, Reader, Setter); 9] = [
            ("manageUsers", Membership::has_manage_users, |m, v| m.manage_users = v),
            ("manageGroups", Membership::has_manage_groups, |m, v| m.manage_groups = v),
            ("managePolicies", Membership::has_manage_policies, |m, v| m.manage_policies = v),
            ("createNewCollections", Membership::has_create_new_collections, |m, v| m.create_new_collections = v),
            ("editAnyCollection", Membership::has_edit_any_collection, |m, v| m.edit_any_collection = v),
            ("deleteAnyCollection", Membership::has_delete_any_collection, |m, v| m.delete_any_collection = v),
            ("accessEventLogs", Membership::has_access_event_logs, |m, v| m.access_event_logs = v),
            ("accessImportExport", Membership::has_access_import_export, |m, v| m.access_import_export = v),
            ("accessReports", Membership::has_access_reports, |m, v| m.access_reports = v),
        ];

        for (name, read, set) in permissions {
            for atype in [
                MembershipType::Owner as i32,
                MembershipType::Admin as i32,
                MembershipType::User as i32,
                MembershipType::Custom as i32,
                UNKNOWN_ATYPE,
            ] {
                let mut member = membership(atype);
                assert!(!read(&member), "{name} must be off while its column is false (atype {atype})");

                set(&mut member, true);
                assert_eq!(
                    read(&member),
                    atype == MembershipType::Custom as i32,
                    "{name} is only meaningful on a Custom membership (atype {atype})"
                );
            }
        }

        // Clearing has to reach every one of the nine; a forgotten field would leave authority behind
        // on a member that was just moved off the Custom role.
        let mut member = membership(MembershipType::Custom as i32);
        for (_, _, set) in permissions {
            set(&mut member, true);
        }
        member.clear_custom_permissions();
        for (name, read, _) in permissions {
            assert!(!read(&member), "{name} survived clear_custom_permissions");
        }

        // `manageAllCollections` is a client-side aggregate: selected exactly when all three child
        // permissions are.
        let all_collections = |atype, create, edit, delete| {
            let mut member = membership(atype);
            member.create_new_collections = create;
            member.edit_any_collection = edit;
            member.delete_any_collection = delete;
            member
        };
        let custom = MembershipType::Custom as i32;
        assert!(all_collections(custom, true, true, true).has_manage_all_collections());
        for (missing, member) in [
            ("createNewCollections", all_collections(custom, false, true, true)),
            ("editAnyCollection", all_collections(custom, true, false, true)),
            ("deleteAnyCollection", all_collections(custom, true, true, false)),
            // And, like every other reader, the aggregate is gated on the type.
            ("the Custom role", all_collections(MembershipType::User as i32, true, true, true)),
        ] {
            assert!(!member.has_manage_all_collections(), "{missing} missing must clear the aggregate");
        }
    }
}
