use derive_more::{AsRef, From};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, core::two_factor},
    db::{
        DbConn,
        schema::{org_policies, users_organizations},
    },
    error::MapResult,
};

use super::{Membership, MembershipId, MembershipStatus, MembershipType, OrganizationId, TwoFactor, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = org_policies)]
#[diesel(primary_key(uuid))]
pub struct OrgPolicy {
    pub uuid: OrgPolicyId,
    pub org_uuid: OrganizationId,
    pub atype: i32,
    pub enabled: bool,
    pub data: String,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Enums/PolicyType.cs
#[derive(Copy, Clone, Eq, PartialEq, num_derive::FromPrimitive)]
pub enum OrgPolicyType {
    TwoFactorAuthentication = 0,
    MasterPassword = 1,
    PasswordGenerator = 2,
    SingleOrg = 3,
    // RequireSso = 4, // Not supported
    PersonalOwnership = 5,
    DisableSend = 6,
    SendOptions = 7,
    ResetPassword = 8,
    // MaximumVaultTimeout = 9, // Not supported (Not AGPLv3 Licensed)
    // DisablePersonalVaultExport = 10, // Not supported (Not AGPLv3 Licensed)
    // ActivateAutofill = 11,
    // AutomaticAppLogIn = 12,
    // FreeFamiliesSponsorshipPolicy = 13,
    RemoveUnlockWithPin = 14,
    RestrictedItemTypes = 15,
    UriMatchDefaults = 16,
    // AutotypeDefaultSetting = 17, // Not supported yet
    AutomaticUserConfirmation = 18,
    // BlockClaimedDomainAccountCreation = 19, // Not supported (Not AGPLv3 Licensed)
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Models/Data/Organizations/Policies/SendOptionsPolicyData.cs#L5
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOptionsPolicyData {
    #[serde(rename = "disableHideEmail", alias = "DisableHideEmail")]
    pub disable_hide_email: bool,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Models/Data/Organizations/Policies/ResetPasswordDataModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordDataModel {
    #[serde(rename = "autoEnrollEnabled", alias = "AutoEnrollEnabled")]
    pub auto_enroll_enabled: bool,
}

/// Local methods
impl OrgPolicy {
    pub fn new(org_uuid: OrganizationId, atype: OrgPolicyType, enabled: bool, data: String) -> Self {
        Self {
            uuid: OrgPolicyId(crate::util::get_uuid()),
            org_uuid,
            atype: atype as i32,
            enabled,
            data,
        }
    }

    pub fn has_type(&self, policy_type: OrgPolicyType) -> bool {
        self.atype == policy_type as i32
    }

    pub fn to_json(&self) -> Value {
        let data_json: Value = serde_json::from_str(&self.data).unwrap_or(Value::Null);
        let mut policy = json!({
            "id": self.uuid,
            "organizationId": self.org_uuid,
            "type": self.atype,
            "data": data_json,
            "enabled": self.enabled,
            "revisionDate": null,
            "object": "policy",
        });

        // Upstream adds this key/value
        // Allow enabling Single Org policy when the organization has claimed domains.
        // See: (https://github.com/bitwarden/server/pull/5565)
        // We return the same to prevent possible issues
        if self.atype == 8i32 {
            policy["canToggleState"] = json!(true);
        }

        policy
    }
}

/// Database methods
impl OrgPolicy {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(org_policies::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(org_policies::table)
                            .filter(org_policies::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving org_policy")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving org_policy")
            }
            postgresql {
                // We need to make sure we're not going to violate the unique constraint on org_uuid and atype.
                // This happens automatically on other DBMS backends due to replace_into(). PostgreSQL does
                // not support multiple constraints on ON CONFLICT clauses.
                let _: () = diesel::delete(
                    org_policies::table
                        .filter(org_policies::org_uuid.eq(&self.org_uuid))
                        .filter(org_policies::atype.eq(&self.atype)),
                )
                .execute(conn)
                .map_res("Error deleting org_policy for insert")?;

                diesel::insert_into(org_policies::table)
                    .values(self)
                    .on_conflict(org_policies::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving org_policy")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(org_policies::table.filter(org_policies::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting org_policy")
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            org_policies::table
                .filter(org_policies::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading org_policy")
        })
        .await
    }

    pub async fn find_confirmed_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(org_policies::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .select(org_policies::all_columns)
                .load::<Self>(conn)
                .expect("Error loading org_policy")
        })
        .await
    }

    pub async fn find_by_org_and_type(
        org_uuid: &OrganizationId,
        policy_type: OrgPolicyType,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            org_policies::table
                .filter(org_policies::org_uuid.eq(org_uuid))
                .filter(org_policies::atype.eq(policy_type as i32))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(org_policies::table.filter(org_policies::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting org_policy")
        })
        .await
    }

    pub async fn find_accepted_and_confirmed_by_user_and_active_policy(
        user_uuid: &UserId,
        policy_type: OrgPolicyType,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(org_policies::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .filter(users_organizations::status.eq(MembershipStatus::Accepted as i32))
                .or_filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(org_policies::atype.eq(policy_type as i32))
                .filter(org_policies::enabled.eq(true))
                .select(org_policies::all_columns)
                .load::<Self>(conn)
                .expect("Error loading org_policy")
        })
        .await
    }

    pub async fn find_confirmed_by_user_and_active_policy(
        user_uuid: &UserId,
        policy_type: OrgPolicyType,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(org_policies::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(org_policies::atype.eq(policy_type as i32))
                .filter(org_policies::enabled.eq(true))
                .select(org_policies::all_columns)
                .load::<Self>(conn)
                .expect("Error loading org_policy")
        })
        .await
    }

    /// Returns true if the user belongs to an org that has enabled the specified policy type,
    /// and the user is not an owner or admin of that org. This is only useful for checking
    /// applicability of policy types that have these particular semantics.
    pub async fn is_applicable_to_user(
        user_uuid: &UserId,
        policy_type: OrgPolicyType,
        exclude_org_uuid: Option<&OrganizationId>,
        conn: &DbConn,
    ) -> bool {
        for policy in
            OrgPolicy::find_accepted_and_confirmed_by_user_and_active_policy(user_uuid, policy_type, conn).await
        {
            // Check if we need to skip this organization.
            if exclude_org_uuid.is_some() && *exclude_org_uuid.unwrap() == policy.org_uuid {
                continue;
            }

            if let Some(user) = Membership::find_confirmed_by_user_and_org(user_uuid, &policy.org_uuid, conn).await
                && user.atype < MembershipType::Admin
            {
                return true;
            }
        }
        false
    }

    /// Returns every membership of the user, in any status and of any role, in an organization which has
    /// `policy_type` enabled. Contrary to the queries above this filters nothing away, the caller decides
    /// which memberships it cares about, like Bitwarden does per policy.
    /// https://github.com/bitwarden/server/blob/b3d1eb9a7854322f106efa55c191c1a4da9f8645/src/Core/AdminConsole/OrganizationFeatures/Policies/PolicyRequirements/BasePolicyRequirementFactory.cs
    pub async fn find_memberships_by_user_and_active_policy(
        user_uuid: &UserId,
        policy_type: OrgPolicyType,
        conn: &DbConn,
    ) -> Vec<Membership> {
        conn.run(move |conn| {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(org_policies::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .filter(org_policies::atype.eq(policy_type as i32))
                .filter(org_policies::enabled.eq(true))
                .select(users_organizations::all_columns)
                .load::<Membership>(conn)
                .expect("Error loading memberships by org_policy")
        })
        .await
    }

    /// Requires both the server wide config option and the policy of this organization, mirroring
    /// Bitwarden where support has to enable the feature on top of the policy.
    pub async fn is_auto_confirm_enabled(org_uuid: &OrganizationId, conn: &DbConn) -> bool {
        CONFIG.org_auto_confirm_enabled()
            && match Self::find_by_org_and_type(org_uuid, OrgPolicyType::AutomaticUserConfirmation, conn).await {
                Some(p) => p.enabled,
                None => false,
            }
    }

    pub async fn check_user_allowed(m: &Membership, action: &str, conn: &DbConn) -> EmptyResult {
        if m.atype < MembershipType::Admin && m.status > (MembershipStatus::Invited as i32) {
            // Enforce TwoFactor/TwoStep login
            if let Some(p) = Self::find_by_org_and_type(&m.org_uuid, OrgPolicyType::TwoFactorAuthentication, conn).await
                && p.enabled
                && TwoFactor::find_by_user(&m.user_uuid, conn).await.is_empty()
            {
                if CONFIG.email_2fa_auto_fallback() {
                    two_factor::email::find_and_activate_email_2fa(&m.user_uuid, conn).await?;
                } else {
                    err!(format!("Cannot {} because 2FA is required (membership {})", action, m.uuid));
                }
            }

            // Check if the user is part of another Organization with SingleOrg activated
            if Self::is_applicable_to_user(&m.user_uuid, OrgPolicyType::SingleOrg, Some(&m.org_uuid), conn).await {
                err!(format!(
                    "Cannot {} because another organization policy forbids it (membership {})",
                    action, m.uuid
                ));
            }

            if let Some(p) = Self::find_by_org_and_type(&m.org_uuid, OrgPolicyType::SingleOrg, conn).await
                && p.enabled
                && Membership::count_accepted_and_confirmed_by_user(&m.user_uuid, &m.org_uuid, conn).await > 0
            {
                err!(format!(
                    "Cannot {} because the organization policy forbids being part of other organization (membership {})",
                    action, m.uuid
                ));
            }
        }

        // Stricter than the SingleOrg block above: this policy exempts no role and no status.
        // https://github.com/bitwarden/server/blob/b3d1eb9a7854322f106efa55c191c1a4da9f8645/src/Core/AdminConsole/OrganizationFeatures/Policies/Enforcement/AutoConfirm/AutomaticUserConfirmationPolicyEnforcementHandler.cs
        if AutoConfirmRequirement::for_user(&m.user_uuid, conn).await.forbids_membership_outside(&m.org_uuid) {
            err!(format!(
                "Cannot {} because another organization confirms its members automatically and forbids other memberships (membership {})",
                action, m.uuid
            ));
        }

        if Self::is_auto_confirm_enabled(&m.org_uuid, conn).await
            && Membership::count_accepted_confirmed_and_revoked_by_user(&m.user_uuid, &m.org_uuid, conn).await > 0
        {
            err!(format!(
                "Cannot {} because the organization confirms its members automatically and forbids being part of other organizations (membership {})",
                action, m.uuid
            ));
        }

        Ok(())
    }

    pub async fn org_is_reset_password_auto_enroll(org_uuid: &OrganizationId, conn: &DbConn) -> bool {
        // Account recovery depends on outbound mail. When SMTP is disabled, treat the
        // auto-enroll policy as inactive so invites/registration are not forced to
        // supply a reset-password key (see check_reset_password_applicable).
        if !CONFIG.mail_enabled() {
            return false;
        }

        match OrgPolicy::find_by_org_and_type(org_uuid, OrgPolicyType::ResetPassword, conn).await {
            Some(policy) => match serde_json::from_str::<ResetPasswordDataModel>(&policy.data) {
                Ok(opts) => {
                    return policy.enabled && opts.auto_enroll_enabled;
                }
                _ => error!("Failed to deserialize ResetPasswordDataModel: {}", policy.data),
            },
            None => return false,
        }

        false
    }

    /// Returns true if the user belongs to an org that has enabled the `DisableHideEmail`
    /// option of the `Send Options` policy, and the user is not an owner or admin of that org.
    pub async fn is_hide_email_disabled(user_uuid: &UserId, conn: &DbConn) -> bool {
        for policy in
            OrgPolicy::find_confirmed_by_user_and_active_policy(user_uuid, OrgPolicyType::SendOptions, conn).await
        {
            if let Some(user) = Membership::find_confirmed_by_user_and_org(user_uuid, &policy.org_uuid, conn).await
                && user.atype < MembershipType::Admin
            {
                match serde_json::from_str::<SendOptionsPolicyData>(&policy.data) {
                    Ok(opts) => {
                        if opts.disable_hide_email {
                            return true;
                        }
                    }
                    _ => error!("Failed to deserialize SendOptionsPolicyData: {}", policy.data),
                }
            }
        }
        false
    }

    pub async fn is_enabled_for_member(member_uuid: &MembershipId, policy_type: OrgPolicyType, conn: &DbConn) -> bool {
        if let Some(member) = Membership::find_by_uuid(member_uuid, conn).await
            && let Some(policy) = OrgPolicy::find_by_org_and_type(&member.org_uuid, policy_type, conn).await
        {
            return policy.enabled;
        }
        false
    }
}

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrgPolicyId(String);

/// The memberships of a user in organizations which confirm their members automatically.
///
/// Bitwarden models this as a policy requirement: a value answering what the policy forbids this user.
/// Contrary to every other policy this one exempts no role and no status, so an owner or an admin is
/// bound just like a plain member. Not every operation looks at every status though, which is why each
/// question below states which memberships it counts.
/// https://github.com/bitwarden/server/blob/b3d1eb9a7854322f106efa55c191c1a4da9f8645/src/Core/AdminConsole/OrganizationFeatures/Policies/PolicyRequirements/AutomaticUserConfirmationPolicyRequirement.cs
pub struct AutoConfirmRequirement(Vec<Membership>);

impl AutoConfirmRequirement {
    /// Always empty while the server wide config option is off: the policy can not be enabled anywhere
    /// then and so enforces nothing.
    pub async fn for_user(user_uuid: &UserId, conn: &DbConn) -> Self {
        if !CONFIG.org_auto_confirm_enabled() {
            return Self(Vec::new());
        }

        Self(
            OrgPolicy::find_memberships_by_user_and_active_policy(
                user_uuid,
                OrgPolicyType::AutomaticUserConfirmation,
                conn,
            )
            .await,
        )
    }

    /// The user may not create another organization. Every membership counts, an open invitation and any
    /// role included, which is what makes this stricter than SingleOrg. Mirrors `CannotCreateNewOrganization()`.
    pub fn forbids_creating_organization(&self) -> bool {
        !self.0.is_empty()
    }

    /// A membership in an organization other than `org_uuid` forbids the user to be part of `org_uuid`.
    /// Mirrors `IsEnabledForOrganizationsOtherThan(organizationId)`.
    pub fn forbids_membership_outside(&self, org_uuid: &OrganizationId) -> bool {
        self.0.iter().any(|m| &m.org_uuid != org_uuid)
    }

    /// The user may neither grant nor accept emergency access, which would hand its account, and with
    /// it the organization vault, to somebody the organization never vetted. Only an open invitation is
    /// exempt, see [`Membership::counts_for_auto_confirm`].
    /// Mirrors `GrantorCannotInviteToEmergencyAccess()` and `GranteeCannotAcceptEmergencyAccess()`.
    pub fn forbids_emergency_access(&self) -> bool {
        self.0.iter().any(Membership::counts_for_auto_confirm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org(name: &str) -> OrganizationId {
        OrganizationId::from(String::from(name))
    }

    fn membership(org_uuid: &OrganizationId, atype: MembershipType, status: i32) -> Membership {
        let mut member = Membership::new(UserId::from(String::from("user")), org_uuid.clone(), None);
        member.atype = atype as i32;
        member.status = status;
        member
    }

    /// The revoked counterpart of `status`, stored the way `Membership::revoke` does it.
    fn revoked(org_uuid: &OrganizationId, atype: MembershipType, status: i32) -> Membership {
        let mut member = membership(org_uuid, atype, status);
        assert!(member.revoke(), "status {status} can not be revoked");
        member
    }

    /// Unlike SingleOrg, which lets owners and admins through, this policy exempts no role and no
    /// status, so any membership blocks creating another organization.
    #[test]
    fn no_role_and_no_status_may_create_another_organization() {
        let auto_confirm_org = org("auto-confirm");

        for atype in [MembershipType::User, MembershipType::Manager, MembershipType::Admin, MembershipType::Owner] {
            let requirement =
                AutoConfirmRequirement(vec![membership(&auto_confirm_org, atype, MembershipStatus::Confirmed as i32)]);
            assert!(requirement.forbids_creating_organization(), "type {} must not create an org", atype as i32);
        }

        for member in [
            membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Invited as i32),
            membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Accepted as i32),
            membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Confirmed as i32),
            revoked(&auto_confirm_org, MembershipType::User, MembershipStatus::Accepted as i32),
            revoked(&auto_confirm_org, MembershipType::User, MembershipStatus::Confirmed as i32),
        ] {
            let status = member.status;
            assert!(
                AutoConfirmRequirement(vec![member]).forbids_creating_organization(),
                "status {status} must not create an org"
            );
        }
    }

    /// The organization which enabled the policy is the one membership that may exist; a user in no
    /// such organization is not restricted by this policy at all.
    #[test]
    fn only_a_membership_in_another_organization_is_forbidden() {
        let auto_confirm_org = org("auto-confirm");
        let requirement = AutoConfirmRequirement(vec![membership(
            &auto_confirm_org,
            MembershipType::User,
            MembershipStatus::Confirmed as i32,
        )]);

        assert!(!requirement.forbids_membership_outside(&auto_confirm_org));
        assert!(requirement.forbids_membership_outside(&org("other")));

        let none = AutoConfirmRequirement(Vec::new());
        assert!(!none.forbids_creating_organization());
        assert!(!none.forbids_membership_outside(&org("other")));
        assert!(!none.forbids_emergency_access());
    }

    /// Only an open invitation leaves emergency access alone, that account did not join yet and may
    /// still decline. Revoked memberships count because a restore adds no second accept step, so an
    /// emergency access created while revoked would survive it.
    #[test]
    fn every_status_but_an_open_invitation_forbids_emergency_access() {
        let auto_confirm_org = org("auto-confirm");

        for (member, forbidden) in [
            (membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Invited as i32), false),
            (membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Accepted as i32), true),
            (membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Confirmed as i32), true),
            (revoked(&auto_confirm_org, MembershipType::User, MembershipStatus::Invited as i32), true),
            (revoked(&auto_confirm_org, MembershipType::User, MembershipStatus::Accepted as i32), true),
            (revoked(&auto_confirm_org, MembershipType::User, MembershipStatus::Confirmed as i32), true),
        ] {
            let status = member.status;
            assert_eq!(
                AutoConfirmRequirement(vec![member]).forbids_emergency_access(),
                forbidden,
                "status {status} is handled incorrectly"
            );
        }

        // One joined membership is enough, next to an invitation which does not restrict by itself.
        let requirement = AutoConfirmRequirement(vec![
            membership(&org("invited-to"), MembershipType::User, MembershipStatus::Invited as i32),
            membership(&auto_confirm_org, MembershipType::User, MembershipStatus::Confirmed as i32),
        ]);
        assert!(requirement.forbids_emergency_access());
    }
}
