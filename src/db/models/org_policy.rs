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
    // AutoConfirm = 18, // Not supported (not implemented yet)
    // BlockClaimedDomainAccountCreation = 19, // Not supported (Not AGPLv3 Licensed)
    // OrganizationUserNotification = 20, // Not supported (not implemented yet)
    SendControls = 21,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Models/Data/Organizations/Policies/SendOptionsPolicyData.cs#L5
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOptionsPolicyData {
    #[serde(rename = "disableHideEmail", alias = "DisableHideEmail")]
    pub disable_hide_email: bool,
}

// https://github.com/bitwarden/server/blob/main/src/Core/AdminConsole/Models/Data/Organizations/Policies/SendControlsAllowedAccessControl.cs
#[derive(Copy, Clone, Eq, PartialEq, num_derive::FromPrimitive)]
pub enum SendWhoCanAccessType {
    Any = 0,
    PasswordProtected = 1,
    SpecificPeople = 2,
}

// https://github.com/bitwarden/server/blob/main/src/Core/AdminConsole/Models/Data/Organizations/Policies/SendControlsPolicyData.cs
//
// The shipped web vault only renders the first four fields; the last two already exist upstream and
// are parsed and enforced here as well.
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendControlsPolicyData {
    #[serde(rename = "disableSend", alias = "DisableSend", default)]
    pub disable_send: bool,
    #[serde(rename = "disableHideEmail", alias = "DisableHideEmail", default)]
    pub disable_hide_email: bool,
    #[serde(rename = "whoCanAccess", alias = "WhoCanAccess", default)]
    pub who_can_access: Option<i32>,
    #[serde(rename = "allowedDomains", alias = "AllowedDomains", default)]
    pub allowed_domains: Option<String>,
    #[serde(rename = "deletionHours", alias = "DeletionHours", default)]
    pub deletion_hours: Option<i32>,
    #[serde(rename = "allowedSendTypes", alias = "AllowedSendTypes", default)]
    pub allowed_send_types: Option<Vec<i32>>,
}

impl SendControlsPolicyData {
    pub fn required_access_type(&self) -> Option<SendWhoCanAccessType> {
        self.who_can_access.and_then(num_traits::FromPrimitive::from_i32)
    }
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

    /// Reads the `Send controls` data, falling back to the defaults when the stored data is missing
    /// or unreadable: a broken payload must not accidentally lock users out of creating Sends.
    pub fn send_controls_data(&self) -> SendControlsPolicyData {
        if let Ok(data) = serde_json::from_str::<SendControlsPolicyData>(&self.data) {
            return data;
        }

        if self.data != "null" && !self.data.is_empty() {
            error!("Failed to deserialize SendControlsPolicyData: {}", self.data);
        }
        SendControlsPolicyData::default()
    }

    /// Combines the `Send controls` policies of every organization the user is a plain member of.
    /// Like upstreams `SendControlsPolicyRequirementFactory`: the two toggles are ORed, the other
    /// restrictions come from the first organization that sets them.
    pub async fn send_controls_for_user(user_uuid: &UserId, conn: &DbConn) -> SendControlsPolicyData {
        let mut result = SendControlsPolicyData::default();
        for policy in
            OrgPolicy::find_confirmed_by_user_and_active_policy(user_uuid, OrgPolicyType::SendControls, conn).await
        {
            if let Some(user) = Membership::find_confirmed_by_user_and_org(user_uuid, &policy.org_uuid, conn).await
                && user.atype < MembershipType::Admin
            {
                let data = policy.send_controls_data();
                result.disable_send |= data.disable_send;
                result.disable_hide_email |= data.disable_hide_email;
                result.who_can_access = result.who_can_access.or(data.who_can_access);
                result.allowed_domains = result.allowed_domains.or(data.allowed_domains);
                result.deletion_hours = result.deletion_hours.or(data.deletion_hours);
                result.allowed_send_types = result.allowed_send_types.or(data.allowed_send_types);
            }
        }
        result
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_controls_data_parses_client_payloads_and_pascal_case_aliases() {
        let data: SendControlsPolicyData = serde_json::from_str(
            r#"{"disableSend":true,"disableHideEmail":true,"whoCanAccess":1,"allowedDomains":null}"#,
        )
        .unwrap();

        assert!(data.disable_send);
        assert!(data.disable_hide_email);
        assert!(data.required_access_type() == Some(SendWhoCanAccessType::PasswordProtected));
        assert!(data.allowed_domains.is_none());
        assert!(data.deletion_hours.is_none());
        assert!(data.allowed_send_types.is_none());

        let data: SendControlsPolicyData = serde_json::from_str(r#"{"DisableSend":true}"#).unwrap();

        assert!(data.disable_send);
        assert!(!data.disable_hide_email);
        assert!(data.required_access_type().is_none());
    }

    #[test]
    fn a_policy_without_readable_data_restricts_nothing() {
        let org_uuid = OrganizationId::from(String::from("00000000-0000-0000-0000-000000000000"));
        let policy = OrgPolicy::new(org_uuid, OrgPolicyType::SendControls, true, "null".to_owned());
        let data = policy.send_controls_data();

        assert!(!data.disable_send);
        assert!(!data.disable_hide_email);
        assert!(data.required_access_type().is_none());
        assert!(data.deletion_hours.is_none());
    }
}
