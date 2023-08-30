use serde::Deserialize;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;
use crate::util::UpCase;

use super::{TwoFactor, UserOrgStatus, UserOrgType, UserOrganization};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = org_policies)]
    #[diesel(primary_key(uuid))]
    pub struct OrgPolicy {
        pub uuid: String,
        pub org_uuid: String,
        pub atype: i32,
        pub enabled: bool,
        pub data: String,
    }
}

// https://github.com/bitwarden/server/blob/b86a04cef9f1e1b82cf18e49fc94e017c641130c/src/Core/Enums/PolicyType.cs
#[derive(Copy, Clone, Eq, PartialEq, num_derive::FromPrimitive)]
pub enum OrgPolicyType {
    TwoFactorAuthentication = 0,
    MasterPassword = 1,
    PasswordGenerator = 2,
    SingleOrg = 3,
    RequireSso = 4,
    PersonalOwnership = 5,
    DisableSend = 6,
    SendOptions = 7,
    ResetPassword = 8,
    // MaximumVaultTimeout = 9, // Not supported (Not AGPLv3 Licensed)
    // DisablePersonalVaultExport = 10, // Not supported (Not AGPLv3 Licensed)
}

// https://github.com/bitwarden/server/blob/5cbdee137921a19b1f722920f0fa3cd45af2ef0f/src/Core/Models/Data/Organizations/Policies/SendOptionsPolicyData.cs
#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendOptionsPolicyData {
    pub DisableHideEmail: bool,
}

// https://github.com/bitwarden/server/blob/5cbdee137921a19b1f722920f0fa3cd45af2ef0f/src/Core/Models/Data/Organizations/Policies/ResetPasswordDataModel.cs
#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct ResetPasswordDataModel {
    pub AutoEnrollEnabled: bool,
}

pub type OrgPolicyResult = Result<(), OrgPolicyErr>;

#[derive(Debug)]
pub enum OrgPolicyErr {
    TwoFactorMissing,
    SingleOrgEnforced,
}

/// Local methods
impl OrgPolicy {
    pub fn new(org_uuid: String, atype: OrgPolicyType, data: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            org_uuid,
            atype: atype as i32,
            enabled: false,
            data,
        }
    }

    pub fn has_type(&self, policy_type: OrgPolicyType) -> bool {
        self.atype == policy_type as i32
    }

    pub fn to_json(&self) -> Value {
        let data_json: Value = serde_json::from_str(&self.data).unwrap_or(Value::Null);
        json!({
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Type": self.atype,
            "Data": data_json,
            "Enabled": self.enabled,
            "Object": "policy",
        })
    }
}

/// Database methods
impl OrgPolicy {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(org_policies::table)
                    .values(OrgPolicyDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(org_policies::table)
                            .filter(org_policies::uuid.eq(&self.uuid))
                            .set(OrgPolicyDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving org_policy")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving org_policy")
            }
            postgresql {
                let value = OrgPolicyDb::to_db(self);
                // We need to make sure we're not going to violate the unique constraint on org_uuid and atype.
                // This happens automatically on other DBMS backends due to replace_into(). PostgreSQL does
                // not support multiple constraints on ON CONFLICT clauses.
                diesel::delete(
                    org_policies::table
                        .filter(org_policies::org_uuid.eq(&self.org_uuid))
                        .filter(org_policies::atype.eq(&self.atype)),
                )
                .execute(conn)
                .map_res("Error deleting org_policy for insert")?;

                diesel::insert_into(org_policies::table)
                    .values(&value)
                    .on_conflict(org_policies::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving org_policy")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(org_policies::table.filter(org_policies::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting org_policy")
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            org_policies::table
                .filter(org_policies::uuid.eq(uuid))
                .first::<OrgPolicyDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_org(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            org_policies::table
                .filter(org_policies::org_uuid.eq(org_uuid))
                .load::<OrgPolicyDb>(conn)
                .expect("Error loading org_policy")
                .from_db()
        }}
    }

    pub async fn find_confirmed_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(
                        users_organizations::org_uuid.eq(org_policies::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid)))
                )
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .select(org_policies::all_columns)
                .load::<OrgPolicyDb>(conn)
                .expect("Error loading org_policy")
                .from_db()
        }}
    }

    pub async fn find_by_org_and_type(org_uuid: &str, policy_type: OrgPolicyType, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            org_policies::table
                .filter(org_policies::org_uuid.eq(org_uuid))
                .filter(org_policies::atype.eq(policy_type as i32))
                .first::<OrgPolicyDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(org_policies::table.filter(org_policies::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting org_policy")
        }}
    }

    pub async fn find_accepted_and_confirmed_by_user_and_active_policy(
        user_uuid: &str,
        policy_type: OrgPolicyType,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(
                        users_organizations::org_uuid.eq(org_policies::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid)))
                )
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Accepted as i32)
                )
                .or_filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .filter(org_policies::atype.eq(policy_type as i32))
                .filter(org_policies::enabled.eq(true))
                .select(org_policies::all_columns)
                .load::<OrgPolicyDb>(conn)
                .expect("Error loading org_policy")
                .from_db()
        }}
    }

    pub async fn find_confirmed_by_user_and_active_policy(
        user_uuid: &str,
        policy_type: OrgPolicyType,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            org_policies::table
                .inner_join(
                    users_organizations::table.on(
                        users_organizations::org_uuid.eq(org_policies::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid)))
                )
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .filter(org_policies::atype.eq(policy_type as i32))
                .filter(org_policies::enabled.eq(true))
                .select(org_policies::all_columns)
                .load::<OrgPolicyDb>(conn)
                .expect("Error loading org_policy")
                .from_db()
        }}
    }

    /// Returns true if the user belongs to an org that has enabled the specified policy type,
    /// and the user is not an owner or admin of that org. This is only useful for checking
    /// applicability of policy types that have these particular semantics.
    pub async fn is_applicable_to_user(
        user_uuid: &str,
        policy_type: OrgPolicyType,
        exclude_org_uuid: Option<&str>,
        conn: &mut DbConn,
    ) -> bool {
        for policy in
            OrgPolicy::find_accepted_and_confirmed_by_user_and_active_policy(user_uuid, policy_type, conn).await
        {
            // Check if we need to skip this organization.
            if exclude_org_uuid.is_some() && exclude_org_uuid.unwrap() == policy.org_uuid {
                continue;
            }

            if let Some(user) = UserOrganization::find_by_user_and_org(user_uuid, &policy.org_uuid, conn).await {
                if user.atype < UserOrgType::Admin {
                    return true;
                }
            }
        }
        false
    }

    pub async fn is_user_allowed(
        user_uuid: &str,
        org_uuid: &str,
        exclude_current_org: bool,
        conn: &mut DbConn,
    ) -> OrgPolicyResult {
        // Enforce TwoFactor/TwoStep login
        if TwoFactor::find_by_user(user_uuid, conn).await.is_empty() {
            match Self::find_by_org_and_type(org_uuid, OrgPolicyType::TwoFactorAuthentication, conn).await {
                Some(p) if p.enabled => {
                    return Err(OrgPolicyErr::TwoFactorMissing);
                }
                _ => {}
            };
        }

        // Enforce Single Organization Policy of other organizations user is a member of
        // This check here needs to exclude this current org-id, else an accepted user can not be confirmed.
        let exclude_org = if exclude_current_org {
            Some(org_uuid)
        } else {
            None
        };
        if Self::is_applicable_to_user(user_uuid, OrgPolicyType::SingleOrg, exclude_org, conn).await {
            return Err(OrgPolicyErr::SingleOrgEnforced);
        }

        Ok(())
    }

    pub async fn org_is_reset_password_auto_enroll(org_uuid: &str, conn: &mut DbConn) -> bool {
        match OrgPolicy::find_by_org_and_type(org_uuid, OrgPolicyType::ResetPassword, conn).await {
            Some(policy) => match serde_json::from_str::<UpCase<ResetPasswordDataModel>>(&policy.data) {
                Ok(opts) => {
                    return policy.enabled && opts.data.AutoEnrollEnabled;
                }
                _ => error!("Failed to deserialize ResetPasswordDataModel: {}", policy.data),
            },
            None => return false,
        }

        false
    }

    /// Returns true if the user belongs to an org that has enabled the `DisableHideEmail`
    /// option of the `Send Options` policy, and the user is not an owner or admin of that org.
    pub async fn is_hide_email_disabled(user_uuid: &str, conn: &mut DbConn) -> bool {
        for policy in
            OrgPolicy::find_confirmed_by_user_and_active_policy(user_uuid, OrgPolicyType::SendOptions, conn).await
        {
            if let Some(user) = UserOrganization::find_by_user_and_org(user_uuid, &policy.org_uuid, conn).await {
                if user.atype < UserOrgType::Admin {
                    match serde_json::from_str::<UpCase<SendOptionsPolicyData>>(&policy.data) {
                        Ok(opts) => {
                            if opts.data.DisableHideEmail {
                                return true;
                            }
                        }
                        _ => error!("Failed to deserialize SendOptionsPolicyData: {}", policy.data),
                    }
                }
            }
        }
        false
    }
}
