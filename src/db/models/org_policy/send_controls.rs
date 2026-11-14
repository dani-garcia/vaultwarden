//! The Send controls policy (21) absorbs the legacy `Disable Send` (6) and `Send Options` (7) policies.
//! Like upstream, the three are kept in sync in both directions, so clients that only know the legacy
//! policies keep enforcing the same rules, and Sends are checked against all of them.
//!
//! https://github.com/bitwarden/server/tree/04a4d7548b07d18ab7327ddaae81a05fd893a820/src/Core/AdminConsole/OrganizationFeatures/Policies

use chrono::TimeDelta;
use diesel::prelude::*;
use num_traits::FromPrimitive;
use serde::Deserialize;
use serde_json::Value;

use super::{OrgPolicy, OrgPolicyType, SendOptionsPolicyData};
use crate::{
    api::{ApiResult, EmptyResult},
    db::{
        DbConn,
        models::{MembershipStatus, MembershipType, OrganizationId, Send, SendType, UserId},
        schema::{org_policies, users_organizations},
    },
};

const SEND_POLICIES: [i32; 3] =
    [OrgPolicyType::DisableSend as i32, OrgPolicyType::SendOptions as i32, OrgPolicyType::SendControls as i32];

// SendWhoCanAccessType. Specific people requires Sends with email verification, which are not supported.
const ACCESS_ANY: i32 = 0;
const ACCESS_PASSWORD: i32 = 1;
const ACCESS_SPECIFIC_PEOPLE: i32 = 2;

// https://github.com/bitwarden/server/blob/04a4d7548b07d18ab7327ddaae81a05fd893a820/src/Core/AdminConsole/Models/Data/Organizations/Policies/SendControlsPolicyData.cs
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct SendControlsPolicyData {
    #[serde(alias = "DisableSend")]
    disable_send: bool,
    #[serde(alias = "DisableHideEmail")]
    disable_hide_email: bool,
    #[serde(alias = "WhoCanAccess")]
    who_can_access: Option<i32>,
    #[serde(alias = "AllowedDomains")]
    allowed_domains: Option<String>,
    #[serde(alias = "DeletionHours")]
    deletion_hours: Option<i32>,
    #[serde(alias = "AllowedSendTypes")]
    allowed_send_types: Option<Vec<i32>>,
}

impl SendControlsPolicyData {
    /// Validates the data an organization saves. Requiring email verification, which allowed domains
    /// depend on, would leave members unable to create any Send, so it is refused.
    fn parse(data: Option<&Value>) -> ApiResult<Self> {
        let data = match Option::<Self>::deserialize(data.unwrap_or(&Value::Null)) {
            Ok(data) => data.unwrap_or_default(),
            Err(e) => err!(format!("Invalid Send controls policy data: {e}")),
        };
        match data.who_can_access {
            None | Some(ACCESS_ANY | ACCESS_PASSWORD) => (),
            Some(ACCESS_SPECIFIC_PEOPLE) => {
                err!("Sends with email verification are not supported, so that access type cannot be required")
            }
            Some(_) => err!("Invalid Send controls access type"),
        }
        if data.allowed_domains.is_some() {
            err!("Allowed domains require Sends with email verification, which are not supported")
        }
        if data.deletion_hours.is_some_and(|hours| hours < 1) {
            err!("The maximum lifetime of a Send has to be at least one hour")
        }
        // Current clients may also list Item Sends (2), which can not be created here.
        if let Some(types) = &data.allowed_send_types
            && (types.iter().any(|t| !(0..=2).contains(t))
                || !types.iter().any(|t| *t == SendType::Text as i32 || *t == SendType::File as i32))
        {
            err!("The allowed Send types have to include Text or File")
        }
        Ok(data)
    }

    /// Every organization's restrictions apply, so a less strict organization never relaxes a stricter
    /// one, independent of the order the policies are loaded in.
    fn merge(&mut self, other: Self) {
        self.disable_send |= other.disable_send;
        self.disable_hide_email |= other.disable_hide_email;
        self.who_can_access = self.who_can_access.max(other.who_can_access);
        self.deletion_hours = match (self.deletion_hours, other.deletion_hours) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.allowed_send_types = match (self.allowed_send_types.take(), other.allowed_send_types) {
            (Some(a), Some(b)) => Some(a.into_iter().filter(|t| b.contains(t)).collect()),
            (a, b) => a.or(b),
        };
    }

    /// Checks the Send as it would be saved, like upstream's `SendValidationService`.
    fn check_send(&self, send: &Send) -> EmptyResult {
        if self.disable_send {
            err!("Due to an Enterprise Policy, you are only able to delete an existing Send.")
        }
        if self.disable_hide_email && send.hide_email.unwrap_or(false) {
            err!(
                "Due to an Enterprise Policy, you are not allowed to hide your email address \
                  from recipients when creating or editing a Send."
            )
        }
        if self.who_can_access == Some(ACCESS_PASSWORD) && send.password_hash.is_none() {
            err!("Due to an Enterprise policy your Sends must be protected by password")
        }
        if let Some(types) = &self.allowed_send_types
            && !types.contains(&send.atype)
        {
            let names: Vec<&str> = types
                .iter()
                .map(|t| match *t {
                    0 => "Text",
                    1 => "File",
                    _ => "Unknown",
                })
                .collect();
            err!(format!("Due to an Enterprise policy your Sends must be of the following types: {}", names.join(", ")))
        }
        // Upstream allows for up to a minute of skew between the deletion and the creation date.
        if let Some(hours) = self.deletion_hours
            && send.deletion_date - send.creation_date - TimeDelta::minutes(1) > TimeDelta::hours(i64::from(hours))
        {
            let (duration, unit) = if hours >= 24 {
                (hours / 24, "day")
            } else {
                (hours, "hour")
            };
            let plural = if duration > 1 {
                "s"
            } else {
                ""
            };
            err!(format!(
                "Due to an Enterprise policy your Sends must have deletion dates no more than {duration} {unit}{plural} from their creation dates"
            ))
        }
        Ok(())
    }
}

/// Whether an enabled `Send Options` policy disables hiding the email. Unreadable data keeps the option on.
fn hide_email_disabled(policy: &OrgPolicy) -> bool {
    policy.enabled
        && serde_json::from_str::<Option<SendOptionsPolicyData>>(&policy.data).map_or_else(
            |_| {
                error!("Failed to deserialize SendOptionsPolicyData: {}", policy.data);
                true
            },
            |data| data.is_some_and(|d| d.disable_hide_email),
        )
}

/// The options of the legacy policies, as Send controls holds them. A disabled `Send Options` policy
/// counts as off, so a later save of Send controls does not switch its stored option back on.
fn legacy_send_options(policies: &[OrgPolicy]) -> (bool, bool) {
    let disable_send = policies.iter().any(|p| p.has_type(OrgPolicyType::DisableSend) && p.enabled);
    let disable_hide_email = policies.iter().any(|p| p.has_type(OrgPolicyType::SendOptions) && hide_email_disabled(p));
    (disable_send, disable_hide_email)
}

/// Mirrors a saved Send policy into the others, like upstream's `SendControlsSyncPolicyEvent`,
/// `DisableSendSyncPolicyEvent` and `SendOptionsSyncPolicyEvent`, and returns the policies to save.
/// `policies` are the organization's policies, including the saved one.
fn mirror_send_policies(saved: &OrgPolicy, policies: &[OrgPolicy]) -> ApiResult<Vec<OrgPolicy>> {
    let find_or_new = |policy_type| {
        policies
            .iter()
            .find(|p| p.has_type(policy_type))
            .cloned()
            .unwrap_or_else(|| OrgPolicy::new(saved.org_uuid.clone(), policy_type, false, String::from("null")))
    };

    if saved.has_type(OrgPolicyType::SendControls) {
        let data = saved.send_controls_data();
        let mut disable_send = find_or_new(OrgPolicyType::DisableSend);
        disable_send.enabled = saved.enabled && data.disable_send;
        let mut send_options = find_or_new(OrgPolicyType::SendOptions);
        send_options.enabled = saved.enabled && data.disable_hide_email;
        send_options.data = serde_json::to_string(&SendOptionsPolicyData {
            disable_hide_email: data.disable_hide_email,
        })?;
        return Ok(vec![disable_send, send_options]);
    }

    let mut controls = find_or_new(OrgPolicyType::SendControls);
    let mut data = controls.send_controls_data();
    (data.disable_send, data.disable_hide_email) = legacy_send_options(policies);
    // Turning a legacy policy off must not switch off the restrictions only Send controls has.
    controls.enabled |= data.disable_send || data.disable_hide_email;
    controls.data = serde_json::to_string(&data)?;
    Ok(vec![controls])
}

impl OrgPolicy {
    /// Stored data was validated when saved; data that can not be read blocks Sends instead of allowing them.
    fn send_controls_data(&self) -> SendControlsPolicyData {
        let data = serde_json::from_str::<Value>(&self.data).ok();
        data.and_then(|data| SendControlsPolicyData::parse(Some(&data)).ok()).unwrap_or_else(|| {
            error!("Invalid Send controls policy data, blocking Sends: {}", self.data);
            SendControlsPolicyData {
                disable_send: true,
                ..Default::default()
            }
        })
    }

    /// Validates the data of a Send policy before it is saved and returns the data to store.
    pub fn send_policy_data(policy_type: OrgPolicyType, data: Option<Value>) -> ApiResult<Option<Value>> {
        match policy_type {
            OrgPolicyType::SendControls => {
                Ok(Some(serde_json::to_value(SendControlsPolicyData::parse(data.as_ref())?)?))
            }
            OrgPolicyType::SendOptions => {
                if let Some(value) = &data
                    && let Err(e) = Option::<SendOptionsPolicyData>::deserialize(value)
                {
                    err!(format!("Invalid Send options policy data: {e}"))
                }
                Ok(data)
            }
            _ => Ok(data),
        }
    }

    /// Keeps Send controls and the legacy Send policies in sync after one of them was saved.
    pub async fn sync_send_policies(saved: &Self, conn: &DbConn) -> EmptyResult {
        if !SEND_POLICIES.contains(&saved.atype) {
            return Ok(());
        }
        for mut policy in mirror_send_policies(saved, &Self::find_by_org(&saved.org_uuid, conn).await)? {
            policy.save(conn).await?;
        }
        Ok(())
    }

    /// Upstream's `PolicyQuery`: until Send controls is saved, it is derived from the legacy policies, so the
    /// current policy editor shows what is enforced instead of turning it off on the next save.
    pub fn synthesize_send_controls(org_id: &OrganizationId, policies: &[Self]) -> Self {
        let (disable_send, disable_hide_email) = legacy_send_options(policies);
        let data = SendControlsPolicyData {
            disable_send,
            disable_hide_email,
            ..Default::default()
        };
        Self::new(
            org_id.clone(),
            OrgPolicyType::SendControls,
            disable_send || disable_hide_email,
            json!(data).to_string(),
        )
    }

    /// Enforces the Send policies of every organization in which the user is an accepted or confirmed
    /// member below Admin on the Send as it would be saved. Deleting a Send stays possible.
    pub async fn check_send(user_id: &UserId, send: &Send, conn: &DbConn) -> EmptyResult {
        let policies = conn
            .run(move |conn| {
                org_policies::table
                    .inner_join(users_organizations::table.on(users_organizations::org_uuid.eq(org_policies::org_uuid)))
                    .filter(users_organizations::user_uuid.eq(user_id))
                    .filter(
                        users_organizations::status
                            .eq_any([MembershipStatus::Accepted as i32, MembershipStatus::Confirmed as i32]),
                    )
                    // Owners and admins are exempt. The numbers of MembershipType are not its order.
                    .filter(users_organizations::atype.ne(MembershipType::Owner as i32))
                    .filter(users_organizations::atype.ne(MembershipType::Admin as i32))
                    .filter(org_policies::enabled.eq(true))
                    .filter(org_policies::atype.eq_any(SEND_POLICIES))
                    .select(org_policies::all_columns)
                    .load::<Self>(conn)
            })
            .await?;

        let mut controls = SendControlsPolicyData::default();
        for policy in policies {
            match OrgPolicyType::from_i32(policy.atype) {
                Some(OrgPolicyType::DisableSend) => controls.disable_send = true,
                Some(OrgPolicyType::SendOptions) => controls.disable_hide_email |= hide_email_disabled(&policy),
                _ => controls.merge(policy.send_controls_data()),
            }
        }
        controls.check_send(send)
    }
}
