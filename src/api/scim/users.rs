//
// SCIM /Users endpoints. The SCIM User id is the org-membership uuid
// (MembershipId), not the global user uuid: SCIM is org-scoped and one person
// can belong to several organizations.
//
// Deprovisioning maps to REVOKE, never delete: the membership row and its
// akey survive, so restore is lossless and needs no re-confirmation. This is
// a deliberate deviation from RFC 7644 DELETE semantics, matching the
// existing Directory Connector import endpoint, and it means a compromised
// SCIM token cannot destroy memberships.
//
// Provisioning creates at most Invited (or Accepted when mail is disabled
// and the user already has credentials). Confirmed requires an admin client
// to wrap the org key for the member; no server-side path can do that.
//
use rocket::Route;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        EmptyResult,
        core::log_event,
        scim::{
            ScimJson, ScimResponse,
            error::ScimError,
            filter::parse_eq_filter,
            guard::ScimToken,
            models::ScimUserRequest,
            patch::{PatchOp, parse_user_patch},
        },
    },
    db::{
        DbConn,
        models::{
            EventType, Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization,
            User,
        },
    },
    mail,
    util::is_valid_email,
};

pub fn routes() -> Vec<Route> {
    routes![list_users, get_user, post_user, patch_user, delete_user]
}

// Synthetic acting user recorded in the org event log for SCIM-driven
// changes, following the ACTING_ADMIN_USER precedent in the admin panel.
const SCIM_ACTOR: &str = "vaultwarden-scim-00000-000000000000";
// Device type recorded for SCIM events: 14 = UnknownBrowser, same as admin.
const SCIM_DEVICE_TYPE: i32 = 14;

// The single place the revocation encoding is interpreted: revoked statuses
// are stored as status - 128 (ACTIVATE_REVOKE_DIFF), so every stored revoked
// value is <= Revoked (-1). Never compare equality against Revoked.
fn membership_active(member: &Membership) -> bool {
    member.status > MembershipStatus::Revoked as i32
}

fn to_scim_user(member: &Membership, user: &User, token: &ScimToken) -> Value {
    let location = format!("{}/scim/v2/{}/Users/{}", CONFIG.domain(), token.org_uuid, member.uuid);
    json!({
        "schemas": [crate::api::scim::discovery::USER_SCHEMA_URN],
        "id": member.uuid,
        "externalId": member.external_id,
        "userName": user.email,
        "displayName": user.name,
        "active": membership_active(member),
        "emails": [{"value": user.email, "primary": true, "type": "work"}],
        "meta": {
            "resourceType": "User",
            "location": location,
        },
    })
}

async fn log_scim_event(event_type: EventType, member: &Membership, token: &ScimToken, conn: &DbConn) {
    log_event(
        event_type as i32,
        &member.uuid,
        &token.org_uuid,
        &SCIM_ACTOR.into(),
        SCIM_DEVICE_TYPE,
        &token.ip.ip,
        conn,
    )
    .await;
}

fn list_response(total: usize, start_index: usize, resources: &[Value]) -> ScimResponse {
    ScimResponse::ok(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "itemsPerPage": resources.len(),
        "startIndex": start_index,
        "Resources": resources,
    }))
}

#[derive(FromForm)]
pub struct ListParams {
    filter: Option<String>,
    #[field(name = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
}

#[get("/v2/<_>/Users?<params..>")]
async fn list_users(params: ListParams, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    // Resolve the matching memberships first, then paginate.
    let members: Vec<Membership> = if let Some(raw_filter) = params.filter.as_deref() {
        let eq = parse_eq_filter(raw_filter)?;
        match eq.attribute.as_str() {
            // find_by_mail lowercases internally, so a mixed-case userName
            // from Entra still matches the lowercased stored email.
            "username" | "emails.value" => match User::find_by_mail(&eq.value, &conn).await {
                Some(user) => {
                    Membership::find_by_user_and_org(&user.uuid, &token.org_uuid, &conn).await.into_iter().collect()
                }
                None => Vec::new(),
            },
            "externalid" => {
                Membership::find_by_external_id_and_org(&eq.value, &token.org_uuid, &conn).await.into_iter().collect()
            }
            _ => {
                return Err(ScimError::bad_request(
                    "invalidFilter",
                    "Filterable attributes are userName and externalId",
                ));
            }
        }
    } else {
        Membership::find_by_org(&token.org_uuid, &conn).await
    };

    let total = members.len();
    let start_index = usize::try_from(params.start_index.unwrap_or(1)).unwrap_or(1).max(1);
    let count = usize::try_from(params.count.unwrap_or(100)).unwrap_or(0).min(200);

    let mut resources = Vec::new();
    for member in members.into_iter().skip(start_index - 1).take(count) {
        // A membership always references a user; a missing row would be a
        // dangling foreign key, so surface it as a 500 rather than skip.
        let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
            return Err(ScimError::internal());
        };
        resources.push(to_scim_user(&member, &user, &token));
    }

    Ok(list_response(total, start_index, &resources))
}

#[get("/v2/<_>/Users/<member_id>")]
async fn get_user(member_id: MembershipId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

#[post("/v2/<_>/Users", data = "<data>")]
async fn post_user(data: ScimJson<ScimUserRequest>, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let request = data.0;

    let Some(email) = request.email() else {
        return Err(ScimError::bad_request("invalidValue", "userName (or a primary email) must be an email address"));
    };
    if !is_valid_email(email) {
        return Err(ScimError::bad_request("invalidValue", "userName is not a valid email address"));
    }

    // Uniqueness: by externalId and by email, both scoped to the org.
    if let Some(external_id) = request.external_id.as_deref()
        && Membership::find_by_external_id_and_org(external_id, &token.org_uuid, &conn).await.is_some()
    {
        return Err(ScimError::conflict("uniqueness", "A member with this externalId already exists"));
    }
    if Membership::find_by_email_and_org(email, &token.org_uuid, &conn).await.is_some() {
        return Err(ScimError::conflict("uniqueness", "A member with this userName already exists"));
    }

    let Some(org) = Organization::find_by_uuid(&token.org_uuid, &conn).await else {
        return Err(ScimError::internal());
    };

    // Mirrors the Directory Connector import: link an existing account by
    // email, or create a shell account (no keypair yet) that the invite email
    // lets the person register.
    let mut user_created = false;
    let user = if let Some(user) = User::find_by_mail(email, &conn).await {
        user
    } else {
        let mut new_user = User::new(email, request.display_name());
        new_user.save(&conn).await.map_err(|_| ScimError::internal())?;
        if !CONFIG.mail_enabled() {
            Invitation::new(&new_user.email).save(&conn).await.map_err(|_| ScimError::internal())?;
        }
        user_created = true;
        new_user
    };

    // Reaching Accepted directly is only possible when no invite mail will be
    // sent and the account already has credentials to log in with.
    let member_status = if CONFIG.mail_enabled() || user.password_hash.is_empty() {
        MembershipStatus::Invited as i32
    } else {
        MembershipStatus::Accepted as i32
    };

    // RFC 7644 allows creating a resource already deactivated; store the
    // membership pre-revoked and send no invite mail in that case.
    let create_active = request.active.is_none_or(|b| b.0);

    let mut member = Membership::new(user.uuid.clone(), token.org_uuid.clone(), Some(org.billing_email.clone()));
    member.set_external_id(request.external_id.clone());
    member.access_all = false;
    member.atype = MembershipType::User as i32;
    member.status = member_status;
    if !create_active {
        member.revoke();
    }
    member.save(&conn).await.map_err(|_| ScimError::internal())?;

    if create_active
        && CONFIG.mail_enabled()
        && let Err(e) = mail::send_invite(
            &user,
            token.org_uuid.clone(),
            member.uuid.clone(),
            &org.name,
            Some(org.billing_email.clone()),
        )
        .await
    {
        error!("SCIM provisioning rollback, invite mail failed: {e:#?}");
        let rollback: EmptyResult = if user_created {
            user.delete(&conn).await
        } else {
            member.delete(&conn).await
        };
        drop(rollback);
        return Err(ScimError::internal());
    }

    log_scim_event(EventType::OrganizationUserInvited, &member, &token, &conn).await;
    if !create_active {
        log_scim_event(EventType::OrganizationUserRevoked, &member, &token, &conn).await;
    }

    let location = format!("{}/scim/v2/{}/Users/{}", CONFIG.domain(), token.org_uuid, member.uuid);
    Ok(ScimResponse::created(location, to_scim_user(&member, &user, &token)))
}

#[patch("/v2/<_>/Users/<member_id>", data = "<data>")]
async fn patch_user(
    member_id: MembershipId,
    data: ScimJson<PatchOp>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };

    let patch = parse_user_patch(&data.0)?;
    let Some(desired_active) = patch.active else {
        return Err(ScimError::bad_request("invalidValue", "No supported attributes in patch (supported: active)"));
    };

    if desired_active {
        restore_member(&mut member, &token, &conn).await?;
    } else {
        revoke_member(&mut member, &token, &conn).await?;
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

// DELETE deprovisions by revoking, identically to PATCH active:false. The
// membership row is kept: see the module comment.
#[delete("/v2/<_>/Users/<member_id>")]
async fn delete_user(member_id: MembershipId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    revoke_member(&mut member, &token, &conn).await?;
    Ok(ScimResponse::no_content())
}

async fn revoke_member(member: &mut Membership, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if !membership_active(member) {
        // Already revoked: deprovisioning is idempotent.
        return Ok(());
    }

    // Never leave an organization without a confirmed owner.
    if member.atype == MembershipType::Owner
        && member.status == MembershipStatus::Confirmed as i32
        && Membership::count_confirmed_by_org_and_type(&token.org_uuid, MembershipType::Owner, conn).await <= 1
    {
        return Err(ScimError::conflict("mutability", "Cannot revoke the last confirmed owner of the organization"));
    }

    member.revoke();
    member.save(conn).await.map_err(|_| ScimError::internal())?;
    log_scim_event(EventType::OrganizationUserRevoked, member, token, conn).await;
    Ok(())
}

async fn restore_member(member: &mut Membership, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if membership_active(member) {
        return Ok(());
    }

    member.restore();
    // Policy check runs on the restored status, mirroring restore_member_impl.
    if OrgPolicy::check_user_allowed(member, "restore", conn).await.is_err() {
        return Err(ScimError::bad_request("invalidValue", "Restore is blocked by an organization policy"));
    }
    member.save(conn).await.map_err(|_| ScimError::internal())?;
    log_scim_event(EventType::OrganizationUserRestored, member, token, conn).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_with_status(status: i32) -> Membership {
        let mut member = Membership::new("test-user".to_owned().into(), "test-org".to_owned().into(), None);
        member.status = status;
        member
    }

    #[test]
    fn active_mapping_handles_revocation_offsets() {
        // Stored revoked values are status - 128; Revoked (-1) itself is a
        // sentinel that never hits the database.
        for (status, expected_active) in [(2, true), (1, true), (0, true), (-126, false), (-127, false), (-128, false)]
        {
            assert_eq!(membership_active(&member_with_status(status)), expected_active, "status {status}");
        }
    }

    #[test]
    fn revoke_restore_arithmetic_round_trips() {
        for initial in [0, 1, 2] {
            let mut member = member_with_status(initial);
            assert!(member.revoke());
            assert_eq!(member.status, initial - 128);
            assert!(!member.revoke(), "revoke must be idempotent");
            assert!(member.restore());
            assert_eq!(member.status, initial);
            assert!(!member.restore(), "restore must be idempotent");
        }
    }

    #[test]
    fn from_i32_still_rejects_revoked_values() {
        // Regression canary: OrgHeaders relies on revoked statuses mapping to
        // None. If upstream ever changes this, revisit membership_active().
        assert!(MembershipStatus::from_i32(-126).is_none());
        assert!(MembershipStatus::from_i32(-128).is_none());
        assert!(MembershipStatus::from_i32(-1).is_none());
    }
}
