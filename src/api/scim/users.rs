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
use std::collections::HashMap;

use rocket::Route;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        EmptyResult,
        core::log_event,
        scim::{
            SCIM_ACTOR, SCIM_DEVICE_TYPE, ScimJson, ScimResponse,
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
            User, UserId,
        },
    },
    mail,
    util::is_valid_email,
};

pub fn routes() -> Vec<Route> {
    routes![list_users, get_user, post_user, put_user, patch_user, delete_user]
}

// The single place the revocation encoding is interpreted: revoked statuses
// are stored as status - 128 (ACTIVATE_REVOKE_DIFF), so every stored revoked
// value is <= Revoked (-1). Never compare equality against Revoked.
fn membership_active(member: &Membership) -> bool {
    member.status > MembershipStatus::Revoked as i32
}

fn to_scim_user(member: &Membership, user: &User, token: &ScimToken) -> Value {
    let location = crate::api::scim::resource_location(&token.org_uuid, "Users", &member.uuid);
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
    let (start_index, count) = crate::api::scim::page_bounds(params.start_index, params.count);

    let page: Vec<Membership> = members.into_iter().skip(start_index - 1).take(count).collect();
    let user_ids: Vec<UserId> = page.iter().map(|member| member.user_uuid.clone()).collect();
    let users: HashMap<UserId, User> =
        User::find_by_uuids(&user_ids, &conn).await.into_iter().map(|user| (user.uuid.clone(), user)).collect();

    let mut resources = Vec::with_capacity(page.len());
    for member in &page {
        // A membership always references a user; a missing row would be a
        // dangling foreign key, so surface it as a 500 rather than skip.
        let Some(user) = users.get(&member.user_uuid) else {
            return Err(ScimError::internal());
        };
        resources.push(to_scim_user(member, user, &token));
    }

    Ok(crate::api::scim::list_response(total, start_index, &resources))
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
        rollback_provisioning(user, member, user_created, &conn).await;
        return Err(ScimError::internal());
    }

    log_scim_event(EventType::OrganizationUserInvited, &member, &token, &conn).await;
    if !create_active {
        log_scim_event(EventType::OrganizationUserRevoked, &member, &token, &conn).await;
    }

    let location = crate::api::scim::resource_location(&token.org_uuid, "Users", &member.uuid);
    Ok(ScimResponse::created(location, to_scim_user(&member, &user, &token)))
}

// Rollback for a provisioning that failed after its rows were written. The
// destructive decision lives here so it can be tested directly: a user this
// request created is removed entirely (User::delete cascades the membership),
// while a pre-existing account must survive and only the new membership goes.
pub(super) async fn rollback_provisioning(user: User, member: Membership, user_created: bool, conn: &DbConn) {
    let rollback: EmptyResult = if user_created {
        user.delete(conn).await
    } else {
        member.delete(conn).await
    };
    if let Err(rollback_err) = rollback {
        let orphan = if user_created {
            "user"
        } else {
            "membership"
        };
        error!("SCIM provisioning rollback failed, orphaned {orphan} row remains: {rollback_err:#?}");
    }
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

    if let Some(external_id) = patch.external_id.as_deref() {
        update_external_id(&mut member, external_id, &token, &conn).await?;
    }

    match patch.active {
        Some(true) => restore_member(&mut member, &token, &conn).await?,
        Some(false) => revoke_member(&mut member, &token, &conn).await?,
        // Every operation was an accepted-but-ignored attribute (for example
        // a displayName rename): succeed and return the current state.
        None => {}
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

// PUT replaces the attributes SCIM owns: externalId and active. userName,
// name, and role deliberately do not sync: email is the login identity and
// user.name is global to the person, while roles cannot round-trip through
// Vaultwarden's membership types. The response reflects the actual state.
#[put("/v2/<_>/Users/<member_id>", data = "<data>")]
async fn put_user(
    member_id: MembershipId,
    data: ScimJson<ScimUserRequest>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let request = data.0;

    if let Some(external_id) = request.external_id.as_deref() {
        update_external_id(&mut member, external_id, &token, &conn).await?;
    }

    match request.active.map(|b| b.0) {
        Some(true) => restore_member(&mut member, &token, &conn).await?,
        Some(false) => revoke_member(&mut member, &token, &conn).await?,
        None => {}
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

async fn update_external_id(
    member: &mut Membership,
    external_id: &str,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if member.external_id.as_deref() == Some(external_id) {
        return Ok(());
    }
    // The externalId is the correlation key: enforce uniqueness within the org.
    if Membership::find_by_external_id_and_org(external_id, &token.org_uuid, conn).await.is_some() {
        return Err(ScimError::conflict("uniqueness", "A member with this externalId already exists"));
    }
    member.set_external_id(Some(external_id.to_owned()));
    member.save(conn).await.map_err(|_| ScimError::internal())?;
    log_scim_event(EventType::OrganizationUserUpdated, member, token, conn).await;
    Ok(())
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

    // A member restored to Invited has never joined the org. The original
    // invite may never have been sent (created active:false) or have expired,
    // so re-send it; otherwise the person has a membership and shell account
    // they were never told about and cannot register into.
    if member.status == MembershipStatus::Invited as i32
        && CONFIG.mail_enabled()
        && let (Some(user), Some(org)) =
            (User::find_by_uuid(&member.user_uuid, conn).await, Organization::find_by_uuid(&token.org_uuid, conn).await)
        && let Err(e) = mail::send_invite(
            &user,
            token.org_uuid.clone(),
            member.uuid.clone(),
            &org.name,
            Some(org.billing_email.clone()),
        )
        .await
    {
        // The membership is already restored and valid; a mail hiccup must not
        // fail the deprovision-reprovision cycle. Surface it in the log.
        error!("SCIM restore succeeded but re-sending the invite failed: {e:#?}");
    }

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
