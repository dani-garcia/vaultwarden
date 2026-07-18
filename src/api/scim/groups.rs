//
// SCIM /Groups endpoints. The SCIM Group id is Vaultwarden's GroupId, and
// member values are MembershipIds (the same ids the /Users endpoints expose),
// which is why User provisioning must precede Group assignment.
//
// SCIM owns group existence and membership only. Collection access stays an
// in-app admin decision: the IdP decides who is in a group, the vault admin
// decides what the group can see.
//
// Requires ORG_GROUPS_ENABLED. Unlike ldap_import, which silently skips
// groups when disabled, these endpoints fail loudly so a misconfigured
// deployment is visible in the IdP instead of quietly not syncing.
//
use rocket::Route;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        core::log_event,
        scim::{
            ScimJson, ScimResponse,
            error::ScimError,
            filter::parse_eq_filter,
            guard::ScimToken,
            patch::{PatchOp, parse_group_patch},
        },
    },
    db::{
        DbConn,
        models::{EventType, Group, GroupId, GroupUser, Membership, MembershipId},
    },
};

pub fn routes() -> Vec<Route> {
    routes![list_groups, get_group, post_group, put_group, patch_group, delete_group]
}

const SCIM_ACTOR: &str = "vaultwarden-scim-00000-000000000000";
const SCIM_DEVICE_TYPE: i32 = 14;

fn check_groups_enabled() -> Result<(), ScimError> {
    if !CONFIG.org_groups_enabled() {
        return Err(ScimError::not_implemented("Group support is disabled on this server (ORG_GROUPS_ENABLED=false)"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupMember {
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupRequest {
    display_name: Option<String>,
    external_id: Option<String>,
    #[serde(default)]
    members: Vec<ScimGroupMember>,
}

async fn to_scim_group(group: &Group, token: &ScimToken, include_members: bool, conn: &DbConn) -> Value {
    let location = format!("{}/scim/v2/{}/Groups/{}", CONFIG.domain(), token.org_uuid, group.uuid);
    let mut body = json!({
        "schemas": [crate::api::scim::discovery::GROUP_SCHEMA_URN],
        "id": group.uuid,
        "externalId": group.external_id,
        "displayName": group.name,
        "meta": {
            "resourceType": "Group",
            "location": location,
        },
    });
    if include_members {
        let members: Vec<Value> = GroupUser::find_by_group(&group.uuid, &token.org_uuid, conn)
            .await
            .iter()
            .map(|gu| json!({"value": gu.users_organizations_uuid}))
            .collect();
        body["members"] = json!(members);
    }
    body
}

async fn log_group_event(event_type: EventType, group: &Group, token: &ScimToken, conn: &DbConn) {
    log_event(
        event_type as i32,
        &group.uuid,
        &token.org_uuid,
        &SCIM_ACTOR.into(),
        SCIM_DEVICE_TYPE,
        &token.ip.ip,
        conn,
    )
    .await;
}

// Resolves a SCIM member value to a membership of THIS org, or a 400: group
// assignment requires the user to be provisioned into the org first.
async fn resolve_member(value: &str, token: &ScimToken, conn: &DbConn) -> Result<MembershipId, ScimError> {
    let member_id: MembershipId = value.to_owned().into();
    match Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, conn).await {
        Some(member) => Ok(member.uuid),
        None => Err(ScimError::bad_request(
            "invalidValue",
            "members must reference existing members of this organization (provision the user first)",
        )),
    }
}

async fn set_members(
    group: &Group,
    member_ids: Vec<MembershipId>,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    GroupUser::delete_all_by_group(&group.uuid, &token.org_uuid, conn).await.map_err(|_| ScimError::internal())?;
    for member_id in member_ids {
        let mut group_user = GroupUser::new(group.uuid.clone(), member_id);
        group_user.save(conn).await.map_err(|_| ScimError::internal())?;
    }
    Ok(())
}

#[derive(FromForm)]
pub struct GroupListParams {
    filter: Option<String>,
    #[field(name = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    #[field(name = "excludedAttributes")]
    excluded_attributes: Option<String>,
}

#[get("/v2/<_>/Groups?<params..>")]
async fn list_groups(params: GroupListParams, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;

    let groups: Vec<Group> = if let Some(raw_filter) = params.filter.as_deref() {
        let eq = parse_eq_filter(raw_filter)?;
        match eq.attribute.as_str() {
            "displayname" => Group::find_by_organization(&token.org_uuid, &conn)
                .await
                .into_iter()
                .filter(|g| g.name == eq.value)
                .collect(),
            "externalid" => {
                Group::find_by_external_id_and_org(&eq.value, &token.org_uuid, &conn).await.into_iter().collect()
            }
            _ => {
                return Err(ScimError::bad_request(
                    "invalidFilter",
                    "Filterable attributes are displayName and externalId",
                ));
            }
        }
    } else {
        Group::find_by_organization(&token.org_uuid, &conn).await
    };

    // Entra requests excludedAttributes=members on list syncs; honoring it
    // avoids loading every group's member set.
    let include_members = !params.excluded_attributes.as_deref().is_some_and(|excluded| excluded.contains("members"));

    let total = groups.len();
    let start_index = usize::try_from(params.start_index.unwrap_or(1)).unwrap_or(1).max(1);
    let count = usize::try_from(params.count.unwrap_or(100)).unwrap_or(0).min(200);

    let mut resources = Vec::new();
    for group in groups.into_iter().skip(start_index - 1).take(count) {
        resources.push(to_scim_group(&group, &token, include_members, &conn).await);
    }

    Ok(ScimResponse::ok(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "itemsPerPage": resources.len(),
        "startIndex": start_index,
        "Resources": resources,
    })))
}

#[get("/v2/<_>/Groups/<group_id>")]
async fn get_group(group_id: GroupId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

#[post("/v2/<_>/Groups", data = "<data>")]
async fn post_group(
    data: ScimJson<ScimGroupRequest>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let request = data.0;

    let Some(display_name) = request.display_name.as_deref().filter(|n| !n.trim().is_empty()) else {
        return Err(ScimError::bad_request("invalidValue", "displayName is required"));
    };

    if let Some(external_id) = request.external_id.as_deref()
        && Group::find_by_external_id_and_org(external_id, &token.org_uuid, &conn).await.is_some()
    {
        return Err(ScimError::conflict("uniqueness", "A group with this externalId already exists"));
    }

    // Resolve members before creating anything, so a bad member list cannot
    // leave a half-created group behind.
    let mut member_ids = Vec::with_capacity(request.members.len());
    for member in &request.members {
        member_ids.push(resolve_member(&member.value, &token, &conn).await?);
    }

    let mut group = Group::new(token.org_uuid.clone(), display_name.to_owned(), false, request.external_id.clone());
    group.save(&conn).await.map_err(|_| ScimError::internal())?;
    set_members(&group, member_ids, &token, &conn).await?;

    log_group_event(EventType::GroupCreated, &group, &token, &conn).await;

    let location = format!("{}/scim/v2/{}/Groups/{}", CONFIG.domain(), token.org_uuid, group.uuid);
    let body = to_scim_group(&group, &token, true, &conn).await;
    Ok(ScimResponse::created(location, body))
}

// PUT is a full replacement: displayName, externalId, and the member set.
#[put("/v2/<_>/Groups/<group_id>", data = "<data>")]
async fn put_group(
    group_id: GroupId,
    data: ScimJson<ScimGroupRequest>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(mut group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let request = data.0;

    let mut member_ids = Vec::with_capacity(request.members.len());
    for member in &request.members {
        member_ids.push(resolve_member(&member.value, &token, &conn).await?);
    }

    if let Some(display_name) = request.display_name.as_deref().filter(|n| !n.trim().is_empty()) {
        group.name = display_name.to_owned();
    }
    if request.external_id.is_some() {
        group.set_external_id(request.external_id.clone());
    }
    group.save(&conn).await.map_err(|_| ScimError::internal())?;
    set_members(&group, member_ids, &token, &conn).await?;

    log_group_event(EventType::GroupUpdated, &group, &token, &conn).await;

    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

#[patch("/v2/<_>/Groups/<group_id>", data = "<data>")]
async fn patch_group(
    group_id: GroupId,
    data: ScimJson<PatchOp>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(mut group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };

    let patch = parse_group_patch(&data.0)?;

    if let Some(display_name) = patch.display_name.as_deref().filter(|n| !n.trim().is_empty()) {
        group.name = display_name.to_owned();
        group.save(&conn).await.map_err(|_| ScimError::internal())?;
    }
    if let Some(external_id) = patch.external_id.clone() {
        group.set_external_id(Some(external_id));
        group.save(&conn).await.map_err(|_| ScimError::internal())?;
    }

    if let Some(replacement) = patch.replace_members {
        let mut member_ids = Vec::with_capacity(replacement.len());
        for value in &replacement {
            member_ids.push(resolve_member(value, &token, &conn).await?);
        }
        set_members(&group, member_ids, &token, &conn).await?;
    } else {
        // True diff semantics: adds insert (idempotently via replace_into in
        // GroupUser::save), removes delete only the listed member links.
        for value in &patch.add_members {
            let member_id = resolve_member(value, &token, &conn).await?;
            let mut group_user = GroupUser::new(group.uuid.clone(), member_id);
            group_user.save(&conn).await.map_err(|_| ScimError::internal())?;
        }
        for value in &patch.remove_members {
            // Removing a member who is not in the org (or already absent from
            // the group) is a no-op, not an error: Entra retries removals.
            let member_id: MembershipId = value.clone().into();
            GroupUser::delete_by_group_and_member(&group.uuid, &member_id, &conn)
                .await
                .map_err(|_| ScimError::internal())?;
        }
    }

    log_group_event(EventType::GroupUpdated, &group, &token, &conn).await;

    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

// Deleting a group only removes an access mapping: it carries no E2EE state
// (unlike memberships, where delete would destroy the wrapped org key), so a
// real delete is safe and matches RFC semantics.
#[delete("/v2/<_>/Groups/<group_id>")]
async fn delete_group(group_id: GroupId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    log_group_event(EventType::GroupDeleted, &group, &token, &conn).await;
    group.delete(&token.org_uuid, &conn).await.map_err(|_| ScimError::internal())?;
    Ok(ScimResponse::no_content())
}
