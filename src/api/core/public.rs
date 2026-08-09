use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rocket::{
    Request, Route,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult, Notify, UpdateType},
    auth,
    db::{
        DbConn,
        models::{
            Collection, CollectionGroup, CollectionId, CollectionUser, EventType, Group, GroupId, GroupUser,
            Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization,
            OrganizationApiKey, OrganizationId, User,
        },
    },
    mail,
    util::NumberOrString,
};

use super::events::log_public_event;

pub fn routes() -> Vec<Route> {
    routes![
        ldap_import,
        get_members,
        get_member,
        get_member_group_ids,
        get_groups,
        get_group,
        get_group_member_ids,
        get_collections,
        get_collection,
        post_member,
        put_member,
        delete_member,
        put_member_group_ids,
        post_member_reinvite,
        post_member_revoke,
        post_member_restore,
        post_group,
        put_group,
        delete_group,
        put_group_member_ids,
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
    // largeImport: bool, // For now this will not be used, upstream uses this to prevent syncs of more then 2000 users or groups without the flag set.
}

#[post("/public/organization/import", data = "<data>")]
async fn ldap_import(data: Json<OrgImportData>, token: PublicToken, conn: DbConn) -> EmptyResult {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/OrganizationService.cs#L1203

    let org_id = token.0;
    let data = data.into_inner();

    for user_data in &data.members {
        let mut user_created: bool = false;
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
                // Only revoke a user if it is not the last confirmed owner
                let revoked = if member.atype == MembershipType::Owner
                    && member.status == MembershipStatus::Confirmed as i32
                {
                    if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
                        warn!("Can't revoke the last owner");
                        false
                    } else {
                        member.revoke()
                    }
                } else {
                    member.revoke()
                };

                let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    member.save(&conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
            let mut restored = member.restore();
            let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
            // Enforce org policies as every other restore path does.
            // If the user is not allowed, we revoke again and continue so the external_id is still updated.
            if restored && let Err(e) = OrgPolicy::check_user_allowed(&member, "restore", &conn).await {
                warn!("Not restoring {}: {e:?}", user_data.email);
                member.revoke();
                restored = false;
            }
            if restored || ext_modified {
                member.save(&conn).await?;
            }
        } else {
            // If user is not part of the organization
            let user = if let Some(user) = User::find_by_mail(&user_data.email, &conn).await {
                user
            } else {
                // User does not exist yet
                let mut new_user = User::new(&user_data.email, None);
                new_user.save(&conn).await?;

                if !CONFIG.mail_enabled() {
                    Invitation::new(&new_user.email).save(&conn).await?;
                }
                user_created = true;
                new_user
            };
            let member_status = if CONFIG.mail_enabled() || user.password_hash.is_empty() {
                MembershipStatus::Invited as i32
            } else {
                MembershipStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
            };

            let (org_name, org_email) = if let Some(org) = Organization::find_by_uuid(&org_id, &conn).await {
                (org.name, org.billing_email)
            } else {
                err!("Error looking up organization")
            };

            let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org_email.clone()));
            new_member.set_external_id(Some(user_data.external_id.clone()));
            new_member.access_all = false;
            new_member.atype = MembershipType::User as i32;
            new_member.status = member_status;

            new_member.save(&conn).await?;

            if CONFIG.mail_enabled()
                && let Err(e) =
                    mail::send_invite(&user, org_id.clone(), new_member.uuid.clone(), &org_name, Some(org_email)).await
            {
                // Upon error delete the user, invite and org member records when needed
                if user_created {
                    user.delete(&conn).await?;
                } else {
                    new_member.delete(&conn).await?;
                }

                err!(format!("Error sending invite: {e:?} "));
            }
        }
    }

    if CONFIG.org_groups_enabled() {
        for group_data in &data.groups {
            let group_uuid = if let Some(group) =
                Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &conn).await
            {
                group.uuid
            } else {
                let mut group =
                    Group::new(org_id.clone(), group_data.name.clone(), false, Some(group_data.external_id.clone()));
                group.save(&conn).await?;
                group.uuid
            };

            GroupUser::delete_all_by_group(&group_uuid, &org_id, &conn).await?;

            for ext_id in &group_data.member_external_ids {
                if let Some(member) = Membership::find_by_external_id_and_org(ext_id, &org_id, &conn).await {
                    let mut group_user = GroupUser::new(group_uuid.clone(), member.uuid.clone());
                    group_user.save(&conn).await?;
                }
            }
        }
    } else {
        warn!("Group support is disabled, groups will not be imported!");
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        // Generate a HashSet to quickly verify if a member is listed or not.
        let sync_members: HashSet<String> = data.members.into_iter().map(|m| m.external_id).collect();
        for member in Membership::find_by_org(&org_id, &conn).await {
            if let Some(ref user_external_id) = member.external_id
                && !sync_members.contains(user_external_id)
            {
                if member.atype == MembershipType::Owner && member.status == MembershipStatus::Confirmed as i32 {
                    // Removing owner, check that there is at least one other confirmed owner
                    if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
                        warn!("Can't delete the last owner");
                        continue;
                    }
                }
                member.delete(&conn).await?;
            }
        }
    }

    Ok(())
}

// These endpoints implement the read side of the organization Public API so an
// organization-scoped API client can read back the members, groups, and
// collections (and their associations) that the existing
// "/public/organization/import" endpoint writes. They all reuse the PublicToken
// guard, so they are authorized by the same organization API key.

// Base member object. The list endpoint returns this as-is; the single-member
// endpoint extends it with "collections".
async fn member_to_json(member: &Membership, conn: &DbConn) -> Value {
    let (name, email) = match User::find_by_uuid(&member.user_uuid, conn).await {
        Some(user) => {
            let name = if user.name.is_empty() {
                Value::Null
            } else {
                Value::String(user.name)
            };
            (name, Value::String(user.email))
        }
        None => (Value::Null, Value::Null),
    };

    json!({
        "object": "member",
        "id": member.uuid,
        "userId": member.user_uuid,
        "name": name,
        "email": email,
        "type": member.atype,
        "externalId": member.external_id,
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "status": member.status,
    })
}

// Base group object. The list endpoint returns this as-is; the single-group
// endpoint extends it with "collections".
fn group_to_json(group: &Group) -> Value {
    json!({
        "object": "group",
        "id": group.uuid,
        "name": group.name,
        "accessAll": group.access_all,
        "externalId": group.external_id,
    })
}

// Base collection object. The Bitwarden Public API keys collections by id and
// externalId only; the name is deliberately omitted because it is end-to-end
// encrypted ciphertext. The single-collection endpoint extends it with "groups".
fn collection_to_json(collection: &Collection) -> Value {
    json!({
        "object": "collection",
        "id": collection.uuid,
        "externalId": collection.external_id,
    })
}

#[get("/public/members")]
async fn get_members(token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let mut members_json = Vec::new();
    for member in Membership::find_by_org(&org_id, &conn).await {
        members_json.push(member_to_json(&member, &conn).await);
    }

    Ok(Json(json!({
        "object": "list",
        "data": members_json,
        "continuationToken": null,
    })))
}

#[get("/public/members/<member_id>")]
async fn get_member(member_id: MembershipId, token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    let collections: Vec<Value> = CollectionUser::find_by_organization_and_user_uuid(&org_id, &member.user_uuid, &conn)
        .await
        .iter()
        .map(|c| {
            json!({
                "id": c.collection_uuid,
                "readOnly": c.read_only,
                "hidePasswords": c.hide_passwords,
                "manage": c.manage,
            })
        })
        .collect();

    let mut member_json = member_to_json(&member, &conn).await;
    member_json["collections"] = json!(collections);

    Ok(Json(member_json))
}

#[get("/public/members/<member_id>/group-ids")]
async fn get_member_group_ids(member_id: MembershipId, token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    if Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await.is_none() {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    }

    // GroupUser links a group to a membership, so a member's group ids are the
    // group uuids of the GroupUser rows referencing this membership.
    let group_ids: Vec<GroupId> =
        GroupUser::find_by_member(&member_id, &conn).await.into_iter().map(|gu| gu.groups_uuid).collect();

    Ok(Json(json!(group_ids)))
}

#[get("/public/groups")]
async fn get_groups(token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let groups_json: Vec<Value> = Group::find_by_organization(&org_id, &conn).await.iter().map(group_to_json).collect();

    Ok(Json(json!({
        "object": "list",
        "data": groups_json,
        "continuationToken": null,
    })))
}

#[get("/public/groups/<group_id>")]
async fn get_group(group_id: GroupId, token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err_code!(format!("Group {group_id} not found in organization"), 404);
    };

    let collections: Vec<Value> = CollectionGroup::find_by_group(&group_id, &org_id, &conn)
        .await
        .iter()
        .map(|c| {
            json!({
                "id": c.collections_uuid,
                "readOnly": c.read_only,
                "hidePasswords": c.hide_passwords,
                "manage": c.manage,
            })
        })
        .collect();

    let mut group_json = group_to_json(&group);
    group_json["collections"] = json!(collections);

    Ok(Json(group_json))
}

#[get("/public/groups/<group_id>/member-ids")]
async fn get_group_member_ids(group_id: GroupId, token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err_code!(format!("Group {group_id} not found in organization"), 404);
    }

    // A group's member ids are the membership uuids of its GroupUser rows.
    let member_ids: Vec<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
        .await
        .into_iter()
        .map(|gu| gu.users_organizations_uuid)
        .collect();

    Ok(Json(json!(member_ids)))
}

#[get("/public/collections")]
async fn get_collections(token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let collections_json: Vec<Value> =
        Collection::find_by_organization(&org_id, &conn).await.iter().map(collection_to_json).collect();

    Ok(Json(json!({
        "object": "list",
        "data": collections_json,
        "continuationToken": null,
    })))
}

#[get("/public/collections/<collection_id>")]
async fn get_collection(collection_id: CollectionId, token: PublicToken, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let Some(collection) = Collection::find_by_uuid_and_org(&collection_id, &org_id, &conn).await else {
        err_code!(format!("Collection {collection_id} not found in organization"), 404);
    };

    let groups: Vec<Value> = CollectionGroup::find_by_collection(&collection_id, &conn)
        .await
        .iter()
        .map(|c| {
            json!({
                "id": c.groups_uuid,
                "readOnly": c.read_only,
                "hidePasswords": c.hide_passwords,
                "manage": c.manage,
            })
        })
        .collect();

    let mut collection_json = collection_to_json(&collection);
    collection_json["groups"] = json!(groups);

    Ok(Json(collection_json))
}

// These endpoints implement the write side of the organization Public API. Together
// with the read endpoints above they replace the need to drive every change through
// "/public/organization/import", which is a full directory snapshot and revokes any
// member missing from the payload when overwriteExisting is set.
//
// The write paths mirror the equivalent internal endpoints in `organizations.rs`, but
// are guarded by PublicToken instead of AdminHeaders. A PublicToken carries only an
// organization, so the per-actor permission checks of the internal API do not apply;
// the guards that protect organization integrity (last confirmed owner, org policies,
// group support being enabled) are kept.

// Bitwarden models an assignment to a collection as its id plus the permissions granted.
// Upstream: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Public/Models/AssociationWithPermissionsBaseModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssociationData {
    id: CollectionId,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberCreateData {
    email: String,
    r#type: NumberOrString,
    external_id: Option<String>,
    #[serde(default)]
    collections: Vec<AssociationData>,
    #[serde(default)]
    groups: Vec<GroupId>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberUpdateData {
    r#type: NumberOrString,
    external_id: Option<String>,
    #[serde(default)]
    collections: Vec<AssociationData>,
    #[serde(default)]
    groups: Vec<GroupId>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupCreateUpdateData {
    name: String,
    // Upstream dropped accessAll from its group model, but the Vaultwarden group still
    // carries the flag, so it is accepted here and defaults to false when omitted.
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    #[serde(default)]
    collections: Vec<AssociationData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupIdsData {
    group_ids: Vec<GroupId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberIdsData {
    member_ids: Vec<MembershipId>,
}

// HACK: We need the raw user-type to be sure custom role is selected to determine the access_all permission
// The from_str() will convert the custom role type into a manager role type
fn member_type_and_access_all(
    r#type: NumberOrString,
    permissions: &HashMap<String, Value>,
) -> Option<(MembershipType, bool)> {
    let raw_type = &r#type.into_string();
    // MembershipType::from_str will convert custom (4) to manager (3)
    let new_type = MembershipType::from_str(raw_type)?;

    // HACK: This converts the Custom role which has the `Manage all collections` box checked into an access_all flag
    // Since the parent checkbox is not sent to the server we need to check and verify the child checkboxes
    // If the box is not checked, the user will still be a manager, but not with the access_all permission
    let access_all = new_type >= MembershipType::Admin
        || (raw_type.eq("4")
            && permissions.get("editAnyCollection") == Some(&json!(true))
            && permissions.get("deleteAnyCollection") == Some(&json!(true))
            && permissions.get("createNewCollections") == Some(&json!(true)));

    Some((new_type, access_all))
}

async fn validate_collections(collections: &[AssociationData], org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    let org_collections = Collection::find_by_organization(org_id, conn).await;
    let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
    if let Some(e) = collections.iter().find(|c| !org_collection_ids.contains(&c.id)) {
        err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
    }
    Ok(())
}

async fn validate_groups(group_ids: &[GroupId], org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    let org_groups = Group::find_by_organization(org_id, conn).await;
    let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|g| &g.uuid).collect();
    if let Some(e) = group_ids.iter().find(|g| !org_group_ids.contains(g)) {
        err!("Invalid group", format!("Group {} does not belong to organization {}!", e, org_id))
    }
    Ok(())
}

async fn validate_members(member_ids: &[MembershipId], org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    let org_memberships = Membership::find_by_org(org_id, conn).await;
    let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
    if let Some(e) = member_ids.iter().find(|m| !org_membership_ids.contains(m)) {
        err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
    }
    Ok(())
}

// Replace a member's collection assignments. Members of type Admin or Owner reach every
// collection through their type, so no explicit assignments are stored for them.
async fn set_member_collections(
    member: &Membership,
    collections: &[AssociationData],
    org_id: &OrganizationId,
    conn: &DbConn,
) -> EmptyResult {
    for c in CollectionUser::find_by_organization_and_user_uuid(org_id, &member.user_uuid, conn).await {
        c.delete(conn).await?;
    }

    if !member.access_all {
        for col in collections {
            CollectionUser::save(&member.user_uuid, &col.id, col.read_only, col.hide_passwords, col.manage, conn)
                .await?;
        }
    }

    Ok(())
}

async fn set_member_groups(member: &Membership, group_ids: &[GroupId], conn: &DbConn) -> EmptyResult {
    GroupUser::delete_all_by_member(&member.uuid, conn).await?;
    for group_id in group_ids {
        let mut group_entry = GroupUser::new(group_id.clone(), member.uuid.clone());
        group_entry.save(conn).await?;
    }

    Ok(())
}

async fn set_group_collections(
    group: &Group,
    collections: &[AssociationData],
    org_id: &OrganizationId,
    conn: &DbConn,
) -> EmptyResult {
    CollectionGroup::delete_all_by_group(&group.uuid, org_id, conn).await?;
    for col in collections {
        let mut collection_group =
            CollectionGroup::new(col.id.clone(), group.uuid.clone(), col.read_only, col.hide_passwords, col.manage);
        collection_group.save(org_id, conn).await?;
    }

    Ok(())
}

// A Public API client is not a member of the organization, so invites are recorded as
// coming from the organization itself, the same way "/public/organization/import" does.
async fn org_name_and_email(org_id: &OrganizationId, conn: &DbConn) -> Result<(String, String), crate::error::Error> {
    let Some(org) = Organization::find_by_uuid(org_id, conn).await else {
        err!("Error looking up organization")
    };

    Ok((org.name, org.billing_email))
}

#[post("/public/members", data = "<data>")]
async fn post_member(data: Json<MemberCreateData>, token: PublicToken, ip: auth::ClientIp, conn: DbConn) -> JsonResult {
    let org_id = token.0;
    let data = data.into_inner();

    let Some((new_type, access_all)) = member_type_and_access_all(data.r#type, &data.permissions) else {
        err!("Invalid type")
    };

    validate_collections(&data.collections, &org_id, &conn).await?;
    validate_groups(&data.groups, &org_id, &conn).await?;

    let mut user_created = false;
    let mut member_status = MembershipStatus::Invited as i32;
    let user = match User::find_by_mail(&data.email, &conn).await {
        None => {
            if !CONFIG.invitations_allowed() {
                err!(format!("User does not exist: {}", data.email))
            }

            if !CONFIG.is_email_domain_allowed(&data.email) {
                err!("Email domain not eligible for invitations")
            }

            if !CONFIG.mail_enabled() {
                Invitation::new(&data.email).save(&conn).await?;
            }

            let mut new_user = User::new(&data.email, None);
            new_user.save(&conn).await?;
            user_created = true;
            new_user
        }
        Some(user) => {
            if Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
                err!(format!("User already in organization: {}", data.email))
            }

            if !CONFIG.mail_enabled() {
                if user.password_hash.is_empty() {
                    Invitation::new(&data.email).save(&conn).await?;
                } else {
                    // automatically accept existing users if mail is disabled
                    member_status = MembershipStatus::Accepted as i32;
                }
            }
            user
        }
    };

    let (org_name, org_email) = org_name_and_email(&org_id, &conn).await?;

    let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(org_email.clone()));
    new_member.access_all = access_all;
    new_member.atype = new_type as i32;
    new_member.status = member_status;
    new_member.set_external_id(data.external_id.clone());
    new_member.save(&conn).await?;

    if CONFIG.mail_enabled()
        && let Err(e) =
            mail::send_invite(&user, org_id.clone(), new_member.uuid.clone(), &org_name, Some(org_email)).await
    {
        // Upon error delete the user, invite and org member records when needed
        if user_created {
            user.delete(&conn).await?;
        } else {
            new_member.delete(&conn).await?;
        }

        err!(format!("Error sending invite: {e:?} "));
    }

    log_public_event(EventType::OrganizationUserInvited as i32, &new_member.uuid, &org_id, &ip.ip, &conn).await;

    set_member_collections(&new_member, &data.collections, &org_id, &conn).await?;
    set_member_groups(&new_member, &data.groups, &conn).await?;

    Ok(Json(member_to_json(&new_member, &conn).await))
}

#[put("/public/members/<member_id>", data = "<data>")]
async fn put_member(
    member_id: MembershipId,
    data: Json<MemberUpdateData>,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let data = data.into_inner();

    let Some((new_type, access_all)) = member_type_and_access_all(data.r#type, &data.permissions) else {
        err!("Invalid type")
    };

    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    validate_collections(&data.collections, &org_id, &conn).await?;
    validate_groups(&data.groups, &org_id, &conn).await?;

    if member.atype == MembershipType::Owner
        && new_type != MembershipType::Owner
        && member.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner permission, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    member.access_all = access_all;
    member.atype = new_type as i32;
    member.set_external_id(data.external_id.clone());

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member,
    // admin::update_membership_type. We need to perform the check after changing the type.
    OrgPolicy::check_user_allowed(&member, "modify", &conn).await?;

    set_member_collections(&member, &data.collections, &org_id, &conn).await?;
    set_member_groups(&member, &data.groups, &conn).await?;

    member.save(&conn).await?;

    log_public_event(EventType::OrganizationUserUpdated as i32, &member.uuid, &org_id, &ip.ip, &conn).await;

    Ok(Json(member_to_json(&member, &conn).await))
}

#[delete("/public/members/<member_id>")]
async fn delete_member(
    member_id: MembershipId,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let org_id = token.0;
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    if member.atype == MembershipType::Owner && member.status == MembershipStatus::Confirmed as i32 {
        // Removing owner, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    log_public_event(EventType::OrganizationUserRemoved as i32, &member.uuid, &org_id, &ip.ip, &conn).await;

    if let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await {
        // There is no device behind a Public API request, so no push device to exclude.
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, None, &conn).await;

        if !CONFIG.mail_enabled()
            && !Membership::find_invited_by_user(&user.uuid, &conn).await.into_iter().any(|m| m.uuid != member.uuid)
        {
            Invitation::take(&user.email, &conn).await;
        }
    }

    member.delete(&conn).await
}

#[put("/public/members/<member_id>/group-ids", data = "<data>")]
async fn put_member_group_ids(
    member_id: MembershipId,
    data: Json<GroupIdsData>,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> EmptyResult {
    let org_id = token.0;
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    let data = data.into_inner();
    validate_groups(&data.group_ids, &org_id, &conn).await?;

    set_member_groups(&member, &data.group_ids, &conn).await?;

    log_public_event(EventType::OrganizationUserUpdatedGroups as i32, &member.uuid, &org_id, &ip.ip, &conn).await;

    Ok(())
}

#[post("/public/members/<member_id>/reinvite")]
async fn post_member_reinvite(member_id: MembershipId, token: PublicToken, conn: DbConn) -> EmptyResult {
    let org_id = token.0;
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    if member.status != MembershipStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found.")
    };

    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err!("Invitations are not allowed.")
    }

    let (org_name, org_email) = org_name_and_email(&org_id, &conn).await?;

    if CONFIG.mail_enabled() {
        mail::send_invite(&user, org_id.clone(), member.uuid, &org_name, Some(org_email)).await?;
    } else if user.password_hash.is_empty() {
        Invitation::new(&user.email).save(&conn).await?;
    } else {
        Invitation::take(&user.email, &conn).await;
        let mut member = member;
        member.status = MembershipStatus::Accepted as i32;
        member.save(&conn).await?;
    }

    Ok(())
}

#[post("/public/members/<member_id>/revoke")]
async fn post_member_revoke(
    member_id: MembershipId,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> EmptyResult {
    let org_id = token.0;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    if member.status <= MembershipStatus::Revoked as i32 {
        err!("User is already revoked")
    }

    if member.atype == MembershipType::Owner
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err!("Organization must have at least one confirmed owner")
    }

    member.revoke();
    member.save(&conn).await?;

    log_public_event(EventType::OrganizationUserRevoked as i32, &member.uuid, &org_id, &ip.ip, &conn).await;

    Ok(())
}

#[post("/public/members/<member_id>/restore")]
async fn post_member_restore(
    member_id: MembershipId,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> EmptyResult {
    let org_id = token.0;
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err_code!(format!("Member {member_id} not found in organization"), 404);
    };

    if member.status >= MembershipStatus::Accepted as i32 {
        err!("User is already active")
    }

    member.restore();
    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member,
    // admin::update_membership_type. It needs to happen after restoring to see the correct status.
    OrgPolicy::check_user_allowed(&member, "restore", &conn).await?;
    member.save(&conn).await?;

    log_public_event(EventType::OrganizationUserRestored as i32, &member.uuid, &org_id, &ip.ip, &conn).await;

    Ok(())
}

#[post("/public/groups", data = "<data>")]
async fn post_group(
    data: Json<GroupCreateUpdateData>,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let data = data.into_inner();
    validate_collections(&data.collections, &org_id, &conn).await?;

    let mut group = Group::new(org_id.clone(), data.name.clone(), data.access_all, data.external_id.clone());
    group.save(&conn).await?;

    set_group_collections(&group, &data.collections, &org_id, &conn).await?;

    log_public_event(EventType::GroupCreated as i32, &group.uuid, &org_id, &ip.ip, &conn).await;

    Ok(Json(group_to_json(&group)))
}

#[put("/public/groups/<group_id>", data = "<data>")]
async fn put_group(
    group_id: GroupId,
    data: Json<GroupCreateUpdateData>,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(mut group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err_code!(format!("Group {group_id} not found in organization"), 404);
    };

    let data = data.into_inner();
    validate_collections(&data.collections, &org_id, &conn).await?;

    group.name.clone_from(&data.name);
    group.access_all = data.access_all;
    // Unlike the internal endpoint, the external_id is updatable here. The Public API is
    // the directory integration surface, the same one "/public/organization/import" uses
    // to assign external ids in the first place.
    group.set_external_id(data.external_id.clone());
    group.save(&conn).await?;

    // Member assignments are owned by "/public/groups/<group_id>/member-ids" and are
    // deliberately left untouched here.
    set_group_collections(&group, &data.collections, &org_id, &conn).await?;

    log_public_event(EventType::GroupUpdated as i32, &group.uuid, &org_id, &ip.ip, &conn).await;

    Ok(Json(group_to_json(&group)))
}

#[delete("/public/groups/<group_id>")]
async fn delete_group(group_id: GroupId, token: PublicToken, ip: auth::ClientIp, conn: DbConn) -> EmptyResult {
    let org_id = token.0;
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err_code!(format!("Group {group_id} not found in organization"), 404);
    };

    log_public_event(EventType::GroupDeleted as i32, &group.uuid, &org_id, &ip.ip, &conn).await;

    group.delete(&org_id, &conn).await
}

#[put("/public/groups/<group_id>/member-ids", data = "<data>")]
async fn put_group_member_ids(
    group_id: GroupId,
    data: Json<MemberIdsData>,
    token: PublicToken,
    ip: auth::ClientIp,
    conn: DbConn,
) -> EmptyResult {
    let org_id = token.0;
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err_code!(format!("Group {group_id} not found in organization"), 404);
    }

    let data = data.into_inner();
    validate_members(&data.member_ids, &org_id, &conn).await?;

    GroupUser::delete_all_by_group(&group_id, &org_id, &conn).await?;
    for member_id in &data.member_ids {
        let mut user_entry = GroupUser::new(group_id.clone(), member_id.clone());
        user_entry.save(&conn).await?;

        log_public_event(EventType::OrganizationUserUpdatedGroups as i32, member_id, &org_id, &ip.ip, &conn).await;
    }

    Ok(())
}

pub struct PublicToken(OrganizationId);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();
        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };
        // Check JWT token is valid and get device and user from it
        let Ok(claims) = auth::decode_api_org(access_token) else {
            err_handler!("Invalid claim")
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().timestamp();
        if time_now < claims.nbf {
            err_handler!("Token issued in the future");
        }
        if time_now > claims.exp {
            err_handler!("Token expired");
        }
        // Check if claims.iss is domain|claims.scope[0]
        let complete_host = format!("{}|{}", CONFIG.domain_origin(), claims.scope[0]);
        if complete_host != claims.iss {
            err_handler!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };
        let Some(org_id) = claims.client_id.strip_prefix("organization.") else {
            err_handler!("Malformed client_id")
        };
        let org_id: OrganizationId = org_id.to_owned().into();
        let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(&org_id, &conn).await else {
            err_handler!("Invalid client_id")
        };
        if org_api_key.org_uuid != claims.client_sub {
            err_handler!("Token not issued for this org");
        }
        if org_api_key.uuid != claims.sub {
            err_handler!("Token not issued for this client");
        }

        Outcome::Success(PublicToken(claims.client_sub))
    }
}
