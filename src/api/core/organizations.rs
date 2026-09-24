use std::collections::{HashMap, HashSet};

use num_traits::FromPrimitive;
use rocket::{Route, http::Status, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::admin::FAKE_ADMIN_UUID,
    api::{
        ApiResult, EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::{CipherSyncData, CipherSyncType, accept_org_invite, log_event, two_factor},
    },
    auth::{
        AccessImportExportHeaders, AdminHeaders, CollectionDeleteHeaders, CollectionReadHeaders, Headers,
        ManageGroupsHeaders, ManagePoliciesHeaders, ManageUsersHeaders, ManageUsersOrGroupsHeaders, ManagerHeaders,
        ManagerHeadersLoose, OrgMemberHeaders, OwnerHeaders, can_read_collection_access,
        can_read_collection_with_access, decode_invite, may_access_import_export,
    },
    db::{
        DbConn,
        models::{
            Cipher, CipherAccessScope, CipherId, Collection, CollectionCipher, CollectionGroup, CollectionId,
            CollectionUser, EventType, Group, GroupId, GroupUser, Invitation, Membership, MembershipId,
            MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, Organization, OrganizationApiKey,
            OrganizationId, TwoFactor, TwoFactorType, User, UserId, custom_role_permissions,
        },
    },
    mail,
    sso::FAKE_SSO_IDENTIFIER,
    util::{NumberOrString, convert_json_key_lcase_first},
};

pub fn routes() -> Vec<Route> {
    routes![
        get_organization,
        create_organization,
        delete_organization,
        post_delete_organization,
        leave_organization,
        get_user_collections,
        get_org_collections,
        get_org_collections_details,
        get_org_collection_detail,
        get_collection_users,
        put_organization,
        post_organization,
        post_organization_collections,
        post_bulk_access_collections,
        post_organization_collection_update,
        put_organization_collection_update,
        delete_organization_collection,
        post_organization_collection_delete,
        bulk_delete_organization_collections,
        post_bulk_collections,
        get_assigned_org_details,
        get_org_details,
        get_org_domain_sso_verified,
        get_members,
        send_invite,
        reinvite_member,
        bulk_reinvite_members,
        confirm_invite,
        bulk_confirm_invite,
        accept_invite,
        get_org_user_mini_details,
        get_user,
        edit_member,
        put_member,
        delete_member,
        bulk_delete_member,
        post_org_import,
        list_policies,
        list_policies_token,
        get_dummy_master_password_policy,
        get_master_password_policy,
        get_policy,
        put_policy,
        put_policy_vnext,
        get_plans,
        post_org_keys,
        get_organization_keys,
        get_organization_public_key,
        bulk_public_keys,
        revoke_member,
        bulk_revoke_members,
        restore_member,
        restore_member_vnext,
        bulk_restore_members,
        get_groups,
        get_groups_details,
        post_groups,
        get_group,
        put_group,
        post_group,
        get_group_details,
        delete_group,
        post_delete_group,
        bulk_delete_groups,
        get_group_members,
        put_group_members,
        post_delete_group_member,
        put_reset_password_enrollment,
        get_reset_password_details,
        put_reset_password,
        put_recover_account,
        get_org_export,
        post_api_key,
        rotate_api_key,
        get_billing_metadata,
        get_billing_warnings,
        get_auto_enroll_status,
        get_self_host_billing_metadata,
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,
    #[allow(dead_code)]
    plan_type: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrganizationUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullCollectionData {
    name: String,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
    external_id: Option<String>,
}

fn validate_collection_access(manage: bool, read_only: bool, hide_passwords: bool) -> EmptyResult {
    if manage && (read_only || hide_passwords) {
        err!(
            "The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true."
        )
    }
    Ok(())
}

impl FullCollectionData {
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for group in &self.groups {
            validate_collection_access(group.manage, group.read_only, group.hide_passwords)?;
        }
        for user in &self.users {
            validate_collection_access(user.manage, user.read_only, user.hide_passwords)?;
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(&m.id)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e.id, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionGroupData {
    hide_passwords: bool,
    id: GroupId,
    read_only: bool,
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionMembershipData {
    hide_passwords: bool,
    id: MembershipId,
    read_only: bool,
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkGroupIds {
    ids: Vec<GroupId>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkMembershipIds {
    ids: Vec<MembershipId>,
}

#[post("/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: Json<OrgData>, conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.into_inner();
    let (private_key, public_key) = if let Some(keys) = data.keys {
        (Some(keys.encrypted_private_key), Some(keys.public_key))
    } else {
        (None, None)
    };

    let org = Organization::new(data.name, &data.billing_email, private_key, public_key);
    let mut member = Membership::new(headers.user.uuid, org.uuid.clone(), None);
    let collection = Collection::new(org.uuid.clone(), data.collection_name, None);

    member.akey = data.key;
    member.atype = MembershipType::Owner as i32;
    member.status = MembershipStatus::Confirmed as i32;

    org.save(&conn).await?;
    member.save(&conn).await?;
    collection.save(&conn).await?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
async fn delete_organization(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();

    data.validate(&headers.user, true, &conn).await?;

    match Organization::find_by_uuid(&org_id, &conn).await {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn).await,
    }
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
async fn post_delete_organization(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization(org_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/leave")]
async fn leave_organization(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> EmptyResult {
    if headers.membership.status != MembershipStatus::Confirmed as i32 {
        err!("You need to be a Member of the Organization to call this endpoint")
    }
    let membership = headers.membership;

    if membership.atype == MembershipType::Owner
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err!("The last owner can't leave")
    }

    log_event(
        EventType::OrganizationUserLeft,
        &membership.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    membership.delete(&conn).await
}

#[get("/organizations/<org_id>")]
async fn get_organization(org_id: OrganizationId, headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        Ok(Json(organization.to_json()))
    } else {
        err!("Can't find organization details")
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
async fn put_organization(
    org_id: OrganizationId,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_organization(org_id, headers, data, conn).await
}

#[post("/organizations/<org_id>", data = "<data>")]
async fn post_organization(
    org_id: OrganizationId,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let data: OrganizationUpdateData = data.into_inner();

    let Some(mut org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    org.name = data.name;
    org.billing_email = data.billing_email.to_lowercase();

    org.save(&conn).await?;

    log_event(
        EventType::OrganizationUpdated,
        org_id.as_ref(),
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
async fn get_user_collections(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(json!({
        "data":
            Collection::find_by_user_uuid(headers.user.uuid, &conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    }))
}

// Called during the SSO enrollment
// The `identifier` should be the value returned by `get_org_domain_sso_verified`
// The returned `Id` will then be passed to `get_master_password_policy` which will mainly ignore it
#[get("/organizations/<identifier>/auto-enroll-status")]
async fn get_auto_enroll_status(identifier: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let org = if identifier == FAKE_SSO_IDENTIFIER {
        match Membership::find_main_user_org(&headers.user.uuid, &conn).await {
            Some(member) => Organization::find_by_uuid(&member.org_uuid, &conn).await,
            None => None,
        }
    } else {
        Organization::find_by_uuid(&identifier.into(), &conn).await
    };

    let (id, identifier, rp_auto_enroll) = match org {
        None => (identifier.to_owned(), identifier.to_owned(), false),
        Some(org) => (
            org.uuid.to_string(),
            org.uuid.to_string(),
            OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await,
        ),
    };

    Ok(Json(json!({
        "id": id,
        "identifier": identifier,
        "resetPasswordEnabled": rp_auto_enroll,
    })))
}

#[get("/organizations/<org_id>/collections")]
async fn get_org_collections(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let can_read_all = may_read_all_collections(&headers.membership);
    let all_collections = Collection::find_by_organization(&org_id, &conn).await;
    let collections = if can_read_all {
        all_collections
    } else {
        // Same rule as `has_explicit_collection_manage_access`, resolved in one query instead of one
        // per collection.
        let explicitly_managed = headers.membership.explicitly_managed_collection_ids(&conn).await;
        all_collections.into_iter().filter(|collection| explicitly_managed.contains(&collection.uuid)).collect()
    };
    Ok(Json(json!({
        "data": collections.iter().map(Collection::to_json).collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/collections/details")]
async fn get_org_collections_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(member) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err!("User is not part of organization")
    };

    // get all collection memberships for the current organization
    let col_users = CollectionUser::find_by_organization_swap_user_uuid_with_member_uuid(&org_id, &conn).await;
    // Generate a HashMap to get the correct MembershipType per user to determine the manage permission
    // We use the uuid instead of the user_uuid here, since that is what is used in CollectionUser
    // This lists other members for admins, so it must not depend on the membership status
    let membership_type: HashMap<MembershipId, i32> =
        Membership::find_by_org(&org_id, &conn).await.into_iter().map(|m| (m.uuid, m.atype)).collect();

    // check if current user has full access to the organization (either directly or via any group)
    let has_full_access_to_org = member.has_full_access()
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(&org_id, &member.uuid, &conn).await);

    let can_read_all_access_details = may_read_all_collections_with_access(&member);
    // Get all admins, owners and managers who can manage/access all.
    let manage_all_members = Membership::find_confirmed_and_manage_all_by_org(&org_id, &conn).await;

    let mut data = Vec::new();
    for col in Collection::find_by_organization(&org_id, &conn).await {
        // check whether the current user has access to the given collection
        let assigned = has_full_access_to_org
            || CollectionUser::has_access_to_collection_by_user(&col.uuid, &member.user_uuid, &conn).await
            || (CONFIG.org_groups_enabled()
                && GroupUser::has_access_to_collection_by_member(&col.uuid, &member.uuid, &conn).await);

        if !can_read_all_access_details && !can_read_collection_access(&member, &col.uuid, &conn).await {
            continue;
        }

        let collection_users: Vec<_> = col_users.iter().filter(|user| user.collection_uuid == col.uuid).collect();
        let stored_membership_ids: HashSet<_> = collection_users.iter().map(|user| &user.membership_uuid).collect();
        let mut users: Vec<Value> = collection_users
            .iter()
            .map(|collection_member| {
                collection_member.to_json_details_for_member(
                    *membership_type.get(&collection_member.membership_uuid).unwrap_or(&(MembershipType::User as i32)),
                )
            })
            .collect();
        users.extend(manage_all_members.iter().filter(|member| !stored_membership_ids.contains(&member.uuid)).map(
            |member| {
                json!({
                    "id": member.uuid,
                    "readOnly": false,
                    "hidePasswords": false,
                    "manage": true,
                })
            },
        ));

        let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
            CollectionGroup::find_by_collection(&col.uuid, &conn)
                .await
                .iter()
                .map(CollectionGroup::to_json_details_for_group)
                .collect()
        } else {
            Vec::new()
        };

        let mut json_object = col.to_json_details(&headers.user.uuid, None, &conn).await;
        json_object["assigned"] = json!(assigned);
        json_object["users"] = json!(users);
        json_object["groups"] = json!(groups);
        json_object["object"] = json!("collectionAccessDetails");
        json_object["unmanaged"] = json!(false);
        data.push(json_object);
    }

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })))
}

fn may_read_all_collections(member: &Membership) -> bool {
    member.has_full_access()
        || member.has_manage_groups()
        || member.has_delete_any_collection()
        || member.has_access_import_export()
}

fn may_read_all_collections_with_access(member: &Membership) -> bool {
    member.has_full_access()
        || member.has_delete_any_collection()
        || member.has_manage_users()
        || member.has_manage_groups()
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
async fn post_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // Create is independent from Edit/Delete. In particular, Edit any collection (full access to
    // every collection) must not implicitly grant this endpoint.
    if !headers.membership.can_create_new_collections() {
        err!("You don't have permission to create collections")
    }

    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    let collection = Collection::new(org_id.clone(), data.name, data.external_id);
    collection.save(&conn).await?;

    for group in data.groups {
        CollectionGroup::new(collection.uuid.clone(), group.id, group.read_only, group.hide_passwords, group.manage)
            .save(&org_id, &conn)
            .await?;
    }

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        CollectionUser::save(
            &member.user_uuid,
            &collection.uuid,
            user.read_only,
            user.hide_passwords,
            user.manage,
            &conn,
        )
        .await?;
    }

    log_event(
        EventType::CollectionCreated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(collection.to_json_details(&headers.membership.user_uuid, None, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionAccessData {
    collection_ids: Vec<CollectionId>,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
}

#[post("/organizations/<org_id>/collections/bulk-access", data = "<data>", rank = 1)]
async fn post_bulk_access_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionAccessData>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionAccessData = data.into_inner();

    for group in &data.groups {
        validate_collection_access(group.manage, group.read_only, group.hide_passwords)?;
    }
    for user in &data.users {
        validate_collection_access(user.manage, user.read_only, user.hide_passwords)?;
    }

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    // Security: authorization is per collection below, via `auth::can_modify_collection_access`, which
    // mirrors upstream authorizing this route against *both* `ModifyUserAccess` and `ModifyGroupAccess`:
    // the regular collection-update authorization (Owner/Admin, `Edit any collection`, or a real
    // per-collection Manage grant), or `Manage users` *and* `Manage groups` together. Group `access_all`
    // deliberately does not satisfy it (the previous `is_manageable_by_user` check accepted it, and
    // disagreed with the single-edit endpoint).

    // Upstream loads the collections with `GetManyByManyIdsAsync()` and compares the number of rows it
    // got back with the number of requested ids, so a repeated id fails the request; an empty list is
    // rejected by `BulkAddCollectionAccessCommand` ("No collections were provided.") and by the bulk
    // authorization handler, which fails on an empty resource set. Both are checked before anything is
    // read or written, so a rejected request mutates nothing and logs no event.
    if data.collection_ids.is_empty() {
        err!("No collections were provided")
    }
    if data.collection_ids.iter().collect::<HashSet<&CollectionId>>().len() != data.collection_ids.len() {
        err!("One or more collections not found", "The request contains duplicate collection ids")
    }

    // Security and atomicity: validate the whole request against this organization before mutating
    // anything — every collection, group and user must belong to it and be manageable by the caller.
    // Only then does the first write happen, so a foreign-tenant group can never be linked and a later
    // invalid element cannot leave earlier collections already changed.
    let org_groups = Group::find_by_organization(&org_id, &conn).await;
    let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|g| &g.uuid).collect();
    if let Some(g) = data.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
        err!("Invalid group", format!("Group {} does not belong to organization {}!", g.id, org_id))
    }
    for user in &data.users {
        if Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await.is_none() {
            err!("User is not part of organization")
        }
    }
    let mut collections = Vec::with_capacity(data.collection_ids.len());
    for col_id in &data.collection_ids {
        let Some(collection) = Collection::find_by_uuid_and_org(col_id, &org_id, &conn).await else {
            err!("Collection not found")
        };

        if !crate::auth::can_modify_collection_access(&headers.membership, &collection.uuid, &conn).await {
            err!("Collection not found", "The current user isn't allowed to modify this collection's access")
        }

        collections.push(collection);
    }

    for collection in collections {
        // update collection modification date
        collection.save(&conn).await?;

        log_event(
            EventType::CollectionUpdated,
            &collection.uuid,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;

        // Add/update, never replace: every assignment the request does not mention is left alone.
        for group in &data.groups {
            CollectionGroup::new(
                collection.uuid.clone(),
                group.id.clone(),
                group.read_only,
                group.hide_passwords,
                group.manage,
            )
            .save(&org_id, &conn)
            .await?;
        }

        for user in &data.users {
            let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
                err!("User is not part of organization")
            };

            CollectionUser::save(
                &member.user_uuid,
                &collection.uuid,
                user.read_only,
                user.hide_passwords,
                user.manage,
                &conn,
            )
            .await?;
        }
    }

    Ok(())
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn put_organization_collection_update(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    post_organization_collection_update(org_id, col_id, headers, data, conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>", rank = 2)]
async fn post_organization_collection_update(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    let Some(mut collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found")
    };

    collection.name = data.name;
    collection.external_id = match data.external_id {
        Some(external_id) if !external_id.trim().is_empty() => Some(external_id),
        _ => None,
    };

    collection.save(&conn).await?;

    log_event(
        EventType::CollectionUpdated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    CollectionGroup::delete_all_by_collection(&col_id, &org_id, &conn).await?;

    for group in data.groups {
        CollectionGroup::new(col_id.clone(), group.id, group.read_only, group.hide_passwords, group.manage)
            .save(&org_id, &conn)
            .await?;
    }

    CollectionUser::delete_all_by_collection(&col_id, &conn).await?;

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        CollectionUser::save(&member.user_uuid, &col_id, user.read_only, user.hide_passwords, user.manage, &conn)
            .await?;
    }

    Ok(Json(collection.to_json_details(&headers.user.uuid, None, &conn).await))
}

async fn delete_organization_collection_impl(
    org_id: &OrganizationId,
    col_id: &CollectionId,
    headers: &CollectionDeleteHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(collection) = Collection::find_by_uuid_and_org(col_id, org_id, conn).await else {
        err!("Collection not found", "Collection does not exist or does not belong to this organization")
    };
    log_event(
        EventType::CollectionDeleted,
        &collection.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
    collection.delete(conn).await
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
async fn delete_organization_collection(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionDeleteHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>/delete")]
async fn post_organization_collection_delete(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionDeleteHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionIds {
    ids: Vec<CollectionId>,
}

/// Upstream resolves a bulk delete through `GetManyByManyIdsAsync(model.Ids)` and then compares the
/// number of loaded collections against the number of requested ids, so a repeated id resolves to one
/// entity and fails that count check. Duplicates are therefore rejected instead of deduplicated.
/// An empty request is rejected as well: upstream's bulk authorization handler fails closed on an
/// empty resource set. Both checks run before the first deletion, so nothing is authorized, deleted
/// or logged for a rejected request.
fn bulk_delete_collection_targets(ids: Vec<CollectionId>) -> ApiResult<Vec<CollectionId>> {
    if ids.is_empty() {
        err!("No collections were provided")
    }
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        err!("Collection not found", "The request contains duplicate collection ids")
    }
    Ok(ids)
}

#[delete("/organizations/<org_id>/collections", data = "<data>")]
async fn bulk_delete_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionIds>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionIds = data.into_inner();

    let collections = bulk_delete_collection_targets(data.ids)?;

    // Full prevalidation (org scope and delete permission for every id) happens here, before the first
    // deletion: one foreign or unknown collection in the request means nothing is deleted at all.
    let headers = CollectionDeleteHeaders::from_loose(headers, &collections, &conn).await?;

    for col_id in collections {
        delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await?;
    }
    Ok(())
}

// Upstream guards this route with `BulkCollectionOperations.ReadWithAccess`, which — unlike the
// `ReadAccess` used by `/collections/<col_id>/users` below — also admits `Manage users`. Hence the
// route-specific `can_read_collection_with_access` instead of the general `CollectionReadHeaders`
// guard: extending that guard would have changed the `/users` endpoint along with it.
#[get("/organizations/<org_id>/collections/<col_id>/details")]
async fn get_org_collection_detail(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeadersLoose,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    match Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            // Authorize against the resolved collection, never against the request-supplied id.
            if !can_read_collection_with_access(&headers.membership, &collection.uuid, &conn).await {
                err!("Collection not found", "The current user isn't allowed to read this collection's access")
            }

            let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
                CollectionGroup::find_by_collection(&collection.uuid, &conn)
                    .await
                    .iter()
                    .map(CollectionGroup::to_json_details_for_group)
                    .collect()
            } else {
                // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
                // so just act as if there are no groups.
                Vec::new()
            };

            // Generate a HashMap to get the correct MembershipType per user to determine the manage permission
            // We use the uuid instead of the user_uuid here, since that is what is used in CollectionUser
            // This lists other members for admins, so it must not depend on the membership status
            let membership_type: HashMap<MembershipId, i32> =
                Membership::find_by_org(&org_id, &conn).await.into_iter().map(|m| (m.uuid, m.atype)).collect();

            let users: Vec<Value> =
                CollectionUser::find_by_org_and_coll_swap_user_uuid_with_member_uuid(&org_id, &collection.uuid, &conn)
                    .await
                    .iter()
                    .map(|collection_member| {
                        collection_member.to_json_details_for_member(
                            *membership_type
                                .get(&collection_member.membership_uuid)
                                .unwrap_or(&(MembershipType::User as i32)),
                        )
                    })
                    .collect();

            let assigned = Collection::can_access_collection(&headers.membership, &collection.uuid, &conn).await;

            let mut json_object = collection.to_json_details(&headers.user.uuid, None, &conn).await;
            json_object["assigned"] = json!(assigned);
            json_object["users"] = json!(users);
            json_object["groups"] = json!(groups);
            json_object["object"] = json!("collectionAccessDetails");

            Ok(Json(json_object))
        }
    }
}

#[get("/organizations/<org_id>/collections/<col_id>/users")]
async fn get_collection_users(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionReadHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    // Get org and collection, check that collection is from org
    let Some(collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found in Organization")
    };

    let mut member_list = Vec::new();
    for col_user in CollectionUser::find_by_collection(&collection.uuid, &conn).await {
        member_list.push(
            Membership::find_by_user_and_org(&col_user.user_uuid, &org_id, &conn)
                .await
                .unwrap()
                .to_json_user_access_restrictions(&col_user),
        );
    }

    Ok(Json(json!(member_list)))
}

#[derive(FromForm)]
struct OrgIdData {
    #[field(name = "organizationId")]
    organization_id: OrganizationId,
}

fn filter_ciphers_for_organization(ciphers: Vec<Cipher>, org_id: &OrganizationId) -> Vec<Cipher> {
    ciphers.into_iter().filter(|cipher| cipher.organization_uuid.as_ref() == Some(org_id)).collect()
}

// The Admin Console calls this when the acting member may not read every cipher: DeleteAnyCollection
// alone needs an empty successful response so the collection list can finish loading.
//
// Security: start from the regular user-visible cipher query and constrain it to the requested
// organization. DeleteAnyCollection must never make cipher contents visible.
#[get("/ciphers/organization-details/assigned?<data..>")]
async fn get_assigned_org_details(data: OrgIdData, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(membership) =
        Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &conn).await
    else {
        err_code!("Resource not found.", "User is not a confirmed member of the organization", Status::NotFound.code);
    };

    Ok(Json(json!({
        "data": assigned_org_ciphers_json(&membership, &headers.host, &conn).await?,
        "object": "list",
        "continuationToken": null,
    })))
}

// Serialize exactly the organization ciphers the user is actually assigned to, directly or via a group.
// `CipherSyncType::User` keeps the per-cipher access restrictions in place, so nothing outside the
// caller's own collections is returned and every cipher carries its real `edit`/`viewPassword` flags.
// NOTE: as everywhere else in Vaultwarden (and Bitwarden), `hidePasswords` is reported as
// `viewPassword: false` rather than redacted server-side, so this assigned portion matches what the
// same member receives from `/api/sync`.
//
// On top of that, upstream's `GetAssignedOrganizationCiphers` adds the organization's *unassigned*
// ciphers for the roles allowed to reach them (`CanAccessUnassignedCiphersAsync`: Owner/Admin, or a
// Custom member holding `Edit any collection`) -- which is exactly `Membership::has_full_access`. This
// is deliberately the only place that widens the scope: the regular `/api/sync` view stays as it is.
async fn assigned_org_ciphers_json(membership: &Membership, host: &str, conn: &DbConn) -> Result<Value, crate::Error> {
    let user_id = &membership.user_uuid;
    let org_id = &membership.org_uuid;

    let ciphers = filter_ciphers_for_organization(Cipher::find_by_user_visible(user_id, conn).await, org_id);
    let assigned: HashSet<CipherId> = ciphers.iter().map(|cipher| cipher.uuid.clone()).collect();

    let cipher_sync_data = CipherSyncData::new(user_id, CipherSyncType::User, conn).await;
    let mut ciphers_json = Vec::new();

    // Assigned ciphers keep the user's actual collection restrictions.
    for cipher in ciphers {
        ciphers_json.push(cipher.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::User, conn).await?);
    }

    // Bitwarden exposes unassigned ciphers with full edit/password access to
    // Owner/Admin and Custom members with EditAnyCollection.
    if membership.has_full_access() {
        for cipher in Cipher::find_unassigned_by_org(org_id, conn)
            .await
            .into_iter()
            .filter(|cipher| !assigned.contains(&cipher.uuid))
        {
            // Use Organization serialization here so the normal user-access
            // assertion is deliberately skipped for this already-authorized
            // special case. Add the user-specific fields below explicitly.
            let mut unassigned_cipher_json =
                cipher.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::Organization, conn).await?;

            unassigned_cipher_json["folderId"] = json!(cipher_sync_data.cipher_folders.get(&cipher.uuid).cloned());
            unassigned_cipher_json["favorite"] = json!(cipher_sync_data.cipher_favorites.contains(&cipher.uuid));
            unassigned_cipher_json["archivedDate"] = json!(
                cipher_sync_data
                    .cipher_archives
                    .get(&cipher.uuid)
                    .map_or(Value::Null, |date| Value::String(crate::util::format_date(date)))
            );

            unassigned_cipher_json["edit"] = json!(true);
            unassigned_cipher_json["viewPassword"] = json!(true);
            unassigned_cipher_json["permissions"] = json!({
                "delete": true,
                "restore": true,
            });

            ciphers_json.push(unassigned_cipher_json);
        }
    }

    Ok(Value::Array(ciphers_json))
}

// The organization cipher list the clients use for the admin vault view and for computing reports
// locally. Bitwarden grants the complete organization scope to AccessReports and AccessImportExport.
#[get("/ciphers/organization-details?<data..>")]
async fn get_org_details(data: OrgIdData, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if data.organization_id != headers.membership.org_uuid {
        err_code!("Resource not found.", "Organization id's do not match", Status::NotFound.code);
    }

    let ciphers_json = match organization_report_scope(&headers.membership) {
        OrganizationReportScope::Complete => {
            get_org_details_impl(&data.organization_id, &headers.host, &headers.user.uuid, &conn).await?
        }
        OrganizationReportScope::Denied => {
            err_code!(
                "Resource not found.",
                "User does not have permission to read the organization ciphers",
                Status::NotFound.code
            );
        }
    };

    Ok(Json(json!({
        "data": ciphers_json,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn get_org_details_impl(
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    ciphers_to_org_json(Cipher::find_by_org(org_id, conn).await, org_id, host, user_id, conn).await
}

// Serialize an already-authorized set of organization ciphers. The caller decides which ciphers go
// in: `CipherSyncType::Organization` skips the per-cipher access restrictions, so this must never be
// handed a cipher the user is not allowed to see.
async fn ciphers_to_org_json(
    ciphers: Vec<Cipher>,
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let mut cipher_sync_data = CipherSyncData::new(user_id, CipherSyncType::Organization, conn).await;
    cipher_sync_data.cipher_collections =
        index_cipher_collections(Cipher::get_collections_with_cipher_by_organization(org_id, conn).await);

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(c.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::Organization, conn).await?);
    }
    Ok(json!(ciphers_json))
}

fn index_cipher_collections(relations: Vec<(CipherId, CollectionId)>) -> HashMap<CipherId, Vec<CollectionId>> {
    relations.into_iter().fold(HashMap::new(), |mut indexed, (cipher_id, collection_id)| {
        indexed.entry(cipher_id).or_default().push(collection_id);
        indexed
    })
}

// Returning a Domain/Organization here allow to prefill it and prevent prompting the user
// So we return a dummy value, since we only support a single SSO integration, and do not use the response anywhere
// In use since `v2025.6.0`, appears to use only the first `organizationIdentifier`
#[post("/organizations/domain/sso/verified")]
fn get_org_domain_sso_verified() -> JsonResult {
    // Always return a dummy value, no matter if SSO is enabled or not
    Ok(Json(json!({
        "object": "list",
        "data": [{
            "organizationIdentifier": FAKE_SSO_IDENTIFIER,
            // These appear to be unused
            "organizationName": FAKE_SSO_IDENTIFIER,
            "domainName": CONFIG.domain()
        }],
        "continuationToken": null
    })))
}

#[derive(FromForm)]
struct GetOrgUserData {
    #[field(name = "includeCollections")]
    include_collections: Option<bool>,
    #[field(name = "includeGroups")]
    include_groups: Option<bool>,
}

#[get("/organizations/<org_id>/users?<data..>")]
async fn get_members(
    data: GetOrgUserData,
    org_id: OrganizationId,
    // Security (audit M-1): the full member list exposes each member's PII, 2FA/enrollment status,
    // permission flags and (optionally) collection/group assignments. Reading it requires the
    // 'Manage Users' permission (or Admin/Owner), matching Bitwarden. Members who only need to
    // reference other users (e.g. the collection dialog) use the member-readable mini-details.
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let mut users_json = Vec::new();
    for u in Membership::find_by_org(&org_id, &conn).await {
        // The user can be a manager instead of an admin, but we've checked above that they have full access
        users_json.push(
            u.to_json_details_for_admin(
                data.include_collections.unwrap_or(false),
                data.include_groups.unwrap_or(false),
                &conn,
            )
            .await,
        );
    }

    Ok(Json(json!({
        "data": users_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[post("/organizations/<org_id>/keys", data = "<data>")]
async fn post_org_keys(
    org_id: OrganizationId,
    data: Json<OrgKeyData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: OrgKeyData = data.into_inner();

    let mut org = if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        if organization.private_key.is_some() && organization.public_key.is_some() {
            err!("Organization Keys already exist")
        }
        organization
    } else {
        err!("Can't find organization details")
    };

    org.private_key = Some(data.encrypted_private_key);
    org.public_key = Some(data.public_key);

    org.save(&conn).await?;

    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": org.public_key,
        "privateKey": org.private_key,
    })))
}

// Struct, parser, subset check and writer are all expanded from the single permission list in
// `db::models::organization`, so they cannot list different sets of permissions.
macro_rules! define_custom_role_permissions {
    ($($field:ident, $json_key:literal, $accessor:ident);* $(;)?) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        // This is intentionally a permission bitmap: every field represents an independent API grant.
        #[allow(clippy::struct_excessive_bools)]
        struct CustomRolePermissions {
            $( $field: bool, )*
        }

        impl CustomRolePermissions {
            /// Type-check and read every known permission key. See [`Self::read_known`].
            fn parse(permissions: &HashMap<String, Value>) -> Result<Self, crate::Error> {
                Ok(Self {
                    $( $field: Self::read_known(permissions, $json_key)?, )*
                })
            }

            /// The permissions a membership currently holds, as stored.
            fn from_membership(membership: &Membership) -> Self {
                Self {
                    $( $field: membership.$field, )*
                }
            }

            /// Whether every requested permission is one the caller holds themselves. The accessors are
            /// type-gated, so a stale flag on a non-Custom caller never delegates anything.
            fn is_subset_of(self, caller: &Membership) -> bool {
                $( (!self.$field || caller.$accessor()) )&&*
            }

            fn apply_to(self, membership: &mut Membership) {
                $( membership.$field = self.$field; )*
            }
        }
    };
}
custom_role_permissions!(define_custom_role_permissions);

impl CustomRolePermissions {
    /// Read one known permission key.
    ///
    /// An absent key is `false`: the object is the complete set the caller wants. A key that *is* present
    /// must be a JSON boolean — treating `"true"`, `1` or `null` as "not `Value::Bool(true)`" turned a
    /// malformed request into a silent permission *removal* that still answered 200.
    fn read_known(permissions: &HashMap<String, Value>, key: &str) -> Result<bool, crate::Error> {
        match permissions.get(key) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(other) => {
                let found = match other {
                    Value::Null => "null",
                    Value::String(_) => "a string",
                    Value::Number(_) => "a number",
                    Value::Array(_) => "an array",
                    Value::Object(_) => "an object",
                    Value::Bool(_) => unreachable!("booleans are handled above"),
                };
                err!(format!("Invalid permissions: '{key}' must be true or false, but is {found}"))
            }
        }
    }

    /// Parse a permissions object.
    ///
    /// Every known key is type-checked even when the role makes the flags inert, so a malformed request is
    /// rejected identically whatever role it names, and always before anything is mutated. Unknown keys are
    /// ignored: Bitwarden sends `manageSso`, `manageScim` and `manageResetPassword`, and rejecting them
    /// would break clients over permissions Vaultwarden does not implement.
    fn from_request(member_type: MembershipType, permissions: &HashMap<String, Value>) -> Result<Self, crate::Error> {
        let parsed = Self::parse(permissions)?;

        if member_type == MembershipType::Custom {
            Ok(parsed)
        } else {
            Ok(Self::default())
        }
    }

    /// Parse permissions for an existing member without treating an omitted permissions object as
    /// an instruction to clear every Custom-role grant. Older clients send legacy role value `3`
    /// without the modern object; that value is normalized to Custom for compatibility.
    fn from_edit_request(
        member_type: MembershipType,
        permissions: Option<&HashMap<String, Value>>,
        membership: &Membership,
    ) -> Result<Self, crate::Error> {
        Ok(match permissions {
            Some(permissions) => Self::from_request(member_type, permissions)?,
            None if member_type == MembershipType::Custom && membership.atype == MembershipType::Custom as i32 => {
                Self::from_membership(membership)
            }
            None => Self::default(),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    emails: Vec<String>,
    groups: Vec<GroupId>,
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
}

impl InviteData {
    async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in self.collections.iter().flatten() {
            validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
        }

        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().flatten().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(g)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e, org_id))
        }

        Ok(())
    }
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
async fn send_invite(
    org_id: OrganizationId,
    data: Json<InviteData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: InviteData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    let raw_type = &data.r#type.into_string();
    let Some(new_type) = MembershipType::from_str(raw_type) else {
        err!("Invalid type")
    };

    if !may_provision_member_type(headers.membership_type, new_type) {
        err!("You don't have permission to invite this role")
    }

    // manageAllCollections is a client-only aggregate; its three children are persisted independently.
    // Parsed and type-checked before the loop below creates any user, invitation or membership, so a
    // malformed value leaves nothing behind.
    let custom_permissions = CustomRolePermissions::from_request(new_type, &data.permissions)?;

    if !may_grant_custom_permissions(&headers.membership, new_type, Some(custom_permissions)) {
        err!("Custom users can only grant the same custom permissions that they have")
    }

    if headers.membership_type == MembershipType::Custom {
        for group_id in &data.groups {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_some_and(|group| group.access_all) {
                err!("Only Admins and Owners can add a member to a legacy access-all group")
            }
        }
    }

    let mut user_created: bool;
    for email in &data.emails {
        let mut member_status = MembershipStatus::Invited as i32;
        let user = match User::find_by_mail(email, &conn).await {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {email}"))
                }

                if !CONFIG.is_email_domain_allowed(email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    Invitation::new(email).save(&conn).await?;
                }

                let mut new_user = User::new(email, None);
                new_user.save(&conn).await?;
                user_created = true;
                new_user
            }
            Some(user) => {
                if Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
                    err!(format!("User already in organization: {email}"))
                }

                if !CONFIG.mail_enabled() {
                    if user.password_hash.is_empty() {
                        Invitation::new(email).save(&conn).await?;
                    } else {
                        // automatically accept existing users if mail is disabled
                        member_status = MembershipStatus::Accepted as i32;
                    }
                }
                user_created = false;
                user
            }
        };

        let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(headers.user.email.clone()));
        new_member.atype = new_type as i32;
        custom_permissions.apply_to(&mut new_member);
        new_member.status = member_status;
        new_member.save(&conn).await?;

        if CONFIG.mail_enabled() {
            let org_name = if let Some(org) = Organization::find_by_uuid(&org_id, &conn).await {
                org.name
            } else {
                err!("Error looking up organization")
            };

            if let Err(e) = mail::send_invite(
                &user,
                org_id.clone(),
                new_member.uuid.clone(),
                &org_name,
                Some(headers.user.email.clone()),
            )
            .await
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

        log_event(
            EventType::OrganizationUserInvited,
            &new_member.uuid,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;

        for col in data.collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser::save(
                        &user.uuid,
                        &collection.uuid,
                        col.read_only,
                        col.hide_passwords,
                        col.manage,
                        &conn,
                    )
                    .await?;
                }
            }
        }

        for group_id in &data.groups {
            let mut group_entry = GroupUser::new(group_id.clone(), new_member.uuid.clone());
            group_entry.save(&conn).await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/reinvite", data = "<data>")]
async fn bulk_reinvite_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match reinvite_member_impl(&org_id, &member_id, &headers, &conn).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/reinvite")]
async fn reinvite_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    reinvite_member_impl(&org_id, &member_id, &headers, &conn).await
}

/// Reinvite and confirm are guarded by `ManageUsersRequirement` alone upstream — neither
/// `ResendOrganizationInviteCommand` nor `ConfirmOrganizationUserCommand` consults the acting member's
/// role against the target's. Neither action can change a role, so the actor/target matrix that
/// update, remove, revoke and restore still enforce does not apply here.
async fn reinvite_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    let Some(member) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The user hasn't been invited to the organization.")
    };

    if member.status != MembershipStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
        err!("User not found.")
    };

    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err!("Invitations are not allowed.")
    }

    let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
        org.name
    } else {
        err!("Error looking up organization.")
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(&user, org_id.clone(), member.uuid, &org_name, Some(headers.user.email.clone())).await?;
    } else if user.password_hash.is_empty() {
        let invitation = Invitation::new(&user.email);
        invitation.save(conn).await?;
    } else {
        Invitation::take(&user.email, conn).await;
        let mut member = member;
        member.status = MembershipStatus::Accepted as i32;
        member.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

#[post("/organizations/<org_id>/users/<member_id>/accept", data = "<data>")]
async fn accept_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<AcceptData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    // The web-vault passes org_id and member_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner();
    let claims = decode_invite(&data.token)?;

    // Don't allow other users from accepting an invitation.
    if !claims.email.eq(&headers.user.email) {
        err!("Invitation was issued to a different account", "Claim does not match user_id")
    }

    // If a claim org_id does not match the one in from the URI, something is wrong.
    if !claims.org_id.eq(&org_id) {
        err!("Error accepting the invitation", "Claim does not match the org_id")
    }

    // If a claim does not have a member_id or it does not match the one in from the URI, something is wrong.
    if !claims.member_id.eq(&member_id) {
        err!("Error accepting the invitation", "Claim does not match the member_id")
    }

    let member_id = &claims.member_id;
    Invitation::take(&claims.email, &conn).await;

    // skip invitation logic when we were invited via the /admin panel
    if **member_id != FAKE_ADMIN_UUID {
        let Some(mut membership) = Membership::find_by_uuid_and_org(member_id, &claims.org_id, &conn).await else {
            err!("Error accepting the invitation")
        };

        let reset_password_key = match OrgPolicy::org_is_reset_password_auto_enroll(&membership.org_uuid, &conn).await {
            true if data.reset_password_key.is_none() => err!("Reset password key is required, but not provided."),
            true => data.reset_password_key,
            false => None,
        };

        // In case the user was invited before the mail was saved in db.
        membership.invited_by_email = membership.invited_by_email.or(claims.invited_by_email);

        accept_org_invite(&headers.user, membership, reset_password_key, &conn).await?;
    } else if CONFIG.mail_enabled() {
        // User was invited from /admin, so they are automatically confirmed
        let org_name = CONFIG.invitation_org_name();
        mail::send_invite_confirmed(&claims.email, &org_name).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    id: Option<MembershipId>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

#[post("/organizations/<org_id>/users/confirm", data = "<data>")]
async fn bulk_confirm_invite(
    org_id: OrganizationId,
    data: Json<BulkConfirmData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.keys {
        Some(keys) => {
            for invite in keys {
                // The id is request-controlled and optional. Unwrapping it aborted the worker with a 500 and, because
                // the panic unwound mid-loop, discarded the response for every entry already confirmed in the same
                // batch. Report it as a per-entry error, like an id that is present but empty.
                let Some(member_id) = invite.id else {
                    bulk_response.push(json!(
                        {
                            "object": "OrganizationBulkConfirmResponseModel",
                            "id": null,
                            "error": "Key or UserId is not set, unable to process request"
                        }
                    ));
                    continue;
                };
                let user_key = invite.key.unwrap_or_default();
                let err_msg = match confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationBulkConfirmResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/confirm", data = "<data>")]
async fn confirm_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<ConfirmData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let user_key = data.key.unwrap_or_default();
    confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await
}

async fn confirm_invite_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    key: &str,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if key.is_empty() || member_id.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let Some(mut member_to_confirm) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The specified user isn't a member of the organization")
    };

    if member_to_confirm.status != MembershipStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    member_to_confirm.status = MembershipStatus::Confirmed as i32;
    member_to_confirm.akey = key.to_owned();

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    OrgPolicy::check_user_allowed(&member_to_confirm, "confirm", conn).await?;

    log_event(
        EventType::OrganizationUserConfirmed,
        &member_to_confirm.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled() {
        let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
            org.name
        } else {
            err!("Error looking up organization.")
        };
        let address = if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
            user.email
        } else {
            err!("Error looking up user.")
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    let save_result = member_to_confirm.save(conn).await;

    if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;
    }

    save_result
}

// Organization user mini-details are available to every confirmed organization member, matching
// upstream's `MemberOrProvider` authorization for this route. That broadens metadata visibility (id,
// user id, name, email, membership type, status) compared with Vaultwarden's previous Manager-only
// behaviour, and is intentional: a broad range of client flows depends on basic member lookups.
#[get("/organizations/<org_id>/users/mini-details", rank = 1)]
async fn get_org_user_mini_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let mut members_json = Vec::new();
    for m in Membership::find_by_org(&org_id, &conn).await {
        members_json.push(m.to_json_mini_details(&conn).await);
    }

    Ok(Json(json!({
        "data": members_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/users/<member_id>?<data..>", rank = 2)]
async fn get_user(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: GetOrgUserData,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(user) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't a member of the organization")
    };

    // In this case, when groups are requested we also need to include collections.
    // Else these will not be shown in the interface, and could lead to missing collections when saved.
    let include_groups = data.include_groups.unwrap_or(false);
    Ok(Json(
        user.to_json_details_for_admin(data.include_collections.unwrap_or(include_groups), include_groups, &conn).await,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditUserData {
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    groups: Option<Vec<GroupId>>,
    permissions: Option<HashMap<String, Value>>,
}

#[put("/organizations/<org_id>/users/<member_id>", data = "<data>", rank = 1)]
async fn put_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<EditUserData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    edit_member(org_id, member_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/users/<member_id>", data = "<data>", rank = 1)]
async fn edit_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<EditUserData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: EditUserData = data.into_inner();
    for collection in data.collections.iter().flatten() {
        validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
    }

    let raw_type = &data.r#type.into_string();
    let Some(new_type) = MembershipType::from_str(raw_type) else {
        err!("Invalid type")
    };

    let Some(mut member_to_edit) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't member of the organization")
    };

    // Parsed (and type-checked) here, long before the write phase further down, so a malformed
    // permission value leaves the role, the permission flags, the collection assignments and the
    // group memberships exactly as they were.
    let custom_permissions =
        CustomRolePermissions::from_edit_request(new_type, data.permissions.as_ref(), &member_to_edit)?;
    let requested_custom_permissions = data.permissions.as_ref().map(|_| custom_permissions);
    if !may_change_member_type(headers.membership_type, member_to_edit.atype, new_type) {
        err!("You don't have permission to manage the current or requested member role")
    }

    if member_to_edit.atype == MembershipType::Owner
        && new_type != MembershipType::Owner
        && member_to_edit.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner permission, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    if !may_grant_custom_permissions(&headers.membership, new_type, requested_custom_permissions) {
        err!("Custom users can only grant the same custom permissions that they have")
    }

    custom_permissions.apply_to(&mut member_to_edit);
    member_to_edit.atype = new_type as i32;

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    // We need to perform the check after changing the type since `admin` is exempt.
    OrgPolicy::check_user_allowed(&member_to_edit, "modify", &conn).await?;

    let mut collection_assignments: Vec<(CollectionId, bool, bool, bool)> = Vec::new();
    for col in data.collections.iter().flatten() {
        let Some(collection) = Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await else {
            err!("Collection not found in Organization")
        };
        collection_assignments.push((collection.uuid, col.read_only, col.hide_passwords, col.manage));
    }

    for group_id in data.groups.iter().flatten() {
        if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_none() {
            err!("Group not found in this organization")
        }
    }

    if headers.membership_type == MembershipType::Custom {
        let current_groups: HashSet<GroupId> = GroupUser::find_by_member(&member_to_edit.uuid, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.groups_uuid)
            .collect();
        for group_id in data.groups.iter().flatten().filter(|group_id| !current_groups.contains(*group_id)) {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_some_and(|group| group.access_all) {
                err!("Only Admins and Owners can add a member to a legacy access-all group")
            }
        }
    }

    for collection_user in
        CollectionUser::find_by_organization_and_user_uuid(&org_id, &member_to_edit.user_uuid, &conn).await
    {
        collection_user.delete(&conn).await?;
    }
    for (collection_id, read_only, hide_passwords, manage) in collection_assignments {
        CollectionUser::save(&member_to_edit.user_uuid, &collection_id, read_only, hide_passwords, manage, &conn)
            .await?;
    }

    GroupUser::delete_all_by_member(&member_to_edit.uuid, &conn).await?;
    for group_id in data.groups.iter().flatten() {
        let mut group_entry = GroupUser::new(group_id.clone(), member_to_edit.uuid.clone());
        group_entry.save(&conn).await?;
    }

    log_event(
        EventType::OrganizationUserUpdated,
        &member_to_edit.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    member_to_edit.save(&conn).await
}

#[delete("/organizations/<org_id>/users", data = "<data>")]
async fn bulk_delete_member(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[delete("/organizations/<org_id>/users/<member_id>")]
async fn delete_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await
}

async fn delete_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(member_to_delete) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("User to delete isn't member of the organization")
    };

    if !may_delete_stored_member_type(headers.membership_type, member_to_delete.atype) {
        err!("You don't have permission to delete this user")
    }

    if member_to_delete.atype == MembershipType::Owner && member_to_delete.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    log_event(
        EventType::OrganizationUserRemoved,
        &member_to_delete.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if let Some(user) = User::find_by_uuid(&member_to_delete.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;

        if !CONFIG.mail_enabled()
            && !Membership::find_invited_by_user(&user.uuid, conn)
                .await
                .into_iter()
                .any(|m| m.uuid != member_to_delete.uuid)
        {
            Invitation::take(&user.email, conn).await;
        }
    }

    member_to_delete.delete(conn).await
}

#[post("/organizations/<org_id>/users/public-keys", data = "<data>")]
async fn bulk_public_keys(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    // Check all received Membership UUID's and find the matching User to retrieve the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that Membership UUID.
    // The web-vault will then ignore that user for the following steps.
    for member_id in data.ids {
        match Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await {
            Some(member) => match User::find_by_uuid(&member.user_uuid, &conn).await {
                Some(user) => bulk_response.push(json!(
                    {
                        "object": "organizationUserPublicKeyResponseModel",
                        "id": member_id,
                        "userId": user.uuid,
                        "key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("Membership doesn't exist"),
        }
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

use super::ciphers::{CipherData, CipherUpdateAuthorization, update_cipher_from_data};

// The import endpoint only ever uses the name/id/external_id of a collection.
// Bitwarden's own server ignores `groups`/`users` here too, so do not make them
// mandatory: clients are free to leave them out.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportCollectionData {
    name: String,
    id: Option<CollectionId>,
    external_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportData {
    ciphers: Vec<CipherData>,
    collections: Vec<ImportCollectionData>,
    collection_relationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelationsData {
    // Cipher index
    key: usize,
    // Collection index
    value: usize,
}

// https://github.com/bitwarden/server/blob/e8afc9eb63901402fd160198e70eb865e011144a/src/Api/Tools/Controllers/ImportCiphersController.cs
#[post("/ciphers/import-organization?<query..>", data = "<data>")]
async fn post_org_import(
    query: OrgIdData,
    data: Json<ImportData>,
    headers: OrgMemberHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let org_id = query.organization_id;
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    // AccessImportExport authorizes the complete organization import. Other confirmed members keep
    // the regular per-target Create/Update authorization.
    if !headers.membership.has_status(MembershipStatus::Confirmed) {
        err!("You need to be a confirmed member of this organization to import into it")
    }
    let organization_write_authorized = may_access_import_export(&headers.membership);

    let data: ImportData = data.into_inner();
    if data.collections.is_empty() && !organization_write_authorized {
        err!("Not enough privileges to import into this organization")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    // Robustness: validate every collection<->cipher relationship index against the payload *before*
    // creating anything. `key` indexes into `ciphers` and `value` into `collections`, and an out-of-range
    // index would otherwise panic when the relations are applied — after rows have already been written.
    let import_cipher_count = data.ciphers.len();
    let import_collection_count = data.collections.len();
    for relation in &data.collection_relationships {
        if relation.key >= import_cipher_count || relation.value >= import_collection_count {
            err!(
                "Invalid collection relationship",
                "A collection relationship references a non-existent cipher or collection"
            )
        }
    }

    // Security: index the existing collections by id so the per-collection authorization below can run
    // the collection-*update* predicate `auth::can_edit_collection` on them. Upstream resolves
    // `BulkCollectionOperations.ImportCiphers` through the very same `CanUpdateCollectionAsync` as a
    // collection update, so importing into an existing collection needs Owner/Admin, `Edit any
    // collection` or a real per-collection Manage grant. A plain write assignment
    // (`readOnly = false`, `manage = false`) is deliberately *not* enough — the previous
    // `is_writable_by_user` check accepted it and was more permissive than upstream.
    let existing_collections: HashMap<CollectionId, Collection> =
        Collection::find_by_organization(&org_id, &conn).await.into_iter().map(|c| (c.uuid.clone(), c)).collect();

    // Finish every request-controlled collection authorization check before the first new collection
    // is written. This matters for the PR's create-only Custom role: a payload may name a new
    // collection first and an existing, unauthorized collection later. Rejecting the latter only in
    // the write loop left the former behind even though the request failed.
    for col in &data.collections {
        if let Some(collection) = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id)) {
            let can_update = crate::auth::can_edit_collection(&headers.membership, &collection.uuid, &conn).await;
            if !may_import_to_collection(
                &headers.membership,
                OrganizationImportTarget::Existing {
                    can_update,
                },
            ) {
                err!(Compact, "The current user isn't allowed to manage this collection")
            }
        } else if !may_import_to_collection(&headers.membership, OrganizationImportTarget::New) {
            err!(Compact, "The current user isn't allowed to create new collections")
        }
    }

    let mut collections: Vec<CollectionId> = Vec::with_capacity(data.collections.len());
    for col in data.collections {
        let existing = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id));
        let collection_uuid = if let Some(collection) = existing {
            collection.uuid.clone()
        } else {
            let new_collection = Collection::new(org_id.clone(), col.name, col.external_id);
            new_collection.save(&conn).await?;
            // Import-created collections do not carry the regular create endpoint's user access
            // selections. Give a create-only importer Manage access to the collection they just
            // created, matching Bitwarden's organization-import behavior.
            if !headers.membership.has_full_access() {
                CollectionUser::save(&headers.membership.user_uuid, &new_collection.uuid, false, false, true, &conn)
                    .await?;
            }
            new_collection.uuid
        };

        collections.push(collection_uuid);
    }

    // Read the relations between collections and ciphers
    // Ciphers can be in multiple collections at the same time
    let mut relations = Vec::with_capacity(data.collection_relationships.len());
    for relation in data.collection_relationships {
        relations.push((relation.key, relation.value));
    }

    let headers: Headers = headers.into();

    let mut ciphers: Vec<CipherId> = Vec::with_capacity(data.ciphers.len());
    for mut cipher_data in data.ciphers {
        // Always clear folder_id's via an organization import
        cipher_data.folder_id = None;
        // Replace the client-provided, unvalidated organizationId with the real target org
        cipher_data.organization_id = Some(org_id.clone());
        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        update_cipher_from_data(
            &mut cipher,
            cipher_data,
            &headers,
            CipherUpdateAuthorization::organization_import(collections.clone(), organization_write_authorized),
            &conn,
            &nt,
            UpdateType::None,
        )
        .await?;
        ciphers.push(cipher.uuid);
    }

    // Assign the collections. Indices were bounds-validated above, but use `.get()` here as well so
    // any future drift fails closed with an error instead of panicking.
    for (cipher_index, col_index) in relations {
        let (Some(cipher_id), Some(col_id)) = (ciphers.get(cipher_index), collections.get(col_index)) else {
            err!(Compact, "Invalid collection relationship")
        };
        CollectionCipher::save(cipher_id, col_id, &conn).await?;
    }

    let mut user = headers.user;
    user.update_revision(&conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionsData {
    organization_id: OrganizationId,
    cipher_ids: Vec<CipherId>,
    collection_ids: HashSet<CollectionId>,
    remove_collections: bool,
}

// This endpoint is only reachable via the organization view, therefore this endpoint is located here
// Also Bitwarden does not send out Notifications for these changes, it only does this for individual cipher collection updates
#[post("/ciphers/bulk-collections", data = "<data>")]
async fn post_bulk_collections(data: Json<BulkCollectionsData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: BulkCollectionsData = data.into_inner();

    if Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &conn).await.is_none() {
        err!("You need to be a Member of the Organization to call this endpoint")
    }

    // Get all the collection available to the user in one query
    // Also filter based upon the provided collections
    let user_collections: HashMap<CollectionId, Collection> =
        Collection::find_by_organization_and_user_uuid(&data.organization_id, &headers.user.uuid, &conn)
            .await
            .into_iter()
            .filter_map(|c| {
                if data.collection_ids.contains(&c.uuid) {
                    Some((c.uuid.clone(), c))
                } else {
                    None
                }
            })
            .collect();

    // Verify if all the collections requested exists and are writable for the user, else abort
    for collection_uuid in &data.collection_ids {
        match user_collections.get(collection_uuid) {
            Some(collection) if collection.is_writable_by_user(&headers.user.uuid, &conn).await => (),
            _ => err_code!("Resource not found", "User does not have access to a collection", 404),
        }
    }

    for cipher_id in &data.cipher_ids {
        // Only act on existing cipher uuid's
        // Do not abort the operation just ignore it, it could be a cipher was just deleted for example
        //
        // Upstream authorizes this route with `CanModifyCipherCollectionsAsync`, which resolves
        // through `CanEditAllCiphersAsync` -- so a member with organization-wide cipher authority
        // reaches every cipher of the organization here, exactly as the collection half above
        // already does.
        if let Some(cipher) = Cipher::find_by_uuid_and_org(cipher_id, &data.organization_id, &conn).await
            && cipher.is_write_accessible_to_user(&headers.user.uuid, CipherAccessScope::OrganizationAdmin, &conn).await
        {
            // When selecting a specific collection from the left filter list, and use the bulk option, you can remove an item from that collection
            // In these cases the client will call this endpoint twice, once for adding the new collections and a second for deleting.
            if data.remove_collections {
                for collection in &data.collection_ids {
                    CollectionCipher::delete(&cipher.uuid, collection, &conn).await?;
                }
            } else {
                for collection in &data.collection_ids {
                    CollectionCipher::save(&cipher.uuid, collection, &conn).await?;
                }
            }
        }
    }

    Ok(())
}

// `ManagePoliciesRequirement` upstream, exactly as the single-policy route below: a member without the
// permission is refused rather than served an empty list. Policy *enforcement* is unaffected — holding
// `managePolicies` does not make a Custom member exempt from any policy.
#[get("/organizations/<org_id>/policies")]
async fn list_policies(org_id: OrganizationId, headers: ManagePoliciesHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let policies_json: Vec<Value> =
        OrgPolicy::find_by_org(&org_id, &conn).await.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
async fn list_policies_token(org_id: OrganizationId, token: &str, conn: DbConn) -> JsonResult {
    let invite = decode_invite(token)?;

    if invite.org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // exit early when we have been invited via /admin panel
    if org_id.as_ref() == FAKE_ADMIN_UUID {
        return Ok(Json(json!({})));
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

// Called during the SSO enrollment return the default policy
#[get("/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password", rank = 1)]
fn get_dummy_master_password_policy() -> JsonResult {
    let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
        Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
        _ => (false, "null".to_owned()),
    };
    let policy = OrgPolicy::new(FAKE_SSO_IDENTIFIER.into(), OrgPolicyType::MasterPassword, enabled, data);
    Ok(Json(policy.to_json()))
}

// Called during the SSO enrollment return the org policy if it exists
#[get("/organizations/<org_id>/policies/master-password", rank = 2)]
async fn get_master_password_policy(org_id: OrganizationId, _headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    let policy =
        OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::MasterPassword, &conn).await.unwrap_or_else(|| {
            let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
                Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
                _ => (false, "null".to_owned()),
            };

            OrgPolicy::new(org_id, OrgPolicyType::MasterPassword, enabled, data)
        });

    Ok(Json(policy.to_json()))
}

#[get("/organizations/<org_id>/policies/<pol_type>", rank = 3)]
async fn get_policy(org_id: OrganizationId, pol_type: i32, headers: ManagePoliciesHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    let policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "null".to_owned()),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    data: Option<Value>,
}

#[derive(Deserialize)]
struct PutPolicy {
    policy: PolicyData,
    // Ignore metadata for now as we do not yet support this
    // "metadata": {
    //     "defaultUserCollectionName": "2.xx|xx==|xx="
    // }
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
async fn put_policy(
    org_id: OrganizationId,
    pol_type: i32,
    data: Json<PutPolicy>,
    headers: ManagePoliciesHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PolicyData = data.into_inner().policy;

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    // Bitwarden only allows the Reset Password policy when Single Org policy is enabled
    // Vaultwarden encouraged to use multiple orgs instead of groups because groups were not available in the past
    // Now that groups are available we can enforce this option when wanted.
    // We put this behind a config option to prevent breaking current installation.
    // Maybe we want to enable this by default in the future, but currently it is disabled by default.
    if CONFIG.enforce_single_org_with_reset_pw_policy() {
        if pol_type_enum == OrgPolicyType::ResetPassword && data.enabled {
            let single_org_policy_enabled =
                match OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::SingleOrg, &conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if !single_org_policy_enabled {
                err!("Single Organization policy is not enabled. It is mandatory for this policy to be enabled.")
            }
        }

        // Also prevent the Single Org Policy to be disabled if the Reset Password policy is enabled
        if pol_type_enum == OrgPolicyType::SingleOrg && !data.enabled {
            let reset_pw_policy_enabled =
                match OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::ResetPassword, &conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if reset_pw_policy_enabled {
                err!("Account recovery policy is enabled. It is not allowed to disable this policy.")
            }
        }
    }

    // When enabling the TwoFactorAuthentication policy, revoke all members that do not have 2FA
    if pol_type_enum == OrgPolicyType::TwoFactorAuthentication && data.enabled {
        two_factor::enforce_2fa_policy_for_org(
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await?;
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type_enum == OrgPolicyType::SingleOrg && data.enabled {
        for mut member in Membership::find_by_org(&org_id, &conn).await {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org,
            // and never to the member enabling it -- see `Membership::is_policy_enforcement_target`.
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            if member.is_policy_enforcement_target(&headers.user.uuid)
                && member.status != MembershipStatus::Invited as i32
                && Membership::count_accepted_and_confirmed_by_user(&member.user_uuid, &member.org_uuid, &conn).await
                    > 0
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, &conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, &conn).await.unwrap();

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(
                    EventType::OrganizationUserRemoved,
                    &member.uuid,
                    &org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    &conn,
                )
                .await;

                member.revoke();
                member.save(&conn).await?;
            }
        }
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "{}".to_owned()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(&conn).await?;

    log_event(
        EventType::PolicyUpdated,
        policy.uuid.as_ref(),
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(policy.to_json()))
}

// Deprecated with client v2026.5.0
#[put("/organizations/<org_id>/policies/<pol_type>/vnext", data = "<data>")]
async fn put_policy_vnext(
    org_id: OrganizationId,
    pol_type: i32,
    data: Json<PutPolicy>,
    headers: ManagePoliciesHeaders,
    conn: DbConn,
) -> JsonResult {
    put_policy(org_id, pol_type, data, headers, conn).await
}

#[get("/plans")]
fn get_plans() -> Json<Value> {
    // Respond with a minimal json just enough to allow the creation of an new organization.
    Json(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        },{
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

#[get("/organizations/<_org_id>/billing/metadata")]
fn get_billing_metadata(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(empty_data_json())
}

#[get("/organizations/<_org_id>/billing/vnext/warnings")]
fn get_billing_warnings(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    Json(json!({
        "freeTrial":null,
        "inactiveSubscription":null,
        "resellerRenewal":null,
        "taxId":null,
    }))
}

#[get("/organizations/<_org_id>/billing/vnext/self-host/metadata")]
fn get_self_host_billing_metadata(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(json!({
        "isOnSecretsManagerStandalone": false, // Secrets Manager is not supported by Vaultwarden
        "organizationOccupiedSeats": 0 // Vaultwarden does not count seats
    }))
}

fn empty_data_json() -> Value {
    json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkRevokeMembershipIds {
    ids: Option<Vec<MembershipId>>,
}

#[put("/organizations/<org_id>/users/<member_id>/revoke")]
async fn revoke_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    revoke_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/revoke", data = "<data>")]
async fn bulk_revoke_members(
    org_id: OrganizationId,
    data: Json<BulkRevokeMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.ids {
        Some(members) => {
            for member_id in members {
                let err_msg = match revoke_member_impl(&org_id, &member_id, &headers, &conn).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationUserBulkResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn revoke_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        Some(mut member) if member.status > MembershipStatus::Revoked as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            if !may_revoke_stored_member_type(headers.membership_type, member.atype) {
                err!("You don't have permission to revoke this user")
            }
            if member.atype == MembershipType::Owner
                && Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1
            {
                err!("Organization must have at least one confirmed owner")
            }

            member.revoke();
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already revoked"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

#[put("/organizations/<org_id>/users/<member_id>/restore/vnext")]
async fn restore_member_vnext(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    // Vaultwarden does not (yet) support the per User Collection linked to the `Enforce organization data ownership` policy.
    // Therefor we ignore the `defaultUserCollectionName` data sent and just call restore_member
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/<member_id>/restore")]
async fn restore_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/restore", data = "<data>")]
async fn bulk_restore_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match restore_member_impl(&org_id, &member_id, &headers, &conn).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationUserBulkResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn restore_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        // Revoking stores `status - 128`, so every revoked value is accepted, not only -1.
        Some(mut member) if member.status <= MembershipStatus::Revoked as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            if !may_manage_stored_member_type(headers.membership_type, member.atype) {
                err!("You don't have permission to restore this user")
            }

            member.restore();
            // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
            // This check need to be done after restoring to work with the correct status
            OrgPolicy::check_user_allowed(&member, "restore", conn).await?;
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRestored,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already active"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

fn may_read_basic_directory(membership: &Membership) -> bool {
    membership.has_full_access()
        || membership.has_manage_users()
        || membership.has_manage_groups()
        || membership.can_create_new_collections()
        || membership.has_access_reports()
}

async fn can_read_basic_directory(org_id: &OrganizationId, membership: &Membership, conn: &DbConn) -> bool {
    may_read_basic_directory(membership)
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(org_id, &membership.uuid, conn).await)
        || Collection::has_manageable_collection_by_user(org_id, &membership.user_uuid, conn).await
}

async fn get_groups_data(details: bool, org_id: OrganizationId, conn: DbConn) -> JsonResult {
    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        let groups = Group::find_by_organization(&org_id, &conn).await;
        let mut groups_json = Vec::with_capacity(groups.len());

        if details {
            for g in groups {
                groups_json.push(g.to_json_details(&conn).await);
            }
        } else {
            for g in groups {
                groups_json.push(g.to_json());
            }
        }
        groups_json
    } else {
        // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
        // so just act as if there are no groups.
        Vec::new()
    };

    Ok(Json(json!({
        "data": groups,
        "object": "list",
        "continuationToken": null,
    })))
}

// The plain group list (id, name, externalId) exposes no access mappings. Upstream guards it with
// `OrganizationCollectionManagementAccessRequirement`, so it stays readable for members who have a
// reason to see it — the web vault needs it to render group names.
#[get("/organizations/<org_id>/groups")]
async fn get_groups(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    if !can_read_basic_directory(&org_id, &headers.membership, &conn).await {
        err_code!("Resource not found.", "User does not have access", Status::NotFound.code);
    }
    get_groups_data(false, org_id, conn).await
}

// Group *details* expose accessAll, external IDs and collection mappings. Upstream guards the details
// *list* with `ManageUsersOrGroupsRequirement` and the *single* group below with the narrower
// `ManageGroupsRequirement`, so the two are authorized separately. Neither accepts organization-wide
// collection reach or a legacy `groups.access_all` membership as a substitute.
#[get("/organizations/<org_id>/groups/details", rank = 1)]
async fn get_groups_details(org_id: OrganizationId, headers: ManageUsersOrGroupsHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    get_groups_data(true, org_id, conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    collections: Vec<CollectionData>,
    users: Vec<MembershipId>,
}

impl GroupRequest {
    pub fn to_group(&self, org_uuid: &OrganizationId) -> Group {
        Group::new(org_uuid.clone(), self.name.clone(), self.access_all, self.external_id.clone())
    }

    pub fn update_group(&self, mut group: Group) -> Group {
        group.name.clone_from(&self.name);
        group.access_all = self.access_all;
        // Group Updates do not support changing the external_id
        // These input fields are in a disabled state, and can only be updated/added via ldap_import

        group
    }

    /// Validate if all the collections and members belong to the provided organization
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in &self.collections {
            validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
        }

        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(m)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    id: CollectionId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
}

impl CollectionData {
    pub fn to_collection_group(&self, groups_uuid: GroupId) -> CollectionGroup {
        CollectionGroup::new(self.id.clone(), groups_uuid, self.read_only, self.hide_passwords, self.manage)
    }
}

#[post("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn post_group(
    org_id: OrganizationId,
    group_id: GroupId,
    data: Json<GroupRequest>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    put_group(org_id, group_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/groups", data = "<data>")]
async fn post_groups(
    org_id: OrganizationId,
    headers: ManageGroupsHeaders,
    data: Json<GroupRequest>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;
    if group_request.access_all && headers.membership_type == MembershipType::Custom {
        err!("Only Admins and Owners can create a legacy access-all group")
    }

    let group = group_request.to_group(&org_id);

    log_event(
        EventType::GroupCreated,
        &group.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    add_update_group(group, group_request.collections, group_request.users, org_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn put_group(
    org_id: OrganizationId,
    group_id: GroupId,
    data: Json<GroupRequest>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;
    if group_request.access_all && !group.access_all && headers.membership_type == MembershipType::Custom {
        err!("Only Admins and Owners can enable legacy access-all group access")
    }
    if group_request.access_all && headers.membership_type == MembershipType::Custom {
        let current_members: HashSet<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.users_organizations_uuid)
            .collect();
        if group_request.users.iter().any(|member_id| !current_members.contains(member_id)) {
            err!("Only Admins and Owners can add a member to a legacy access-all group")
        }
    }

    let updated_group = group_request.update_group(group);
    let response = add_update_group(
        updated_group,
        group_request.collections,
        group_request.users,
        org_id.clone(),
        &headers,
        &conn,
    )
    .await?;

    log_event(
        EventType::GroupUpdated,
        &group_id,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(response)
}

fn may_change_member_type(caller_type: MembershipType, current_atype: i32, new_type: MembershipType) -> bool {
    MembershipType::from_i32(current_atype).is_some_and(|current_type| {
        may_manage_member_type(caller_type, current_type) && may_manage_member_type(caller_type, new_type)
    })
}

/// Whether a caller with user-management access may perform lifecycle actions on a target role.
///
/// Owners may manage every role. Admins may manage Admin, Custom, and User memberships, but never
/// Owners. Custom members holding `manage_users` may manage Users and other Custom members.
fn may_manage_member_type(caller_type: MembershipType, target_type: MembershipType) -> bool {
    match caller_type {
        MembershipType::Owner => true,
        MembershipType::Admin => target_type != MembershipType::Owner,
        MembershipType::Custom => matches!(target_type, MembershipType::User | MembershipType::Custom),
        MembershipType::User => false,
    }
}

fn may_manage_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    MembershipType::from_i32(target_atype).is_some_and(|target_type| may_manage_member_type(caller_type, target_type))
}

/// Whether a caller may create or remove a membership of `target_type`.
///
/// Currently the same rule as [`may_manage_member_type`]; kept separate because upstream treats
/// provisioning and managing as distinct operations, and this is where they would diverge.
fn may_provision_member_type(caller_type: MembershipType, target_type: MembershipType) -> bool {
    may_manage_member_type(caller_type, target_type)
}

/// Whether a caller may act on a membership whose stored `atype` this build cannot interpret.
///
/// Such a row (a future build, a partial rollback, a hand edit) holds no authority -- `OrgHeaders`
/// refuses it and every permission flag on it is inert -- but the helpers above fail closed on the
/// unknown value, which left nobody able to remove it either, unlike Vaultwarden. So: an Owner only, and
/// only for the two actions that reduce what the row can become. Editing and restoring keep refusing,
/// because they preserve or reactivate a role the server cannot reason about.
fn may_act_on_unknown_stored_member_type(caller_type: MembershipType) -> bool {
    caller_type == MembershipType::Owner
}

/// Whether a caller may delete `target_atype`. Provisioning rules for a role this build knows;
/// Owner-only for one it does not (see [`may_act_on_unknown_stored_member_type`]).
fn may_delete_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    match MembershipType::from_i32(target_atype) {
        Some(role) => may_provision_member_type(caller_type, role),
        None => may_act_on_unknown_stored_member_type(caller_type),
    }
}

/// Whether a caller may revoke `target_atype`. Management rules for a role this build knows;
/// Owner-only for one it does not.
fn may_revoke_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    match MembershipType::from_i32(target_atype) {
        Some(role) => may_manage_member_type(caller_type, role),
        None => may_act_on_unknown_stored_member_type(caller_type),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrganizationImportTarget {
    Existing {
        /// The outcome of `auth::can_edit_collection` for this collection — upstream resolves
        /// `BulkCollectionOperations.ImportCiphers` through exactly the same `CanUpdateCollectionAsync`
        /// it uses for a collection update, so this is the collection-update authorization, not a
        /// write/edit assignment. A `readOnly = false, manage = false` assignment does not qualify.
        can_update: bool,
    },
    New,
}

fn may_import_to_collection(caller: &Membership, target: OrganizationImportTarget) -> bool {
    if !caller.has_status(MembershipStatus::Confirmed) {
        return false;
    }
    if may_access_import_export(caller) {
        return true;
    }

    match target {
        OrganizationImportTarget::Existing {
            can_update,
        } => can_update,
        OrganizationImportTarget::New => caller.can_create_new_collections(),
    }
}

fn may_grant_custom_permissions(
    caller: &Membership,
    target_type: MembershipType,
    requested: Option<CustomRolePermissions>,
) -> bool {
    !caller.has_type(MembershipType::Custom)
        || target_type != MembershipType::Custom
        || requested.is_none_or(|permissions| permissions.is_subset_of(caller))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrganizationReportScope {
    Complete,
    Denied,
}

fn organization_report_scope(caller: &Membership) -> OrganizationReportScope {
    if caller.has_status(MembershipStatus::Confirmed)
        && (caller.has_full_access() || caller.has_access_import_export() || caller.has_access_reports())
    {
        OrganizationReportScope::Complete
    } else {
        OrganizationReportScope::Denied
    }
}

async fn add_update_group(
    mut group: Group,
    collections: Vec<CollectionData>,
    members: Vec<MembershipId>,
    org_id: OrganizationId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> JsonResult {
    group.save(conn).await?;

    CollectionGroup::delete_all_by_group(&group.uuid, &org_id, conn).await?;
    for col_selection in collections {
        col_selection.to_collection_group(group.uuid.clone()).save(&org_id, conn).await?;
    }

    GroupUser::delete_all_by_group(&group.uuid, &org_id, conn).await?;
    for assigned_member in members {
        let mut user_entry = GroupUser::new(group.uuid.clone(), assigned_member.clone());
        user_entry.save(conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            &assigned_member,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }

    Ok(Json(json!({
        "id": group.uuid,
        "organizationId": group.organizations_uuid,
        "name": group.name,
        "accessAll": group.access_all,
        "externalId": group.external_id,
        "object": "group"
    })))
}

// Upstream guards this with `ManageGroupsRequirement` — deliberately narrower than the details *list*
// above, which also admits `Manage users`.
#[get("/organizations/<org_id>/groups/<group_id>/details")]
async fn get_group_details(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json_details(&conn).await))
}

#[post("/organizations/<org_id>/groups/<group_id>/delete")]
async fn post_delete_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_group_impl(&org_id, &group_id, &headers, &conn).await
}

#[delete("/organizations/<org_id>/groups/<group_id>")]
async fn delete_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_group_impl(&org_id, &group_id, &headers, &conn).await
}

async fn delete_group_impl(
    org_id: &OrganizationId,
    group_id: &GroupId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = find_group_in_organization(group_id, org_id, conn).await?;
    delete_authorized_group(&group, org_id, headers, conn).await
}

async fn find_group_in_organization(
    group_id: &GroupId,
    org_id: &OrganizationId,
    conn: &DbConn,
) -> Result<Group, crate::Error> {
    let Some(group) = Group::find_by_uuid_and_org(group_id, org_id, conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };
    Ok(group)
}

async fn delete_authorized_group(
    group: &Group,
    org_id: &OrganizationId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> EmptyResult {
    log_event(
        EventType::GroupDeleted,
        &group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    group.delete(org_id, conn).await
}

#[delete("/organizations/<org_id>/groups", data = "<data>")]
async fn bulk_delete_groups(
    org_id: OrganizationId,
    data: Json<BulkGroupIds>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let data: BulkGroupIds = data.into_inner();

    // Resolve the complete request before the first event or deletion so a foreign id cannot leave a
    // valid prefix already deleted.
    let mut groups = Vec::with_capacity(data.ids.len());
    let mut seen_group_ids = HashSet::with_capacity(data.ids.len());
    for group_id in data.ids {
        if !seen_group_ids.insert(group_id.clone()) {
            err!("Duplicate group id in bulk delete request")
        }
        groups.push(find_group_in_organization(&group_id, &org_id, &conn).await?);
    }

    for group in &groups {
        delete_authorized_group(group, &org_id, &headers, &conn).await?;
    }
    Ok(())
}

#[get("/organizations/<org_id>/groups/<group_id>", rank = 2)]
async fn get_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json()))
}

#[get("/organizations/<org_id>/groups/<group_id>/users")]
async fn get_group_members(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err!("Group could not be found!", "Group uuid is invalid or does not belong to the organization")
    }

    let group_members: Vec<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
        .await
        .iter()
        .map(|entry| entry.users_organizations_uuid.clone())
        .collect();

    Ok(Json(json!(group_members)))
}

#[put("/organizations/<org_id>/groups/<group_id>/users", data = "<data>")]
async fn put_group_members(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    data: Json<Vec<MembershipId>>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group could not be found!", "Group uuid is invalid or does not belong to the organization")
    };

    let assigned_members = data.into_inner();

    let org_memberships = Membership::find_by_org(&org_id, &conn).await;
    let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
    if let Some(e) = assigned_members.iter().find(|m| !org_membership_ids.contains(m)) {
        err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
    }

    if group.access_all && headers.membership_type == MembershipType::Custom {
        let current_members: HashSet<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.users_organizations_uuid)
            .collect();
        if assigned_members.iter().any(|member_id| !current_members.contains(member_id)) {
            err!("Only Admins and Owners can add a member to a legacy access-all group")
        }
    }

    GroupUser::delete_all_by_group(&group_id, &org_id, &conn).await?;
    for assigned_member in assigned_members {
        let mut user_entry = GroupUser::new(group_id.clone(), assigned_member.clone());
        user_entry.save(&conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            &assigned_member,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    }

    Ok(())
}

#[post("/organizations/<org_id>/groups/<group_id>/delete-user/<member_id>")]
async fn post_delete_group_member(
    org_id: OrganizationId,
    group_id: GroupId,
    member_id: MembershipId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await.is_none() {
        err!("User could not be found or does not belong to the organization.");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err!("Group could not be found or does not belong to the organization.");
    }

    log_event(
        EventType::OrganizationUserUpdatedGroups,
        &member_id,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    GroupUser::delete_by_group_and_member(&group_id, &member_id, &conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserResetPasswordEnrollmentRequest {
    reset_password_key: Option<String>,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserRecoverAccountRequest {
    new_master_password_hash: Option<String>,
    key: Option<String>,

    #[serde(default)]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

// Upstream reports this is the renamed endpoint instead of `/keys`
// But the clients do not seem to use this at all
// Just add it here in case they will
#[get("/organizations/<org_id>/public-key")]
async fn get_organization_public_key(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

// Obsolete - Renamed to public-key (2023.8), left for backwards compatibility with older clients
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Controllers/OrganizationsController.cs#L487-L492
#[get("/organizations/<org_id>/keys")]
async fn get_organization_keys(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    get_organization_public_key(org_id, headers, conn).await
}

// Will allow to reset 2FA too
// https://github.com/bitwarden/clients/blob/web-v2026.4.2/libs/admin-console/src/common/organization-user/models/requests/organization-user-reset-password.request.ts
#[put("/organizations/<org_id>/users/<member_id>/recover-account", data = "<data>")]
async fn put_recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    data: Json<OrganizationUserRecoverAccountRequest>,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    recover_account(org_id, member_id, headers, data.into_inner(), conn, nt).await
}

// Deprecated since `v2026.4.2`
#[put("/organizations/<org_id>/users/<member_id>/reset-password", data = "<data>")]
async fn put_reset_password(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    data: Json<OrganizationUserRecoverAccountRequest>,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    recover_account(org_id, member_id, headers, data.into_inner(), conn, nt).await
}

async fn recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    req: OrganizationUserRecoverAccountRequest,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org.uuid, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(mut user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    if member.reset_password_key.is_none() {
        err!("Password reset not or not correctly enrolled");
    }
    if member.status != (MembershipStatus::Confirmed as i32) {
        err!("Organization user must be confirmed for password reset functionality");
    }

    let fallback_2fa_email = if req.reset_two_factor && CONFIG.email_2fa_auto_fallback() {
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email as i32, &conn).await.is_none()
    } else {
        false
    };

    // Sending email first ensure working email configuration and the resulting user notification.
    // Also this might add some protection against security flaws and misuse
    if let Err(e) = mail::send_admin_account_recovery(
        &user.email,
        user.display_name(),
        &org.name,
        req.reset_master_password,
        req.reset_two_factor,
        fallback_2fa_email,
    )
    .await
    {
        err!(format!("Error sending user reset password email: {e:#?}"));
    }

    if req.reset_master_password {
        if let Some(key) = req.key
            && let Some(hash) = req.new_master_password_hash
        {
            user.set_password(hash.as_str(), Some(key), true, None, &conn).await?;
        } else {
            err_code!("Unprocessable request", "Missing fields to reset password", Status::UnprocessableEntity.code);
        }
    }

    if req.reset_two_factor {
        TwoFactor::delete_all_by_user(&user.uuid, &conn).await?;
        if !fallback_2fa_email || two_factor::email::find_and_activate_email_2fa(&user.uuid, &conn).await.is_err() {
            two_factor::enforce_2fa_policy(&user, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
                .await?;
        }
    }

    user.save(&conn).await?;

    nt.send_logout(&user, None, &conn).await;

    if req.reset_master_password {
        headers.log_event(EventType::OrganizationUserAdminResetPassword, &member_id, &org_id, &conn).await;
    }

    if req.reset_two_factor {
        headers.log_event(EventType::OrganizationUserAdminResetTwoFactor, &member_id, &org_id, &conn).await;
    }

    Ok(())
}

#[get("/organizations/<org_id>/users/<member_id>/reset-password-details")]
async fn get_reset_password_details(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/Organizations/OrganizationUserResponseModel.cs#L190
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": member_id,
        "kdf": user.client_kdf_type,
        "kdfIterations": user.client_kdf_iter,
        "kdfMemory": user.client_kdf_memory,
        "kdfParallelism": user.client_kdf_parallelism,
        "resetPasswordKey": member.reset_password_key,
        "encryptedPrivateKey": org.private_key,
    })))
}

async fn check_reset_password_applicable_and_permissions(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    check_reset_password_applicable(org_id, conn).await?;

    let Some(target_user) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("Reset target user not found")
    };

    // Resetting user must be higher/equal to user to reset
    match headers.membership_type {
        MembershipType::Owner => Ok(()),
        MembershipType::Admin if target_user.atype <= MembershipType::Admin => Ok(()),
        _ => err!("No permission to reset this user's password"),
    }
}

async fn check_reset_password_applicable(org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Password reset is not supported on an email-disabled instance.");
    }

    let Some(policy) = OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, conn).await else {
        err!("Policy not found")
    };

    if !policy.enabled {
        err!("Reset password policy not enabled");
    }

    Ok(())
}

#[put("/organizations/<org_id>/users/<user_id>/reset-password-enrollment", data = "<data>")]
async fn put_reset_password_enrollment(
    org_id: OrganizationId,
    user_id: UserId,
    headers: OrgMemberHeaders,
    data: Json<OrganizationUserResetPasswordEnrollmentRequest>,
    conn: DbConn,
) -> EmptyResult {
    if user_id != headers.user.uuid {
        err!("User to enroll isn't member of required organization", "The user_id and acting user do not match");
    }

    let mut membership = headers.membership;

    check_reset_password_applicable(&org_id, &conn).await?;

    let reset_request = data.into_inner();

    let reset_password_key = match reset_request.reset_password_key {
        None => None,
        Some(ref key) if key.is_empty() => None,
        Some(key) => Some(key),
    };

    if reset_password_key.is_none() && OrgPolicy::org_is_reset_password_auto_enroll(&org_id, &conn).await {
        err!("Reset password can't be withdrawn due to an enterprise policy");
    }

    if reset_password_key.is_some() {
        PasswordOrOtpData {
            master_password_hash: reset_request.master_password_hash,
            otp: reset_request.otp,
        }
        .validate(&headers.user, true, &conn)
        .await?;
    }

    membership.reset_password_key = reset_password_key;
    membership.save(&conn).await?;

    let event_type = if membership.reset_password_key.is_some() {
        EventType::OrganizationUserResetPasswordEnroll
    } else {
        EventType::OrganizationUserResetPasswordWithdraw
    };

    log_event(event_type, &membership.uuid, &org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    Ok(())
}

// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
// https://github.com/bitwarden/server/blob/e8afc9eb63901402fd160198e70eb865e011144a/src/Api/Tools/Controllers/OrganizationExportController.cs
#[get("/organizations/<org_id>/export")]
async fn get_org_export(org_id: OrganizationId, headers: AccessImportExportHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let ciphers = Cipher::find_by_org(&org_id, &conn).await;

    let collections_json: Value = collections.iter().map(Collection::to_json).collect();

    Ok(Json(json!({
        "collections": convert_json_key_lcase_first(collections_json),
        "ciphers": convert_json_key_lcase_first(ciphers_to_org_json(ciphers, &org_id, &headers.host, &headers.user.uuid, &conn).await?),
    })))
}

async fn api_key(
    org_id: &OrganizationId,
    data: Json<PasswordOrOtpData>,
    rotate: bool,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    // Validate the admin users password/otp
    data.validate(&user, true, &conn).await?;

    let org_api_key = if let Some(mut org_api_key) = OrganizationApiKey::find_by_org_uuid(org_id, &conn).await {
        if rotate {
            org_api_key.api_key = crate::crypto::generate_api_key();
            org_api_key.revision_date = chrono::Utc::now().naive_utc();
            org_api_key.save(&conn).await.expect("Error rotating organization API Key");
        }
        org_api_key
    } else {
        let api_key = crate::crypto::generate_api_key();
        let new_org_api_key = OrganizationApiKey::new(org_id.clone(), api_key);
        new_org_api_key.save(&conn).await.expect("Error creating organization API Key");
        new_org_api_key
    };

    Ok(Json(json!({
      "apiKey": org_api_key.api_key,
      "revisionDate": crate::util::format_date(&org_api_key.revision_date),
      "object": "apiKey",
    })))
}

#[post("/organizations/<org_id>/api-key", data = "<data>")]
async fn post_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, false, headers, conn).await
}

#[post("/organizations/<org_id>/rotate-api-key", data = "<data>")]
async fn rotate_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, true, headers, conn).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{Value, json};

    use super::{
        CustomRolePermissions as Perms, may_change_member_type, may_delete_stored_member_type,
        may_grant_custom_permissions, may_manage_member_type, may_revoke_stored_member_type,
    };
    use crate::db::models::{Membership, MembershipStatus, MembershipType};
    use MembershipType::{Admin, Custom, Owner, User};

    const UNKNOWN_ATYPE: i32 = Membership::UNKNOWN_ATYPE;

    /// Every permission, with the way to set it on a request and on a stored membership.
    type SetRequested = fn(&mut Perms);
    type SetStored = fn(&mut Membership);
    const PERMISSIONS: [(&str, SetRequested, SetStored); 9] = [
        ("manageUsers", |p| p.manage_users = true, |m| m.manage_users = true),
        ("manageGroups", |p| p.manage_groups = true, |m| m.manage_groups = true),
        ("managePolicies", |p| p.manage_policies = true, |m| m.manage_policies = true),
        ("createNewCollections", |p| p.create_new_collections = true, |m| m.create_new_collections = true),
        ("editAnyCollection", |p| p.edit_any_collection = true, |m| m.edit_any_collection = true),
        ("deleteAnyCollection", |p| p.delete_any_collection = true, |m| m.delete_any_collection = true),
        ("accessEventLogs", |p| p.access_event_logs = true, |m| m.access_event_logs = true),
        ("accessImportExport", |p| p.access_import_export = true, |m| m.access_import_export = true),
        ("accessReports", |p| p.access_reports = true, |m| m.access_reports = true),
    ];

    fn member(atype: MembershipType, set: impl FnOnce(&mut Membership)) -> Membership {
        Membership::for_test(atype as i32, MembershipStatus::Confirmed, set)
    }

    fn requested(set: SetRequested) -> Perms {
        let mut permissions = Perms::default();
        set(&mut permissions);
        permissions
    }

    fn object(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect()
    }

    /// Who may act on whose membership.
    ///
    /// The hierarchy is what keeps `manageUsers` from being a way up: it lets a Custom member run the
    /// member dialog, but only over the half of the organization below Admin.
    #[test]
    fn member_type_authority_matrix() {
        // (caller, may manage [Owner, Admin, Custom, User])
        let cases = [
            ("Owner", Owner, [true, true, true, true]),
            // An Admin manages everything below itself, never another Owner.
            ("Admin", Admin, [false, true, true, true]),
            // A Custom member holding manageUsers stays inside its own half of the hierarchy.
            ("Custom", Custom, [false, false, true, true]),
            ("User", User, [false, false, false, false]),
        ];

        for (name, caller, expected) in cases {
            for (target, allowed) in [Owner, Admin, Custom, User].into_iter().zip(expected) {
                assert_eq!(may_manage_member_type(caller, target), allowed, "{name} acting on role {}", target as i32);
            }
        }

        // A role change needs authority over the role the member *has* and the one it would *get*, so
        // neither end can be used to step outside the caller's half of the hierarchy.
        assert!(may_change_member_type(Admin, Custom as i32, User));
        assert!(!may_change_member_type(Admin, Custom as i32, Owner), "an Admin must not promote anyone to Owner");
        assert!(!may_change_member_type(Custom, Admin as i32, User), "a Custom member must not demote an Admin");
        assert!(!may_change_member_type(Custom, User as i32, Admin), "a Custom member must not promote to Admin");

        // A stored role this build cannot interpret holds no authority, but somebody still has to be
        // able to get rid of the row. Only an Owner may, and only with the two actions that reduce what
        // the row can become: editing or restoring it would preserve a role the server cannot reason
        // about.
        for caller in [Owner, Admin, Custom, User] {
            let owner_only = caller == Owner;
            for (action, allowed) in [
                ("deleting", may_delete_stored_member_type(caller, UNKNOWN_ATYPE)),
                ("revoking", may_revoke_stored_member_type(caller, UNKNOWN_ATYPE)),
            ] {
                assert_eq!(allowed, owner_only, "{action} an unknown stored role as role {}", caller as i32);
            }
            assert!(
                !may_change_member_type(caller, UNKNOWN_ATYPE, User),
                "an unknown stored role must never be edited into a known one"
            );
        }

        // For a role this build does know, delete and revoke follow the same hierarchy.
        assert!(may_delete_stored_member_type(Admin, Custom as i32));
        assert!(!may_delete_stored_member_type(Admin, Owner as i32));
        assert!(!may_revoke_stored_member_type(Custom, Admin as i32));
    }

    /// A Custom member running the member dialog may hand on only what they hold themselves.
    ///
    /// Without this, `manageUsers` would be a one-step path to every other permission: grant yourself
    /// nothing, create a Custom member with `managePolicies`, and act through them.
    #[test]
    fn custom_permissions_cannot_be_escalated() {
        // Each permission is its own gate: holding one lets a caller pass on that one and no other.
        for (granted, _, hold) in PERMISSIONS {
            let caller = member(Custom, hold);
            for (asked_for, set, _) in PERMISSIONS {
                let allowed = requested(set).is_subset_of(&caller);
                assert_eq!(allowed, asked_for == granted, "a caller holding {granted} granting {asked_for}");
            }
            assert!(Perms::default().is_subset_of(&caller), "{granted}: an empty request is always within the set");
        }

        // The same permissions on a stale, non-Custom membership are inert, so their holder can pass on
        // nothing at all.
        let stale = member(User, |m| {
            for (_, _, hold) in PERMISSIONS {
                hold(m);
            }
        });
        for (asked_for, set, _) in PERMISSIONS {
            assert!(!requested(set).is_subset_of(&stale), "a stale {asked_for} flag must not be delegatable");
        }

        // The endpoint guard, which contains only what a *Custom* delegator may pass on.
        let delegator = member(Custom, |m| {
            m.manage_users = true;
            m.edit_any_collection = true;
        });
        let admin = member(Admin, |_| {});
        let policies = || Some(requested(|p| p.manage_policies = true));

        // (case, caller, target role, requested permissions, allowed)
        let grants = [
            (
                "a permission the delegator holds",
                &delegator,
                Custom,
                Some(requested(|p| p.edit_any_collection = true)),
                true,
            ),
            ("a permission the delegator lacks", &delegator, Custom, policies(), false),
            // An Admin or Owner holds every permission by role and is not constrained by this guard.
            ("an Admin granting anything", &admin, Custom, policies(), true),
            // A target that is not Custom cannot carry permissions, so there is nothing to contain.
            ("a non-Custom target", &delegator, User, policies(), true),
            // No permissions object means no grant to check. Whether the caller may reach the endpoint
            // at all is `ManageUsersHeaders`, not this guard.
            ("no permissions object", &delegator, Custom, None, true),
        ];
        for (case, caller, target, permissions, allowed) in grants {
            assert_eq!(may_grant_custom_permissions(caller, target, permissions), allowed, "{case}");
        }
    }

    /// How a permissions object is read off the wire.
    ///
    /// The strictness matters because this is a *replace*: whatever comes out of the parser becomes the
    /// member's complete set. Reading a malformed value as "not true" once turned a bad request into a
    /// silent permission removal that still answered 200.
    #[test]
    fn custom_permissions_are_parsed_strictly() {
        // A present key must be a JSON boolean; an absent one is simply false.
        let booleans = object(&[("editAnyCollection", json!(true)), ("manageUsers", json!(false))]);
        assert_eq!(
            Perms::from_request(Custom, &booleans).expect("booleans parse"),
            requested(|p| p.edit_any_collection = true)
        );

        for bad in [json!(null), json!("true"), json!(1), json!([true]), json!({"value": true})] {
            let malformed = object(&[("editAnyCollection", bad.clone())]);
            assert!(
                Perms::from_request(Custom, &malformed).is_err(),
                "{bad} must be rejected rather than read as a permission removal"
            );
            // The check runs before the role is considered, so the same request fails the same way
            // whatever role it names.
            assert!(Perms::from_request(User, &malformed).is_err(), "{bad} must be rejected for a non-Custom role too");
        }

        // Bitwarden sends permissions Vaultwarden does not implement; rejecting them would break the
        // official clients. And only a Custom member carries permissions at all.
        let unknown_keys = object(&[("manageSso", json!(true)), ("manageScim", json!("x")), ("manageReset", json!(1))]);
        let known_key = object(&[("managePolicies", json!(true))]);
        for (case, member_type, permissions) in
            [("unknown keys", Custom, &unknown_keys), ("a non-Custom role", Admin, &known_key)]
        {
            assert_eq!(
                Perms::from_request(member_type, permissions).expect("valid object"),
                Perms::default(),
                "{case}"
            );
        }

        // Editing an existing member. An *omitted* object is not an instruction to clear every grant,
        // because older clients send the legacy role value without one; an explicitly empty object is.
        let held = member(Custom, |m| m.access_reports = true);
        let stale = member(User, |m| m.access_reports = true);
        assert_eq!(
            Perms::from_edit_request(Custom, None, &held).expect("omitted object"),
            requested(|p| p.access_reports = true)
        );
        // (case, requested role, permissions object, stored membership)
        let cleared = [
            ("an explicitly empty object", Custom, Some(&object(&[])), &held),
            ("a role change away from Custom", User, None, &held),
            ("a stale set on a non-Custom membership", Custom, None, &stale),
        ];
        for (case, member_type, permissions, membership) in cleared {
            assert_eq!(
                Perms::from_edit_request(member_type, permissions, membership).expect("valid request"),
                Perms::default(),
                "{case}"
            );
        }

        // Applying has to reach all nine columns; a forgotten one would drop a granted permission.
        let mut everything = Perms::default();
        for (_, set, _) in PERMISSIONS {
            set(&mut everything);
        }
        let mut target = member(Custom, |_| {});
        everything.apply_to(&mut target);
        assert_eq!(Perms::from_membership(&target), everything, "apply_to must write every permission it parsed");
    }
}
