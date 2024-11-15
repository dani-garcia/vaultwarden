use num_traits::FromPrimitive;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::{
    api::{
        core::{log_event, two_factor, CipherSyncData, CipherSyncType},
        EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
    },
    auth::{decode_invite, AdminHeaders, ClientVersion, Headers, ManagerHeaders, ManagerHeadersLoose, OwnerHeaders},
    db::{models::*, DbConn},
    error::Error,
    mail,
    util::{convert_json_key_lcase_first, NumberOrString},
    CONFIG,
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
        put_collection_users,
        put_organization,
        post_organization,
        post_organization_collections,
        delete_organization_collection_user,
        post_organization_collection_delete_user,
        post_organization_collection_update,
        put_organization_collection_update,
        delete_organization_collection,
        post_organization_collection_delete,
        bulk_delete_organization_collections,
        post_bulk_collections,
        get_org_details,
        get_org_users,
        send_invite,
        reinvite_user,
        bulk_reinvite_user,
        confirm_invite,
        bulk_confirm_invite,
        accept_invite,
        get_user,
        edit_user,
        put_organization_user,
        delete_user,
        bulk_delete_user,
        post_delete_user,
        post_org_import,
        list_policies,
        list_policies_token,
        get_policy,
        put_policy,
        get_organization_tax,
        get_plans,
        get_plans_all,
        get_plans_tax_rates,
        import,
        post_org_keys,
        get_organization_keys,
        get_organization_public_key,
        bulk_public_keys,
        deactivate_organization_user,
        bulk_deactivate_organization_user,
        revoke_organization_user,
        bulk_revoke_organization_user,
        activate_organization_user,
        bulk_activate_organization_user,
        restore_organization_user,
        bulk_restore_organization_user,
        get_groups,
        post_groups,
        get_group,
        put_group,
        post_group,
        get_group_details,
        delete_group,
        post_delete_group,
        bulk_delete_groups,
        get_group_users,
        put_group_users,
        get_user_groups,
        post_user_groups,
        put_user_groups,
        delete_group_user,
        post_delete_group_user,
        put_reset_password_enrollment,
        get_reset_password_details,
        put_reset_password,
        get_org_export,
        api_key,
        rotate_api_key,
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
struct NewCollectionData {
    name: String,
    groups: Vec<NewCollectionObjectData>,
    users: Vec<NewCollectionObjectData>,
    external_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewCollectionObjectData {
    hide_passwords: bool,
    id: String,
    read_only: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrgBulkIds {
    ids: Vec<String>,
}

#[post("/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: Json<OrgData>, mut conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &mut conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.into_inner();
    let (private_key, public_key) = if data.keys.is_some() {
        let keys: OrgKeyData = data.keys.unwrap();
        (Some(keys.encrypted_private_key), Some(keys.public_key))
    } else {
        (None, None)
    };

    let org = Organization::new(data.name, data.billing_email, private_key, public_key);
    let mut user_org = UserOrganization::new(headers.user.uuid, org.uuid.clone());
    let collection = Collection::new(org.uuid.clone(), data.collection_name, None);

    user_org.akey = data.key;
    user_org.access_all = true;
    user_org.atype = UserOrgType::Owner as i32;
    user_org.status = UserOrgStatus::Confirmed as i32;

    org.save(&mut conn).await?;
    user_org.save(&mut conn).await?;
    collection.save(&mut conn).await?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
async fn delete_organization(
    org_id: &str,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();

    data.validate(&headers.user, true, &mut conn).await?;

    match Organization::find_by_uuid(org_id, &mut conn).await {
        None => err!("Organization not found"),
        Some(org) => org.delete(&mut conn).await,
    }
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
async fn post_delete_organization(
    org_id: &str,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization(org_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/leave")]
async fn leave_organization(org_id: &str, headers: Headers, mut conn: DbConn) -> EmptyResult {
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, org_id, &mut conn).await {
        None => err!("User not part of organization"),
        Some(user_org) => {
            if user_org.atype == UserOrgType::Owner
                && UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, &mut conn).await <= 1
            {
                err!("The last owner can't leave")
            }

            log_event(
                EventType::OrganizationUserRemoved as i32,
                &user_org.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                &mut conn,
            )
            .await;

            user_org.delete(&mut conn).await
        }
    }
}

#[get("/organizations/<org_id>")]
async fn get_organization(org_id: &str, _headers: OwnerHeaders, mut conn: DbConn) -> JsonResult {
    match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => Ok(Json(organization.to_json())),
        None => err!("Can't find organization details"),
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
async fn put_organization(
    org_id: &str,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_organization(org_id, headers, data, conn).await
}

#[post("/organizations/<org_id>", data = "<data>")]
async fn post_organization(
    org_id: &str,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    mut conn: DbConn,
) -> JsonResult {
    let data: OrganizationUpdateData = data.into_inner();

    let mut org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    org.name = data.name;
    org.billing_email = data.billing_email;

    org.save(&mut conn).await?;

    log_event(
        EventType::OrganizationUpdated as i32,
        org_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
async fn get_user_collections(headers: Headers, mut conn: DbConn) -> Json<Value> {
    Json(json!({
        "data":
            Collection::find_by_user_uuid(headers.user.uuid, &mut conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    }))
}

#[get("/organizations/<org_id>/collections")]
async fn get_org_collections(org_id: &str, _headers: ManagerHeadersLoose, mut conn: DbConn) -> Json<Value> {
    Json(json!({
        "data": _get_org_collections(org_id, &mut conn).await,
        "object": "list",
        "continuationToken": null,
    }))
}

#[get("/organizations/<org_id>/collections/details")]
async fn get_org_collections_details(org_id: &str, headers: ManagerHeadersLoose, mut conn: DbConn) -> JsonResult {
    let mut data = Vec::new();

    let user_org = match UserOrganization::find_by_user_and_org(&headers.user.uuid, org_id, &mut conn).await {
        Some(u) => u,
        None => err!("User is not part of organization"),
    };

    // get all collection memberships for the current organization
    let coll_users = CollectionUser::find_by_organization(org_id, &mut conn).await;

    // check if current user has full access to the organization (either directly or via any group)
    let has_full_access_to_org = user_org.access_all
        || (CONFIG.org_groups_enabled()
            && GroupUser::has_full_access_by_member(org_id, &user_org.uuid, &mut conn).await);

    for col in Collection::find_by_organization(org_id, &mut conn).await {
        // check whether the current user has access to the given collection
        let assigned = has_full_access_to_org
            || CollectionUser::has_access_to_collection_by_user(&col.uuid, &user_org.user_uuid, &mut conn).await
            || (CONFIG.org_groups_enabled()
                && GroupUser::has_access_to_collection_by_member(&col.uuid, &user_org.uuid, &mut conn).await);

        // get the users assigned directly to the given collection
        let users: Vec<Value> = coll_users
            .iter()
            .filter(|collection_user| collection_user.collection_uuid == col.uuid)
            .map(|collection_user| SelectionReadOnly::to_collection_user_details_read_only(collection_user).to_json())
            .collect();

        // get the group details for the given collection
        let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
            CollectionGroup::find_by_collection(&col.uuid, &mut conn)
                .await
                .iter()
                .map(|collection_group| {
                    SelectionReadOnly::to_collection_group_details_read_only(collection_group).to_json()
                })
                .collect()
        } else {
            Vec::with_capacity(0)
        };

        let mut json_object = col.to_json_details(&headers.user.uuid, None, &mut conn).await;
        json_object["assigned"] = json!(assigned);
        json_object["users"] = json!(users);
        json_object["groups"] = json!(groups);
        json_object["object"] = json!("collectionAccessDetails");
        json_object["unmanaged"] = json!(false);
        data.push(json_object)
    }

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn _get_org_collections(org_id: &str, conn: &mut DbConn) -> Value {
    Collection::find_by_organization(org_id, conn).await.iter().map(Collection::to_json).collect::<Value>()
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
async fn post_organization_collections(
    org_id: &str,
    headers: ManagerHeadersLoose,
    data: Json<NewCollectionData>,
    mut conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner();

    let org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let collection = Collection::new(org.uuid, data.name, data.external_id);
    collection.save(&mut conn).await?;

    log_event(
        EventType::CollectionCreated as i32,
        &collection.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    for group in data.groups {
        CollectionGroup::new(collection.uuid.clone(), group.id, group.read_only, group.hide_passwords)
            .save(&mut conn)
            .await?;
    }

    for user in data.users {
        let org_user = match UserOrganization::find_by_uuid(&user.id, &mut conn).await {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if org_user.access_all {
            continue;
        }

        CollectionUser::save(&org_user.user_uuid, &collection.uuid, user.read_only, user.hide_passwords, &mut conn)
            .await?;
    }

    if headers.org_user.atype == UserOrgType::Manager && !headers.org_user.access_all {
        CollectionUser::save(&headers.org_user.user_uuid, &collection.uuid, false, false, &mut conn).await?;
    }

    Ok(Json(collection.to_json()))
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn put_organization_collection_update(
    org_id: &str,
    col_id: &str,
    headers: ManagerHeaders,
    data: Json<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    post_organization_collection_update(org_id, col_id, headers, data, conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn post_organization_collection_update(
    org_id: &str,
    col_id: &str,
    headers: ManagerHeaders,
    data: Json<NewCollectionData>,
    mut conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner();

    let org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let mut collection = match Collection::find_by_uuid(col_id, &mut conn).await {
        Some(collection) => collection,
        None => err!("Collection not found"),
    };

    if collection.org_uuid != org.uuid {
        err!("Collection is not owned by organization");
    }

    collection.name = data.name;
    collection.external_id = match data.external_id {
        Some(external_id) if !external_id.trim().is_empty() => Some(external_id),
        _ => None,
    };

    collection.save(&mut conn).await?;

    log_event(
        EventType::CollectionUpdated as i32,
        &collection.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    CollectionGroup::delete_all_by_collection(col_id, &mut conn).await?;

    for group in data.groups {
        CollectionGroup::new(String::from(col_id), group.id, group.read_only, group.hide_passwords)
            .save(&mut conn)
            .await?;
    }

    CollectionUser::delete_all_by_collection(col_id, &mut conn).await?;

    for user in data.users {
        let org_user = match UserOrganization::find_by_uuid(&user.id, &mut conn).await {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if org_user.access_all {
            continue;
        }

        CollectionUser::save(&org_user.user_uuid, col_id, user.read_only, user.hide_passwords, &mut conn).await?;
    }

    Ok(Json(collection.to_json_details(&headers.user.uuid, None, &mut conn).await))
}

#[delete("/organizations/<org_id>/collections/<col_id>/user/<org_user_id>")]
async fn delete_organization_collection_user(
    org_id: &str,
    col_id: &str,
    org_user_id: &str,
    _headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    let collection = match Collection::find_by_uuid(col_id, &mut conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                collection
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    };

    match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, &mut conn).await {
        None => err!("User not found in organization"),
        Some(user_org) => {
            match CollectionUser::find_by_collection_and_user(&collection.uuid, &user_org.user_uuid, &mut conn).await {
                None => err!("User not assigned to collection"),
                Some(col_user) => col_user.delete(&mut conn).await,
            }
        }
    }
}

#[post("/organizations/<org_id>/collections/<col_id>/delete-user/<org_user_id>")]
async fn post_organization_collection_delete_user(
    org_id: &str,
    col_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_user(org_id, col_id, org_user_id, headers, conn).await
}

async fn _delete_organization_collection(
    org_id: &str,
    col_id: &str,
    headers: &ManagerHeaders,
    conn: &mut DbConn,
) -> EmptyResult {
    match Collection::find_by_uuid(col_id, conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                log_event(
                    EventType::CollectionDeleted as i32,
                    &collection.uuid,
                    org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    conn,
                )
                .await;
                collection.delete(conn).await
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    }
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
async fn delete_organization_collection(
    org_id: &str,
    col_id: &str,
    headers: ManagerHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    _delete_organization_collection(org_id, col_id, &headers, &mut conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DeleteCollectionData {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    org_id: String,
}

#[post("/organizations/<org_id>/collections/<col_id>/delete", data = "<_data>")]
async fn post_organization_collection_delete(
    org_id: &str,
    col_id: &str,
    headers: ManagerHeaders,
    _data: Json<DeleteCollectionData>,
    mut conn: DbConn,
) -> EmptyResult {
    _delete_organization_collection(org_id, col_id, &headers, &mut conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionIds {
    ids: Vec<String>,
}

#[delete("/organizations/<org_id>/collections", data = "<data>")]
async fn bulk_delete_organization_collections(
    org_id: &str,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionIds>,
    mut conn: DbConn,
) -> EmptyResult {
    let data: BulkCollectionIds = data.into_inner();

    let collections = data.ids;

    let headers = ManagerHeaders::from_loose(headers, &collections, &mut conn).await?;

    for col_id in collections {
        _delete_organization_collection(org_id, &col_id, &headers, &mut conn).await?
    }
    Ok(())
}

#[get("/organizations/<org_id>/collections/<coll_id>/details")]
async fn get_org_collection_detail(
    org_id: &str,
    coll_id: &str,
    headers: ManagerHeaders,
    mut conn: DbConn,
) -> JsonResult {
    match Collection::find_by_uuid_and_user(coll_id, headers.user.uuid.clone(), &mut conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            let user_org = match UserOrganization::find_by_user_and_org(&headers.user.uuid, org_id, &mut conn).await {
                Some(u) => u,
                None => err!("User is not part of organization"),
            };

            let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
                CollectionGroup::find_by_collection(&collection.uuid, &mut conn)
                    .await
                    .iter()
                    .map(|collection_group| {
                        SelectionReadOnly::to_collection_group_details_read_only(collection_group).to_json()
                    })
                    .collect()
            } else {
                // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
                // so just act as if there are no groups.
                Vec::with_capacity(0)
            };

            let users: Vec<Value> =
                CollectionUser::find_by_collection_swap_user_uuid_with_org_user_uuid(&collection.uuid, &mut conn)
                    .await
                    .iter()
                    .map(|collection_user| {
                        SelectionReadOnly::to_collection_user_details_read_only(collection_user).to_json()
                    })
                    .collect();

            let assigned = Collection::can_access_collection(&user_org, &collection.uuid, &mut conn).await;

            let mut json_object = collection.to_json_details(&headers.user.uuid, None, &mut conn).await;
            json_object["assigned"] = json!(assigned);
            json_object["users"] = json!(users);
            json_object["groups"] = json!(groups);
            json_object["object"] = json!("collectionAccessDetails");

            Ok(Json(json_object))
        }
    }
}

#[get("/organizations/<org_id>/collections/<coll_id>/users")]
async fn get_collection_users(org_id: &str, coll_id: &str, _headers: ManagerHeaders, mut conn: DbConn) -> JsonResult {
    // Get org and collection, check that collection is from org
    let collection = match Collection::find_by_uuid_and_org(coll_id, org_id, &mut conn).await {
        None => err!("Collection not found in Organization"),
        Some(collection) => collection,
    };

    let mut user_list = Vec::new();
    for col_user in CollectionUser::find_by_collection(&collection.uuid, &mut conn).await {
        user_list.push(
            UserOrganization::find_by_user_and_org(&col_user.user_uuid, org_id, &mut conn)
                .await
                .unwrap()
                .to_json_user_access_restrictions(&col_user),
        );
    }

    Ok(Json(json!(user_list)))
}

#[put("/organizations/<org_id>/collections/<coll_id>/users", data = "<data>")]
async fn put_collection_users(
    org_id: &str,
    coll_id: &str,
    data: Json<Vec<CollectionData>>,
    _headers: ManagerHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    // Get org and collection, check that collection is from org
    if Collection::find_by_uuid_and_org(coll_id, org_id, &mut conn).await.is_none() {
        err!("Collection not found in Organization")
    }

    // Delete all the user-collections
    CollectionUser::delete_all_by_collection(coll_id, &mut conn).await?;

    // And then add all the received ones (except if the user has access_all)
    for d in data.iter() {
        let user = match UserOrganization::find_by_uuid(&d.id, &mut conn).await {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if user.access_all {
            continue;
        }

        CollectionUser::save(&user.user_uuid, coll_id, d.read_only, d.hide_passwords, &mut conn).await?;
    }

    Ok(())
}

#[derive(FromForm)]
struct OrgIdData {
    #[field(name = "organizationId")]
    organization_id: String,
}

#[get("/ciphers/organization-details?<data..>")]
async fn get_org_details(data: OrgIdData, headers: Headers, mut conn: DbConn) -> JsonResult {
    if UserOrganization::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &mut conn)
        .await
        .is_none()
    {
        err_code!("Resource not found.", rocket::http::Status::NotFound.code);
    }

    Ok(Json(json!({
        "data": _get_org_details(&data.organization_id, &headers.host, &headers.user.uuid, &mut conn).await,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn _get_org_details(org_id: &str, host: &str, user_uuid: &str, conn: &mut DbConn) -> Value {
    let ciphers = Cipher::find_by_org(org_id, conn).await;
    let cipher_sync_data = CipherSyncData::new(user_uuid, CipherSyncType::Organization, conn).await;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json
            .push(c.to_json(host, user_uuid, Some(&cipher_sync_data), CipherSyncType::Organization, conn).await);
    }
    json!(ciphers_json)
}

#[derive(FromForm)]
struct GetOrgUserData {
    #[field(name = "includeCollections")]
    include_collections: Option<bool>,
    #[field(name = "includeGroups")]
    include_groups: Option<bool>,
}

#[get("/organizations/<org_id>/users?<data..>")]
async fn get_org_users(
    data: GetOrgUserData,
    org_id: &str,
    _headers: ManagerHeadersLoose,
    mut conn: DbConn,
) -> Json<Value> {
    let mut users_json = Vec::new();
    for u in UserOrganization::find_by_org(org_id, &mut conn).await {
        users_json.push(
            u.to_json_user_details(
                data.include_collections.unwrap_or(false),
                data.include_groups.unwrap_or(false),
                &mut conn,
            )
            .await,
        );
    }

    Json(json!({
        "data": users_json,
        "object": "list",
        "continuationToken": null,
    }))
}

#[post("/organizations/<org_id>/keys", data = "<data>")]
async fn post_org_keys(org_id: &str, data: Json<OrgKeyData>, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    let data: OrgKeyData = data.into_inner();

    let mut org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => {
            if organization.private_key.is_some() && organization.public_key.is_some() {
                err!("Organization Keys already exist")
            }
            organization
        }
        None => err!("Can't find organization details"),
    };

    org.private_key = Some(data.encrypted_private_key);
    org.public_key = Some(data.public_key);

    org.save(&mut conn).await?;

    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": org.public_key,
        "privateKey": org.private_key,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    id: String,
    read_only: bool,
    hide_passwords: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    emails: Vec<String>,
    groups: Vec<String>,
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    #[serde(default)]
    access_all: bool,
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
async fn send_invite(org_id: &str, data: Json<InviteData>, headers: AdminHeaders, mut conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner();

    let new_type = match UserOrgType::from_str(&data.r#type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if new_type != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can invite Managers, Admins or Owners")
    }

    for email in data.emails.iter() {
        let mut user_org_status = UserOrgStatus::Invited as i32;
        let user = match User::find_by_mail(email, &mut conn).await {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {email}"))
                }

                if !CONFIG.is_email_domain_allowed(email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    let invitation = Invitation::new(email);
                    invitation.save(&mut conn).await?;
                }

                let mut user = User::new(email.clone());
                user.save(&mut conn).await?;
                user
            }
            Some(user) => {
                if UserOrganization::find_by_user_and_org(&user.uuid, org_id, &mut conn).await.is_some() {
                    err!(format!("User already in organization: {email}"))
                } else {
                    // automatically accept existing users if mail is disabled
                    if !CONFIG.mail_enabled() && !user.password_hash.is_empty() {
                        user_org_status = UserOrgStatus::Accepted as i32;
                    }
                    user
                }
            }
        };

        let mut new_user = UserOrganization::new(user.uuid.clone(), String::from(org_id));
        let access_all = data.access_all;
        new_user.access_all = access_all;
        new_user.atype = new_type;
        new_user.status = user_org_status;

        // If no accessAll, add the collections received
        if !access_all {
            for col in data.collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&col.id, org_id, &mut conn).await {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        CollectionUser::save(
                            &user.uuid,
                            &collection.uuid,
                            col.read_only,
                            col.hide_passwords,
                            &mut conn,
                        )
                        .await?;
                    }
                }
            }
        }

        new_user.save(&mut conn).await?;

        for group in data.groups.iter() {
            let mut group_entry = GroupUser::new(String::from(group), user.uuid.clone());
            group_entry.save(&mut conn).await?;
        }

        log_event(
            EventType::OrganizationUserInvited as i32,
            &new_user.uuid,
            org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &mut conn,
        )
        .await;

        if CONFIG.mail_enabled() {
            let org_name = match Organization::find_by_uuid(org_id, &mut conn).await {
                Some(org) => org.name,
                None => err!("Error looking up organization"),
            };

            mail::send_invite(
                &user,
                Some(String::from(org_id)),
                Some(new_user.uuid),
                &org_name,
                Some(headers.user.email.clone()),
            )
            .await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/reinvite", data = "<data>")]
async fn bulk_reinvite_user(
    org_id: &str,
    data: Json<OrgBulkIds>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for org_user_id in data.ids {
        let err_msg = match _reinvite_user(org_id, &org_user_id, &headers.user.email, &mut conn).await {
            Ok(_) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": org_user_id,
                "error": err_msg
            }
        ))
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

#[post("/organizations/<org_id>/users/<user_org>/reinvite")]
async fn reinvite_user(org_id: &str, user_org: &str, headers: AdminHeaders, mut conn: DbConn) -> EmptyResult {
    _reinvite_user(org_id, user_org, &headers.user.email, &mut conn).await
}

async fn _reinvite_user(org_id: &str, user_org: &str, invited_by_email: &str, conn: &mut DbConn) -> EmptyResult {
    let user_org = match UserOrganization::find_by_uuid(user_org, conn).await {
        Some(user_org) => user_org,
        None => err!("The user hasn't been invited to the organization."),
    };

    if user_org.status != UserOrgStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let user = match User::find_by_uuid(&user_org.user_uuid, conn).await {
        Some(user) => user,
        None => err!("User not found."),
    };

    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err!("Invitations are not allowed.")
    }

    let org_name = match Organization::find_by_uuid(org_id, conn).await {
        Some(org) => org.name,
        None => err!("Error looking up organization."),
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(
            &user,
            Some(org_id.to_string()),
            Some(user_org.uuid),
            &org_name,
            Some(invited_by_email.to_string()),
        )
        .await?;
    } else if user.password_hash.is_empty() {
        let invitation = Invitation::new(&user.email);
        invitation.save(conn).await?;
    } else {
        let _ = Invitation::take(&user.email, conn).await;
        let mut user_org = user_org;
        user_org.status = UserOrgStatus::Accepted as i32;
        user_org.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

#[post("/organizations/<org_id>/users/<_org_user_id>/accept", data = "<data>")]
async fn accept_invite(org_id: &str, _org_user_id: &str, data: Json<AcceptData>, mut conn: DbConn) -> EmptyResult {
    // The web-vault passes org_id and org_user_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner();
    let claims = decode_invite(&data.token)?;

    match User::find_by_mail(&claims.email, &mut conn).await {
        Some(user) => {
            Invitation::take(&claims.email, &mut conn).await;

            if let (Some(user_org), Some(org)) = (&claims.user_org_id, &claims.org_id) {
                let mut user_org = match UserOrganization::find_by_uuid_and_org(user_org, org, &mut conn).await {
                    Some(user_org) => user_org,
                    None => err!("Error accepting the invitation"),
                };

                if user_org.status != UserOrgStatus::Invited as i32 {
                    err!("User already accepted the invitation")
                }

                let master_password_required = OrgPolicy::org_is_reset_password_auto_enroll(org, &mut conn).await;
                if data.reset_password_key.is_none() && master_password_required {
                    err!("Reset password key is required, but not provided.");
                }

                // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
                // It returns different error messages per function.
                if user_org.atype < UserOrgType::Admin {
                    match OrgPolicy::is_user_allowed(&user_org.user_uuid, org_id, false, &mut conn).await {
                        Ok(_) => {}
                        Err(OrgPolicyErr::TwoFactorMissing) => {
                            if CONFIG.email_2fa_auto_fallback() {
                                two_factor::email::activate_email_2fa(&user, &mut conn).await?;
                            } else {
                                err!("You cannot join this organization until you enable two-step login on your user account");
                            }
                        }
                        Err(OrgPolicyErr::SingleOrgEnforced) => {
                            err!("You cannot join this organization because you are a member of an organization which forbids it");
                        }
                    }
                }

                user_org.status = UserOrgStatus::Accepted as i32;

                if master_password_required {
                    user_org.reset_password_key = data.reset_password_key;
                }

                user_org.save(&mut conn).await?;
            }
        }
        None => err!("Invited user not found"),
    }

    if CONFIG.mail_enabled() {
        let mut org_name = CONFIG.invitation_org_name();
        if let Some(org_id) = &claims.org_id {
            org_name = match Organization::find_by_uuid(org_id, &mut conn).await {
                Some(org) => org.name,
                None => err!("Organization not found."),
            };
        };
        if let Some(invited_by_email) = &claims.invited_by_email {
            // User was invited to an organization, so they must be confirmed manually after acceptance
            mail::send_invite_accepted(&claims.email, invited_by_email, &org_name).await?;
        } else {
            // User was invited from /admin, so they are automatically confirmed
            mail::send_invite_confirmed(&claims.email, &org_name).await?;
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    id: Option<String>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

#[post("/organizations/<org_id>/users/confirm", data = "<data>")]
async fn bulk_confirm_invite(
    org_id: &str,
    data: Json<BulkConfirmData>,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> Json<Value> {
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.keys {
        Some(keys) => {
            for invite in keys {
                let org_user_id = invite.id.unwrap_or_default();
                let user_key = invite.key.unwrap_or_default();
                let err_msg = match _confirm_invite(org_id, &org_user_id, &user_key, &headers, &mut conn, &nt).await {
                    Ok(_) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationBulkConfirmResponseModel",
                        "id": org_user_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

#[post("/organizations/<org_id>/users/<org_user_id>/confirm", data = "<data>")]
async fn confirm_invite(
    org_id: &str,
    org_user_id: &str,
    data: Json<ConfirmData>,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let user_key = data.key.unwrap_or_default();
    _confirm_invite(org_id, org_user_id, &user_key, &headers, &mut conn, &nt).await
}

async fn _confirm_invite(
    org_id: &str,
    org_user_id: &str,
    key: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if key.is_empty() || org_user_id.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let mut user_to_confirm = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    if user_to_confirm.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can confirm Managers, Admins or Owners")
    }

    if user_to_confirm.status != UserOrgStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if user_to_confirm.atype < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_confirm.user_uuid, org_id, true, conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                if CONFIG.email_2fa_auto_fallback() {
                    two_factor::email::find_and_activate_email_2fa(&user_to_confirm.user_uuid, conn).await?;
                } else {
                    err!("You cannot confirm this user because they have not setup 2FA");
                }
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot confirm this user because they are a member of an organization which forbids it");
            }
        }
    }

    user_to_confirm.status = UserOrgStatus::Confirmed as i32;
    user_to_confirm.akey = key.to_string();

    log_event(
        EventType::OrganizationUserConfirmed as i32,
        &user_to_confirm.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled() {
        let org_name = match Organization::find_by_uuid(org_id, conn).await {
            Some(org) => org.name,
            None => err!("Error looking up organization."),
        };
        let address = match User::find_by_uuid(&user_to_confirm.user_uuid, conn).await {
            Some(user) => user.email,
            None => err!("Error looking up user."),
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    let save_result = user_to_confirm.save(conn).await;

    if let Some(user) = User::find_by_uuid(&user_to_confirm.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user).await;
    }

    save_result
}

#[get("/organizations/<org_id>/users/<org_user_id>?<data..>")]
async fn get_user(
    org_id: &str,
    org_user_id: &str,
    data: GetOrgUserData,
    _headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    let user = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, &mut conn).await {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    // In this case, when groups are requested we also need to include collections.
    // Else these will not be shown in the interface, and could lead to missing collections when saved.
    let include_groups = data.include_groups.unwrap_or(false);
    Ok(Json(
        user.to_json_user_details(data.include_collections.unwrap_or(include_groups), include_groups, &mut conn).await,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditUserData {
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    groups: Option<Vec<String>>,
    #[serde(default)]
    access_all: bool,
}

#[put("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
async fn put_organization_user(
    org_id: &str,
    org_user_id: &str,
    data: Json<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    edit_user(org_id, org_user_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
async fn edit_user(
    org_id: &str,
    org_user_id: &str,
    data: Json<EditUserData>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    let data: EditUserData = data.into_inner();

    let new_type = match UserOrgType::from_str(&data.r#type.into_string()) {
        Some(new_type) => new_type,
        None => err!("Invalid type"),
    };

    let mut user_to_edit = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, &mut conn).await {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    if new_type != user_to_edit.atype
        && (user_to_edit.atype >= UserOrgType::Admin || new_type >= UserOrgType::Admin)
        && headers.org_user_type != UserOrgType::Owner
    {
        err!("Only Owners can grant and remove Admin or Owner privileges")
    }

    if user_to_edit.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can edit Owner users")
    }

    if user_to_edit.atype == UserOrgType::Owner
        && new_type != UserOrgType::Owner
        && user_to_edit.status == UserOrgStatus::Confirmed as i32
    {
        // Removing owner permission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, &mut conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if new_type < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_edit.user_uuid, org_id, true, &mut conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                if CONFIG.email_2fa_auto_fallback() {
                    two_factor::email::find_and_activate_email_2fa(&user_to_edit.user_uuid, &mut conn).await?;
                } else {
                    err!("You cannot modify this user to this type because they have not setup 2FA");
                }
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because they are a member of an organization which forbids it");
            }
        }
    }

    user_to_edit.access_all = data.access_all;
    user_to_edit.atype = new_type as i32;

    // Delete all the odd collections
    for c in CollectionUser::find_by_organization_and_user_uuid(org_id, &user_to_edit.user_uuid, &mut conn).await {
        c.delete(&mut conn).await?;
    }

    // If no accessAll, add the collections received
    if !data.access_all {
        for col in data.collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&col.id, org_id, &mut conn).await {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser::save(
                        &user_to_edit.user_uuid,
                        &collection.uuid,
                        col.read_only,
                        col.hide_passwords,
                        &mut conn,
                    )
                    .await?;
                }
            }
        }
    }

    GroupUser::delete_all_by_user(&user_to_edit.uuid, &mut conn).await?;

    for group in data.groups.iter().flatten() {
        let mut group_entry = GroupUser::new(String::from(group), user_to_edit.uuid.clone());
        group_entry.save(&mut conn).await?;
    }

    log_event(
        EventType::OrganizationUserUpdated as i32,
        &user_to_edit.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    user_to_edit.save(&mut conn).await
}

#[delete("/organizations/<org_id>/users", data = "<data>")]
async fn bulk_delete_user(
    org_id: &str,
    data: Json<OrgBulkIds>,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for org_user_id in data.ids {
        let err_msg = match _delete_user(org_id, &org_user_id, &headers, &mut conn, &nt).await {
            Ok(_) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": org_user_id,
                "error": err_msg
            }
        ))
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

#[delete("/organizations/<org_id>/users/<org_user_id>")]
async fn delete_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_user(org_id, org_user_id, &headers, &mut conn, &nt).await
}

#[post("/organizations/<org_id>/users/<org_user_id>/delete")]
async fn post_delete_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_user(org_id, org_user_id, &headers, &mut conn, &nt).await
}

async fn _delete_user(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    let user_to_delete = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(user) => user,
        None => err!("User to delete isn't member of the organization"),
    };

    if user_to_delete.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can delete Admins or Owners")
    }

    if user_to_delete.atype == UserOrgType::Owner && user_to_delete.status == UserOrgStatus::Confirmed as i32 {
        // Removing owner, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    log_event(
        EventType::OrganizationUserRemoved as i32,
        &user_to_delete.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if let Some(user) = User::find_by_uuid(&user_to_delete.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user).await;
    }

    user_to_delete.delete(conn).await
}

#[post("/organizations/<org_id>/users/public-keys", data = "<data>")]
async fn bulk_public_keys(
    org_id: &str,
    data: Json<OrgBulkIds>,
    _headers: AdminHeaders,
    mut conn: DbConn,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner();

    let mut bulk_response = Vec::new();
    // Check all received UserOrg UUID's and find the matching User to retrieve the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that UserOrg UUID.
    // The web-vault will then ignore that user for the following steps.
    for user_org_id in data.ids {
        match UserOrganization::find_by_uuid_and_org(&user_org_id, org_id, &mut conn).await {
            Some(user_org) => match User::find_by_uuid(&user_org.user_uuid, &mut conn).await {
                Some(user) => bulk_response.push(json!(
                    {
                        "object": "organizationUserPublicKeyResponseModel",
                        "id": user_org_id,
                        "userId": user.uuid,
                        "key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("UserOrg doesn't exist"),
        }
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

use super::ciphers::update_cipher_from_data;
use super::ciphers::CipherData;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportData {
    ciphers: Vec<CipherData>,
    collections: Vec<NewCollectionData>,
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

#[post("/ciphers/import-organization?<query..>", data = "<data>")]
async fn post_org_import(
    query: OrgIdData,
    data: Json<ImportData>,
    headers: AdminHeaders,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data: ImportData = data.into_inner();
    let org_id = query.organization_id;

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    let mut collections = Vec::new();
    for coll in data.collections {
        let collection = Collection::new(org_id.clone(), coll.name, coll.external_id);
        if collection.save(&mut conn).await.is_err() {
            collections.push(Err(Error::new("Failed to create Collection", "Failed to create Collection")));
        } else {
            collections.push(Ok(collection));
        }
    }

    // Read the relations between collections and ciphers
    let mut relations = Vec::new();
    for relation in data.collection_relationships {
        relations.push((relation.key, relation.value));
    }

    let headers: Headers = headers.into();

    let mut ciphers = Vec::new();
    for cipher_data in data.ciphers {
        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        update_cipher_from_data(&mut cipher, cipher_data, &headers, None, &mut conn, &nt, UpdateType::None).await.ok();
        ciphers.push(cipher);
    }

    // Assign the collections
    for (cipher_index, coll_index) in relations {
        let cipher_id = &ciphers[cipher_index].uuid;
        let coll = &collections[coll_index];
        let coll_id = match coll {
            Ok(coll) => coll.uuid.as_str(),
            Err(_) => err!("Failed to assign to collection"),
        };

        CollectionCipher::save(cipher_id, coll_id, &mut conn).await?;
    }

    let mut user = headers.user;
    user.update_revision(&mut conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct BulkCollectionsData {
    organization_id: String,
    cipher_ids: Vec<String>,
    collection_ids: HashSet<String>,
    remove_collections: bool,
}

// This endpoint is only reachable via the organization view, therefor this endpoint is located here
// Also Bitwarden does not send out Notifications for these changes, it only does this for individual cipher collection updates
#[post("/ciphers/bulk-collections", data = "<data>")]
async fn post_bulk_collections(data: Json<BulkCollectionsData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    let data: BulkCollectionsData = data.into_inner();

    // This feature does not seem to be active on all the clients
    // To prevent future issues, add a check to block a call when this is set to true
    if data.remove_collections {
        err!("Bulk removing of collections is not yet implemented")
    }

    // Get all the collection available to the user in one query
    // Also filter based upon the provided collections
    let user_collections: HashMap<String, Collection> =
        Collection::find_by_organization_and_user_uuid(&data.organization_id, &headers.user.uuid, &mut conn)
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

    // Verify if all the collections requested exists and are writeable for the user, else abort
    for collection_uuid in &data.collection_ids {
        match user_collections.get(collection_uuid) {
            Some(collection) if collection.is_writable_by_user(&headers.user.uuid, &mut conn).await => (),
            _ => err_code!("Resource not found", "User does not have access to a collection", 404),
        }
    }

    for cipher_id in data.cipher_ids.iter() {
        // Only act on existing cipher uuid's
        // Do not abort the operation just ignore it, it could be a cipher was just deleted for example
        if let Some(cipher) = Cipher::find_by_uuid_and_org(cipher_id, &data.organization_id, &mut conn).await {
            if cipher.is_write_accessible_to_user(&headers.user.uuid, &mut conn).await {
                for collection in &data.collection_ids {
                    CollectionCipher::save(&cipher.uuid, collection, &mut conn).await?;
                }
            }
        };
    }

    Ok(())
}

#[get("/organizations/<org_id>/policies")]
async fn list_policies(org_id: &str, _headers: AdminHeaders, mut conn: DbConn) -> Json<Value> {
    let policies = OrgPolicy::find_by_org(org_id, &mut conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    }))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
async fn list_policies_token(org_id: &str, token: &str, mut conn: DbConn) -> JsonResult {
    // web-vault 2024.6.2 seems to send these values and cause logs to output errors
    // Catch this and prevent errors in the logs
    // TODO: CleanUp after 2024.6.x is not used anymore.
    if org_id == "undefined" && token == "undefined" {
        return Ok(Json(json!({})));
    }

    let invite = decode_invite(token)?;

    let invite_org_id = match invite.org_id {
        Some(invite_org_id) => invite_org_id,
        None => err!("Invalid token"),
    };

    if invite_org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(org_id, &mut conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/<pol_type>")]
async fn get_policy(org_id: &str, pol_type: i32, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid or unsupported policy type"),
    };

    let policy = match OrgPolicy::find_by_org_and_type(org_id, pol_type_enum, &mut conn).await {
        Some(p) => p,
        None => OrgPolicy::new(String::from(org_id), pol_type_enum, "null".to_string()),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    #[serde(rename = "type")]
    _type: i32,
    data: Option<Value>,
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
async fn put_policy(
    org_id: &str,
    pol_type: i32,
    data: Json<PolicyData>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    let data: PolicyData = data.into_inner();

    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid or unsupported policy type"),
    };

    // Bitwarden only allows the Reset Password policy when Single Org policy is enabled
    // Vaultwarden encouraged to use multiple orgs instead of groups because groups were not available in the past
    // Now that groups are available we can enforce this option when wanted.
    // We put this behind a config option to prevent breaking current installation.
    // Maybe we want to enable this by default in the future, but currently it is disabled by default.
    if CONFIG.enforce_single_org_with_reset_pw_policy() {
        if pol_type_enum == OrgPolicyType::ResetPassword && data.enabled {
            let single_org_policy_enabled =
                match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::SingleOrg, &mut conn).await {
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
                match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, &mut conn).await {
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
            org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &mut conn,
        )
        .await?;
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type_enum == OrgPolicyType::SingleOrg && data.enabled {
        for member in UserOrganization::find_by_org(org_id, &mut conn).await.into_iter() {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            // We check if the count is larger then 1, because it includes this organization also.
            if member.atype < UserOrgType::Admin
                && member.status != UserOrgStatus::Invited as i32
                && UserOrganization::count_accepted_and_confirmed_by_user(&member.user_uuid, &mut conn).await > 1
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, &mut conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, &mut conn).await.unwrap();

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(
                    EventType::OrganizationUserRemoved as i32,
                    &member.uuid,
                    org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    &mut conn,
                )
                .await;

                member.delete(&mut conn).await?;
            }
        }
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(org_id, pol_type_enum, &mut conn).await {
        Some(p) => p,
        None => OrgPolicy::new(String::from(org_id), pol_type_enum, "{}".to_string()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(&mut conn).await?;

    log_event(
        EventType::PolicyUpdated as i32,
        &policy.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    Ok(Json(policy.to_json()))
}

#[allow(unused_variables)]
#[get("/organizations/<org_id>/tax")]
fn get_organization_tax(org_id: &str, _headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    // Upstream sends "Only allowed when not self hosted." As an error message.
    // If we do the same it will also output this to the log, which is overkill.
    // An empty list/data also works fine.
    Json(_empty_data_json())
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

#[get("/plans/all")]
fn get_plans_all() -> Json<Value> {
    get_plans()
}

#[get("/plans/sales-tax-rates")]
fn get_plans_tax_rates(_headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(_empty_data_json())
}

fn _empty_data_json() -> Value {
    json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    #[allow(dead_code)]
    name: String, // "GroupName"
    #[allow(dead_code)]
    external_id: String, // "cn=GroupName,ou=Groups,dc=example,dc=com"
    #[allow(dead_code)]
    users: Vec<String>, // ["uid=user,ou=People,dc=example,dc=com"]
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String, // "user@maildomain.net"
    #[allow(dead_code)]
    external_id: String, // "uid=user,ou=People,dc=example,dc=com"
    deleted: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    #[allow(dead_code)]
    groups: Vec<OrgImportGroupData>,
    overwrite_existing: bool,
    users: Vec<OrgImportUserData>,
}

#[post("/organizations/<org_id>/import", data = "<data>")]
async fn import(org_id: &str, data: Json<OrgImportData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    let data = data.into_inner();

    // TODO: Currently we aren't storing the externalId's anywhere, so we also don't have a way
    // to differentiate between auto-imported users and manually added ones.
    // This means that this endpoint can end up removing users that were added manually by an admin,
    // as opposed to upstream which only removes auto-imported users.

    // User needs to be admin or owner to use the Directory Connector
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, org_id, &mut conn).await {
        Some(user_org) if user_org.atype >= UserOrgType::Admin => { /* Okay, nothing to do */ }
        Some(_) => err!("User has insufficient permissions to use Directory Connector"),
        None => err!("User not part of organization"),
    };

    for user_data in &data.users {
        if user_data.deleted {
            // If user is marked for deletion and it exists, delete it
            if let Some(user_org) = UserOrganization::find_by_email_and_org(&user_data.email, org_id, &mut conn).await {
                log_event(
                    EventType::OrganizationUserRemoved as i32,
                    &user_org.uuid,
                    org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    &mut conn,
                )
                .await;

                user_org.delete(&mut conn).await?;
            }

        // If user is not part of the organization, but it exists
        } else if UserOrganization::find_by_email_and_org(&user_data.email, org_id, &mut conn).await.is_none() {
            if let Some(user) = User::find_by_mail(&user_data.email, &mut conn).await {
                let user_org_status = if CONFIG.mail_enabled() {
                    UserOrgStatus::Invited as i32
                } else {
                    UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
                };

                let mut new_org_user = UserOrganization::new(user.uuid.clone(), String::from(org_id));
                new_org_user.access_all = false;
                new_org_user.atype = UserOrgType::User as i32;
                new_org_user.status = user_org_status;

                new_org_user.save(&mut conn).await?;

                log_event(
                    EventType::OrganizationUserInvited as i32,
                    &new_org_user.uuid,
                    org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    &mut conn,
                )
                .await;

                if CONFIG.mail_enabled() {
                    let org_name = match Organization::find_by_uuid(org_id, &mut conn).await {
                        Some(org) => org.name,
                        None => err!("Error looking up organization"),
                    };

                    mail::send_invite(
                        &user,
                        Some(String::from(org_id)),
                        Some(new_org_user.uuid),
                        &org_name,
                        Some(headers.user.email.clone()),
                    )
                    .await?;
                }
            }
        }
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        for user_org in UserOrganization::find_by_org_and_type(org_id, UserOrgType::User, &mut conn).await {
            if let Some(user_email) = User::find_by_uuid(&user_org.user_uuid, &mut conn).await.map(|u| u.email) {
                if !data.users.iter().any(|u| u.email == user_email) {
                    log_event(
                        EventType::OrganizationUserRemoved as i32,
                        &user_org.uuid,
                        org_id,
                        &headers.user.uuid,
                        headers.device.atype,
                        &headers.ip.ip,
                        &mut conn,
                    )
                    .await;

                    user_org.delete(&mut conn).await?;
                }
            }
        }
    }

    Ok(())
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/<org_user_id>/deactivate")]
async fn deactivate_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    _revoke_organization_user(org_id, org_user_id, &headers, &mut conn).await
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/deactivate", data = "<data>")]
async fn bulk_deactivate_organization_user(
    org_id: &str,
    data: Json<OrgBulkRevokeData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    bulk_revoke_organization_user(org_id, data, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/revoke")]
async fn revoke_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    _revoke_organization_user(org_id, org_user_id, &headers, &mut conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrgBulkRevokeData {
    ids: Option<Vec<String>>,
}

#[put("/organizations/<org_id>/users/revoke", data = "<data>")]
async fn bulk_revoke_organization_user(
    org_id: &str,
    data: Json<OrgBulkRevokeData>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> Json<Value> {
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.ids {
        Some(org_users) => {
            for org_user_id in org_users {
                let err_msg = match _revoke_organization_user(org_id, &org_user_id, &headers, &mut conn).await {
                    Ok(_) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationUserBulkResponseModel",
                        "id": org_user_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

async fn _revoke_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
) -> EmptyResult {
    match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(mut user_org) if user_org.status > UserOrgStatus::Revoked as i32 => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can revoke other owners")
            }
            if user_org.atype == UserOrgType::Owner
                && UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, conn).await <= 1
            {
                err!("Organization must have at least one confirmed owner")
            }

            user_org.revoke();
            user_org.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked as i32,
                &user_org.uuid,
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

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/<org_user_id>/activate")]
async fn activate_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    _restore_organization_user(org_id, org_user_id, &headers, &mut conn).await
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/activate", data = "<data>")]
async fn bulk_activate_organization_user(
    org_id: &str,
    data: Json<OrgBulkIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    bulk_restore_organization_user(org_id, data, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/restore")]
async fn restore_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    _restore_organization_user(org_id, org_user_id, &headers, &mut conn).await
}

#[put("/organizations/<org_id>/users/restore", data = "<data>")]
async fn bulk_restore_organization_user(
    org_id: &str,
    data: Json<OrgBulkIds>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> Json<Value> {
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    for org_user_id in data.ids {
        let err_msg = match _restore_organization_user(org_id, &org_user_id, &headers, &mut conn).await {
            Ok(_) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationUserBulkResponseModel",
                "id": org_user_id,
                "error": err_msg
            }
        ));
    }

    Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    }))
}

async fn _restore_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
) -> EmptyResult {
    match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(mut user_org) if user_org.status < UserOrgStatus::Accepted as i32 => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can restore other owners")
            }

            // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
            // It returns different error messages per function.
            if user_org.atype < UserOrgType::Admin {
                match OrgPolicy::is_user_allowed(&user_org.user_uuid, org_id, false, conn).await {
                    Ok(_) => {}
                    Err(OrgPolicyErr::TwoFactorMissing) => {
                        if CONFIG.email_2fa_auto_fallback() {
                            two_factor::email::find_and_activate_email_2fa(&user_org.user_uuid, conn).await?;
                        } else {
                            err!("You cannot restore this user because they have not setup 2FA");
                        }
                    }
                    Err(OrgPolicyErr::SingleOrgEnforced) => {
                        err!("You cannot restore this user because they are a member of an organization which forbids it");
                    }
                }
            }

            user_org.restore();
            user_org.save(conn).await?;

            log_event(
                EventType::OrganizationUserRestored as i32,
                &user_org.uuid,
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

#[get("/organizations/<org_id>/groups")]
async fn get_groups(org_id: &str, _headers: ManagerHeadersLoose, mut conn: DbConn) -> JsonResult {
    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        // Group::find_by_organization(&org_id, &mut conn).await.iter().map(Group::to_json).collect::<Value>()
        let groups = Group::find_by_organization(org_id, &mut conn).await;
        let mut groups_json = Vec::with_capacity(groups.len());

        for g in groups {
            groups_json.push(g.to_json_details(&mut conn).await)
        }
        groups_json
    } else {
        // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
        // so just act as if there are no groups.
        Vec::with_capacity(0)
    };

    Ok(Json(json!({
        "data": groups,
        "object": "list",
        "continuationToken": null,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    collections: Vec<SelectionReadOnly>,
    users: Vec<String>,
}

impl GroupRequest {
    pub fn to_group(&self, organizations_uuid: &str) -> Group {
        Group::new(String::from(organizations_uuid), self.name.clone(), self.access_all, self.external_id.clone())
    }

    pub fn update_group(&self, mut group: Group) -> Group {
        group.name.clone_from(&self.name);
        group.access_all = self.access_all;
        // Group Updates do not support changing the external_id
        // These input fields are in a disabled state, and can only be updated/added via ldap_import

        group
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SelectionReadOnly {
    id: String,
    read_only: bool,
    hide_passwords: bool,
}

impl SelectionReadOnly {
    pub fn to_collection_group(&self, groups_uuid: String) -> CollectionGroup {
        CollectionGroup::new(self.id.clone(), groups_uuid, self.read_only, self.hide_passwords)
    }

    pub fn to_collection_group_details_read_only(collection_group: &CollectionGroup) -> SelectionReadOnly {
        SelectionReadOnly {
            id: collection_group.groups_uuid.clone(),
            read_only: collection_group.read_only,
            hide_passwords: collection_group.hide_passwords,
        }
    }

    pub fn to_collection_user_details_read_only(collection_user: &CollectionUser) -> SelectionReadOnly {
        SelectionReadOnly {
            id: collection_user.user_uuid.clone(),
            read_only: collection_user.read_only,
            hide_passwords: collection_user.hide_passwords,
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}

#[post("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn post_group(
    org_id: &str,
    group_id: &str,
    data: Json<GroupRequest>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    put_group(org_id, group_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/groups", data = "<data>")]
async fn post_groups(org_id: &str, headers: AdminHeaders, data: Json<GroupRequest>, mut conn: DbConn) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group_request = data.into_inner();
    let group = group_request.to_group(org_id);

    log_event(
        EventType::GroupCreated as i32,
        &group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    add_update_group(group, group_request.collections, group_request.users, org_id, &headers, &mut conn).await
}

#[put("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn put_group(
    org_id: &str,
    group_id: &str,
    data: Json<GroupRequest>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = match Group::find_by_uuid(group_id, &mut conn).await {
        Some(group) => group,
        None => err!("Group not found"),
    };

    let group_request = data.into_inner();
    let updated_group = group_request.update_group(group);

    CollectionGroup::delete_all_by_group(group_id, &mut conn).await?;
    GroupUser::delete_all_by_group(group_id, &mut conn).await?;

    log_event(
        EventType::GroupUpdated as i32,
        &updated_group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    add_update_group(updated_group, group_request.collections, group_request.users, org_id, &headers, &mut conn).await
}

async fn add_update_group(
    mut group: Group,
    collections: Vec<SelectionReadOnly>,
    users: Vec<String>,
    org_id: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
) -> JsonResult {
    group.save(conn).await?;

    for selection_read_only_request in collections {
        let mut collection_group = selection_read_only_request.to_collection_group(group.uuid.clone());
        collection_group.save(conn).await?;
    }

    for assigned_user_id in users {
        let mut user_entry = GroupUser::new(group.uuid.clone(), assigned_user_id.clone());
        user_entry.save(conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups as i32,
            &assigned_user_id,
            org_id,
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
        "externalId": group.external_id
    })))
}

#[get("/organizations/<_org_id>/groups/<group_id>/details")]
async fn get_group_details(_org_id: &str, group_id: &str, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = match Group::find_by_uuid(group_id, &mut conn).await {
        Some(group) => group,
        _ => err!("Group could not be found!"),
    };

    Ok(Json(group.to_json_details(&mut conn).await))
}

#[post("/organizations/<org_id>/groups/<group_id>/delete")]
async fn post_delete_group(org_id: &str, group_id: &str, headers: AdminHeaders, mut conn: DbConn) -> EmptyResult {
    _delete_group(org_id, group_id, &headers, &mut conn).await
}

#[delete("/organizations/<org_id>/groups/<group_id>")]
async fn delete_group(org_id: &str, group_id: &str, headers: AdminHeaders, mut conn: DbConn) -> EmptyResult {
    _delete_group(org_id, group_id, &headers, &mut conn).await
}

async fn _delete_group(org_id: &str, group_id: &str, headers: &AdminHeaders, conn: &mut DbConn) -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = match Group::find_by_uuid(group_id, conn).await {
        Some(group) => group,
        _ => err!("Group not found"),
    };

    log_event(
        EventType::GroupDeleted as i32,
        &group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    group.delete(conn).await
}

#[delete("/organizations/<org_id>/groups", data = "<data>")]
async fn bulk_delete_groups(
    org_id: &str,
    data: Json<OrgBulkIds>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let data: OrgBulkIds = data.into_inner();

    for group_id in data.ids {
        _delete_group(org_id, &group_id, &headers, &mut conn).await?
    }
    Ok(())
}

#[get("/organizations/<_org_id>/groups/<group_id>")]
async fn get_group(_org_id: &str, group_id: &str, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = match Group::find_by_uuid(group_id, &mut conn).await {
        Some(group) => group,
        _ => err!("Group not found"),
    };

    Ok(Json(group.to_json()))
}

#[get("/organizations/<_org_id>/groups/<group_id>/users")]
async fn get_group_users(_org_id: &str, group_id: &str, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    match Group::find_by_uuid(group_id, &mut conn).await {
        Some(_) => { /* Do nothing */ }
        _ => err!("Group could not be found!"),
    };

    let group_users: Vec<String> = GroupUser::find_by_group(group_id, &mut conn)
        .await
        .iter()
        .map(|entry| entry.users_organizations_uuid.clone())
        .collect();

    Ok(Json(json!(group_users)))
}

#[put("/organizations/<org_id>/groups/<group_id>/users", data = "<data>")]
async fn put_group_users(
    org_id: &str,
    group_id: &str,
    headers: AdminHeaders,
    data: Json<Vec<String>>,
    mut conn: DbConn,
) -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    match Group::find_by_uuid(group_id, &mut conn).await {
        Some(_) => { /* Do nothing */ }
        _ => err!("Group could not be found!"),
    };

    GroupUser::delete_all_by_group(group_id, &mut conn).await?;

    let assigned_user_ids = data.into_inner();
    for assigned_user_id in assigned_user_ids {
        let mut user_entry = GroupUser::new(String::from(group_id), assigned_user_id.clone());
        user_entry.save(&mut conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups as i32,
            &assigned_user_id,
            org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &mut conn,
        )
        .await;
    }

    Ok(())
}

#[get("/organizations/<_org_id>/users/<user_id>/groups")]
async fn get_user_groups(_org_id: &str, user_id: &str, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    match UserOrganization::find_by_uuid(user_id, &mut conn).await {
        Some(_) => { /* Do nothing */ }
        _ => err!("User could not be found!"),
    };

    let user_groups: Vec<String> =
        GroupUser::find_by_user(user_id, &mut conn).await.iter().map(|entry| entry.groups_uuid.clone()).collect();

    Ok(Json(json!(user_groups)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserUpdateGroupsRequest {
    group_ids: Vec<String>,
}

#[post("/organizations/<org_id>/users/<org_user_id>/groups", data = "<data>")]
async fn post_user_groups(
    org_id: &str,
    org_user_id: &str,
    data: Json<OrganizationUserUpdateGroupsRequest>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    put_user_groups(org_id, org_user_id, data, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/groups", data = "<data>")]
async fn put_user_groups(
    org_id: &str,
    org_user_id: &str,
    data: Json<OrganizationUserUpdateGroupsRequest>,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let user_org = match UserOrganization::find_by_uuid(org_user_id, &mut conn).await {
        Some(uo) => uo,
        _ => err!("User could not be found!"),
    };

    if user_org.org_uuid != org_id {
        err!("Group doesn't belong to organization");
    }

    GroupUser::delete_all_by_user(org_user_id, &mut conn).await?;

    let assigned_group_ids = data.into_inner();
    for assigned_group_id in assigned_group_ids.group_ids {
        let mut group_user = GroupUser::new(assigned_group_id.clone(), String::from(org_user_id));
        group_user.save(&mut conn).await?;
    }

    log_event(
        EventType::OrganizationUserUpdatedGroups as i32,
        org_user_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    Ok(())
}

#[post("/organizations/<org_id>/groups/<group_id>/delete-user/<org_user_id>")]
async fn post_delete_group_user(
    org_id: &str,
    group_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_group_user(org_id, group_id, org_user_id, headers, conn).await
}

#[delete("/organizations/<org_id>/groups/<group_id>/users/<org_user_id>")]
async fn delete_group_user(
    org_id: &str,
    group_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let user_org = match UserOrganization::find_by_uuid(org_user_id, &mut conn).await {
        Some(uo) => uo,
        _ => err!("User could not be found!"),
    };

    if user_org.org_uuid != org_id {
        err!("User doesn't belong to organization");
    }

    let group = match Group::find_by_uuid(group_id, &mut conn).await {
        Some(g) => g,
        _ => err!("Group could not be found!"),
    };

    if group.organizations_uuid != org_id {
        err!("Group doesn't belong to organization");
    }

    log_event(
        EventType::OrganizationUserUpdatedGroups as i32,
        org_user_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    GroupUser::delete_by_group_id_and_user_id(group_id, org_user_id, &mut conn).await
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
struct OrganizationUserResetPasswordRequest {
    new_master_password_hash: String,
    key: String,
}

// Upstrem reports this is the renamed endpoint instead of `/keys`
// But the clients do not seem to use this at all
// Just add it here in case they will
#[get("/organizations/<org_id>/public-key")]
async fn get_organization_public_key(org_id: &str, _headers: Headers, mut conn: DbConn) -> JsonResult {
    let org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(organization) => organization,
        None => err!("Organization not found"),
    };

    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

// Obsolete - Renamed to public-key (2023.8), left for backwards compatibility with older clients
// https://github.com/bitwarden/server/blob/25dc0c9178e3e3584074bbef0d4be827b7c89415/src/Api/AdminConsole/Controllers/OrganizationsController.cs#L463-L468
#[get("/organizations/<org_id>/keys")]
async fn get_organization_keys(org_id: &str, headers: Headers, conn: DbConn) -> JsonResult {
    get_organization_public_key(org_id, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/reset-password", data = "<data>")]
async fn put_reset_password(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    data: Json<OrganizationUserResetPasswordRequest>,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(org) => org,
        None => err!("Required organization not found"),
    };

    let org_user = match UserOrganization::find_by_uuid_and_org(org_user_id, &org.uuid, &mut conn).await {
        Some(user) => user,
        None => err!("User to reset isn't member of required organization"),
    };

    let user = match User::find_by_uuid(&org_user.user_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("User not found"),
    };

    check_reset_password_applicable_and_permissions(org_id, org_user_id, &headers, &mut conn).await?;

    if org_user.reset_password_key.is_none() {
        err!("Password reset not or not correctly enrolled");
    }
    if org_user.status != (UserOrgStatus::Confirmed as i32) {
        err!("Organization user must be confirmed for password reset functionality");
    }

    // Sending email before resetting password to ensure working email configuration and the resulting
    // user notification. Also this might add some protection against security flaws and misuse
    if let Err(e) = mail::send_admin_reset_password(&user.email, &user.name, &org.name).await {
        err!(format!("Error sending user reset password email: {e:#?}"));
    }

    let reset_request = data.into_inner();

    let mut user = user;
    user.set_password(reset_request.new_master_password_hash.as_str(), Some(reset_request.key), true, None);
    user.save(&mut conn).await?;

    nt.send_logout(&user, None).await;

    log_event(
        EventType::OrganizationUserAdminResetPassword as i32,
        org_user_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    Ok(())
}

#[get("/organizations/<org_id>/users/<org_user_id>/reset-password-details")]
async fn get_reset_password_details(
    org_id: &str,
    org_user_id: &str,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    let org = match Organization::find_by_uuid(org_id, &mut conn).await {
        Some(org) => org,
        None => err!("Required organization not found"),
    };

    let org_user = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, &mut conn).await {
        Some(user) => user,
        None => err!("User to reset isn't member of required organization"),
    };

    let user = match User::find_by_uuid(&org_user.user_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("User not found"),
    };

    check_reset_password_applicable_and_permissions(org_id, org_user_id, &headers, &mut conn).await?;

    // https://github.com/bitwarden/server/blob/3b50ccb9f804efaacdc46bed5b60e5b28eddefcf/src/Api/Models/Response/Organizations/OrganizationUserResponseModel.cs#L111
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "kdf":user.client_kdf_type,
        "kdfIterations":user.client_kdf_iter,
        "kdfMemory":user.client_kdf_memory,
        "kdfParallelism":user.client_kdf_parallelism,
        "resetPasswordKey":org_user.reset_password_key,
        "encryptedPrivateKey":org.private_key,

    })))
}

async fn check_reset_password_applicable_and_permissions(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &mut DbConn,
) -> EmptyResult {
    check_reset_password_applicable(org_id, conn).await?;

    let target_user = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(user) => user,
        None => err!("Reset target user not found"),
    };

    // Resetting user must be higher/equal to user to reset
    match headers.org_user_type {
        UserOrgType::Owner => Ok(()),
        UserOrgType::Admin if target_user.atype <= UserOrgType::Admin => Ok(()),
        _ => err!("No permission to reset this user's password"),
    }
}

async fn check_reset_password_applicable(org_id: &str, conn: &mut DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Password reset is not supported on an email-disabled instance.");
    }

    let policy = match OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, conn).await {
        Some(p) => p,
        None => err!("Policy not found"),
    };

    if !policy.enabled {
        err!("Reset password policy not enabled");
    }

    Ok(())
}

#[put("/organizations/<org_id>/users/<org_user_id>/reset-password-enrollment", data = "<data>")]
async fn put_reset_password_enrollment(
    org_id: &str,
    org_user_id: &str,
    headers: Headers,
    data: Json<OrganizationUserResetPasswordEnrollmentRequest>,
    mut conn: DbConn,
) -> EmptyResult {
    let mut org_user = match UserOrganization::find_by_user_and_org(&headers.user.uuid, org_id, &mut conn).await {
        Some(u) => u,
        None => err!("User to enroll isn't member of required organization"),
    };

    check_reset_password_applicable(org_id, &mut conn).await?;

    let reset_request = data.into_inner();

    if reset_request.reset_password_key.is_none()
        && OrgPolicy::org_is_reset_password_auto_enroll(org_id, &mut conn).await
    {
        err!("Reset password can't be withdrawed due to an enterprise policy");
    }

    if reset_request.reset_password_key.is_some() {
        PasswordOrOtpData {
            master_password_hash: reset_request.master_password_hash,
            otp: reset_request.otp,
        }
        .validate(&headers.user, true, &mut conn)
        .await?;
    }

    org_user.reset_password_key = reset_request.reset_password_key;
    org_user.save(&mut conn).await?;

    let log_id = if org_user.reset_password_key.is_some() {
        EventType::OrganizationUserResetPasswordEnroll as i32
    } else {
        EventType::OrganizationUserResetPasswordWithdraw as i32
    };

    log_event(log_id, org_user_id, org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &mut conn).await;

    Ok(())
}

// This is a new function active since the v2022.9.x clients.
// It combines the previous two calls done before.
// We call those two functions here and combine them ourselves.
//
// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
#[get("/organizations/<org_id>/export")]
async fn get_org_export(
    org_id: &str,
    headers: AdminHeaders,
    client_version: Option<ClientVersion>,
    mut conn: DbConn,
) -> Json<Value> {
    // Since version v2023.1.0 the format of the export is different.
    // Also, this endpoint was created since v2022.9.0.
    // Therefore, we will check for any version smaller then v2023.1.0 and return a different response.
    // If we can't determine the version, we will use the latest default v2023.1.0 and higher.
    // https://github.com/bitwarden/server/blob/9ca93381ce416454734418c3a9f99ab49747f1b6/src/Api/Controllers/OrganizationExportController.cs#L44
    let use_list_response_model = if let Some(client_version) = client_version {
        let ver_match = semver::VersionReq::parse("<2023.1.0").unwrap();
        ver_match.matches(&client_version.0)
    } else {
        false
    };

    // Also both main keys here need to be lowercase, else the export will fail.
    if use_list_response_model {
        // Backwards compatible pre v2023.1.0 response
        Json(json!({
            "collections": {
                "data": convert_json_key_lcase_first(_get_org_collections(org_id, &mut conn).await),
                "object": "list",
                "continuationToken": null,
            },
            "ciphers": {
                "data": convert_json_key_lcase_first(_get_org_details(org_id, &headers.host, &headers.user.uuid, &mut conn).await),
                "object": "list",
                "continuationToken": null,
            }
        }))
    } else {
        // v2023.1.0 and newer response
        Json(json!({
            "collections": convert_json_key_lcase_first(_get_org_collections(org_id, &mut conn).await),
            "ciphers": convert_json_key_lcase_first(_get_org_details(org_id, &headers.host, &headers.user.uuid, &mut conn).await),
        }))
    }
}

async fn _api_key(
    org_id: &str,
    data: Json<PasswordOrOtpData>,
    rotate: bool,
    headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    // Validate the admin users password/otp
    data.validate(&user, true, &mut conn).await?;

    let org_api_key = match OrganizationApiKey::find_by_org_uuid(org_id, &conn).await {
        Some(mut org_api_key) => {
            if rotate {
                org_api_key.api_key = crate::crypto::generate_api_key();
                org_api_key.revision_date = chrono::Utc::now().naive_utc();
                org_api_key.save(&conn).await.expect("Error rotating organization API Key");
            }
            org_api_key
        }
        None => {
            let api_key = crate::crypto::generate_api_key();
            let new_org_api_key = OrganizationApiKey::new(String::from(org_id), api_key);
            new_org_api_key.save(&conn).await.expect("Error creating organization API Key");
            new_org_api_key
        }
    };

    Ok(Json(json!({
      "apiKey": org_api_key.api_key,
      "revisionDate": crate::util::format_date(&org_api_key.revision_date),
      "object": "apiKey",
    })))
}

#[post("/organizations/<org_id>/api-key", data = "<data>")]
async fn api_key(org_id: &str, data: Json<PasswordOrOtpData>, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    _api_key(org_id, data, false, headers, conn).await
}

#[post("/organizations/<org_id>/rotate-api-key", data = "<data>")]
async fn rotate_api_key(
    org_id: &str,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    _api_key(org_id, data, true, headers, conn).await
}
