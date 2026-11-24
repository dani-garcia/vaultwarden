use std::collections::HashSet;

use chrono::Utc;
use rocket::{
    Request, Route,
    request::{FromRequest, Outcome},
    serde::json::Json,
};

use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth,
    db::{
        DbConn,
        models::{
            Collection, CollectionGroup, CollectionId, Group, GroupId, GroupUser, Invitation, Membership,
            MembershipStatus, MembershipType, OrgPolicy, Organization, OrganizationApiKey, OrganizationId, User,
        },
    },
    mail,
};

pub fn routes() -> Vec<Route> {
    routes![ldap_import, get_groups, get_group, get_group_member_ids, get_collections, get_collection, put_collection]
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

    // Like upstream, the import never removes Owners, so it doesn't revoke or restore them either.
    for user_data in &data.members {
        let mut user_created: bool = false;
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
                let revoked = member.atype != MembershipType::Owner && member.revoke();
                let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    member.save(&conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
            let mut restored = member.atype != MembershipType::Owner && member.restore();
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
            let group_uuid = if let Some(mut group) =
                Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &conn).await
            {
                if group.name != group_data.name {
                    group.name = group_data.name.clone();
                    group.save(&conn).await?;
                }
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
                    let group_user = GroupUser::new(group_uuid.clone(), member.uuid.clone());
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
                && member.atype != MembershipType::Owner
            {
                member.delete(&conn).await?;
            }
        }
    }

    Ok(())
}

// Groups and collections, as in Bitwarden's public API (`/public/groups`, `/public/collections`):
// https://github.com/bitwarden/server/blob/main/src/Api/AdminConsole/Public/Controllers/GroupsController.cs
// https://github.com/bitwarden/server/blob/main/src/Api/AdminConsole/Public/Controllers/CollectionsController.cs
// Same response shapes, so tools written for Bitwarden's organization API key work here too.

fn check_groups_enabled() -> EmptyResult {
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }
    Ok(())
}

fn association_json(id: &impl serde::Serialize, read_only: bool, hide_passwords: bool, manage: bool) -> Value {
    json!({
        "id": id,
        "readOnly": read_only,
        "hidePasswords": hide_passwords,
        "manage": manage,
    })
}

async fn public_group_json(group: &Group, conn: &DbConn) -> Value {
    let collections: Vec<Value> = CollectionGroup::find_by_group(&group.uuid, &group.organizations_uuid, conn)
        .await
        .iter()
        .map(|cg| association_json(&cg.collections_uuid, cg.read_only, cg.hide_passwords, cg.manage))
        .collect();
    json!({
        "object": "group",
        "id": group.uuid,
        "name": group.name,
        "externalId": group.external_id,
        "collections": collections,
    })
}

async fn public_collection_json(collection: &Collection, conn: &DbConn) -> Value {
    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        CollectionGroup::find_by_collection(&collection.uuid, conn)
            .await
            .iter()
            .map(|cg| association_json(&cg.groups_uuid, cg.read_only, cg.hide_passwords, cg.manage))
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "object": "collection",
        "id": collection.uuid,
        "externalId": collection.external_id,
        "groups": groups,
    })
}

#[get("/public/groups")]
async fn get_groups(token: PublicToken, conn: DbConn) -> JsonResult {
    check_groups_enabled()?;
    let mut data = Vec::new();
    for group in Group::find_by_organization(&token.0, &conn).await {
        data.push(public_group_json(&group, &conn).await);
    }
    Ok(Json(json!({
        "object": "list",
        "data": data,
    })))
}

#[get("/public/groups/<group_id>")]
async fn get_group(group_id: GroupId, token: PublicToken, conn: DbConn) -> JsonResult {
    check_groups_enabled()?;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &token.0, &conn).await else {
        err_code!("Group not found", "Group does not exist or does not belong to this organization", 404)
    };
    Ok(Json(public_group_json(&group, &conn).await))
}

#[get("/public/groups/<group_id>/member-ids")]
async fn get_group_member_ids(group_id: GroupId, token: PublicToken, conn: DbConn) -> JsonResult {
    check_groups_enabled()?;
    if Group::find_by_uuid_and_org(&group_id, &token.0, &conn).await.is_none() {
        err_code!("Group not found", "Group does not exist or does not belong to this organization", 404)
    }
    let member_ids: Vec<Value> = GroupUser::find_by_group(&group_id, &token.0, &conn)
        .await
        .iter()
        .map(|gu| json!(gu.users_organizations_uuid))
        .collect();
    Ok(Json(Value::Array(member_ids)))
}

#[get("/public/collections")]
async fn get_collections(token: PublicToken, conn: DbConn) -> JsonResult {
    let mut data = Vec::new();
    for collection in Collection::find_by_organization(&token.0, &conn).await {
        data.push(public_collection_json(&collection, &conn).await);
    }
    Ok(Json(json!({
        "object": "list",
        "data": data,
    })))
}

#[get("/public/collections/<col_id>")]
async fn get_collection(col_id: CollectionId, token: PublicToken, conn: DbConn) -> JsonResult {
    let Some(collection) = Collection::find_by_uuid_and_org(&col_id, &token.0, &conn).await else {
        err_code!("Collection not found", "Collection does not exist or does not belong to this organization", 404)
    };
    Ok(Json(public_collection_json(&collection, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicCollectionGroupData {
    id: GroupId,
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicCollectionUpdateData {
    external_id: Option<String>,
    groups: Option<Vec<PublicCollectionGroupData>>,
}

// Sets the collection's external id and, when `groups` is given, replaces its group access. The name (encrypted
// with the organization key) and the access of individual members are left as they are, as in Bitwarden.
#[put("/public/collections/<col_id>", data = "<data>")]
async fn put_collection(
    col_id: CollectionId,
    data: Json<PublicCollectionUpdateData>,
    token: PublicToken,
    conn: DbConn,
) -> JsonResult {
    let org_id = token.0;
    let data = data.into_inner();
    let Some(mut collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err_code!("Collection not found", "Collection does not exist or does not belong to this organization", 404)
    };

    if let Some(groups) = &data.groups {
        check_groups_enabled()?;
        // Validate every group first, so a bad id changes nothing.
        let mut seen = HashSet::new();
        for group in groups {
            if !seen.insert(group.id.clone()) {
                err!("Duplicate group in the request");
            }
            if Group::find_by_uuid_and_org(&group.id, &org_id, &conn).await.is_none() {
                err!("Group not found", "Group does not exist or does not belong to this organization");
            }
        }
    }

    collection.external_id = data.external_id.filter(|e| !e.trim().is_empty());
    collection.save(&conn).await?;

    if let Some(groups) = data.groups {
        CollectionGroup::delete_all_by_collection(&col_id, &org_id, &conn).await?;
        for group in groups {
            CollectionGroup::new(col_id.clone(), group.id, group.read_only, group.hide_passwords, group.manage)
                .save(&org_id, &conn)
                .await?;
        }
    }

    Ok(Json(public_collection_json(&collection, &conn).await))
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

        Outcome::Success(Self(claims.client_sub))
    }
}
