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
            Collection, CollectionGroup, CollectionId, CollectionUser, Group, GroupId, GroupUser, Invitation,
            Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization, OrganizationApiKey,
            OrganizationId, User,
        },
    },
    mail,
};

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
