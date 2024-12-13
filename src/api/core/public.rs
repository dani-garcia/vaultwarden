use chrono::Utc;
use rocket::{
    request::{FromRequest, Outcome},
    serde::json::Json,
    Request, Route,
};

use std::collections::HashSet;

use crate::{
    api::EmptyResult,
    auth,
    db::{models::*, DbConn},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![ldap_import]
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
async fn ldap_import(data: Json<OrgImportData>, token: PublicToken, mut conn: DbConn) -> EmptyResult {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/fd892b2ff4547648a276734fb2b14a8abae2c6f5/src/Core/Services/Implementations/OrganizationService.cs#L1797

    let org_id = token.0;
    let data = data.into_inner();

    for user_data in &data.members {
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut user_org) =
                UserOrganization::find_by_email_and_org(&user_data.email, &org_id, &mut conn).await
            {
                // Only revoke a user if it is not the last confirmed owner
                let revoked = if user_org.atype == UserOrgType::Owner
                    && user_org.status == UserOrgStatus::Confirmed as i32
                {
                    if UserOrganization::count_confirmed_by_org_and_type(&org_id, UserOrgType::Owner, &mut conn).await
                        <= 1
                    {
                        warn!("Can't revoke the last owner");
                        false
                    } else {
                        user_org.revoke()
                    }
                } else {
                    user_org.revoke()
                };

                let ext_modified = user_org.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    user_org.save(&mut conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut user_org) =
            UserOrganization::find_by_email_and_org(&user_data.email, &org_id, &mut conn).await
        {
            let restored = user_org.restore();
            let ext_modified = user_org.set_external_id(Some(user_data.external_id.clone()));
            if restored || ext_modified {
                user_org.save(&mut conn).await?;
            }
        } else {
            // If user is not part of the organization
            let user = match User::find_by_mail(&user_data.email, &mut conn).await {
                Some(user) => user, // exists in vaultwarden
                None => {
                    // User does not exist yet
                    let mut new_user = User::new(user_data.email.clone());
                    new_user.save(&mut conn).await?;

                    if !CONFIG.mail_enabled() {
                        let invitation = Invitation::new(&new_user.email);
                        invitation.save(&mut conn).await?;
                    }
                    new_user
                }
            };
            let user_org_status = if CONFIG.mail_enabled() || user.password_hash.is_empty() {
                UserOrgStatus::Invited as i32
            } else {
                UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
            };

            let mut new_org_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
            new_org_user.set_external_id(Some(user_data.external_id.clone()));
            new_org_user.access_all = false;
            new_org_user.atype = UserOrgType::User as i32;
            new_org_user.status = user_org_status;

            new_org_user.save(&mut conn).await?;

            if CONFIG.mail_enabled() {
                let (org_name, org_email) = match Organization::find_by_uuid(&org_id, &mut conn).await {
                    Some(org) => (org.name, org.billing_email),
                    None => err!("Error looking up organization"),
                };

                mail::send_invite(&user, Some(org_id.clone()), Some(new_org_user.uuid), &org_name, Some(org_email))
                    .await?;
            }
        }
    }

    if CONFIG.org_groups_enabled() {
        for group_data in &data.groups {
            let group_uuid = match Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &mut conn).await
            {
                Some(group) => group.uuid,
                None => {
                    let mut group = Group::new(
                        org_id.clone(),
                        group_data.name.clone(),
                        false,
                        Some(group_data.external_id.clone()),
                    );
                    group.save(&mut conn).await?;
                    group.uuid
                }
            };

            GroupUser::delete_all_by_group(&group_uuid, &mut conn).await?;

            for ext_id in &group_data.member_external_ids {
                if let Some(user_org) = UserOrganization::find_by_external_id_and_org(ext_id, &org_id, &mut conn).await
                {
                    let mut group_user = GroupUser::new(group_uuid.clone(), user_org.uuid.clone());
                    group_user.save(&mut conn).await?;
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
        for user_org in UserOrganization::find_by_org(&org_id, &mut conn).await {
            if let Some(ref user_external_id) = user_org.external_id {
                if !sync_members.contains(user_external_id) {
                    if user_org.atype == UserOrgType::Owner && user_org.status == UserOrgStatus::Confirmed as i32 {
                        // Removing owner, check that there is at least one other confirmed owner
                        if UserOrganization::count_confirmed_by_org_and_type(&org_id, UserOrgType::Owner, &mut conn)
                            .await
                            <= 1
                        {
                            warn!("Can't delete the last owner");
                            continue;
                        }
                    }
                    user_org.delete(&mut conn).await?;
                }
            }
        }
    }

    Ok(())
}

pub struct PublicToken(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();
        // Get access_token
        let access_token: &str = match headers.get_one("Authorization") {
            Some(a) => match a.rsplit("Bearer ").next() {
                Some(split) => split,
                None => err_handler!("No access token provided"),
            },
            None => err_handler!("No access token provided"),
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
        let conn = match DbConn::from_request(request).await {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB"),
        };
        let Some(org_uuid) = claims.client_id.strip_prefix("organization.") else {
            err_handler!("Malformed client_id")
        };
        let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(org_uuid, &conn).await else {
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
