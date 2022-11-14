use chrono::Utc;
use rocket::{
    request::{self, FromRequest, Outcome},
    Request, Route,
};

use crate::{
    api::{EmptyResult, JsonUpcase},
    auth,
    db::{models::*, DbConn},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![ldap_import]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportGroupData {
    Name: String,
    ExternalId: String,
    MemberExternalIds: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportUserData {
    Email: String,
    ExternalId: String,
    Deleted: bool,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportData {
    Groups: Vec<OrgImportGroupData>,
    Members: Vec<OrgImportUserData>,
    OverwriteExisting: bool,
    #[allow(dead_code)]
    LargeImport: bool,
}

#[post("/public/organization/import", data = "<data>")]
async fn ldap_import(data: JsonUpcase<OrgImportData>, token: PublicToken, mut conn: DbConn) -> EmptyResult {
    let _ = &conn;
    let org_id = token.0;
    let data = data.into_inner().data;

    for user_data in &data.Members {
        if user_data.Deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut user_org) =
                UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &mut conn).await
            {
                user_org.revoke();
                user_org.save(&mut conn).await?;
            }

        // If user is part of the organization, restore it
        } else if let Some(mut user_org) =
            UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &mut conn).await
        {
            if user_org.status < UserOrgStatus::Revoked as i32 {
                user_org.restore();
                user_org.save(&mut conn).await?;
            }
        } else {
            // If user is not part of the organization
            let user = match User::find_by_mail(&user_data.Email, &mut conn).await {
                Some(user) => user, // exists in vaultwarden
                None => {
                    // doesn't exist in vaultwarden
                    let mut new_user = User::new(user_data.Email.clone());
                    new_user.set_external_id(Some(user_data.ExternalId.clone()));
                    new_user.save(&mut conn).await?;

                    if !CONFIG.mail_enabled() {
                        let invitation = Invitation::new(new_user.email.clone());
                        invitation.save(&mut conn).await?;
                    }
                    new_user
                }
            };
            let user_org_status = if CONFIG.mail_enabled() {
                UserOrgStatus::Invited as i32
            } else {
                UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
            };

            let mut new_org_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
            new_org_user.access_all = false;
            new_org_user.atype = UserOrgType::User as i32;
            new_org_user.status = user_org_status;

            new_org_user.save(&mut conn).await?;

            if CONFIG.mail_enabled() {
                let (org_name, org_email) = match Organization::find_by_uuid(&org_id, &mut conn).await {
                    Some(org) => (org.name, org.billing_email),
                    None => err!("Error looking up organization"),
                };

                mail::send_invite(
                    &user_data.Email,
                    &user.uuid,
                    Some(org_id.clone()),
                    Some(new_org_user.uuid),
                    &org_name,
                    Some(org_email),
                )
                .await?;
            }
        }
    }

    for group_data in &data.Groups {
        let group_uuid = match Group::find_by_external_id(&group_data.ExternalId, &mut conn).await {
            Some(group) => group.uuid,
            None => {
                let mut group =
                    Group::new(org_id.clone(), group_data.Name.clone(), false, Some(group_data.ExternalId.clone()));
                group.save(&mut conn).await?;
                group.uuid
            }
        };

        GroupUser::delete_all_by_group(&group_uuid, &mut conn).await?;

        for ext_id in &group_data.MemberExternalIds {
            if let Some(user) = User::find_by_external_id(ext_id, &mut conn).await {
                if let Some(user_org) = UserOrganization::find_by_user_and_org(&user.uuid, &org_id, &mut conn).await {
                    let mut group_user = GroupUser::new(group_uuid.clone(), user_org.uuid.clone());
                    group_user.save(&mut conn).await?;
                }
            }
        }
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.OverwriteExisting {
        for user_org in UserOrganization::find_by_org(&org_id, &mut conn).await {
            if let Some(user_external_id) =
                User::find_by_uuid(&user_org.user_uuid, &mut conn).await.map(|u| u.external_id)
            {
                if user_external_id.is_some()
                    && !data.Members.iter().any(|u| u.ExternalId == *user_external_id.as_ref().unwrap())
                {
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

#[derive(Debug)]
pub struct PublicToken(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
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
        let claims = match auth::decode_api_org(access_token) {
            Ok(claims) => claims,
            Err(_) => err_handler!("Invalid claim"),
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().naive_utc().timestamp();
        if time_now < claims.nbf {
            err_handler!("Token issued in the future");
        }
        if time_now > claims.exp {
            err_handler!("Token expired");
        }
        // Check if claims.iss is host|claims.scope[0]
        let host = match auth::Host::from_request(request).await {
            Outcome::Success(host) => host,
            _ => err_handler!("Error getting Host"),
        };
        let complete_host = format!("{}|{}", host.host, claims.scope[0]);
        if complete_host != claims.iss {
            err_handler!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let conn = match DbConn::from_request(request).await {
            Outcome::Success(conn) => conn,
            _ => err_handler!("Error getting DB"),
        };
        let org_uuid = match claims.client_id.strip_prefix("organization.") {
            Some(uuid) => uuid,
            None => err_handler!("Malformed client_id"),
        };
        let org_api_key = match OrganizationApiKey::find_by_org_uuid(org_uuid, &conn).await {
            Some(org_api_key) => org_api_key,
            None => err_handler!("Invalid client_id"),
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
