use num_traits::FromPrimitive;
use rocket::{request::Form, Route};
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, JsonUpcaseVec, Notify, NumberOrString, PasswordData, UpdateType},
    auth::{decode_invite, AdminHeaders, Headers, OwnerHeaders, ManagerHeaders, ManagerHeadersLoose},
    db::{models::*, DbConn},
    mail, CONFIG,
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
        get_org_details,
        get_org_users,
        send_invite,
        reinvite_user,
        confirm_invite,
        accept_invite,
        get_user,
        edit_user,
        put_organization_user,
        delete_user,
        post_delete_user,
        post_org_import,
        list_policies,
        list_policies_token,
        get_policy,
        put_policy,
        get_organization_tax,
        get_plans,
        get_plans_tax_rates,
        import,
    ]
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct OrgData {
    BillingEmail: String,
    CollectionName: String,
    Key: String,
    Name: String,
    #[serde(rename = "PlanType")]
    _PlanType: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrganizationUpdateData {
    BillingEmail: String,
    Name: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct NewCollectionData {
    Name: String,
}

#[post("/organizations", data = "<data>")]
fn create_organization(headers: Headers, data: JsonUpcase<OrgData>, conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }

    let data: OrgData = data.into_inner().data;

    let org = Organization::new(data.Name, data.BillingEmail);
    let mut user_org = UserOrganization::new(headers.user.uuid, org.uuid.clone());
    let collection = Collection::new(org.uuid.clone(), data.CollectionName);

    user_org.akey = data.Key;
    user_org.access_all = true;
    user_org.atype = UserOrgType::Owner as i32;
    user_org.status = UserOrgStatus::Confirmed as i32;

    org.save(&conn)?;
    user_org.save(&conn)?;
    collection.save(&conn)?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
fn delete_organization(
    org_id: String,
    data: JsonUpcase<PasswordData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    match Organization::find_by_uuid(&org_id, &conn) {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn),
    }
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
fn post_delete_organization(
    org_id: String,
    data: JsonUpcase<PasswordData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization(org_id, data, headers, conn)
}

#[post("/organizations/<org_id>/leave")]
fn leave_organization(org_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
        None => err!("User not part of organization"),
        Some(user_org) => {
            if user_org.atype == UserOrgType::Owner {
                let num_owners =
                    UserOrganization::find_by_org_and_type(&org_id, UserOrgType::Owner as i32, &conn).len();

                if num_owners <= 1 {
                    err!("The last owner can't leave")
                }
            }

            user_org.delete(&conn)
        }
    }
}

#[get("/organizations/<org_id>")]
fn get_organization(org_id: String, _headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => Ok(Json(organization.to_json())),
        None => err!("Can't find organization details"),
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
fn put_organization(
    org_id: String,
    headers: OwnerHeaders,
    data: JsonUpcase<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_organization(org_id, headers, data, conn)
}

#[post("/organizations/<org_id>", data = "<data>")]
fn post_organization(
    org_id: String,
    _headers: OwnerHeaders,
    data: JsonUpcase<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    let data: OrganizationUpdateData = data.into_inner().data;

    let mut org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    org.name = data.Name;
    org.billing_email = data.BillingEmail;

    org.save(&conn)?;
    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
fn get_user_collections(headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(json!({
        "Data":
            Collection::find_by_user_uuid(&headers.user.uuid, &conn)
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[get("/organizations/<org_id>/collections")]
fn get_org_collections(org_id: String, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    Ok(Json(json!({
        "Data":
            Collection::find_by_organization(&org_id, &conn)
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
fn post_organization_collections(
    org_id: String,
    headers: ManagerHeadersLoose,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner().data;

    let org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    // Get the user_organization record so that we can check if the user has access to all collections.
    let user_org = match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
        Some(u) => u,
        None => err!("User is not part of organization"),
    };

    let collection = Collection::new(org.uuid, data.Name);
    collection.save(&conn)?;

    // If the user doesn't have access to all collections, only in case of a Manger,
    // then we need to save the creating user uuid (Manager) to the users_collection table.
    // Else the user will not have access to his own created collection.
    if !user_org.access_all {
        CollectionUser::save(&headers.user.uuid, &collection.uuid, false, false, &conn)?;
    }

    Ok(Json(collection.to_json()))
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
fn put_organization_collection_update(
    org_id: String,
    col_id: String,
    headers: ManagerHeaders,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    post_organization_collection_update(org_id, col_id, headers, data, conn)
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
fn post_organization_collection_update(
    org_id: String,
    col_id: String,
    _headers: ManagerHeaders,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner().data;

    let org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let mut collection = match Collection::find_by_uuid(&col_id, &conn) {
        Some(collection) => collection,
        None => err!("Collection not found"),
    };

    if collection.org_uuid != org.uuid {
        err!("Collection is not owned by organization");
    }

    collection.name = data.Name;
    collection.save(&conn)?;

    Ok(Json(collection.to_json()))
}

#[delete("/organizations/<org_id>/collections/<col_id>/user/<org_user_id>")]
fn delete_organization_collection_user(
    org_id: String,
    col_id: String,
    org_user_id: String,
    _headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let collection = match Collection::find_by_uuid(&col_id, &conn) {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                collection
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    };

    match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn) {
        None => err!("User not found in organization"),
        Some(user_org) => {
            match CollectionUser::find_by_collection_and_user(&collection.uuid, &user_org.user_uuid, &conn) {
                None => err!("User not assigned to collection"),
                Some(col_user) => col_user.delete(&conn),
            }
        }
    }
}

#[post("/organizations/<org_id>/collections/<col_id>/delete-user/<org_user_id>")]
fn post_organization_collection_delete_user(
    org_id: String,
    col_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_user(org_id, col_id, org_user_id, headers, conn)
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
fn delete_organization_collection(org_id: String, col_id: String, _headers: ManagerHeaders, conn: DbConn) -> EmptyResult {
    match Collection::find_by_uuid(&col_id, &conn) {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                collection.delete(&conn)
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct DeleteCollectionData {
    Id: String,
    OrgId: String,
}

#[post("/organizations/<org_id>/collections/<col_id>/delete", data = "<_data>")]
fn post_organization_collection_delete(
    org_id: String,
    col_id: String,
    headers: ManagerHeaders,
    _data: JsonUpcase<DeleteCollectionData>,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection(org_id, col_id, headers, conn)
}

#[get("/organizations/<org_id>/collections/<coll_id>/details")]
fn get_org_collection_detail(org_id: String, coll_id: String, headers: ManagerHeaders, conn: DbConn) -> JsonResult {
    match Collection::find_by_uuid_and_user(&coll_id, &headers.user.uuid, &conn) {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            Ok(Json(collection.to_json()))
        }
    }
}

#[get("/organizations/<org_id>/collections/<coll_id>/users")]
fn get_collection_users(org_id: String, coll_id: String, _headers: ManagerHeaders, conn: DbConn) -> JsonResult {
    // Get org and collection, check that collection is from org
    let collection = match Collection::find_by_uuid_and_org(&coll_id, &org_id, &conn) {
        None => err!("Collection not found in Organization"),
        Some(collection) => collection,
    };

    // Get the users from collection
    let user_list: Vec<Value> = CollectionUser::find_by_collection(&collection.uuid, &conn)
        .iter()
        .map(|col_user| {
            UserOrganization::find_by_user_and_org(&col_user.user_uuid, &org_id, &conn)
                .unwrap()
                .to_json_user_access_restrictions(&col_user)
        })
        .collect();

    Ok(Json(json!(user_list)))
}

#[put("/organizations/<org_id>/collections/<coll_id>/users", data = "<data>")]
fn put_collection_users(
    org_id: String,
    coll_id: String,
    data: JsonUpcaseVec<CollectionData>,
    _headers: ManagerHeaders,
    conn: DbConn,
) -> EmptyResult {
    // Get org and collection, check that collection is from org
    if Collection::find_by_uuid_and_org(&coll_id, &org_id, &conn).is_none() {
        err!("Collection not found in Organization")
    }

    // Delete all the user-collections
    CollectionUser::delete_all_by_collection(&coll_id, &conn)?;

    // And then add all the received ones (except if the user has access_all)
    for d in data.iter().map(|d| &d.data) {
        let user = match UserOrganization::find_by_uuid(&d.Id, &conn) {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if user.access_all {
            continue;
        }

        CollectionUser::save(&user.user_uuid, &coll_id,
                             d.ReadOnly, d.HidePasswords,
                             &conn)?;
    }

    Ok(())
}

#[derive(FromForm)]
struct OrgIdData {
    #[form(field = "organizationId")]
    organization_id: String,
}

#[get("/ciphers/organization-details?<data..>")]
fn get_org_details(data: Form<OrgIdData>, headers: Headers, conn: DbConn) -> JsonResult {
    let ciphers = Cipher::find_by_org(&data.organization_id, &conn);
    let ciphers_json: Vec<Value> = ciphers
        .iter()
        .map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn))
        .collect();

    Ok(Json(json!({
      "Data": ciphers_json,
      "Object": "list",
      "ContinuationToken": null,
    })))
}

#[get("/organizations/<org_id>/users")]
fn get_org_users(org_id: String, _headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    let users = UserOrganization::find_by_org(&org_id, &conn);
    let users_json: Vec<Value> = users.iter().map(|c| c.to_json_user_details(&conn)).collect();

    Ok(Json(json!({
        "Data": users_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionData {
    Id: String,
    ReadOnly: bool,
    HidePasswords: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct InviteData {
    Emails: Vec<String>,
    Type: NumberOrString,
    Collections: Option<Vec<CollectionData>>,
    AccessAll: Option<bool>,
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
fn send_invite(org_id: String, data: JsonUpcase<InviteData>, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner().data;

    let new_type = match UserOrgType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if new_type != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can invite Managers, Admins or Owners")
    }

    for email in data.Emails.iter() {
        let mut user_org_status = if CONFIG.mail_enabled() {
            UserOrgStatus::Invited as i32
        } else {
            UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
        };
        let user = match User::find_by_mail(&email, &conn) {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {}", email))
                }

                if !CONFIG.is_email_domain_allowed(&email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    let invitation = Invitation::new(email.clone());
                    invitation.save(&conn)?;
                }

                let mut user = User::new(email.clone());
                user.save(&conn)?;
                user_org_status = UserOrgStatus::Invited as i32;
                user
            }
            Some(user) => {
                if UserOrganization::find_by_user_and_org(&user.uuid, &org_id, &conn).is_some() {
                    err!(format!("User already in organization: {}", email))
                } else {
                    user
                }
            }
        };

        let mut new_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
        let access_all = data.AccessAll.unwrap_or(false);
        new_user.access_all = access_all;
        new_user.atype = new_type;
        new_user.status = user_org_status;

        // If no accessAll, add the collections received
        if !access_all {
            for col in data.Collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&col.Id, &org_id, &conn) {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        CollectionUser::save(&user.uuid, &collection.uuid,
                                             col.ReadOnly, col.HidePasswords,
                                             &conn)?;
                    }
                }
            }
        }

        new_user.save(&conn)?;

        if CONFIG.mail_enabled() {
            let org_name = match Organization::find_by_uuid(&org_id, &conn) {
                Some(org) => org.name,
                None => err!("Error looking up organization"),
            };

            mail::send_invite(
                &email,
                &user.uuid,
                Some(org_id.clone()),
                Some(new_user.uuid),
                &org_name,
                Some(headers.user.email.clone()),
            )?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/<user_org>/reinvite")]
fn reinvite_user(org_id: String, user_org: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    if !CONFIG.invitations_allowed() {
        err!("Invitations are not allowed.")
    }

    if !CONFIG.mail_enabled() {
        err!("SMTP is not configured.")
    }

    let user_org = match UserOrganization::find_by_uuid(&user_org, &conn) {
        Some(user_org) => user_org,
        None => err!("The user hasn't been invited to the organization."),
    };

    if user_org.status != UserOrgStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let user = match User::find_by_uuid(&user_org.user_uuid, &conn) {
        Some(user) => user,
        None => err!("User not found."),
    };

    let org_name = match Organization::find_by_uuid(&org_id, &conn) {
        Some(org) => org.name,
        None => err!("Error looking up organization."),
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(
            &user.email,
            &user.uuid,
            Some(org_id),
            Some(user_org.uuid),
            &org_name,
            Some(headers.user.email),
        )?;
    } else {
        let invitation = Invitation::new(user.email);
        invitation.save(&conn)?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcceptData {
    Token: String,
}

#[post("/organizations/<_org_id>/users/<_org_user_id>/accept", data = "<data>")]
fn accept_invite(_org_id: String, _org_user_id: String, data: JsonUpcase<AcceptData>, conn: DbConn) -> EmptyResult {
    // The web-vault passes org_id and org_user_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner().data;
    let token = &data.Token;
    let claims = decode_invite(&token)?;

    match User::find_by_mail(&claims.email, &conn) {
        Some(_) => {
            Invitation::take(&claims.email, &conn);

            if let (Some(user_org), Some(org)) = (&claims.user_org_id, &claims.org_id) {
                let mut user_org = match UserOrganization::find_by_uuid_and_org(user_org, org, &conn) {
                    Some(user_org) => user_org,
                    None => err!("Error accepting the invitation"),
                };

                if user_org.status != UserOrgStatus::Invited as i32 {
                    err!("User already accepted the invitation")
                }

                user_org.status = UserOrgStatus::Accepted as i32;
                user_org.save(&conn)?;
            }
        }
        None => err!("Invited user not found"),
    }

    if CONFIG.mail_enabled() {
        let mut org_name = CONFIG.invitation_org_name();
        if let Some(org_id) = &claims.org_id {
            org_name = match Organization::find_by_uuid(&org_id, &conn) {
                Some(org) => org.name,
                None => err!("Organization not found."),
            };
        };
        if let Some(invited_by_email) = &claims.invited_by_email {
            // User was invited to an organization, so they must be confirmed manually after acceptance
            mail::send_invite_accepted(&claims.email, invited_by_email, &org_name)?;
        } else {
            // User was invited from /admin, so they are automatically confirmed
            mail::send_invite_confirmed(&claims.email, &org_name)?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/<org_user_id>/confirm", data = "<data>")]
fn confirm_invite(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data = data.into_inner().data;

    let mut user_to_confirm = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn) {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    if user_to_confirm.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can confirm Managers, Admins or Owners")
    }

    if user_to_confirm.status != UserOrgStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    user_to_confirm.status = UserOrgStatus::Confirmed as i32;
    user_to_confirm.akey = match data["Key"].as_str() {
        Some(key) => key.to_string(),
        None => err!("Invalid key provided"),
    };

    if CONFIG.mail_enabled() {
        let org_name = match Organization::find_by_uuid(&org_id, &conn) {
            Some(org) => org.name,
            None => err!("Error looking up organization."),
        };
        let address = match User::find_by_uuid(&user_to_confirm.user_uuid, &conn) {
            Some(user) => user.email,
            None => err!("Error looking up user."),
        };
        mail::send_invite_confirmed(&address, &org_name)?;
    }

    user_to_confirm.save(&conn)
}

#[get("/organizations/<org_id>/users/<org_user_id>")]
fn get_user(org_id: String, org_user_id: String, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let user = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn) {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    Ok(Json(user.to_json_details(&conn)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EditUserData {
    Type: NumberOrString,
    Collections: Option<Vec<CollectionData>>,
    AccessAll: bool,
}

#[put("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
fn put_organization_user(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    edit_user(org_id, org_user_id, data, headers, conn)
}

#[post("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
fn edit_user(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data: EditUserData = data.into_inner().data;

    let new_type = match UserOrgType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type,
        None => err!("Invalid type"),
    };

    let mut user_to_edit = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn) {
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

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permmission, check that there are at least another owner
        let num_owners = UserOrganization::find_by_org_and_type(&org_id, UserOrgType::Owner as i32, &conn).len();

        if num_owners <= 1 {
            err!("Can't delete the last owner")
        }
    }

    user_to_edit.access_all = data.AccessAll;
    user_to_edit.atype = new_type as i32;

    // Delete all the odd collections
    for c in CollectionUser::find_by_organization_and_user_uuid(&org_id, &user_to_edit.user_uuid, &conn) {
        c.delete(&conn)?;
    }

    // If no accessAll, add the collections received
    if !data.AccessAll {
        for col in data.Collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&col.Id, &org_id, &conn) {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser::save(&user_to_edit.user_uuid, &collection.uuid,
                                         col.ReadOnly, col.HidePasswords,
                                         &conn)?;
                }
            }
        }
    }

    user_to_edit.save(&conn)
}

#[delete("/organizations/<org_id>/users/<org_user_id>")]
fn delete_user(org_id: String, org_user_id: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    let user_to_delete = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn) {
        Some(user) => user,
        None => err!("User to delete isn't member of the organization"),
    };

    if user_to_delete.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can delete Admins or Owners")
    }

    if user_to_delete.atype == UserOrgType::Owner {
        // Removing owner, check that there are at least another owner
        let num_owners = UserOrganization::find_by_org_and_type(&org_id, UserOrgType::Owner as i32, &conn).len();

        if num_owners <= 1 {
            err!("Can't delete the last owner")
        }
    }

    user_to_delete.delete(&conn)
}

#[post("/organizations/<org_id>/users/<org_user_id>/delete")]
fn post_delete_user(org_id: String, org_user_id: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    delete_user(org_id, org_user_id, headers, conn)
}

use super::ciphers::update_cipher_from_data;
use super::ciphers::CipherData;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ImportData {
    Ciphers: Vec<CipherData>,
    Collections: Vec<NewCollectionData>,
    CollectionRelationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RelationsData {
    // Cipher index
    Key: usize,
    // Collection index
    Value: usize,
}

#[post("/ciphers/import-organization?<query..>", data = "<data>")]
fn post_org_import(
    query: Form<OrgIdData>,
    data: JsonUpcase<ImportData>,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    let data: ImportData = data.into_inner().data;
    let org_id = query.into_inner().organization_id;

    // Read and create the collections
    let collections: Vec<_> = data
        .Collections
        .into_iter()
        .map(|coll| {
            let collection = Collection::new(org_id.clone(), coll.Name);
            if collection.save(&conn).is_err() {
                err!("Failed to create Collection");
            }

            Ok(collection)
        })
        .collect();

    // Read the relations between collections and ciphers
    let mut relations = Vec::new();
    for relation in data.CollectionRelationships {
        relations.push((relation.Key, relation.Value));
    }

    let headers: Headers = headers.into();

    // Read and create the ciphers
    let ciphers: Vec<_> = data
        .Ciphers
        .into_iter()
        .map(|cipher_data| {
            let mut cipher = Cipher::new(cipher_data.Type, cipher_data.Name.clone());
            update_cipher_from_data(
                &mut cipher,
                cipher_data,
                &headers,
                false,
                &conn,
                &nt,
                UpdateType::CipherCreate,
            )
            .ok();
            cipher
        })
        .collect();

    // Assign the collections
    for (cipher_index, coll_index) in relations {
        let cipher_id = &ciphers[cipher_index].uuid;
        let coll = &collections[coll_index];
        let coll_id = match coll {
            Ok(coll) => coll.uuid.as_str(),
            Err(_) => err!("Failed to assign to collection"),
        };

        CollectionCipher::save(cipher_id, coll_id, &conn)?;
    }

    let mut user = headers.user;
    user.update_revision(&conn)
}

#[get("/organizations/<org_id>/policies")]
fn list_policies(org_id: String, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let policies = OrgPolicy::find_by_org(&org_id, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
fn list_policies_token(org_id: String, token: String, conn: DbConn) -> JsonResult {
    let invite = crate::auth::decode_invite(&token)?;

    let invite_org_id = match invite.org_id {
        Some(invite_org_id) => invite_org_id,
        None => err!("Invalid token"),
    };

    if invite_org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(&org_id, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/<pol_type>")]
fn get_policy(org_id: String, pol_type: i32, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid or unsupported policy type"),
    };

    let policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type, &conn) {
        Some(p) => p,
        None => OrgPolicy::new(org_id, pol_type_enum, "{}".to_string()),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    #[serde(rename = "type")]
    _type: i32,
    data: Value,
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
fn put_policy(org_id: String, pol_type: i32, data: Json<PolicyData>, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let data: PolicyData = data.into_inner();

    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid policy type"),
    };

    let mut policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type, &conn) {
        Some(p) => p,
        None => OrgPolicy::new(org_id, pol_type_enum, "{}".to_string()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(&conn)?;

    Ok(Json(policy.to_json()))
}

#[allow(unused_variables)]
#[get("/organizations/<org_id>/tax")]
fn get_organization_tax(org_id: String, _headers: Headers, _conn: DbConn) -> EmptyResult {
    // Prevent a 404 error, which also causes Javascript errors.
    err!("Only allowed when not self hosted.")
}

#[get("/plans")]
fn get_plans(_headers: Headers, _conn: DbConn) -> JsonResult {
    Ok(Json(json!({
        "Object": "list",
        "Data": [
        {
            "Object": "plan",
            "Type": 0,
            "Product": 0,
            "Name": "Free",
            "IsAnnual": false,
            "NameLocalizationKey": "planNameFree",
            "DescriptionLocalizationKey": "planDescFree",
            "CanBeUsedByBusiness": false,
            "BaseSeats": 2,
            "BaseStorageGb": null,
            "MaxCollections": 2,
            "MaxUsers": 2,
            "HasAdditionalSeatsOption": false,
            "MaxAdditionalSeats": null,
            "HasAdditionalStorageOption": false,
            "MaxAdditionalStorage": null,
            "HasPremiumAccessOption": false,
            "TrialPeriodDays": null,
            "HasSelfHost": false,
            "HasPolicies": false,
            "HasGroups": false,
            "HasDirectory": false,
            "HasEvents": false,
            "HasTotp": false,
            "Has2fa": false,
            "HasApi": false,
            "HasSso": false,
            "UsersGetPremium": false,
            "UpgradeSortOrder": -1,
            "DisplaySortOrder": -1,
            "LegacyYear": null,
            "Disabled": false,
            "StripePlanId": null,
            "StripeSeatPlanId": null,
            "StripeStoragePlanId": null,
            "StripePremiumAccessPlanId": null,
            "BasePrice": 0.0,
            "SeatPrice": 0.0,
            "AdditionalStoragePricePerGb": 0.0,
            "PremiumAccessOptionPrice": 0.0
            }
        ],
        "ContinuationToken": null
    })))
}

#[get("/plans/sales-tax-rates")]
fn get_plans_tax_rates(_headers: Headers, _conn: DbConn) -> JsonResult {
    // Prevent a 404 error, which also causes Javascript errors.
    Ok(Json(json!({
        "Object": "list",
        "Data": [],
        "ContinuationToken": null
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportGroupData {
    Name: String,       // "GroupName"
    ExternalId: String, // "cn=GroupName,ou=Groups,dc=example,dc=com"
    Users: Vec<String>, // ["uid=user,ou=People,dc=example,dc=com"]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportUserData {
    Email: String,      // "user@maildomain.net"
    ExternalId: String, // "uid=user,ou=People,dc=example,dc=com"
    Deleted: bool,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportData {
    Groups: Vec<OrgImportGroupData>,
    OverwriteExisting: bool,
    Users: Vec<OrgImportUserData>,
}

#[post("/organizations/<org_id>/import", data = "<data>")]
fn import(org_id: String, data: JsonUpcase<OrgImportData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner().data;

    // TODO: Currently we aren't storing the externalId's anywhere, so we also don't have a way
    // to differentiate between auto-imported users and manually added ones.
    // This means that this endpoint can end up removing users that were added manually by an admin,
    // as opposed to upstream which only removes auto-imported users.

    // User needs to be admin or owner to use the Directry Connector
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
        Some(user_org) if user_org.atype >= UserOrgType::Admin => { /* Okay, nothing to do */ }
        Some(_) => err!("User has insufficient permissions to use Directory Connector"),
        None => err!("User not part of organization"),
    };

    for user_data in &data.Users {
        if user_data.Deleted {
            // If user is marked for deletion and it exists, delete it
            if let Some(user_org) = UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &conn) {
                user_org.delete(&conn)?;
            }

        // If user is not part of the organization, but it exists
        } else if UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &conn).is_none() {
            if let Some (user) = User::find_by_mail(&user_data.Email, &conn) {
                
                let user_org_status = if CONFIG.mail_enabled() {
                    UserOrgStatus::Invited as i32
                } else {
                    UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
                };

                let mut new_org_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
                new_org_user.access_all = false;
                new_org_user.atype = UserOrgType::User as i32;
                new_org_user.status = user_org_status;

                new_org_user.save(&conn)?;

                if CONFIG.mail_enabled() {
                    let org_name = match Organization::find_by_uuid(&org_id, &conn) {
                        Some(org) => org.name,
                        None => err!("Error looking up organization"),
                    };

                    mail::send_invite(
                        &user_data.Email,
                        &user.uuid,
                        Some(org_id.clone()),
                        Some(new_org_user.uuid),
                        &org_name,
                        Some(headers.user.email.clone()),
                    )?;
                }
            }  
        }
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.OverwriteExisting {
        for user_org in UserOrganization::find_by_org_and_type(&org_id, UserOrgType::User as i32, &conn) {  
            if let Some (user_email) = User::find_by_uuid(&user_org.user_uuid, &conn).map(|u| u.email) {
                if !data.Users.iter().any(|u| u.Email == user_email) {
                    user_org.delete(&conn)?;
                }
            } 
        }
    }

    Ok(())
}
