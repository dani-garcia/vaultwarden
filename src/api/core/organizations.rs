#![allow(unused_imports)]

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use api::{PasswordData, JsonResult, EmptyResult};
use auth::Headers;


#[derive(Deserialize)]
#[allow(non_snake_case)]
struct OrgData {
    billingEmail: String,
    collectionName: String,
    key: String,
    name: String,
    planType: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrganizationUpdateData {
    billingEmail: String,
    name: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct NewCollectionData {
    name: String,
}

#[post("/organizations", data = "<data>")]
fn create_organization(headers: Headers, data: Json<OrgData>, conn: DbConn) -> JsonResult {
    let data: OrgData = data.into_inner();

    let mut org = Organization::new(data.name, data.billingEmail);
    let mut user_org = UserOrganization::new(
        headers.user.uuid.clone(), org.uuid.clone());
    let mut collection = Collection::new(
        org.uuid.clone(), data.collectionName);
    let mut collection_user = CollectionUsers::new(
        headers.user.uuid.clone(),
        collection.uuid.clone(),
    );

    user_org.key = data.key;
    user_org.access_all = true;
    user_org.type_ = UserOrgType::Owner as i32;
    user_org.status = UserOrgStatus::Confirmed as i32;

    org.save(&conn);
    user_org.save(&conn);
    collection.save(&conn);
    collection_user.save(&conn);

    Ok(Json(org.to_json()))
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
fn delete_organization(org_id: String, data: Json<PasswordData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordData = data.into_inner();
    let password_hash = data.masterPasswordHash;

    unimplemented!()
}

#[get("/organizations/<org_id>")]
fn get_organization(org_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    if UserOrganization::find_by_user_and_org( &headers.user.uuid, &org_id, &conn).is_none() {
        err!("User not in Organization or Organization doesn't exist")
    }

    match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => Ok(Json(organization.to_json())),
        None => err!("Can't find organization details")
    }
}

#[post("/organizations/<org_id>", data = "<data>")]
fn post_organization(org_id: String, headers: Headers, data: Json<OrganizationUpdateData>, conn: DbConn) -> JsonResult {
    let data: OrganizationUpdateData = data.into_inner();

    match UserOrganization::find_by_user_and_org( &headers.user.uuid, &org_id, &conn) {
        None => err!("User not in Organization or Organization doesn't exist"),
        Some(org_user) => if org_user.type_ != 0 { // not owner
            err!("Only owner can change Organization details")
        }
    };

    let mut org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details")
    };

    org.name = data.name;
    org.billing_email = data.billingEmail;
    org.save(&conn);

    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
fn get_user_collections(headers: Headers, conn: DbConn) -> JsonResult {

    Ok(Json(json!({
        "Data":
            Collection::find_by_user_uuid(&headers.user.uuid, &conn)
            .expect("Error loading collections")
            .iter()
            .map(|collection| {
                collection.to_json()
            }).collect::<Value>(),
        "Object": "list"
    })))
}

#[get("/organizations/<org_id>/collections")]
fn get_org_collections(org_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    Ok(Json(json!({
        "Data":
            Collection::find_by_organization_and_user_uuid(&org_id, &headers.user.uuid, &conn)
            .unwrap_or(vec![])
            .iter()
            .map(|collection| {
                collection.to_json()
            }).collect::<Value>(),
        "Object": "list"
    })))
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
fn post_organization_collections(org_id: String, headers: Headers, data: Json<NewCollectionData>, conn: DbConn) -> JsonResult {
    let data: NewCollectionData = data.into_inner();

    match UserOrganization::find_by_user_and_org( &headers.user.uuid, &org_id, &conn) {
        None => err!("User not in Organization or Organization doesn't exist"),
        Some(org_user) => if org_user.type_ > 1 { // not owner or admin
            err!("Only Organization owner and admin can add Collection")
        }
    };

    let org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details")
    };

    let mut collection = Collection::new(org.uuid.clone(), data.name);
    let mut collection_user = CollectionUsers::new(
        headers.user.uuid.clone(),
        collection.uuid.clone(),
    );

    collection.save(&conn);
    collection_user.save(&conn);

    Ok(Json(collection.to_json()))
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
fn post_organization_collection_update(org_id: String, col_id: String, headers: Headers, data: Json<NewCollectionData>, conn: DbConn) -> JsonResult {
    let data: NewCollectionData = data.into_inner();

    match UserOrganization::find_by_user_and_org( &headers.user.uuid, &org_id, &conn) {
        None => err!("User not in Organization or Organization doesn't exist"),
        Some(org_user) => if org_user.type_ > 1 { // not owner or admin
            err!("Only Organization owner and admin can update Collection")
        }
    };

    let org = match Organization::find_by_uuid(&org_id, &conn) {
        Some(organization) => organization,
        None => err!("Can't find organization details")
    };

    let mut collection = match Collection::find_by_uuid(&col_id, &conn) {
        Some(collection) => collection,
        None => err!("Collection not found")
    };

    collection.name = data.name.clone();
    collection.save(&conn);

    Ok(Json(collection.to_json()))
}

#[get("/organizations/<org_id>/collections/<coll_id>/details")]
fn get_org_collection_detail(org_id: String, coll_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    match Collection::find_by_uuid_and_user(&coll_id, &headers.user.uuid, &conn) {
        None => err!("Collection not found"),
        Some(collection) => Ok(Json(collection.to_json()))
    }
}

#[get("/organizations/<org_id>/collections/<coll_id>/users")]
fn get_collection_users(org_id: String, coll_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    // Get org and collection, check that collection is from org

    // Get the users from collection

    /*
    The elements from the data array to return have the following structure

    {
        OrganizationUserId:	<id>
        AccessAll:	true
        Name:	    <user_name>
        Email:	    <user_email>
        Type:	    0
        Status:	    2
        ReadOnly:	false
        Object:	    collectionUser
    }
    */

    Ok(Json(json!({
        "Data": [],
        "Object": "list"
    })))
}

#[derive(FromForm)]
#[allow(non_snake_case)]
struct OrgIdData {
    organizationId: String
}

#[get("/ciphers/organization-details?<data>")]
fn get_org_details(data: OrgIdData, headers: Headers, conn: DbConn) -> JsonResult {
    let ciphers = Cipher::find_by_org(&data.organizationId, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn)).collect();

    Ok(Json(json!({
      "Data": ciphers_json,
      "Object": "list",
    })))
}

#[get("/organizations/<org_id>/users")]
fn get_org_users(org_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
        Some(_) => (),
        None => err!("User isn't member of organization")
    }

    let users = UserOrganization::find_by_org(&org_id, &conn);
    let users_json: Vec<Value> = users.iter().map(|c| c.to_json_user_details(&conn)).collect();

    Ok(Json(json!({
        "Data": users_json,
        "Object": "list"
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionData {
    id: String,
    readOnly: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct InviteData {
    emails: Vec<String>,
    #[serde(rename = "type")]
    type_: String,
    collections: Vec<CollectionData>,
    accessAll: bool,
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
fn send_invite(org_id: String, data: Json<InviteData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner();

    let current_user = match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
        Some(user) => user,
        None => err!("The current user isn't member of the organization")
    };

    if current_user.type_ == UserOrgType::User as i32 {
        err!("Users can't invite other people. Ask an Admin or Owner")
    }

    let new_type = match UserOrgType::from_str(data.type_.as_ref()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type")
    };

    if new_type != UserOrgType::User as i32 &&
        current_user.type_ != UserOrgType::Owner as i32 {
        err!("Only Owners can invite Admins or Owners")
    }

    for user_opt in data.emails.iter().map(|email| User::find_by_mail(email, &conn)) {
        match user_opt {
            None => err!("User email does not exist"),
            Some(user) => {
                match UserOrganization::find_by_user_and_org(&user.uuid, &org_id, &conn) {
                    Some(_) => err!("User already in organization"),
                    None => ()
                }

                let mut new_user = UserOrganization::new(
                    user.uuid, org_id.clone());

                if data.accessAll {
                    new_user.access_all = data.accessAll;
                } else {
                    err!("Select collections unimplemented")
                    // TODO create Users_collections
                }

                new_user.type_ = new_type;

                new_user.save(&conn);
            }
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/<user_id>/confirm", data = "<data>")]
fn confirm_invite(org_id: String, user_id: String, data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let current_user = match UserOrganization::find_by_user_and_org(
        &headers.user.uuid, &org_id, &conn) {
        Some(user) => user,
        None => err!("The current user isn't member of the organization")
    };

    if current_user.type_ == UserOrgType::User as i32 {
        err!("Users can't confirm other people. Ask an Admin or Owner")
    }

    let mut user_to_confirm = match UserOrganization::find_by_uuid(&user_id, &conn) {
        Some(user) => user,
        None => err!("User to confirm isn't member of the organization")
    };

    if user_to_confirm.type_ != UserOrgType::User as i32 &&
        current_user.type_ != UserOrgType::Owner as i32 {
        err!("Only Owners can confirm Admins or Owners")
    }

    if user_to_confirm.status != UserOrgStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    user_to_confirm.status = UserOrgStatus::Confirmed as i32;
    user_to_confirm.key = match data["key"].as_str() {
        Some(key) => key.to_string(),
        None => err!("Invalid key provided")
    };

    user_to_confirm.save(&conn);

    Ok(())
}

#[get("/organizations/<org_id>/users/<user_id>")]
fn get_user(org_id: String, user_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    let current_user = match UserOrganization::find_by_user_and_org(
        &headers.user.uuid, &org_id, &conn) {
        Some(user) => user,
        None => err!("The current user isn't member of the organization")
    };

    let user = match UserOrganization::find_by_uuid(&user_id, &conn) {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization")
    };

    Ok(Json(user.to_json_details()))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EditUserData {
    #[serde(rename = "type")]
    type_: String,
    collections: Vec<CollectionData>,
    accessAll: bool,
}

#[post("/organizations/<org_id>/users/<user_id>", data = "<data>", rank = 1)]
fn edit_user(org_id: String, user_id: String, data: Json<EditUserData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: EditUserData = data.into_inner();

    let current_user = match UserOrganization::find_by_user_and_org(
        &headers.user.uuid, &org_id, &conn) {
        Some(user) => user,
        None => err!("The current user isn't member of the organization")
    };

    let new_type = match UserOrgType::from_str(data.type_.as_ref()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type")
    };

    let mut user_to_edit = match UserOrganization::find_by_uuid(&user_id, &conn) {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization")
    };

    if current_user.type_ == UserOrgType::User as i32 {
        err!("Users can't edit users. Ask an Admin or Owner")
    }

    if new_type != UserOrgType::User as i32 &&
        current_user.type_ != UserOrgType::Owner as i32 {
        err!("Only Owners can grant Admin or Owner type")
    }

    if user_to_edit.type_ != UserOrgType::User as i32 &&
        current_user.type_ != UserOrgType::Owner as i32 {
        err!("Only Owners can edit Admin or Owner")
    }

    if user_to_edit.type_ == UserOrgType::Owner as i32 &&
        new_type != UserOrgType::Owner as i32 {

        // Removing owner permmission, check that there are at least another owner
        let num_owners = UserOrganization::find_by_org_and_type(
            &org_id, UserOrgType::Owner as i32, &conn)
            .len();

        if num_owners <= 1 {
            err!("Can't delete the last owner")
        }
    }

    user_to_edit.access_all = data.accessAll;
    user_to_edit.type_ = new_type;

    if data.accessAll {
        // Remove users_collections if there is any
    } else {
        // TODO create users_collections
    }

    user_to_edit.save(&conn);

    Ok(())
}

#[post("/organizations/<org_id>/users/<user_id>/delete")]
fn delete_user(org_id: String, user_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    let current_user = match UserOrganization::find_by_user_and_org(
        &headers.user.uuid, &org_id, &conn) {
        Some(user) => user,
        None => err!("The current user isn't member of the organization")
    };

    if current_user.type_ == UserOrgType::User as i32 {
        err!("Users can't delete other people. Ask an Admin or Owner")
    }

    let user_to_delete = match UserOrganization::find_by_uuid(&user_id, &conn) {
        Some(user) => user,
        None => err!("User to delete isn't member of the organization")
    };

    if user_to_delete.type_ != UserOrgType::User as i32 &&
        current_user.type_ != UserOrgType::Owner as i32 {
        err!("Only Owners can delete Admins or Owners")
    }

    if user_to_delete.type_ == UserOrgType::Owner as i32 {
        // Removing owner, check that there are at least another owner
        let num_owners = UserOrganization::find_by_org_and_type(
            &org_id, UserOrgType::Owner as i32, &conn)
            .len();

        if num_owners <= 1 {
            err!("Can't delete the last owner")
        }
    }

    user_to_delete.delete(&conn);

    // TODO Delete  users_collections from this org

    Ok(())
}