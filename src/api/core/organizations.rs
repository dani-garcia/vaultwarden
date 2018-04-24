#![allow(unused_imports)]

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use api::{JsonResult, EmptyResult};
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

#[post("/organizations", data = "<data>")]
fn create_organization(headers: Headers, data: Json<OrgData>, conn: DbConn) -> JsonResult {
    let data: OrgData = data.into_inner();

    let mut org = Organization::new(data.name, data.billingEmail);
    let mut user_org = UserOrganization::new(
        headers.user.uuid, org.uuid.clone());

    user_org.key = data.key;
    user_org.access_all = true;
    user_org.type_ = UserOrgType::Owner as i32;
    user_org.status = UserOrgStatus::Confirmed as i32;

    org.save(&conn);
    user_org.save(&conn);

    Ok(Json(org.to_json()))
}


// GET /api/collections?writeOnly=false
#[get("/collections")]
fn get_user_collections(headers: Headers, conn: DbConn) -> JsonResult {

    // let collections_json = get_user_collections().map(|c|c.to_json());

    Ok(Json(json!({
        "Data": [],
        "Object": "list"
    })))
}

#[get("/organizations/<org_id>/collections")]
fn get_org_collections(org_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    // let org = get_org_by_id(org_id)
    // let collections_json = org.collections().map(|c|c.to_json());

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

    // Get list of ciphers in org?

    Ok(Json(json!({
        "Data": [],
        "Object": "list"
    })))
}

#[get("/organizations/<org_id>/users")]
fn get_org_users(org_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    // TODO Check if user in org

    let users = UserOrganization::find_by_org(&org_id, &conn);
    let users_json: Vec<Value> = users.iter().map(|c| c.to_json_details(&conn)).collect();

    Ok(Json(json!({
        "Data": users_json,
        "Object": "list"
    })))
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

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct InviteCollectionData {
    id: String,
    readOnly: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct InviteData {
    emails: Vec<String>,
    #[serde(rename = "type")]
    type_: String,
    collections: Vec<InviteCollectionData>,
    accessAll: bool,

}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
fn send_invite(org_id: String, data: Json<InviteData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner();

    // TODO Check that user is in org and admin or more

    for user_opt in data.emails.iter().map(|email| User::find_by_mail(email, &conn)) {
        match user_opt {
            None => err!("User email does not exist"),
            Some(user) => {
                // TODO Check that user is not already in org

                let mut user_org = UserOrganization::new(
                    user.uuid, org_id.clone());

                if data.accessAll {
                    user_org.access_all = data.accessAll;
                } else {
                    err!("Select collections unimplemented")
                    // TODO create Users_collections
                }

                user_org.type_ = match data.type_.as_ref() {
                    "Owner" => UserOrgType::Owner,
                    "Admin" => UserOrgType::Admin,
                    "User" => UserOrgType::User,
                    _ => err!("Invalid type")
                } as i32;

                user_org.save(&conn);
            }
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/<user_id>/confirm", data = "<data>")]
fn confirm_invite(org_id: String, user_id: String, data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    // TODO Check that user is in org and admin or more

    let mut user_org = match UserOrganization::find_by_user_and_org(
        &user_id, &org_id, &conn) {
        Some(user_org) => user_org,
        None => err!("Can't find user")
    };

    if user_org.status != UserOrgStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    user_org.status = UserOrgStatus::Confirmed as i32;
    user_org.key = match data["key"].as_str() {
        Some(key) => key.to_string(),
        None => err!("Invalid key provided")
    };

    user_org.save(&conn);

    Ok(())
}

#[post("/organizations/<org_id>/users/<user_id>/delete")]
fn delete_user(org_id: String, user_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    // TODO Check that user is in org and admin or more
    // TODO To delete a user you need either:
    //      - To be yourself
    //      - To be of a superior type (ex. Owner can delete Admin and User, Admin can delete User)

    // Delete users_organizations and users_collections from this org

    unimplemented!();
}