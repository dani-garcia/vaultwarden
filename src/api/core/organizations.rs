#![allow(unused_imports)]

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use api::{JsonResult, EmptyResult};
use auth::Headers;

#[post("/organizations", data = "<data>")]
fn create_organization(headers: Headers, data: Json<Value>, conn: DbConn) -> JsonResult {
    /*
    Data is a JSON Object with the following entries
        billingEmail	<email>
        collectionName	<encrypted_collection_name>
        key	            <key>
        name	        <unencrypted_name>
        planType	    free
    */

    // We need to add the following key to the users jwt claims
    // orgowner: "<org-id>"

    // This function returns organization.to_json();
    err!("Not implemented")
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


//********************************************************************************************
/*
    We need to modify 'GET /api/profile' to return the users organizations, instead of []

    The elements from that array come from organization.to_json_profile()
*/
