use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use api::{JsonResult, EmptyResult};
use auth::Headers;

#[get("/folders")]
fn get_folders(headers: Headers, conn: DbConn) -> JsonResult {
    let folders = Folder::find_by_user(&headers.user.uuid, &conn);

    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    Ok(Json(json!({
      "Data": folders_json,
      "Object": "list",
    })))
}

#[get("/folders/<uuid>")]
fn get_folder(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    Ok(Json(folder.to_json()))
}

#[derive(Deserialize)]
pub struct FolderData {
    pub name: String
}

#[post("/folders", data = "<data>")]
fn post_folders(data: Json<FolderData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: FolderData = data.into_inner();

    let mut folder = Folder::new(headers.user.uuid.clone(), data.name);

    folder.save(&conn);

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>", data = "<data>")]
fn post_folder(uuid: String, data: Json<FolderData>, headers: Headers, conn: DbConn) -> JsonResult {
    put_folder(uuid, data, headers, conn)
}

#[put("/folders/<uuid>", data = "<data>")]
fn put_folder(uuid: String, data: Json<FolderData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: FolderData = data.into_inner();

    let mut folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    folder.name = data.name;

    folder.save(&conn);

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>/delete")]
fn delete_folder_post(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_folder(uuid, headers, conn)
}

#[delete("/folders/<uuid>")]
fn delete_folder(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    let folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    // Delete FolderCipher mappings
    for fc in FolderCipher::find_by_folder(&uuid, &conn) { fc.delete(&conn).expect("Error deleting mapping"); }

    // Delete the actual folder entry
    folder.delete(&conn);

    Ok(())
}
