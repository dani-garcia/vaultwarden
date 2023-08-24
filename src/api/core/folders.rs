use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, Notify, UpdateType},
    auth::Headers,
    db::{models::*, DbConn},
};

pub fn routes() -> Vec<rocket::Route> {
    routes![get_folders, get_folder, post_folders, post_folder, put_folder, delete_folder_post, delete_folder,]
}

#[get("/folders")]
async fn get_folders(headers: Headers, conn: DbConn) -> Json<Value> {
    let folders = Folder::find_by_user(&headers.user.uuid, &conn).await;
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    Json(json!({
      "Data": folders_json,
      "Object": "list",
      "ContinuationToken": null,
    }))
}

#[get("/folders/<uuid>")]
async fn get_folder(uuid: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let folder = match Folder::find_by_uuid(uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    Ok(Json(folder.to_json()))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct FolderData {
    pub Name: String,
}

#[post("/folders", data = "<data>")]
async fn post_folders(data: JsonUpcase<FolderData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let data: FolderData = data.into_inner().data;

    let mut folder = Folder::new(headers.user.uuid, data.Name);

    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderCreate, &folder, &headers.device.uuid, &conn).await;

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>", data = "<data>")]
async fn post_folder(
    uuid: &str,
    data: JsonUpcase<FolderData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    put_folder(uuid, data, headers, conn, nt).await
}

#[put("/folders/<uuid>", data = "<data>")]
async fn put_folder(
    uuid: &str,
    data: JsonUpcase<FolderData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: FolderData = data.into_inner().data;

    let mut folder = match Folder::find_by_uuid(uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    folder.name = data.Name;

    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderUpdate, &folder, &headers.device.uuid, &conn).await;

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>/delete")]
async fn delete_folder_post(uuid: &str, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    delete_folder(uuid, headers, conn, nt).await
}

#[delete("/folders/<uuid>")]
async fn delete_folder(uuid: &str, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let folder = match Folder::find_by_uuid(uuid, &conn).await {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    // Delete the actual folder entry
    folder.delete(&conn).await?;

    nt.send_folder_update(UpdateType::SyncFolderDelete, &folder, &headers.device.uuid, &conn).await;
    Ok(())
}
