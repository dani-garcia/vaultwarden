use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, Notify, UpdateType},
    auth::Headers,
    db::{models::*, DbConn},
};

pub fn routes() -> Vec<rocket::Route> {
    routes![get_folders, get_folder, post_folders, post_folder, put_folder, delete_folder_post, delete_folder,]
}

#[get("/folders")]
async fn get_folders(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let folders = Folder::find_by_user(&headers.user.uuid, &mut conn).await;
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    Json(json!({
      "data": folders_json,
      "object": "list",
      "continuationToken": null,
    }))
}

#[get("/folders/<uuid>")]
async fn get_folder(uuid: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    match Folder::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await {
        Some(folder) => Ok(Json(folder.to_json())),
        _ => err!("Invalid folder", "Folder does not exist or belongs to another user"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderData {
    pub name: String,
    pub id: Option<String>,
}

#[post("/folders", data = "<data>")]
async fn post_folders(data: Json<FolderData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let data: FolderData = data.into_inner();

    let mut folder = Folder::new(headers.user.uuid, data.name);

    folder.save(&mut conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderCreate, &folder, &headers.device.uuid, &mut conn).await;

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>", data = "<data>")]
async fn post_folder(uuid: &str, data: Json<FolderData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    put_folder(uuid, data, headers, conn, nt).await
}

#[put("/folders/<uuid>", data = "<data>")]
async fn put_folder(
    uuid: &str,
    data: Json<FolderData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: FolderData = data.into_inner();

    let Some(mut folder) = Folder::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await else {
        err!("Invalid folder", "Folder does not exist or belongs to another user")
    };

    folder.name = data.name;

    folder.save(&mut conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderUpdate, &folder, &headers.device.uuid, &mut conn).await;

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>/delete")]
async fn delete_folder_post(uuid: &str, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    delete_folder(uuid, headers, conn, nt).await
}

#[delete("/folders/<uuid>")]
async fn delete_folder(uuid: &str, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let Some(folder) = Folder::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await else {
        err!("Invalid folder", "Folder does not exist or belongs to another user")
    };

    // Delete the actual folder entry
    folder.delete(&mut conn).await?;

    nt.send_folder_update(UpdateType::SyncFolderDelete, &folder, &headers.device.uuid, &mut conn).await;
    Ok(())
}
