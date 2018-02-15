use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use db::DbConn;
use db::models::*;

use auth::Headers;

#[get("/folders")]
fn get_folders(headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let folders = Folder::find_by_user(&headers.user.uuid, &conn);

    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    Ok(Json(json!({
      "Data": folders_json,
      "Object": "list",
    })))
}

#[get("/folders/<uuid>")]
fn get_folder(uuid: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    Ok(Json(folder.to_json()))
}

#[post("/folders", data = "<data>")]
fn post_folders(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let name = &data["name"].as_str();

    if name.is_none() {
        err!("Invalid name")
    }

    let mut folder = Folder::new(headers.user.uuid.clone(), name.unwrap().into());

    folder.save(&conn);

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>", data = "<data>")]
fn post_folder(uuid: String, data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    put_folder(uuid, data, headers, conn)
}

#[put("/folders/<uuid>", data = "<data>")]
fn put_folder(uuid: String, data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let mut folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    let name = &data["name"].as_str();

    if name.is_none() {
        err!("Invalid name")
    }

    folder.name = name.unwrap().into();

    folder.save(&conn);

    Ok(Json(folder.to_json()))
}

#[post("/folders/<uuid>/delete", data = "<_data>")]
fn delete_folder_post(uuid: String, _data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    // Data contains a json object with the id, but we don't need it
    delete_folder(uuid, headers, conn)
}

#[delete("/folders/<uuid>")]
fn delete_folder(uuid: String, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    let folder = match Folder::find_by_uuid(&uuid, &conn) {
        Some(folder) => folder,
        _ => err!("Invalid folder")
    };

    if folder.user_uuid != headers.user.uuid {
        err!("Folder belongs to another user")
    }

    if !Cipher::find_by_folder(&folder.uuid, &conn).is_empty() {
        err!("Folder is not empty")
    }

    folder.delete(&conn);

    Ok(())
}
