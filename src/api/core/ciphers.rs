use std::path::Path;

use rocket::Data;
use rocket::http::ContentType;

use rocket_contrib::{Json, Value};

use multipart::server::{Multipart, SaveResult};
use multipart::server::save::SavedData;

use data_encoding::HEXLOWER;

use db::DbConn;
use db::models::*;

use util;
use crypto;

use api::{JsonResult, EmptyResult};
use auth::Headers;

use CONFIG;

#[get("/sync")]
fn sync(headers: Headers, conn: DbConn) -> JsonResult {
    let user = &headers.user;

    let folders = Folder::find_by_user(&user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    let ciphers = Cipher::find_by_user(&user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &conn)).collect();

    Ok(Json(json!({
        "Profile": user.to_json(),
        "Folders": folders_json,
        "Ciphers": ciphers_json,
        "Domains": {
            "EquivalentDomains": [],
            "GlobalEquivalentDomains": [],
            "Object": "domains",
        },
        "Object": "sync"
    })))
}


#[get("/ciphers")]
fn get_ciphers(headers: Headers, conn: DbConn) -> JsonResult {
    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);

    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &conn)).collect();

    Ok(Json(json!({
      "Data": ciphers_json,
      "Object": "list",
    })))
}

#[get("/ciphers/<uuid>")]
fn get_cipher(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct CipherData {
    #[serde(rename = "type")]
    type_: i32,
    folderId: Option<String>,
    organizationId: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    favorite: Option<bool>,

    login: Option<Value>,
    secureNote: Option<Value>,
    card: Option<Value>,
    identity: Option<Value>,

    fields: Option<Vec<Value>>,
}

#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: Json<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: CipherData = data.into_inner();

    let user_uuid = headers.user.uuid.clone();
    let favorite = data.favorite.unwrap_or(false);
    let mut cipher = Cipher::new(user_uuid, data.type_, favorite);

    update_cipher_from_data(&mut cipher, data, &headers, &conn)?;
    cipher.save(&conn);

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}

fn update_cipher_from_data(cipher: &mut Cipher, data: CipherData, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if let Some(folder_id) = data.folderId {
        match Folder::find_by_uuid(&folder_id, conn) {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist")
        }

        cipher.folder_uuid = Some(folder_id);
    }

    if let Some(org_id) = data.organizationId {
        // TODO: Check if user in org
        cipher.organization_uuid = Some(org_id);
    }

    let mut values = json!({
        "Name": data.name,
        "Notes": data.notes
    });

    let type_data_opt = match data.type_ {
        1 => data.login,
        2 => data.secureNote,
        3 => data.card,
        4 => data.identity,
        _ => err!("Invalid type")
    };

    let type_data = match type_data_opt {
        Some(data) => data,
        None => err!("Data missing")
    };

    // Copy the type data and change the names to the correct case
    if !copy_values(&type_data, &mut values) {
        err!("Data invalid")
    }

    if let Some(ref fields) = data.fields {
        values["Fields"] = Value::Array(fields.iter().map(|f| {
            let mut value = empty_map_value();

            // Copy every field object and change the names to the correct case
            copy_values(&f, &mut value);

            value
        }).collect());
    } else {
        values["Fields"] = Value::Null;
    }

    cipher.data = values.to_string();

    Ok(())
}

fn empty_map_value() -> Value {
    use std::collections::BTreeMap;
    use serde_json;

    serde_json::to_value(BTreeMap::<String, Value>::new()).unwrap()
}

fn copy_values(from: &Value, to: &mut Value) -> bool {
    let map = match from.as_object() {
        Some(map) => map,
        None => return false
    };

    for (key, val) in map {
        to[util::upcase_first(key)] = val.clone();
    }

    true
}

#[post("/ciphers/import", data = "<data>")]
fn post_ciphers_import(data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: Value = data.into_inner();
    let folders_value = data["folders"].as_array().unwrap();
    let ciphers_value = data["ciphers"].as_array().unwrap();
    let relations_value = data["folderRelationships"].as_array().unwrap();

    // Read and create the folders
    let folders: Vec<_> = folders_value.iter().map(|f| {
        let name = f["name"].as_str().unwrap().to_string();
        let mut folder = Folder::new(headers.user.uuid.clone(), name);
        folder.save(&conn);
        folder
    }).collect();

    // Read the relations between folders and ciphers
    let relations = relations_value.iter().map(|r| r["value"].as_u64().unwrap() as usize);

    // Read and create the ciphers
    use serde::Deserialize;
    ciphers_value.iter().zip( relations).map(|(c, fp)| {
        let folder_uuid = folders[fp].uuid.clone();
        let data = CipherData::deserialize(c.clone()).unwrap();

        let user_uuid = headers.user.uuid.clone();
        let favorite = data.favorite.unwrap_or(false);
        let mut cipher = Cipher::new(user_uuid, data.type_, favorite);

        if update_cipher_from_data(&mut cipher, data, &headers, &conn).is_err() { return; }

        cipher.save(&conn);
    });

    Ok(())
}

#[post("/ciphers/<uuid>", data = "<data>")]
fn post_cipher(uuid: String, data: Json<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    put_cipher(uuid, data, headers, conn)
}

#[put("/ciphers/<uuid>", data = "<data>")]
fn put_cipher(uuid: String, data: Json<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: CipherData = data.into_inner();

    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    cipher.favorite = data.favorite.unwrap_or(false);

    update_cipher_from_data(&mut cipher, data, &headers, &conn)?;
    cipher.save(&conn);

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}


#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
fn post_attachment(uuid: String, data: Data, content_type: &ContentType, headers: Headers, conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    let mut params = content_type.params();
    let boundary_pair = params.next().expect("No boundary provided");
    let boundary = boundary_pair.1;

    let base_path = Path::new(&CONFIG.attachments_folder).join(&cipher.uuid);

    Multipart::with_body(data.open(), boundary).foreach_entry(|mut field| {
        let name = field.headers.filename.unwrap(); // This is provided by the client, don't trust it

        let file_name = HEXLOWER.encode(&crypto::get_random(vec![0; 10]));
        let path = base_path.join(&file_name);

        let size = match field.data.save()
            .memory_threshold(0)
            .size_limit(None)
            .with_path(path) {
            SaveResult::Full(SavedData::File(_, size)) => size as i32,
            _ => return
        };

        let attachment = Attachment::new(file_name, cipher.uuid.clone(), name, size);
        println!("Attachment: {:#?}", attachment);
        attachment.save(&conn);
    });

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete")]
fn delete_attachment_post(uuid: String, attachment_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_attachment(uuid, attachment_id, headers, conn)
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>")]
fn delete_attachment(uuid: String, attachment_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    let attachment = match Attachment::find_by_id(&attachment_id, &conn) {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist")
    };

    if attachment.cipher_uuid != uuid {
        err!("Attachment from other cipher")
    }

    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    // Delete attachment
    attachment.delete(&conn);

    Ok(())
}

#[post("/ciphers/<uuid>/delete")]
fn delete_cipher_post(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_cipher(uuid, headers, conn)
}

#[delete("/ciphers/<uuid>")]
fn delete_cipher(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    // Delete attachments
    for a in Attachment::find_by_cipher(&cipher.uuid, &conn) { a.delete(&conn); }

    // Delete cipher
    cipher.delete(&conn);

    Ok(())
}

#[post("/ciphers/delete", data = "<data>")]
fn delete_all(data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    // Delete ciphers and their attachments
    for cipher in Cipher::find_by_user(&user.uuid, &conn) {
        for a in Attachment::find_by_cipher(&cipher.uuid, &conn) { a.delete(&conn); }

        cipher.delete(&conn);
    }

    // Delete folders
    for f in Folder::find_by_user(&user.uuid, &conn) { f.delete(&conn); }

    Ok(())
}
