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

use api::{self, PasswordData, JsonResult, EmptyResult};
use auth::Headers;

use CONFIG;

#[get("/sync")]
fn sync(headers: Headers, conn: DbConn) -> JsonResult {
    let user_json = headers.user.to_json(&conn);

    let folders = Folder::find_by_user(&headers.user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &conn)).collect();

    let domains_json = api::core::get_eq_domains(headers).unwrap().into_inner();

    Ok(Json(json!({
        "Profile": user_json,
        "Folders": folders_json,
        "Ciphers": ciphers_json,
        "Domains": domains_json,
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
    // Folder id is not included in import
    folderId: Option<String>,
    // TODO: Some of these might appear all the time, no need for Option
    organizationId: Option<String>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    */
    #[serde(rename = "type")]
    type_: i32,
    name: String,
    notes: Option<String>,
    fields: Option<Value>,

    // Only one of these should exist, depending on type
    login: Option<Value>,
    secureNote: Option<Value>,
    card: Option<Value>,
    identity: Option<Value>,

    favorite: Option<bool>,
}

#[post("/ciphers/admin", data = "<data>")]
fn post_ciphers_admin(data: Json<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_ciphers(data, headers, conn)
}

#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: Json<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: CipherData = data.into_inner();

    let user_uuid = headers.user.uuid.clone();
    let favorite = data.favorite.unwrap_or(false);
    let mut cipher = Cipher::new(user_uuid, data.type_, data.name.clone(), favorite);

    update_cipher_from_data(&mut cipher, data, &headers, &conn)?;
    cipher.save(&conn);

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}

fn update_cipher_from_data(cipher: &mut Cipher, data: CipherData, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if let Some(ref folder_id) = data.folderId {
        match Folder::find_by_uuid(folder_id, conn) {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist")
        }
    }

    cipher.folder_uuid = data.folderId;

    if let Some(org_id) = data.organizationId {
        match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
            None => err!("You don't have permission to add item to organization"),
            Some(org_user) => if org_user.access_all || org_user.type_ < UserOrgType::User as i32 {
                cipher.organization_uuid = Some(org_id);
            } else {
                err!("You don't have permission to add cipher directly to organization")
            }
        }
    }

    // TODO: ******* Backwards compat start **********
    // To remove backwards compatibility, just create an empty values object,
    // and remove the compat code from cipher::to_json
    let mut values = json!({
        "Name": data.name,
        "Notes": data.notes
    });

    if let Some(ref fields) = data.fields {
        values["Fields"] = Value::Array(fields.as_array().unwrap().iter().map(|f| {
            let mut value = json!({});

            // Copy every field object and change the names to the correct case
            copy_values(&f, &mut value);

            value
        }).collect());
    } else {
        values["Fields"] = Value::Null;
    }
    // TODO: ******* Backwards compat end **********

    if let notes @ Some(_) = data.notes {
        cipher.notes = notes;
    }

    if let Some(fields) = data.fields {
        use serde_json::to_string;
        cipher.fields = to_string(&fields).ok();
    }

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
    copy_values(&type_data, &mut values);

    cipher.data = values.to_string();

    Ok(())
}

fn copy_values(from: &Value, to: &mut Value) {
    if let Some(map) = from.as_object() {
        for (key, val) in map {
            copy_values(val, &mut to[util::upcase_first(key)]);
        }
    } else if let Some(array) = from.as_array() {
        // Initialize array with null values
        *to = json!(vec![Value::Null; array.len()]);

        for (index, val) in array.iter().enumerate() {
            copy_values(val, &mut to[index]);
        }
    } else {
        *to = from.clone();
    }
}

use super::folders::FolderData;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ImportData {
    ciphers: Vec<CipherData>,
    folders: Vec<FolderData>,
    folderRelationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RelationsData {
    // Cipher id
    key: u32,
    // Folder id
    value: u32,
}


#[post("/ciphers/import", data = "<data>")]
fn post_ciphers_import(data: Json<ImportData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ImportData = data.into_inner();

    // Read and create the folders
    let folders: Vec<_> = data.folders.iter().map(|folder| {
        let mut folder = Folder::new(headers.user.uuid.clone(), folder.name.clone());
        folder.save(&conn);
        folder
    }).collect();

    // Read the relations between folders and ciphers
    use std::collections::HashMap;
    let mut relations_map = HashMap::new();

    for relation in data.folderRelationships {
        relations_map.insert(relation.key, relation.value);
    }

    // Read and create the ciphers
    let mut index = 0;
    for cipher_data in data.ciphers {
        let folder_uuid = relations_map.get(&index)
            .map(|i| folders[*i as usize].uuid.clone());

        let user_uuid = headers.user.uuid.clone();
        let favorite = cipher_data.favorite.unwrap_or(false);
        let mut cipher = Cipher::new(user_uuid, cipher_data.type_, cipher_data.name.clone(), favorite);

        if update_cipher_from_data(&mut cipher, cipher_data, &headers, &conn).is_err() { err!("Error creating cipher") }

        cipher.folder_uuid = folder_uuid;

        cipher.save(&conn);
        index += 1;
    }

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
    }).expect("Error processing multipart data");

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
    _delete_cipher_by_uuid(&uuid, &headers, &conn)
}

#[delete("/ciphers/<uuid>")]
fn delete_cipher(uuid: String, headers: Headers, conn: DbConn) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn)
}

#[post("/ciphers/delete", data = "<data>")]
fn delete_cipher_selected(data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: Value = data.into_inner();

    let uuids = match data.get("ids") {
        Some(ids) => match ids.as_array() {
            Some(ids) => ids.iter().filter_map(|uuid| { uuid.as_str() }),
            None => err!("Posted ids field is not an array")
        },
        None => err!("Request missing ids field")
    };

    for uuid in uuids {
        if let error @ Err(_) = _delete_cipher_by_uuid(uuid, &headers, &conn) {
            return error;
        };
    }

    Ok(())
}

#[post("/ciphers/move", data = "<data>")]
fn move_cipher_selected(data: Json<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let folder_id = match data.get("folderId") {
        Some(folder_id) => {
            match folder_id.as_str() {
                Some(folder_id) => {
                    match Folder::find_by_uuid(folder_id, &conn) {
                        Some(folder) => {
                            if folder.user_uuid != headers.user.uuid {
                                err!("Folder is not owned by user")
                            }
                            Some(folder_id.to_string())
                        }
                        None => err!("Folder doesn't exist")
                    }
                }
                None => err!("Folder id provided in wrong format")
            }
        }
        None => None
    };

    let uuids = match data.get("ids") {
        Some(ids) => match ids.as_array() {
            Some(ids) => ids.iter().filter_map(|uuid| { uuid.as_str() }),
            None => err!("Posted ids field is not an array")
        },
        None => err!("Request missing ids field")
    };

    for uuid in uuids {
        let mut cipher = match Cipher::find_by_uuid(uuid, &conn) {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist")
        };

        if cipher.user_uuid != headers.user.uuid {
            err!("Cipher is not owned by user")
        }

        // Move cipher
        cipher.folder_uuid = folder_id.clone();
        cipher.save(&conn);
    }

    Ok(())
}

#[post("/ciphers/purge", data = "<data>")]
fn delete_all(data: Json<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner();
    let password_hash = data.masterPasswordHash;

    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    // Delete ciphers and their attachments
    for cipher in Cipher::find_by_user(&user.uuid, &conn) {
        _delete_cipher(cipher, &conn);
    }

    // Delete folders
    for f in Folder::find_by_user(&user.uuid, &conn) { f.delete(&conn); }

    Ok(())
}

fn _delete_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    _delete_cipher(cipher, conn);

    Ok(())
}

fn _delete_cipher(cipher: Cipher, conn: &DbConn) {
    // Delete the attachments
    for a in Attachment::find_by_cipher(&cipher.uuid, &conn) { a.delete(&conn); }

    // Delete the cipher
    cipher.delete(conn);
}
