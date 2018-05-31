use std::path::Path;
use std::collections::HashSet;

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

use api::{self, PasswordData, JsonResult, EmptyResult, JsonUpcase};
use auth::Headers;

use CONFIG;

#[get("/sync")]
fn sync(headers: Headers, conn: DbConn) -> JsonResult {
    let user_json = headers.user.to_json(&conn);

    let folders = Folder::find_by_user(&headers.user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn)).collect();

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

    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn)).collect();

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

    if !cipher.is_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not owned by user")
    }

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

#[get("/ciphers/<uuid>/admin")]
fn get_cipher_admin(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    // TODO: Implement this correctly
    get_cipher(uuid, headers, conn)
}

#[get("/ciphers/<uuid>/details")]
fn get_cipher_details(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    get_cipher(uuid, headers, conn)
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct CipherData {
    // Folder id is not included in import
    FolderId: Option<String>,
    // TODO: Some of these might appear all the time, no need for Option
    OrganizationId: Option<String>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    */
    Type: i32, // TODO: Change this to NumberOrString
    Name: String,
    Notes: Option<String>,
    Fields: Option<Value>,

    // Only one of these should exist, depending on type
    Login: Option<Value>,
    SecureNote: Option<Value>,
    Card: Option<Value>,
    Identity: Option<Value>,

    Favorite: Option<bool>,
}

#[post("/ciphers/admin", data = "<data>")]
fn post_ciphers_admin(data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    // TODO: Implement this correctly
    post_ciphers(data, headers, conn)
}

#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: CipherData = data.into_inner().data;

    let mut cipher = Cipher::new(data.Type, data.Name.clone());
    update_cipher_from_data(&mut cipher, data, &headers, true, &conn)?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

fn update_cipher_from_data(cipher: &mut Cipher, data: CipherData, headers: &Headers, is_new_or_shared: bool, conn: &DbConn) -> EmptyResult {
    if is_new_or_shared {
        if let Some(org_id) = data.OrganizationId {
            match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
                None => err!("You don't have permission to add item to organization"),
                Some(org_user) => if org_user.has_full_access() {
                    cipher.organization_uuid = Some(org_id);
                    cipher.user_uuid = None;
                } else {
                    err!("You don't have permission to add cipher directly to organization")
                }
            }
        } else {
            cipher.user_uuid = Some(headers.user.uuid.clone());
        }
    }

    if let Some(ref folder_id) = data.FolderId {
        match Folder::find_by_uuid(folder_id, conn) {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist")
        }
    }

    let uppercase_fields = data.Fields.map(|f| {
        let mut value = json!({});
        // Copy every field object and change the names to the correct case
        copy_values(&f, &mut value);
        value
    });

    // TODO: ******* Backwards compat start **********
    // To remove backwards compatibility, just create an empty values object,
    // and remove the compat code from cipher::to_json
    let mut values = json!({
        "Name": data.Name,
        "Notes": data.Notes
    });

    values["Fields"] = uppercase_fields.clone().unwrap_or(Value::Null);
    // TODO: ******* Backwards compat end **********

    let type_data_opt = match data.Type {
        1 => data.Login,
        2 => data.SecureNote,
        3 => data.Card,
        4 => data.Identity,
        _ => err!("Invalid type")
    };

    let type_data = match type_data_opt {
        Some(data) => data,
        None => err!("Data missing")
    };

    // Copy the type data and change the names to the correct case
    copy_values(&type_data, &mut values);

    cipher.favorite = data.Favorite.unwrap_or(false);
    cipher.name = data.Name;
    cipher.notes = data.Notes;
    cipher.fields = uppercase_fields.map(|f| f.to_string());
    cipher.data = values.to_string();

    cipher.save(&conn);

    if cipher.move_to_folder(data.FolderId, &headers.user.uuid, &conn).is_err() {
        err!("Error saving the folder information")
    }

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
    Ciphers: Vec<CipherData>,
    Folders: Vec<FolderData>,
    FolderRelationships: Vec<RelationsData>,
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
fn post_ciphers_import(data: JsonUpcase<ImportData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: ImportData = data.into_inner().data;

    // Read and create the folders
    let folders: Vec<_> = data.Folders.into_iter().map(|folder| {
        let mut folder = Folder::new(headers.user.uuid.clone(), folder.Name);
        folder.save(&conn);
        folder
    }).collect();

    // Read the relations between folders and ciphers
    use std::collections::HashMap;
    let mut relations_map = HashMap::new();

    for relation in data.FolderRelationships {
        relations_map.insert(relation.key, relation.value);
    }

    // Read and create the ciphers
    let mut index = 0;
    for cipher_data in data.Ciphers {
        let folder_uuid = relations_map.get(&index)
            .map(|i| folders[*i as usize].uuid.clone());

        let mut cipher = Cipher::new(cipher_data.Type, cipher_data.Name.clone());
        update_cipher_from_data(&mut cipher, cipher_data, &headers, true, &conn)?;

        cipher.move_to_folder(folder_uuid, &headers.user.uuid.clone(), &conn).ok();

        index += 1;
    }

    Ok(())
}

#[post("/ciphers/<uuid>/admin", data = "<data>")]
fn post_cipher_admin(uuid: String, data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    // TODO: Implement this correctly
    post_cipher(uuid, data, headers, conn)
}

#[post("/ciphers/<uuid>", data = "<data>")]
fn post_cipher(uuid: String, data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    put_cipher(uuid, data, headers, conn)
}

#[put("/ciphers/<uuid>", data = "<data>")]
fn put_cipher(uuid: String, data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: CipherData = data.into_inner().data;

    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
    }

    update_cipher_from_data(&mut cipher, data, &headers, false, &conn)?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionsAdminData {
    CollectionIds: Vec<String>,
}

#[post("/ciphers/<uuid>/collections", data = "<data>")]
fn post_collections_update(uuid: String, data: JsonUpcase<CollectionsAdminData>, headers: Headers, conn: DbConn) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn)
}

#[post("/ciphers/<uuid>/collections-admin", data = "<data>")]
fn post_collections_admin(uuid: String, data: JsonUpcase<CollectionsAdminData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: CollectionsAdminData = data.into_inner().data;

    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
    }

    let posted_collections: HashSet<String> = data.CollectionIds.iter().cloned().collect();
    let current_collections: HashSet<String> = cipher.get_collections(&headers.user.uuid ,&conn).iter().cloned().collect();

    for collection in posted_collections.symmetric_difference(&current_collections) {
        match Collection::find_by_uuid(&collection, &conn) {
            None => err!("Invalid collection ID provided"),
            Some(collection) => {
                if collection.is_writable_by_user(&headers.user.uuid, &conn) {
                    if posted_collections.contains(&collection.uuid) { // Add to collection
                        CollectionCipher::save(&cipher.uuid, &collection.uuid, &conn);
                    } else { // Remove from collection
                        CollectionCipher::delete(&cipher.uuid, &collection.uuid, &conn);
                    }
                } else {
                    err!("No rights to modify the collection")
                }
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ShareCipherData {
    #[serde(deserialize_with = "util::upcase_deserialize")]
    Cipher: CipherData,
    CollectionIds: Vec<String>,
}

#[post("/ciphers/<uuid>/share", data = "<data>")]
fn post_cipher_share(uuid: String, data: JsonUpcase<ShareCipherData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => {
            if cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
                cipher
            } else {
                err!("Cipher is not write accessible")
            }
        },
        None => err!("Cipher doesn't exist")
    };

    match data.Cipher.OrganizationId {
        None => err!("Organization id not provided"),
        Some(_) => {
            update_cipher_from_data(&mut cipher, data.Cipher, &headers, true, &conn)?;
            for collection in data.CollectionIds.iter() {
                match Collection::find_by_uuid(&collection, &conn) {
                    None => err!("Invalid collection ID provided"),
                    Some(collection) => {
                        if collection.is_writable_by_user(&headers.user.uuid, &conn) {
                            CollectionCipher::save(&cipher.uuid.clone(), &collection.uuid, &conn);
                        } else {
                            err!("No rights to modify the collection")
                        }
                    }
                }
            }

            Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
        }
    }
}

#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
fn post_attachment(uuid: String, data: Data, content_type: &ContentType, headers: Headers, conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
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

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
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

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher cannot be deleted by user")
    }

    // Delete attachment
    match attachment.delete(&conn) {
        Ok(()) => Ok(()),
        Err(_) => err!("Deleting attachement failed")
    }
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
fn delete_cipher_selected(data: JsonUpcase<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: Value = data.into_inner().data;

    let uuids = match data.get("Ids") {
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
fn move_cipher_selected(data: JsonUpcase<Value>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner().data;

    let folder_id = match data.get("FolderId") {
        Some(folder_id) => {
            match folder_id.as_str() {
                Some(folder_id) => {
                    match Folder::find_by_uuid(folder_id, &conn) {
                        Some(folder) => {
                            if folder.user_uuid != headers.user.uuid {
                                err!("Folder is not owned by user")
                            }
                            Some(folder.uuid)
                        }
                        None => err!("Folder doesn't exist")
                    }
                }
                None => err!("Folder id provided in wrong format")
            }
        }
        None => None
    };

    let uuids = match data.get("Ids") {
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

        if !cipher.is_accessible_to_user(&headers.user.uuid, &conn) {
            err!("Cipher is not accessible by user")
        }

        // Move cipher
        if cipher.move_to_folder(folder_id.clone(), &headers.user.uuid, &conn).is_err() {
            err!("Error saving the folder information")
        }
        cipher.save(&conn);
    }

    Ok(())
}

#[post("/ciphers/purge", data = "<data>")]
fn delete_all(data: JsonUpcase<PasswordData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;

    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    // Delete ciphers and their attachments
    for cipher in Cipher::find_owned_by_user(&user.uuid, &conn) {
        match cipher.delete(&conn) {
            Ok(()) => (),
            Err(_) => err!("Failed deleting cipher")
        }
    }

    // Delete folders
    for f in Folder::find_by_user(&user.uuid, &conn) {
        match f.delete(&conn) {
            Ok(()) => (),
            Err(_) => err!("Failed deleting folder")
        } 
    }

    Ok(())
}

fn _delete_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher can't be deleted by user")
    }

    match cipher.delete(conn) {
        Ok(()) => Ok(()),
        Err(_) => err!("Failed deleting cipher")
    }
}
