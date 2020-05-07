use std::collections::{HashMap, HashSet};
use std::path::Path;

use rocket::http::ContentType;
use rocket::{request::Form, Data, Route};

use rocket_contrib::json::Json;
use serde_json::Value;

use multipart::server::save::SavedData;
use multipart::server::{Multipart, SaveResult};

use data_encoding::HEXLOWER;

use crate::db::models::*;
use crate::db::DbConn;

use crate::crypto;

use crate::api::{self, EmptyResult, JsonResult, JsonUpcase, Notify, PasswordData, UpdateType};
use crate::auth::Headers;

use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![
        sync,
        get_ciphers,
        get_cipher,
        get_cipher_admin,
        get_cipher_details,
        post_ciphers,
        put_cipher_admin,
        post_ciphers_admin,
        post_ciphers_create,
        post_ciphers_import,
        post_attachment,
        post_attachment_admin,
        post_attachment_share,
        delete_attachment_post,
        delete_attachment_post_admin,
        delete_attachment,
        delete_attachment_admin,
        post_cipher_admin,
        post_cipher_share,
        put_cipher_share,
        put_cipher_share_seleted,
        post_cipher,
        put_cipher,
        delete_cipher_post,
        delete_cipher_post_admin,
        delete_cipher_put,
        delete_cipher_put_admin,
        delete_cipher,
        delete_cipher_admin,
        delete_cipher_selected,
        delete_cipher_selected_post,
        delete_cipher_selected_put,
        restore_cipher_put,
        restore_cipher_put_admin,
        restore_cipher_selected,
        delete_all,
        move_cipher_selected,
        move_cipher_selected_put,
        put_collections_update,
        post_collections_update,
        post_collections_admin,
        put_collections_admin,
    ]
}

#[derive(FromForm, Default)]
struct SyncData {
    #[form(field = "excludeDomains")]
    exclude_domains: bool, // Default: 'false'
}

#[get("/sync?<data..>")]
fn sync(data: Form<SyncData>, headers: Headers, conn: DbConn) -> JsonResult {
    let user_json = headers.user.to_json(&conn);

    let folders = Folder::find_by_user(&headers.user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    let collections = Collection::find_by_user_uuid(&headers.user.uuid, &conn);
    let collections_json: Vec<Value> = collections.iter().map(Collection::to_json).collect();

    let policies = OrgPolicy::find_by_user(&headers.user.uuid, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers
        .iter()
        .map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn))
        .collect();

    let domains_json = if data.exclude_domains {
        Value::Null
    } else {
        api::core::_get_eq_domains(headers, true).unwrap().into_inner()
    };

    Ok(Json(json!({
        "Profile": user_json,
        "Folders": folders_json,
        "Collections": collections_json,
        "Policies": policies_json,
        "Ciphers": ciphers_json,
        "Domains": domains_json,
        "Object": "sync"
    })))
}

#[get("/ciphers")]
fn get_ciphers(headers: Headers, conn: DbConn) -> JsonResult {
    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);

    let ciphers_json: Vec<Value> = ciphers
        .iter()
        .map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn))
        .collect();

    Ok(Json(json!({
      "Data": ciphers_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/ciphers/<uuid>")]
fn get_cipher(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
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
pub struct CipherData {
    // Id is optional as it is included only in bulk share
    pub Id: Option<String>,
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
    pub Type: i32, // TODO: Change this to NumberOrString
    pub Name: String,
    Notes: Option<String>,
    Fields: Option<Value>,

    // Only one of these should exist, depending on type
    Login: Option<Value>,
    SecureNote: Option<Value>,
    Card: Option<Value>,
    Identity: Option<Value>,

    Favorite: Option<bool>,

    PasswordHistory: Option<Value>,

    // These are used during key rotation
    #[serde(rename = "Attachments")]
    _Attachments: Option<Value>, // Unused, contains map of {id: filename}
    Attachments2: Option<HashMap<String, Attachments2Data>>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Attachments2Data {
    FileName: String,
    Key: String,
}

#[post("/ciphers/admin", data = "<data>")]
fn post_ciphers_admin(data: JsonUpcase<ShareCipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    let mut cipher = Cipher::new(data.Cipher.Type, data.Cipher.Name.clone());
    cipher.user_uuid = Some(headers.user.uuid.clone());
    cipher.save(&conn)?;

    share_cipher_by_uuid(&cipher.uuid, data, &headers, &conn, &nt)
}

#[post("/ciphers/create", data = "<data>")]
fn post_ciphers_create(data: JsonUpcase<ShareCipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    post_ciphers_admin(data, headers, conn, nt)
}

#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    let data: CipherData = data.into_inner().data;

    let mut cipher = Cipher::new(data.Type, data.Name.clone());
    update_cipher_from_data(&mut cipher, data, &headers, false, &conn, &nt, UpdateType::CipherCreate)?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

pub fn update_cipher_from_data(
    cipher: &mut Cipher,
    data: CipherData,
    headers: &Headers,
    shared_to_collection: bool,
    conn: &DbConn,
    nt: &Notify,
    ut: UpdateType,
) -> EmptyResult {
    if cipher.organization_uuid.is_some() && cipher.organization_uuid != data.OrganizationId {
        err!("Organization mismatch. Please resync the client before updating the cipher")
    }

    if let Some(org_id) = data.OrganizationId {
        match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn) {
            None => err!("You don't have permission to add item to organization"),
            Some(org_user) => {
                if shared_to_collection
                    || org_user.has_full_access()
                    || cipher.is_write_accessible_to_user(&headers.user.uuid, &conn)
                {
                    cipher.organization_uuid = Some(org_id);
                    cipher.user_uuid = None;
                } else {
                    err!("You don't have permission to add cipher directly to organization")
                }
            }
        }
    } else {
        cipher.user_uuid = Some(headers.user.uuid.clone());
    }

    if let Some(ref folder_id) = data.FolderId {
        match Folder::find_by_uuid(folder_id, conn) {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist"),
        }
    }

    // Modify attachments name and keys when rotating
    if let Some(attachments) = data.Attachments2 {
        for (id, attachment) in attachments {
            let mut saved_att = match Attachment::find_by_id(&id, &conn) {
                Some(att) => att,
                None => err!("Attachment doesn't exist"),
            };

            if saved_att.cipher_uuid != cipher.uuid {
                err!("Attachment is not owned by the cipher")
            }

            saved_att.akey = Some(attachment.Key);
            saved_att.file_name = attachment.FileName;

            saved_att.save(&conn)?;
        }
    }

    let type_data_opt = match data.Type {
        1 => data.Login,
        2 => data.SecureNote,
        3 => data.Card,
        4 => data.Identity,
        _ => err!("Invalid type"),
    };

    let mut type_data = match type_data_opt {
        Some(data) => data,
        None => err!("Data missing"),
    };

    // TODO: ******* Backwards compat start **********
    // To remove backwards compatibility, just delete this code,
    // and remove the compat code from cipher::to_json
    type_data["Name"] = Value::String(data.Name.clone());
    type_data["Notes"] = data.Notes.clone().map(Value::String).unwrap_or(Value::Null);
    type_data["Fields"] = data.Fields.clone().unwrap_or(Value::Null);
    type_data["PasswordHistory"] = data.PasswordHistory.clone().unwrap_or(Value::Null);
    // TODO: ******* Backwards compat end **********

    cipher.favorite = data.Favorite.unwrap_or(false);
    cipher.name = data.Name;
    cipher.notes = data.Notes;
    cipher.fields = data.Fields.map(|f| f.to_string());
    cipher.data = type_data.to_string();
    cipher.password_history = data.PasswordHistory.map(|f| f.to_string());

    cipher.save(&conn)?;
    cipher.move_to_folder(data.FolderId, &headers.user.uuid, &conn)?;

    if ut != UpdateType::None {
        nt.send_cipher_update(ut, &cipher, &cipher.update_users_revision(&conn));
    }

    Ok(())
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
    Key: usize,
    // Folder id
    Value: usize,
}

#[post("/ciphers/import", data = "<data>")]
fn post_ciphers_import(data: JsonUpcase<ImportData>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    let data: ImportData = data.into_inner().data;

    // Read and create the folders
    let mut folders: Vec<_> = Vec::new();
    for folder in data.Folders.into_iter() {
        let mut new_folder = Folder::new(headers.user.uuid.clone(), folder.Name);
        new_folder.save(&conn)?;

        folders.push(new_folder);
    }

    // Read the relations between folders and ciphers
    let mut relations_map = HashMap::new();

    for relation in data.FolderRelationships {
        relations_map.insert(relation.Key, relation.Value);
    }

    // Read and create the ciphers
    for (index, mut cipher_data) in data.Ciphers.into_iter().enumerate() {
        let folder_uuid = relations_map.get(&index).map(|i| folders[*i].uuid.clone());
        cipher_data.FolderId = folder_uuid;

        let mut cipher = Cipher::new(cipher_data.Type, cipher_data.Name.clone());
        update_cipher_from_data(&mut cipher, cipher_data, &headers, false, &conn, &nt, UpdateType::None)?;
    }

    let mut user = headers.user;
    user.update_revision(&conn)?;
    nt.send_user_update(UpdateType::Vault, &user);
    Ok(())
}

#[put("/ciphers/<uuid>/admin", data = "<data>")]
fn put_cipher_admin(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    put_cipher(uuid, data, headers, conn, nt)
}

#[post("/ciphers/<uuid>/admin", data = "<data>")]
fn post_cipher_admin(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    post_cipher(uuid, data, headers, conn, nt)
}

#[post("/ciphers/<uuid>", data = "<data>")]
fn post_cipher(uuid: String, data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    put_cipher(uuid, data, headers, conn, nt)
}

#[put("/ciphers/<uuid>", data = "<data>")]
fn put_cipher(uuid: String, data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    let data: CipherData = data.into_inner().data;

    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
    }

    update_cipher_from_data(&mut cipher, data, &headers, false, &conn, &nt, UpdateType::CipherUpdate)?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionsAdminData {
    CollectionIds: Vec<String>,
}

#[put("/ciphers/<uuid>/collections", data = "<data>")]
fn put_collections_update(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn)
}

#[post("/ciphers/<uuid>/collections", data = "<data>")]
fn post_collections_update(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn)
}

#[put("/ciphers/<uuid>/collections-admin", data = "<data>")]
fn put_collections_admin(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn)
}

#[post("/ciphers/<uuid>/collections-admin", data = "<data>")]
fn post_collections_admin(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    let data: CollectionsAdminData = data.into_inner().data;

    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
    }

    let posted_collections: HashSet<String> = data.CollectionIds.iter().cloned().collect();
    let current_collections: HashSet<String> = cipher
        .get_collections(&headers.user.uuid, &conn)
        .iter()
        .cloned()
        .collect();

    for collection in posted_collections.symmetric_difference(&current_collections) {
        match Collection::find_by_uuid(&collection, &conn) {
            None => err!("Invalid collection ID provided"),
            Some(collection) => {
                if collection.is_writable_by_user(&headers.user.uuid, &conn) {
                    if posted_collections.contains(&collection.uuid) {
                        // Add to collection
                        CollectionCipher::save(&cipher.uuid, &collection.uuid, &conn)?;
                    } else {
                        // Remove from collection
                        CollectionCipher::delete(&cipher.uuid, &collection.uuid, &conn)?;
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
    Cipher: CipherData,
    CollectionIds: Vec<String>,
}

#[post("/ciphers/<uuid>/share", data = "<data>")]
fn post_cipher_share(
    uuid: String,
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    share_cipher_by_uuid(&uuid, data, &headers, &conn, &nt)
}

#[put("/ciphers/<uuid>/share", data = "<data>")]
fn put_cipher_share(
    uuid: String,
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    share_cipher_by_uuid(&uuid, data, &headers, &conn, &nt)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ShareSelectedCipherData {
    Ciphers: Vec<CipherData>,
    CollectionIds: Vec<String>,
}

#[put("/ciphers/share", data = "<data>")]
fn put_cipher_share_seleted(
    data: JsonUpcase<ShareSelectedCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    let mut data: ShareSelectedCipherData = data.into_inner().data;
    let mut cipher_ids: Vec<String> = Vec::new();

    if data.Ciphers.is_empty() {
        err!("You must select at least one cipher.")
    }

    if data.CollectionIds.is_empty() {
        err!("You must select at least one collection.")
    }

    for cipher in data.Ciphers.iter() {
        match cipher.Id {
            Some(ref id) => cipher_ids.push(id.to_string()),
            None => err!("Request missing ids field"),
        };
    }

    let attachments = Attachment::find_by_ciphers(cipher_ids, &conn);

    if !attachments.is_empty() {
        err!("Ciphers should not have any attachments.")
    }

    while let Some(cipher) = data.Ciphers.pop() {
        let mut shared_cipher_data = ShareCipherData {
            Cipher: cipher,
            CollectionIds: data.CollectionIds.clone(),
        };

        match shared_cipher_data.Cipher.Id.take() {
            Some(id) => share_cipher_by_uuid(&id, shared_cipher_data, &headers, &conn, &nt)?,
            None => err!("Request missing ids field"),
        };
    }

    Ok(())
}

fn share_cipher_by_uuid(
    uuid: &str,
    data: ShareCipherData,
    headers: &Headers,
    conn: &DbConn,
    nt: &Notify,
) -> JsonResult {
    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => {
            if cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
                cipher
            } else {
                err!("Cipher is not write accessible")
            }
        }
        None => err!("Cipher doesn't exist"),
    };

    let mut shared_to_collection = false;

    match data.Cipher.OrganizationId.clone() {
        // If we don't get an organization ID, we don't do anything
        // No error because this is used when using the Clone functionality
        None => {},
        Some(organization_uuid) => {

            for uuid in &data.CollectionIds {
                match Collection::find_by_uuid_and_org(uuid, &organization_uuid, &conn) {
                    None => err!("Invalid collection ID provided"),
                    Some(collection) => {
                        if collection.is_writable_by_user(&headers.user.uuid, &conn) {
                            CollectionCipher::save(&cipher.uuid, &collection.uuid, &conn)?;
                            shared_to_collection = true;
                        } else {
                            err!("No rights to modify the collection")
                        }
                    }
                }
            }
        }
    };

    update_cipher_from_data(
        &mut cipher,
        data.Cipher,
        &headers,
        shared_to_collection,
        &conn,
        &nt,
        UpdateType::CipherUpdate,
    )?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
fn post_attachment(
    uuid: String,
    data: Data,
    content_type: &ContentType,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err_discard!("Cipher doesn't exist", data),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err_discard!("Cipher is not write accessible", data)
    }

    let mut params = content_type.params();
    let boundary_pair = params.next().expect("No boundary provided");
    let boundary = boundary_pair.1;

    let size_limit = if let Some(ref user_uuid) = cipher.user_uuid {
        match CONFIG.user_attachment_limit() {
            Some(0) => err_discard!("Attachments are disabled", data),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_user(user_uuid, &conn);
                if left <= 0 {
                    err_discard!("Attachment size limit reached! Delete some files to open space", data)
                }
                Some(left as u64)
            }
            None => None,
        }
    } else if let Some(ref org_uuid) = cipher.organization_uuid {
        match CONFIG.org_attachment_limit() {
            Some(0) => err_discard!("Attachments are disabled", data),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_org(org_uuid, &conn);
                if left <= 0 {
                    err_discard!("Attachment size limit reached! Delete some files to open space", data)
                }
                Some(left as u64)
            }
            None => None,
        }
    } else {
        err_discard!("Cipher is neither owned by a user nor an organization", data);
    };

    let base_path = Path::new(&CONFIG.attachments_folder()).join(&cipher.uuid);

    let mut attachment_key = None;
    let mut error = None;

    Multipart::with_body(data.open(), boundary)
        .foreach_entry(|mut field| {
            match &*field.headers.name {
                "key" => {
                    use std::io::Read;
                    let mut key_buffer = String::new();
                    if field.data.read_to_string(&mut key_buffer).is_ok() {
                        attachment_key = Some(key_buffer);
                    }
                }
                "data" => {
                    // This is provided by the client, don't trust it
                    let name = field.headers.filename.expect("No filename provided");

                    let file_name = HEXLOWER.encode(&crypto::get_random(vec![0; 10]));
                    let path = base_path.join(&file_name);

                    let size = match field.data.save().memory_threshold(0).size_limit(size_limit).with_path(path.clone()) {
                        SaveResult::Full(SavedData::File(_, size)) => size as i32,
                        SaveResult::Full(other) => {
                            std::fs::remove_file(path).ok();
                            error = Some(format!("Attachment is not a file: {:?}", other));
                            return;
                        }
                        SaveResult::Partial(_, reason) => {
                            std::fs::remove_file(path).ok();
                            error = Some(format!("Attachment size limit exceeded with this file: {:?}", reason));
                            return;
                        }
                        SaveResult::Error(e) => {
                            std::fs::remove_file(path).ok();
                            error = Some(format!("Error: {:?}", e));
                            return;
                        }
                    };

                    let mut attachment = Attachment::new(file_name, cipher.uuid.clone(), name, size);
                    attachment.akey = attachment_key.clone();
                    attachment.save(&conn).expect("Error saving attachment");
                }
                _ => error!("Invalid multipart name"),
            }
        })
        .expect("Error processing multipart data");

    if let Some(ref e) = error {
        err!(e);
    }

    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(&conn));

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

#[post("/ciphers/<uuid>/attachment-admin", format = "multipart/form-data", data = "<data>")]
fn post_attachment_admin(
    uuid: String,
    data: Data,
    content_type: &ContentType,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    post_attachment(uuid, data, content_type, headers, conn, nt)
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/share", format = "multipart/form-data", data = "<data>")]
fn post_attachment_share(
    uuid: String,
    attachment_id: String,
    data: Data,
    content_type: &ContentType,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &conn, &nt)?;
    post_attachment(uuid, data, content_type, headers, conn, nt)
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete-admin")]
fn delete_attachment_post_admin(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    delete_attachment(uuid, attachment_id, headers, conn, nt)
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete")]
fn delete_attachment_post(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    delete_attachment(uuid, attachment_id, headers, conn, nt)
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>")]
fn delete_attachment(uuid: String, attachment_id: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &conn, &nt)
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>/admin")]
fn delete_attachment_admin(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &conn, &nt)
}

#[post("/ciphers/<uuid>/delete")]
fn delete_cipher_post(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, false, &nt)
}

#[post("/ciphers/<uuid>/delete-admin")]
fn delete_cipher_post_admin(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, false, &nt)
}

#[put("/ciphers/<uuid>/delete")]
fn delete_cipher_put(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, true, &nt)
}

#[put("/ciphers/<uuid>/delete-admin")]
fn delete_cipher_put_admin(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, true, &nt)
}

#[delete("/ciphers/<uuid>")]
fn delete_cipher(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, false, &nt)
}

#[delete("/ciphers/<uuid>/admin")]
fn delete_cipher_admin(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &conn, false, &nt)
}

#[delete("/ciphers", data = "<data>")]
fn delete_cipher_selected(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt)
}

#[post("/ciphers/delete", data = "<data>")]
fn delete_cipher_selected_post(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt)
}

#[put("/ciphers/delete", data = "<data>")]
fn delete_cipher_selected_put(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, true, nt)
}

#[put("/ciphers/<uuid>/restore")]
fn restore_cipher_put(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _restore_cipher_by_uuid(&uuid, &headers, &conn, &nt)
}

#[put("/ciphers/<uuid>/restore-admin")]
fn restore_cipher_put_admin(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _restore_cipher_by_uuid(&uuid, &headers, &conn, &nt)
}

#[put("/ciphers/restore", data = "<data>")]
fn restore_cipher_selected(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    _restore_multiple_ciphers(data, headers, conn, nt)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct MoveCipherData {
    FolderId: Option<String>,
    Ids: Vec<String>,
}

#[post("/ciphers/move", data = "<data>")]
fn move_cipher_selected(data: JsonUpcase<MoveCipherData>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    let data = data.into_inner().data;
    let user_uuid = headers.user.uuid;

    if let Some(ref folder_id) = data.FolderId {
        match Folder::find_by_uuid(folder_id, &conn) {
            Some(folder) => {
                if folder.user_uuid != user_uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist"),
        }
    }

    for uuid in data.Ids {
        let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        if !cipher.is_accessible_to_user(&user_uuid, &conn) {
            err!("Cipher is not accessible by user")
        }

        // Move cipher
        cipher.move_to_folder(data.FolderId.clone(), &user_uuid, &conn)?;

        nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &[user_uuid.clone()]);
    }

    Ok(())
}

#[put("/ciphers/move", data = "<data>")]
fn move_cipher_selected_put(
    data: JsonUpcase<MoveCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    move_cipher_selected(data, headers, conn, nt)
}

#[derive(FromForm)]
struct OrganizationId {
    #[form(field = "organizationId")]
    org_id: String,
}

#[post("/ciphers/purge?<organization..>", data = "<data>")]
fn delete_all(
    organization: Option<Form<OrganizationId>>,
    data: JsonUpcase<PasswordData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;

    let mut user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    match organization {
        Some(org_data) => {
            // Organization ID in query params, purging organization vault
            match UserOrganization::find_by_user_and_org(&user.uuid, &org_data.org_id, &conn) {
                None => err!("You don't have permission to purge the organization vault"),
                Some(user_org) => {
                    if user_org.atype == UserOrgType::Owner {
                        Cipher::delete_all_by_organization(&org_data.org_id, &conn)?;
                        Collection::delete_all_by_organization(&org_data.org_id, &conn)?;
                        nt.send_user_update(UpdateType::Vault, &user);
                        Ok(())
                    } else {
                        err!("You don't have permission to purge the organization vault");
                    }
                }
            }
        }
        None => {
            // No organization ID in query params, purging user vault
            // Delete ciphers and their attachments
            for cipher in Cipher::find_owned_by_user(&user.uuid, &conn) {
                cipher.delete(&conn)?;
            }

            // Delete folders
            for f in Folder::find_by_user(&user.uuid, &conn) {
                f.delete(&conn)?;
            }

            user.update_revision(&conn)?;
            nt.send_user_update(UpdateType::Vault, &user);
            Ok(())
        }
    }
}

fn _delete_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &DbConn, soft_delete: bool, nt: &Notify) -> EmptyResult {
    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher can't be deleted by user")
    }

    if soft_delete {
        cipher.deleted_at = Some(chrono::Utc::now().naive_utc());
        cipher.save(&conn)?;
    } else {
        cipher.delete(&conn)?;
    }

    nt.send_cipher_update(UpdateType::CipherDelete, &cipher, &cipher.update_users_revision(&conn));
    Ok(())
}

fn _delete_multiple_ciphers(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, soft_delete: bool, nt: Notify) -> EmptyResult {
    let data: Value = data.into_inner().data;

    let uuids = match data.get("Ids") {
        Some(ids) => match ids.as_array() {
            Some(ids) => ids.iter().filter_map(Value::as_str),
            None => err!("Posted ids field is not an array"),
        },
        None => err!("Request missing ids field"),
    };

    for uuid in uuids {
        if let error @ Err(_) = _delete_cipher_by_uuid(uuid, &headers, &conn, soft_delete, &nt) {
            return error;
        };
    }

    Ok(())
}

fn _restore_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &DbConn, nt: &Notify) -> EmptyResult {
    let mut cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher can't be restored by user")
    }

    cipher.deleted_at = None;
    cipher.save(&conn)?;

    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(&conn));
    Ok(())
}

fn _restore_multiple_ciphers(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    let data: Value = data.into_inner().data;

    let uuids = match data.get("Ids") {
        Some(ids) => match ids.as_array() {
            Some(ids) => ids.iter().filter_map(Value::as_str),
            None => err!("Posted ids field is not an array"),
        },
        None => err!("Request missing ids field"),
    };

    for uuid in uuids {
        if let error @ Err(_) = _restore_cipher_by_uuid(uuid, &headers, &conn, &nt) {
            return error;
        };
    }

    Ok(())
}

fn _delete_cipher_attachment_by_id(
    uuid: &str,
    attachment_id: &str,
    headers: &Headers,
    conn: &DbConn,
    nt: &Notify,
) -> EmptyResult {
    let attachment = match Attachment::find_by_id(&attachment_id, &conn) {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist"),
    };

    if attachment.cipher_uuid != uuid {
        err!("Attachment from other cipher")
    }

    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher cannot be deleted by user")
    }

    // Delete attachment
    attachment.delete(&conn)?;
    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(&conn));
    Ok(())
}
