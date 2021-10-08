use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{NaiveDateTime, Utc};
use rocket::{http::ContentType, request::Form, Data, Route};
use rocket_contrib::json::Json;
use serde_json::Value;

use multipart::server::{save::SavedData, Multipart, SaveResult};

use crate::{
    api::{self, EmptyResult, JsonResult, JsonUpcase, Notify, PasswordData, UpdateType},
    auth::Headers,
    crypto,
    db::{models::*, DbConn, DbPool},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    // Note that many routes have an `admin` variant; this seems to be
    // because the stored procedure that upstream Bitwarden uses to determine
    // whether the user can edit a cipher doesn't take into account whether
    // the user is an org owner/admin. The `admin` variant first checks
    // whether the user is an owner/admin of the relevant org, and if so,
    // allows the operation unconditionally.
    //
    // vaultwarden factors in the org owner/admin status as part of
    // determining the write accessibility of a cipher, so most
    // admin/non-admin implementations can be shared.
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
        get_attachment,
        post_attachment_v2,
        post_attachment_v2_data,
        post_attachment,       // legacy
        post_attachment_admin, // legacy
        post_attachment_share,
        delete_attachment_post,
        delete_attachment_post_admin,
        delete_attachment,
        delete_attachment_admin,
        post_cipher_admin,
        post_cipher_share,
        put_cipher_share,
        put_cipher_share_selected,
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
        delete_cipher_selected_admin,
        delete_cipher_selected_post_admin,
        delete_cipher_selected_put_admin,
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

pub fn purge_trashed_ciphers(pool: DbPool) {
    debug!("Purging trashed ciphers");
    if let Ok(conn) = pool.get() {
        Cipher::purge_trash(&conn);
    } else {
        error!("Failed to get DB connection while purging trashed ciphers")
    }
}

#[derive(FromForm, Default)]
struct SyncData {
    #[form(field = "excludeDomains")]
    exclude_domains: bool, // Default: 'false'
}

#[get("/sync?<data..>")]
fn sync(data: Form<SyncData>, headers: Headers, conn: DbConn) -> Json<Value> {
    let user_json = headers.user.to_json(&conn);

    let folders = Folder::find_by_user(&headers.user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    let collections = Collection::find_by_user_uuid(&headers.user.uuid, &conn);
    let collections_json: Vec<Value> =
        collections.iter().map(|c| c.to_json_details(&headers.user.uuid, &conn)).collect();

    let policies = OrgPolicy::find_confirmed_by_user(&headers.user.uuid, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    let ciphers = Cipher::find_by_user_visible(&headers.user.uuid, &conn);
    let ciphers_json: Vec<Value> =
        ciphers.iter().map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn)).collect();

    let sends = Send::find_by_user(&headers.user.uuid, &conn);
    let sends_json: Vec<Value> = sends.iter().map(|s| s.to_json()).collect();

    let domains_json = if data.exclude_domains {
        Value::Null
    } else {
        api::core::_get_eq_domains(headers, true).into_inner()
    };

    Json(json!({
        "Profile": user_json,
        "Folders": folders_json,
        "Collections": collections_json,
        "Policies": policies_json,
        "Ciphers": ciphers_json,
        "Domains": domains_json,
        "Sends": sends_json,
        "unofficialServer": true,
        "Object": "sync"
    }))
}

#[get("/ciphers")]
fn get_ciphers(headers: Headers, conn: DbConn) -> Json<Value> {
    let ciphers = Cipher::find_by_user_visible(&headers.user.uuid, &conn);

    let ciphers_json: Vec<Value> =
        ciphers.iter().map(|c| c.to_json(&headers.host, &headers.user.uuid, &conn)).collect();

    Json(json!({
      "Data": ciphers_json,
      "Object": "list",
      "ContinuationToken": null
    }))
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
    Reprompt: Option<i32>,

    PasswordHistory: Option<Value>,

    // These are used during key rotation
    #[serde(rename = "Attachments")]
    _Attachments: Option<Value>, // Unused, contains map of {id: filename}
    Attachments2: Option<HashMap<String, Attachments2Data>>,

    // The revision datetime (in ISO 8601 format) of the client's local copy
    // of the cipher. This is used to prevent a client from updating a cipher
    // when it doesn't have the latest version, as that can result in data
    // loss. It's not an error when no value is provided; this can happen
    // when using older client versions, or if the operation doesn't involve
    // updating an existing cipher.
    LastKnownRevisionDate: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Attachments2Data {
    FileName: String,
    Key: String,
}

/// Called when an org admin clones an org cipher.
#[post("/ciphers/admin", data = "<data>")]
fn post_ciphers_admin(data: JsonUpcase<ShareCipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    post_ciphers_create(data, headers, conn, nt)
}

/// Called when creating a new org-owned cipher, or cloning a cipher (whether
/// user- or org-owned). When cloning a cipher to a user-owned cipher,
/// `organizationId` is null.
#[post("/ciphers/create", data = "<data>")]
fn post_ciphers_create(data: JsonUpcase<ShareCipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    let mut data: ShareCipherData = data.into_inner().data;

    // Check if there are one more more collections selected when this cipher is part of an organization.
    // err if this is not the case before creating an empty cipher.
    if data.Cipher.OrganizationId.is_some() && data.CollectionIds.is_empty() {
        err!("You must select at least one collection.");
    }

    // This check is usually only needed in update_cipher_from_data(), but we
    // need it here as well to avoid creating an empty cipher in the call to
    // cipher.save() below.
    enforce_personal_ownership_policy(Some(&data.Cipher), &headers, &conn)?;

    let mut cipher = Cipher::new(data.Cipher.Type, data.Cipher.Name.clone());
    cipher.user_uuid = Some(headers.user.uuid.clone());
    cipher.save(&conn)?;

    // When cloning a cipher, the Bitwarden clients seem to set this field
    // based on the cipher being cloned (when creating a new cipher, it's set
    // to null as expected). However, `cipher.created_at` is initialized to
    // the current time, so the stale data check will end up failing down the
    // line. Since this function only creates new ciphers (whether by cloning
    // or otherwise), we can just ignore this field entirely.
    data.Cipher.LastKnownRevisionDate = None;

    share_cipher_by_uuid(&cipher.uuid, data, &headers, &conn, &nt)
}

/// Called when creating a new user-owned cipher.
#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: JsonUpcase<CipherData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    let mut data: CipherData = data.into_inner().data;

    // The web/browser clients set this field to null as expected, but the
    // mobile clients seem to set the invalid value `0001-01-01T00:00:00`,
    // which results in a warning message being logged. This field isn't
    // needed when creating a new cipher, so just ignore it unconditionally.
    data.LastKnownRevisionDate = None;

    let mut cipher = Cipher::new(data.Type, data.Name.clone());
    update_cipher_from_data(&mut cipher, data, &headers, false, &conn, &nt, UpdateType::CipherCreate)?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, &conn)))
}

/// Enforces the personal ownership policy on user-owned ciphers, if applicable.
/// A non-owner/admin user belonging to an org with the personal ownership policy
/// enabled isn't allowed to create new user-owned ciphers or modify existing ones
/// (that were created before the policy was applicable to the user). The user is
/// allowed to delete or share such ciphers to an org, however.
///
/// Ref: https://bitwarden.com/help/article/policies/#personal-ownership
fn enforce_personal_ownership_policy(data: Option<&CipherData>, headers: &Headers, conn: &DbConn) -> EmptyResult {
    if data.is_none() || data.unwrap().OrganizationId.is_none() {
        let user_uuid = &headers.user.uuid;
        let policy_type = OrgPolicyType::PersonalOwnership;
        if OrgPolicy::is_applicable_to_user(user_uuid, policy_type, conn) {
            err!("Due to an Enterprise Policy, you are restricted from saving items to your personal vault.")
        }
    }
    Ok(())
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
    enforce_personal_ownership_policy(Some(&data), headers, conn)?;

    // Check that the client isn't updating an existing cipher with stale data.
    if let Some(dt) = data.LastKnownRevisionDate {
        match NaiveDateTime::parse_from_str(&dt, "%+") {
            // ISO 8601 format
            Err(err) => warn!("Error parsing LastKnownRevisionDate '{}': {}", dt, err),
            Ok(dt) if cipher.updated_at.signed_duration_since(dt).num_seconds() > 1 => {
                err!("The client copy of this cipher is out of date. Resync the client and try again.")
            }
            Ok(_) => (),
        }
    }

    if cipher.organization_uuid.is_some() && cipher.organization_uuid != data.OrganizationId {
        err!("Organization mismatch. Please resync the client before updating the cipher")
    }

    if let Some(org_id) = data.OrganizationId {
        match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, conn) {
            None => err!("You don't have permission to add item to organization"),
            Some(org_user) => {
                if shared_to_collection
                    || org_user.has_full_access()
                    || cipher.is_write_accessible_to_user(&headers.user.uuid, conn)
                {
                    cipher.organization_uuid = Some(org_id);
                    // After some discussion in PR #1329 re-added the user_uuid = None again.
                    // TODO: Audit/Check the whole save/update cipher chain.
                    // Upstream uses the user_uuid to allow a cipher added by a user to an org to still allow the user to view/edit the cipher
                    // even when the user has hide-passwords configured as there policy.
                    // Removing the line below would fix that, but we have to check which effect this would have on the rest of the code.
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
            let mut saved_att = match Attachment::find_by_id(&id, conn) {
                Some(att) => att,
                None => err!("Attachment doesn't exist"),
            };

            if saved_att.cipher_uuid != cipher.uuid {
                // Warn and break here since cloning ciphers provides attachment data but will not be cloned.
                // If we error out here it will break the whole cloning and causes empty ciphers to appear.
                warn!("Attachment is not owned by the cipher");
                break;
            }

            saved_att.akey = Some(attachment.Key);
            saved_att.file_name = attachment.FileName;

            saved_att.save(conn)?;
        }
    }

    // Cleanup cipher data, like removing the 'Response' key.
    // This key is somewhere generated during Javascript so no way for us this fix this.
    // Also, upstream only retrieves keys they actually want to store, and thus skip the 'Response' key.
    // We do not mind which data is in it, the keep our model more flexible when there are upstream changes.
    // But, we at least know we do not need to store and return this specific key.
    fn _clean_cipher_data(mut json_data: Value) -> Value {
        if json_data.is_array() {
            json_data.as_array_mut().unwrap().iter_mut().for_each(|ref mut f| {
                f.as_object_mut().unwrap().remove("Response");
            });
        };
        json_data
    }

    let type_data_opt = match data.Type {
        1 => data.Login,
        2 => data.SecureNote,
        3 => data.Card,
        4 => data.Identity,
        _ => err!("Invalid type"),
    };

    let type_data = match type_data_opt {
        Some(mut data) => {
            // Remove the 'Response' key from the base object.
            data.as_object_mut().unwrap().remove("Response");
            // Remove the 'Response' key from every Uri.
            if data["Uris"].is_array() {
                data["Uris"] = _clean_cipher_data(data["Uris"].clone());
            }
            data
        }
        None => err!("Data missing"),
    };

    cipher.name = data.Name;
    cipher.notes = data.Notes;
    cipher.fields = data.Fields.map(|f| _clean_cipher_data(f).to_string());
    cipher.data = type_data.to_string();
    cipher.password_history = data.PasswordHistory.map(|f| f.to_string());
    cipher.reprompt = data.Reprompt;

    cipher.save(conn)?;
    cipher.move_to_folder(data.FolderId, &headers.user.uuid, conn)?;
    cipher.set_favorite(data.Favorite, &headers.user.uuid, conn)?;

    if ut != UpdateType::None {
        nt.send_cipher_update(ut, cipher, &cipher.update_users_revision(conn));
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
    enforce_personal_ownership_policy(None, &headers, &conn)?;

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

/// Called when an org admin modifies an existing org cipher.
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

    // TODO: Check if only the folder ID or favorite status is being changed.
    // These are per-user properties that technically aren't part of the
    // cipher itself, so the user shouldn't need write access to change these.
    // Interestingly, upstream Bitwarden doesn't properly handle this either.

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
    let current_collections: HashSet<String> =
        cipher.get_collections(&headers.user.uuid, &conn).iter().cloned().collect();

    for collection in posted_collections.symmetric_difference(&current_collections) {
        match Collection::find_by_uuid(collection, &conn) {
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
fn put_cipher_share_selected(
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
    let mut cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => {
            if cipher.is_write_accessible_to_user(&headers.user.uuid, conn) {
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
        None => {}
        Some(organization_uuid) => {
            for uuid in &data.CollectionIds {
                match Collection::find_by_uuid_and_org(uuid, &organization_uuid, conn) {
                    None => err!("Invalid collection ID provided"),
                    Some(collection) => {
                        if collection.is_writable_by_user(&headers.user.uuid, conn) {
                            CollectionCipher::save(&cipher.uuid, &collection.uuid, conn)?;
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
        headers,
        shared_to_collection,
        conn,
        nt,
        UpdateType::CipherUpdate,
    )?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, conn)))
}

/// v2 API for downloading an attachment. This just redirects the client to
/// the actual location of an attachment.
///
/// Upstream added this v2 API to support direct download of attachments from
/// their object storage service. For self-hosted instances, it basically just
/// redirects to the same location as before the v2 API.
#[get("/ciphers/<uuid>/attachment/<attachment_id>")]
fn get_attachment(uuid: String, attachment_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    match Attachment::find_by_id(&attachment_id, &conn) {
        Some(attachment) if uuid == attachment.cipher_uuid => Ok(Json(attachment.to_json(&headers.host))),
        Some(_) => err!("Attachment doesn't belong to cipher"),
        None => err!("Attachment doesn't exist"),
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AttachmentRequestData {
    Key: String,
    FileName: String,
    FileSize: i32,
    AdminRequest: Option<bool>, // true when attaching from an org vault view
}

enum FileUploadType {
    Direct = 0,
    // Azure = 1, // only used upstream
}

/// v2 API for creating an attachment associated with a cipher.
/// This redirects the client to the API it should use to upload the attachment.
/// For upstream's cloud-hosted service, it's an Azure object storage API.
/// For self-hosted instances, it's another API on the local instance.
#[post("/ciphers/<uuid>/attachment/v2", data = "<data>")]
fn post_attachment_v2(
    uuid: String,
    data: JsonUpcase<AttachmentRequestData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &conn) {
        err!("Cipher is not write accessible")
    }

    let attachment_id = crypto::generate_attachment_id();
    let data: AttachmentRequestData = data.into_inner().data;
    let attachment =
        Attachment::new(attachment_id.clone(), cipher.uuid.clone(), data.FileName, data.FileSize, Some(data.Key));
    attachment.save(&conn).expect("Error saving attachment");

    let url = format!("/ciphers/{}/attachment/{}", cipher.uuid, attachment_id);
    let response_key = match data.AdminRequest {
        Some(b) if b => "CipherMiniResponse",
        _ => "CipherResponse",
    };

    Ok(Json(json!({ // AttachmentUploadDataResponseModel
        "Object": "attachment-fileUpload",
        "AttachmentId": attachment_id,
        "Url": url,
        "FileUploadType": FileUploadType::Direct as i32,
        response_key: cipher.to_json(&headers.host, &headers.user.uuid, &conn),
    })))
}

/// Saves the data content of an attachment to a file. This is common code
/// shared between the v2 and legacy attachment APIs.
///
/// When used with the legacy API, this function is responsible for creating
/// the attachment database record, so `attachment` is None.
///
/// When used with the v2 API, post_attachment_v2() has already created the
/// database record, which is passed in as `attachment`.
fn save_attachment(
    mut attachment: Option<Attachment>,
    cipher_uuid: String,
    data: Data,
    content_type: &ContentType,
    headers: &Headers,
    conn: &DbConn,
    nt: Notify,
) -> Result<Cipher, crate::error::Error> {
    let cipher = match Cipher::find_by_uuid(&cipher_uuid, conn) {
        Some(cipher) => cipher,
        None => err_discard!("Cipher doesn't exist", data),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn) {
        err_discard!("Cipher is not write accessible", data)
    }

    // In the v2 API, the attachment record has already been created,
    // so the size limit needs to be adjusted to account for that.
    let size_adjust = match &attachment {
        None => 0,                     // Legacy API
        Some(a) => a.file_size as i64, // v2 API
    };

    let size_limit = if let Some(ref user_uuid) = cipher.user_uuid {
        match CONFIG.user_attachment_limit() {
            Some(0) => err_discard!("Attachments are disabled", data),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_user(user_uuid, conn) + size_adjust;
                if left <= 0 {
                    err_discard!("Attachment storage limit reached! Delete some attachments to free up space", data)
                }
                Some(left as u64)
            }
            None => None,
        }
    } else if let Some(ref org_uuid) = cipher.organization_uuid {
        match CONFIG.org_attachment_limit() {
            Some(0) => err_discard!("Attachments are disabled", data),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_org(org_uuid, conn) + size_adjust;
                if left <= 0 {
                    err_discard!("Attachment storage limit reached! Delete some attachments to free up space", data)
                }
                Some(left as u64)
            }
            None => None,
        }
    } else {
        err_discard!("Cipher is neither owned by a user nor an organization", data);
    };

    let mut params = content_type.params();
    let boundary_pair = params.next().expect("No boundary provided");
    let boundary = boundary_pair.1;

    let base_path = Path::new(&CONFIG.attachments_folder()).join(&cipher_uuid);
    let mut path = PathBuf::new();

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
                    // In the legacy API, this is the encrypted filename
                    // provided by the client, stored to the database as-is.
                    // In the v2 API, this value doesn't matter, as it was
                    // already provided and stored via an earlier API call.
                    let encrypted_filename = field.headers.filename;

                    // This random ID is used as the name of the file on disk.
                    // In the legacy API, we need to generate this value here.
                    // In the v2 API, we use the value from post_attachment_v2().
                    let file_id = match &attachment {
                        Some(attachment) => attachment.id.clone(), // v2 API
                        None => crypto::generate_attachment_id(),  // Legacy API
                    };
                    path = base_path.join(&file_id);

                    let size =
                        match field.data.save().memory_threshold(0).size_limit(size_limit).with_path(path.clone()) {
                            SaveResult::Full(SavedData::File(_, size)) => size as i32,
                            SaveResult::Full(other) => {
                                error = Some(format!("Attachment is not a file: {:?}", other));
                                return;
                            }
                            SaveResult::Partial(_, reason) => {
                                error = Some(format!("Attachment storage limit exceeded with this file: {:?}", reason));
                                return;
                            }
                            SaveResult::Error(e) => {
                                error = Some(format!("Error: {:?}", e));
                                return;
                            }
                        };

                    if let Some(attachment) = &mut attachment {
                        // v2 API

                        // Check the actual size against the size initially provided by
                        // the client. Upstream allows +/- 1 MiB deviation from this
                        // size, but it's not clear when or why this is needed.
                        const LEEWAY: i32 = 1024 * 1024; // 1 MiB
                        let min_size = attachment.file_size - LEEWAY;
                        let max_size = attachment.file_size + LEEWAY;

                        if min_size <= size && size <= max_size {
                            if size != attachment.file_size {
                                // Update the attachment with the actual file size.
                                attachment.file_size = size;
                                attachment.save(conn).expect("Error updating attachment");
                            }
                        } else {
                            attachment.delete(conn).ok();

                            let err_msg = "Attachment size mismatch".to_string();
                            error!("{} (expected within [{}, {}], got {})", err_msg, min_size, max_size, size);
                            error = Some(err_msg);
                        }
                    } else {
                        // Legacy API

                        if encrypted_filename.is_none() {
                            error = Some("No filename provided".to_string());
                            return;
                        }
                        if attachment_key.is_none() {
                            error = Some("No attachment key provided".to_string());
                            return;
                        }
                        let attachment = Attachment::new(
                            file_id,
                            cipher_uuid.clone(),
                            encrypted_filename.unwrap(),
                            size,
                            attachment_key.clone(),
                        );
                        attachment.save(conn).expect("Error saving attachment");
                    }
                }
                _ => error!("Invalid multipart name"),
            }
        })
        .expect("Error processing multipart data");

    if let Some(ref e) = error {
        std::fs::remove_file(path).ok();
        err!(e);
    }

    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(conn));

    Ok(cipher)
}

/// v2 API for uploading the actual data content of an attachment.
/// This route needs a rank specified so that Rocket prioritizes the
/// /ciphers/<uuid>/attachment/v2 route, which would otherwise conflict
/// with this one.
#[post("/ciphers/<uuid>/attachment/<attachment_id>", format = "multipart/form-data", data = "<data>", rank = 1)]
fn post_attachment_v2_data(
    uuid: String,
    attachment_id: String,
    data: Data,
    content_type: &ContentType,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    let attachment = match Attachment::find_by_id(&attachment_id, &conn) {
        Some(attachment) if uuid == attachment.cipher_uuid => Some(attachment),
        Some(_) => err!("Attachment doesn't belong to cipher"),
        None => err!("Attachment doesn't exist"),
    };

    save_attachment(attachment, uuid, data, content_type, &headers, &conn, nt)?;

    Ok(())
}

/// Legacy API for creating an attachment associated with a cipher.
#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
fn post_attachment(
    uuid: String,
    data: Data,
    content_type: &ContentType,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> JsonResult {
    // Setting this as None signifies to save_attachment() that it should create
    // the attachment database record as well as saving the data to disk.
    let attachment = None;

    let cipher = save_attachment(attachment, uuid, data, content_type, &headers, &conn, nt)?;

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
    _delete_multiple_ciphers(data, headers, conn, true, nt) // soft delete
}

#[delete("/ciphers/admin", data = "<data>")]
fn delete_cipher_selected_admin(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    delete_cipher_selected(data, headers, conn, nt)
}

#[post("/ciphers/delete-admin", data = "<data>")]
fn delete_cipher_selected_post_admin(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    delete_cipher_selected_post(data, headers, conn, nt)
}

#[put("/ciphers/delete-admin", data = "<data>")]
fn delete_cipher_selected_put_admin(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify,
) -> EmptyResult {
    delete_cipher_selected_put(data, headers, conn, nt)
}

#[put("/ciphers/<uuid>/restore")]
fn restore_cipher_put(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    _restore_cipher_by_uuid(&uuid, &headers, &conn, &nt)
}

#[put("/ciphers/<uuid>/restore-admin")]
fn restore_cipher_put_admin(uuid: String, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    _restore_cipher_by_uuid(&uuid, &headers, &conn, &nt)
}

#[put("/ciphers/restore", data = "<data>")]
fn restore_cipher_selected(data: JsonUpcase<Value>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    _restore_multiple_ciphers(data, &headers, &conn, &nt)
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
    let mut cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn) {
        err!("Cipher can't be deleted by user")
    }

    if soft_delete {
        cipher.deleted_at = Some(Utc::now().naive_utc());
        cipher.save(conn)?;
        nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(conn));
    } else {
        cipher.delete(conn)?;
        nt.send_cipher_update(UpdateType::CipherDelete, &cipher, &cipher.update_users_revision(conn));
    }

    Ok(())
}

fn _delete_multiple_ciphers(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    soft_delete: bool,
    nt: Notify,
) -> EmptyResult {
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

fn _restore_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &DbConn, nt: &Notify) -> JsonResult {
    let mut cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn) {
        err!("Cipher can't be restored by user")
    }

    cipher.deleted_at = None;
    cipher.save(conn)?;

    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(conn));
    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, conn)))
}

fn _restore_multiple_ciphers(data: JsonUpcase<Value>, headers: &Headers, conn: &DbConn, nt: &Notify) -> JsonResult {
    let data: Value = data.into_inner().data;

    let uuids = match data.get("Ids") {
        Some(ids) => match ids.as_array() {
            Some(ids) => ids.iter().filter_map(Value::as_str),
            None => err!("Posted ids field is not an array"),
        },
        None => err!("Request missing ids field"),
    };

    let mut ciphers: Vec<Value> = Vec::new();
    for uuid in uuids {
        match _restore_cipher_by_uuid(uuid, headers, conn, nt) {
            Ok(json) => ciphers.push(json.into_inner()),
            err => return err,
        }
    }

    Ok(Json(json!({
      "Data": ciphers,
      "Object": "list",
      "ContinuationToken": null
    })))
}

fn _delete_cipher_attachment_by_id(
    uuid: &str,
    attachment_id: &str,
    headers: &Headers,
    conn: &DbConn,
    nt: &Notify,
) -> EmptyResult {
    let attachment = match Attachment::find_by_id(attachment_id, conn) {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist"),
    };

    if attachment.cipher_uuid != uuid {
        err!("Attachment from other cipher")
    }

    let cipher = match Cipher::find_by_uuid(uuid, conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn) {
        err!("Cipher cannot be deleted by user")
    }

    // Delete attachment
    attachment.delete(conn)?;
    nt.send_cipher_update(UpdateType::CipherUpdate, &cipher, &cipher.update_users_revision(conn));
    Ok(())
}
