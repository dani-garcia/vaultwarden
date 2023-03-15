use std::collections::{HashMap, HashSet};

use chrono::{NaiveDateTime, Utc};
use rocket::fs::TempFile;
use rocket::serde::json::Json;
use rocket::{
    form::{Form, FromForm},
    Route,
};
use serde_json::Value;

use crate::{
    api::{self, core::log_event, EmptyResult, JsonResult, JsonUpcase, Notify, PasswordData, UpdateType},
    auth::Headers,
    crypto,
    db::{models::*, DbConn, DbPool},
    CONFIG,
};

use super::folders::FolderData;

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
        post_cipher_partial,
        put_cipher,
        put_cipher_partial,
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

pub async fn purge_trashed_ciphers(pool: DbPool) {
    debug!("Purging trashed ciphers");
    if let Ok(mut conn) = pool.get().await {
        Cipher::purge_trash(&mut conn).await;
    } else {
        error!("Failed to get DB connection while purging trashed ciphers")
    }
}

#[derive(FromForm, Default)]
struct SyncData {
    #[field(name = "excludeDomains")]
    exclude_domains: bool, // Default: 'false'
}

#[get("/sync?<data..>")]
async fn sync(data: SyncData, headers: Headers, mut conn: DbConn) -> Json<Value> {
    let user_json = headers.user.to_json(&mut conn).await;

    // Get all ciphers which are visible by the user
    let ciphers = Cipher::find_by_user_visible(&headers.user.uuid, &mut conn).await;

    let cipher_sync_data = CipherSyncData::new(&headers.user.uuid, CipherSyncType::User, &mut conn).await;

    // Lets generate the ciphers_json using all the gathered info
    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(
            c.to_json(&headers.host, &headers.user.uuid, Some(&cipher_sync_data), CipherSyncType::User, &mut conn)
                .await,
        );
    }

    let collections = Collection::find_by_user_uuid(headers.user.uuid.clone(), &mut conn).await;
    let mut collections_json = Vec::with_capacity(collections.len());
    for c in collections {
        collections_json.push(c.to_json_details(&headers.user.uuid, Some(&cipher_sync_data), &mut conn).await);
    }

    let folders_json: Vec<Value> =
        Folder::find_by_user(&headers.user.uuid, &mut conn).await.iter().map(Folder::to_json).collect();

    let sends_json: Vec<Value> =
        Send::find_by_user(&headers.user.uuid, &mut conn).await.iter().map(Send::to_json).collect();

    let policies_json: Vec<Value> =
        OrgPolicy::find_confirmed_by_user(&headers.user.uuid, &mut conn).await.iter().map(OrgPolicy::to_json).collect();

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
async fn get_ciphers(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let ciphers = Cipher::find_by_user_visible(&headers.user.uuid, &mut conn).await;
    let cipher_sync_data = CipherSyncData::new(&headers.user.uuid, CipherSyncType::User, &mut conn).await;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(
            c.to_json(&headers.host, &headers.user.uuid, Some(&cipher_sync_data), CipherSyncType::User, &mut conn)
                .await,
        );
    }

    Json(json!({
      "Data": ciphers_json,
      "Object": "list",
      "ContinuationToken": null
    }))
}

#[get("/ciphers/<uuid>")]
async fn get_cipher(uuid: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_accessible_to_user(&headers.user.uuid, &mut conn).await {
        err!("Cipher is not owned by user")
    }

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await))
}

#[get("/ciphers/<uuid>/admin")]
async fn get_cipher_admin(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    // TODO: Implement this correctly
    get_cipher(uuid, headers, conn).await
}

#[get("/ciphers/<uuid>/details")]
async fn get_cipher_details(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    get_cipher(uuid, headers, conn).await
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
    pub Type: i32,
    pub Name: String,
    pub Notes: Option<String>,
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
    // 'Attachments' is unused, contains map of {id: filename}
    #[serde(rename = "Attachments")]
    _Attachments: Option<Value>,
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
pub struct PartialCipherData {
    FolderId: Option<String>,
    Favorite: bool,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Attachments2Data {
    FileName: String,
    Key: String,
}

/// Called when an org admin clones an org cipher.
#[post("/ciphers/admin", data = "<data>")]
async fn post_ciphers_admin(
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_ciphers_create(data, headers, conn, nt).await
}

/// Called when creating a new org-owned cipher, or cloning a cipher (whether
/// user- or org-owned). When cloning a cipher to a user-owned cipher,
/// `organizationId` is null.
#[post("/ciphers/create", data = "<data>")]
async fn post_ciphers_create(
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let mut data: ShareCipherData = data.into_inner().data;

    // Check if there are one more more collections selected when this cipher is part of an organization.
    // err if this is not the case before creating an empty cipher.
    if data.Cipher.OrganizationId.is_some() && data.CollectionIds.is_empty() {
        err!("You must select at least one collection.");
    }

    // This check is usually only needed in update_cipher_from_data(), but we
    // need it here as well to avoid creating an empty cipher in the call to
    // cipher.save() below.
    enforce_personal_ownership_policy(Some(&data.Cipher), &headers, &mut conn).await?;

    let mut cipher = Cipher::new(data.Cipher.Type, data.Cipher.Name.clone());
    cipher.user_uuid = Some(headers.user.uuid.clone());
    cipher.save(&mut conn).await?;

    // When cloning a cipher, the Bitwarden clients seem to set this field
    // based on the cipher being cloned (when creating a new cipher, it's set
    // to null as expected). However, `cipher.created_at` is initialized to
    // the current time, so the stale data check will end up failing down the
    // line. Since this function only creates new ciphers (whether by cloning
    // or otherwise), we can just ignore this field entirely.
    data.Cipher.LastKnownRevisionDate = None;

    share_cipher_by_uuid(&cipher.uuid, data, &headers, &mut conn, &nt).await
}

/// Called when creating a new user-owned cipher.
#[post("/ciphers", data = "<data>")]
async fn post_ciphers(data: JsonUpcase<CipherData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let mut data: CipherData = data.into_inner().data;

    // The web/browser clients set this field to null as expected, but the
    // mobile clients seem to set the invalid value `0001-01-01T00:00:00`,
    // which results in a warning message being logged. This field isn't
    // needed when creating a new cipher, so just ignore it unconditionally.
    data.LastKnownRevisionDate = None;

    let mut cipher = Cipher::new(data.Type, data.Name.clone());
    update_cipher_from_data(&mut cipher, data, &headers, false, &mut conn, &nt, UpdateType::SyncCipherCreate).await?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await))
}

/// Enforces the personal ownership policy on user-owned ciphers, if applicable.
/// A non-owner/admin user belonging to an org with the personal ownership policy
/// enabled isn't allowed to create new user-owned ciphers or modify existing ones
/// (that were created before the policy was applicable to the user). The user is
/// allowed to delete or share such ciphers to an org, however.
///
/// Ref: https://bitwarden.com/help/article/policies/#personal-ownership
async fn enforce_personal_ownership_policy(
    data: Option<&CipherData>,
    headers: &Headers,
    conn: &mut DbConn,
) -> EmptyResult {
    if data.is_none() || data.unwrap().OrganizationId.is_none() {
        let user_uuid = &headers.user.uuid;
        let policy_type = OrgPolicyType::PersonalOwnership;
        if OrgPolicy::is_applicable_to_user(user_uuid, policy_type, None, conn).await {
            err!("Due to an Enterprise Policy, you are restricted from saving items to your personal vault.")
        }
    }
    Ok(())
}

pub async fn update_cipher_from_data(
    cipher: &mut Cipher,
    data: CipherData,
    headers: &Headers,
    shared_to_collection: bool,
    conn: &mut DbConn,
    nt: &Notify<'_>,
    ut: UpdateType,
) -> EmptyResult {
    enforce_personal_ownership_policy(Some(&data), headers, conn).await?;

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

    if let Some(note) = &data.Notes {
        if note.len() > 10_000 {
            err!("The field Notes exceeds the maximum encrypted value length of 10000 characters.")
        }
    }

    // Check if this cipher is being transferred from a personal to an organization vault
    let transfer_cipher = cipher.organization_uuid.is_none() && data.OrganizationId.is_some();

    if let Some(org_id) = data.OrganizationId {
        match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, conn).await {
            None => err!("You don't have permission to add item to organization"),
            Some(org_user) => {
                if shared_to_collection
                    || org_user.has_full_access()
                    || cipher.is_write_accessible_to_user(&headers.user.uuid, conn).await
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
        match Folder::find_by_uuid(folder_id, conn).await {
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
            let mut saved_att = match Attachment::find_by_id(&id, conn).await {
                Some(att) => att,
                None => {
                    // Warn and continue here.
                    // A missing attachment means it was removed via an other client.
                    // Also the Desktop Client supports removing attachments and save an update afterwards.
                    // Bitwarden it self ignores these mismatches server side.
                    warn!("Attachment {id} doesn't exist");
                    continue;
                }
            };

            if saved_att.cipher_uuid != cipher.uuid {
                // Warn and break here since cloning ciphers provides attachment data but will not be cloned.
                // If we error out here it will break the whole cloning and causes empty ciphers to appear.
                warn!("Attachment is not owned by the cipher");
                break;
            }

            saved_att.akey = Some(attachment.Key);
            saved_att.file_name = attachment.FileName;

            saved_att.save(conn).await?;
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

    cipher.save(conn).await?;
    cipher.move_to_folder(data.FolderId, &headers.user.uuid, conn).await?;
    cipher.set_favorite(data.Favorite, &headers.user.uuid, conn).await?;

    if ut != UpdateType::None {
        // Only log events for organizational ciphers
        if let Some(org_uuid) = &cipher.organization_uuid {
            let event_type = match (&ut, transfer_cipher) {
                (UpdateType::SyncCipherCreate, true) => EventType::CipherCreated,
                (UpdateType::SyncCipherUpdate, true) => EventType::CipherShared,
                (_, _) => EventType::CipherUpdated,
            };

            log_event(
                event_type as i32,
                &cipher.uuid,
                String::from(org_uuid),
                headers.user.uuid.clone(),
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }

        nt.send_cipher_update(ut, cipher, &cipher.update_users_revision(conn).await, &headers.device.uuid).await;
    }

    Ok(())
}

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
async fn post_ciphers_import(
    data: JsonUpcase<ImportData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    enforce_personal_ownership_policy(None, &headers, &mut conn).await?;

    let data: ImportData = data.into_inner().data;

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_notes(&data.Ciphers)?;

    // Read and create the folders
    let mut folders: Vec<_> = Vec::new();
    for folder in data.Folders.into_iter() {
        let mut new_folder = Folder::new(headers.user.uuid.clone(), folder.Name);
        new_folder.save(&mut conn).await?;

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
        update_cipher_from_data(&mut cipher, cipher_data, &headers, false, &mut conn, &nt, UpdateType::None).await?;
    }

    let mut user = headers.user;
    user.update_revision(&mut conn).await?;
    nt.send_user_update(UpdateType::SyncVault, &user).await;
    Ok(())
}

/// Called when an org admin modifies an existing org cipher.
#[put("/ciphers/<uuid>/admin", data = "<data>")]
async fn put_cipher_admin(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    put_cipher(uuid, data, headers, conn, nt).await
}

#[post("/ciphers/<uuid>/admin", data = "<data>")]
async fn post_cipher_admin(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_cipher(uuid, data, headers, conn, nt).await
}

#[post("/ciphers/<uuid>", data = "<data>")]
async fn post_cipher(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    put_cipher(uuid, data, headers, conn, nt).await
}

#[put("/ciphers/<uuid>", data = "<data>")]
async fn put_cipher(
    uuid: String,
    data: JsonUpcase<CipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: CipherData = data.into_inner().data;

    let mut cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    // TODO: Check if only the folder ID or favorite status is being changed.
    // These are per-user properties that technically aren't part of the
    // cipher itself, so the user shouldn't need write access to change these.
    // Interestingly, upstream Bitwarden doesn't properly handle this either.

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &mut conn).await {
        err!("Cipher is not write accessible")
    }

    update_cipher_from_data(&mut cipher, data, &headers, false, &mut conn, &nt, UpdateType::SyncCipherUpdate).await?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await))
}

#[post("/ciphers/<uuid>/partial", data = "<data>")]
async fn post_cipher_partial(
    uuid: String,
    data: JsonUpcase<PartialCipherData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    put_cipher_partial(uuid, data, headers, conn).await
}

// Only update the folder and favorite for the user, since this cipher is read-only
#[put("/ciphers/<uuid>/partial", data = "<data>")]
async fn put_cipher_partial(
    uuid: String,
    data: JsonUpcase<PartialCipherData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    let data: PartialCipherData = data.into_inner().data;

    let cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if let Some(ref folder_id) = data.FolderId {
        match Folder::find_by_uuid(folder_id, &mut conn).await {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist"),
        }
    }

    // Move cipher
    cipher.move_to_folder(data.FolderId.clone(), &headers.user.uuid, &mut conn).await?;
    // Update favorite
    cipher.set_favorite(Some(data.Favorite), &headers.user.uuid, &mut conn).await?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionsAdminData {
    CollectionIds: Vec<String>,
}

#[put("/ciphers/<uuid>/collections", data = "<data>")]
async fn put_collections_update(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn).await
}

#[post("/ciphers/<uuid>/collections", data = "<data>")]
async fn post_collections_update(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn).await
}

#[put("/ciphers/<uuid>/collections-admin", data = "<data>")]
async fn put_collections_admin(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    post_collections_admin(uuid, data, headers, conn).await
}

#[post("/ciphers/<uuid>/collections-admin", data = "<data>")]
async fn post_collections_admin(
    uuid: String,
    data: JsonUpcase<CollectionsAdminData>,
    headers: Headers,
    mut conn: DbConn,
) -> EmptyResult {
    let data: CollectionsAdminData = data.into_inner().data;

    let cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &mut conn).await {
        err!("Cipher is not write accessible")
    }

    let posted_collections: HashSet<String> = data.CollectionIds.iter().cloned().collect();
    let current_collections: HashSet<String> =
        cipher.get_collections(headers.user.uuid.clone(), &mut conn).await.iter().cloned().collect();

    for collection in posted_collections.symmetric_difference(&current_collections) {
        match Collection::find_by_uuid(collection, &mut conn).await {
            None => err!("Invalid collection ID provided"),
            Some(collection) => {
                if collection.is_writable_by_user(&headers.user.uuid, &mut conn).await {
                    if posted_collections.contains(&collection.uuid) {
                        // Add to collection
                        CollectionCipher::save(&cipher.uuid, &collection.uuid, &mut conn).await?;
                    } else {
                        // Remove from collection
                        CollectionCipher::delete(&cipher.uuid, &collection.uuid, &mut conn).await?;
                    }
                } else {
                    err!("No rights to modify the collection")
                }
            }
        }
    }

    log_event(
        EventType::CipherUpdatedCollections as i32,
        &cipher.uuid,
        cipher.organization_uuid.unwrap(),
        headers.user.uuid.clone(),
        headers.device.atype,
        &headers.ip.ip,
        &mut conn,
    )
    .await;

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ShareCipherData {
    Cipher: CipherData,
    CollectionIds: Vec<String>,
}

#[post("/ciphers/<uuid>/share", data = "<data>")]
async fn post_cipher_share(
    uuid: String,
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    share_cipher_by_uuid(&uuid, data, &headers, &mut conn, &nt).await
}

#[put("/ciphers/<uuid>/share", data = "<data>")]
async fn put_cipher_share(
    uuid: String,
    data: JsonUpcase<ShareCipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let data: ShareCipherData = data.into_inner().data;

    share_cipher_by_uuid(&uuid, data, &headers, &mut conn, &nt).await
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ShareSelectedCipherData {
    Ciphers: Vec<CipherData>,
    CollectionIds: Vec<String>,
}

#[put("/ciphers/share", data = "<data>")]
async fn put_cipher_share_selected(
    data: JsonUpcase<ShareSelectedCipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
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
            Some(id) => share_cipher_by_uuid(&id, shared_cipher_data, &headers, &mut conn, &nt).await?,
            None => err!("Request missing ids field"),
        };
    }

    Ok(())
}

async fn share_cipher_by_uuid(
    uuid: &str,
    data: ShareCipherData,
    headers: &Headers,
    conn: &mut DbConn,
    nt: &Notify<'_>,
) -> JsonResult {
    let mut cipher = match Cipher::find_by_uuid(uuid, conn).await {
        Some(cipher) => {
            if cipher.is_write_accessible_to_user(&headers.user.uuid, conn).await {
                cipher
            } else {
                err!("Cipher is not write accessible")
            }
        }
        None => err!("Cipher doesn't exist"),
    };

    let mut shared_to_collection = false;

    if let Some(organization_uuid) = &data.Cipher.OrganizationId {
        for uuid in &data.CollectionIds {
            match Collection::find_by_uuid_and_org(uuid, organization_uuid, conn).await {
                None => err!("Invalid collection ID provided"),
                Some(collection) => {
                    if collection.is_writable_by_user(&headers.user.uuid, conn).await {
                        CollectionCipher::save(&cipher.uuid, &collection.uuid, conn).await?;
                        shared_to_collection = true;
                    } else {
                        err!("No rights to modify the collection")
                    }
                }
            }
        }
    };

    // When LastKnownRevisionDate is None, it is a new cipher, so send CipherCreate.
    let ut = if data.Cipher.LastKnownRevisionDate.is_some() {
        UpdateType::SyncCipherUpdate
    } else {
        UpdateType::SyncCipherCreate
    };

    update_cipher_from_data(&mut cipher, data.Cipher, headers, shared_to_collection, conn, nt, ut).await?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, conn).await))
}

/// v2 API for downloading an attachment. This just redirects the client to
/// the actual location of an attachment.
///
/// Upstream added this v2 API to support direct download of attachments from
/// their object storage service. For self-hosted instances, it basically just
/// redirects to the same location as before the v2 API.
#[get("/ciphers/<uuid>/attachment/<attachment_id>")]
async fn get_attachment(uuid: String, attachment_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    match Attachment::find_by_id(&attachment_id, &mut conn).await {
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
async fn post_attachment_v2(
    uuid: String,
    data: JsonUpcase<AttachmentRequestData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    let cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &mut conn).await {
        err!("Cipher is not write accessible")
    }

    let attachment_id = crypto::generate_attachment_id();
    let data: AttachmentRequestData = data.into_inner().data;
    let attachment =
        Attachment::new(attachment_id.clone(), cipher.uuid.clone(), data.FileName, data.FileSize, Some(data.Key));
    attachment.save(&mut conn).await.expect("Error saving attachment");

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
        response_key: cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await,
    })))
}

#[derive(FromForm)]
struct UploadData<'f> {
    key: Option<String>,
    data: TempFile<'f>,
}

/// Saves the data content of an attachment to a file. This is common code
/// shared between the v2 and legacy attachment APIs.
///
/// When used with the legacy API, this function is responsible for creating
/// the attachment database record, so `attachment` is None.
///
/// When used with the v2 API, post_attachment_v2() has already created the
/// database record, which is passed in as `attachment`.
async fn save_attachment(
    mut attachment: Option<Attachment>,
    cipher_uuid: String,
    data: Form<UploadData<'_>>,
    headers: &Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> Result<(Cipher, DbConn), crate::error::Error> {
    let cipher = match Cipher::find_by_uuid(&cipher_uuid, &mut conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, &mut conn).await {
        err!("Cipher is not write accessible")
    }

    // In the v2 API, the attachment record has already been created,
    // so the size limit needs to be adjusted to account for that.
    let size_adjust = match &attachment {
        None => 0,                         // Legacy API
        Some(a) => i64::from(a.file_size), // v2 API
    };

    let size_limit = if let Some(ref user_uuid) = cipher.user_uuid {
        match CONFIG.user_attachment_limit() {
            Some(0) => err!("Attachments are disabled"),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_user(user_uuid, &mut conn).await + size_adjust;
                if left <= 0 {
                    err!("Attachment storage limit reached! Delete some attachments to free up space")
                }
                Some(left as u64)
            }
            None => None,
        }
    } else if let Some(ref org_uuid) = cipher.organization_uuid {
        match CONFIG.org_attachment_limit() {
            Some(0) => err!("Attachments are disabled"),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_by_org(org_uuid, &mut conn).await + size_adjust;
                if left <= 0 {
                    err!("Attachment storage limit reached! Delete some attachments to free up space")
                }
                Some(left as u64)
            }
            None => None,
        }
    } else {
        err!("Cipher is neither owned by a user nor an organization");
    };

    let mut data = data.into_inner();

    if let Some(size_limit) = size_limit {
        if data.data.len() > size_limit {
            err!("Attachment storage limit exceeded with this file");
        }
    }

    let file_id = match &attachment {
        Some(attachment) => attachment.id.clone(), // v2 API
        None => crypto::generate_attachment_id(),  // Legacy API
    };

    let folder_path = tokio::fs::canonicalize(&CONFIG.attachments_folder()).await?.join(&cipher_uuid);
    let file_path = folder_path.join(&file_id);
    tokio::fs::create_dir_all(&folder_path).await?;

    let size = data.data.len() as i32;
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
                attachment.save(&mut conn).await.expect("Error updating attachment");
            }
        } else {
            attachment.delete(&mut conn).await.ok();

            err!(format!("Attachment size mismatch (expected within [{min_size}, {max_size}], got {size})"));
        }
    } else {
        // Legacy API
        let encrypted_filename = data.data.raw_name().map(|s| s.dangerous_unsafe_unsanitized_raw().to_string());

        if encrypted_filename.is_none() {
            err!("No filename provided")
        }
        if data.key.is_none() {
            err!("No attachment key provided")
        }
        let attachment = Attachment::new(file_id, cipher_uuid.clone(), encrypted_filename.unwrap(), size, data.key);
        attachment.save(&mut conn).await.expect("Error saving attachment");
    }

    if let Err(_err) = data.data.persist_to(&file_path).await {
        data.data.move_copy_to(file_path).await?
    }

    nt.send_cipher_update(
        UpdateType::SyncCipherUpdate,
        &cipher,
        &cipher.update_users_revision(&mut conn).await,
        &headers.device.uuid,
    )
    .await;

    if let Some(org_uuid) = &cipher.organization_uuid {
        log_event(
            EventType::CipherAttachmentCreated as i32,
            &cipher.uuid,
            String::from(org_uuid),
            headers.user.uuid.clone(),
            headers.device.atype,
            &headers.ip.ip,
            &mut conn,
        )
        .await;
    }

    Ok((cipher, conn))
}

/// v2 API for uploading the actual data content of an attachment.
/// This route needs a rank specified so that Rocket prioritizes the
/// /ciphers/<uuid>/attachment/v2 route, which would otherwise conflict
/// with this one.
#[post("/ciphers/<uuid>/attachment/<attachment_id>", format = "multipart/form-data", data = "<data>", rank = 1)]
async fn post_attachment_v2_data(
    uuid: String,
    attachment_id: String,
    data: Form<UploadData<'_>>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let attachment = match Attachment::find_by_id(&attachment_id, &mut conn).await {
        Some(attachment) if uuid == attachment.cipher_uuid => Some(attachment),
        Some(_) => err!("Attachment doesn't belong to cipher"),
        None => err!("Attachment doesn't exist"),
    };

    save_attachment(attachment, uuid, data, &headers, conn, nt).await?;

    Ok(())
}

/// Legacy API for creating an attachment associated with a cipher.
#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
async fn post_attachment(
    uuid: String,
    data: Form<UploadData<'_>>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    // Setting this as None signifies to save_attachment() that it should create
    // the attachment database record as well as saving the data to disk.
    let attachment = None;

    let (cipher, mut conn) = save_attachment(attachment, uuid, data, &headers, conn, nt).await?;

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, &mut conn).await))
}

#[post("/ciphers/<uuid>/attachment-admin", format = "multipart/form-data", data = "<data>")]
async fn post_attachment_admin(
    uuid: String,
    data: Form<UploadData<'_>>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    post_attachment(uuid, data, headers, conn, nt).await
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/share", format = "multipart/form-data", data = "<data>")]
async fn post_attachment_share(
    uuid: String,
    attachment_id: String,
    data: Form<UploadData<'_>>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &mut conn, &nt).await?;
    post_attachment(uuid, data, headers, conn, nt).await
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete-admin")]
async fn delete_attachment_post_admin(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_attachment(uuid, attachment_id, headers, conn, nt).await
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete")]
async fn delete_attachment_post(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_attachment(uuid, attachment_id, headers, conn, nt).await
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>")]
async fn delete_attachment(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &mut conn, &nt).await
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>/admin")]
async fn delete_attachment_admin(
    uuid: String,
    attachment_id: String,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_cipher_attachment_by_id(&uuid, &attachment_id, &headers, &mut conn, &nt).await
}

#[post("/ciphers/<uuid>/delete")]
async fn delete_cipher_post(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, false, &nt).await
    // permanent delete
}

#[post("/ciphers/<uuid>/delete-admin")]
async fn delete_cipher_post_admin(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, false, &nt).await
    // permanent delete
}

#[put("/ciphers/<uuid>/delete")]
async fn delete_cipher_put(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, true, &nt).await
    // soft delete
}

#[put("/ciphers/<uuid>/delete-admin")]
async fn delete_cipher_put_admin(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, true, &nt).await
}

#[delete("/ciphers/<uuid>")]
async fn delete_cipher(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, false, &nt).await
    // permanent delete
}

#[delete("/ciphers/<uuid>/admin")]
async fn delete_cipher_admin(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    _delete_cipher_by_uuid(&uuid, &headers, &mut conn, false, &nt).await
    // permanent delete
}

#[delete("/ciphers", data = "<data>")]
async fn delete_cipher_selected(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt).await // permanent delete
}

#[post("/ciphers/delete", data = "<data>")]
async fn delete_cipher_selected_post(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt).await // permanent delete
}

#[put("/ciphers/delete", data = "<data>")]
async fn delete_cipher_selected_put(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, true, nt).await // soft delete
}

#[delete("/ciphers/admin", data = "<data>")]
async fn delete_cipher_selected_admin(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt).await // permanent delete
}

#[post("/ciphers/delete-admin", data = "<data>")]
async fn delete_cipher_selected_post_admin(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, false, nt).await // permanent delete
}

#[put("/ciphers/delete-admin", data = "<data>")]
async fn delete_cipher_selected_put_admin(
    data: JsonUpcase<Value>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    _delete_multiple_ciphers(data, headers, conn, true, nt).await // soft delete
}

#[put("/ciphers/<uuid>/restore")]
async fn restore_cipher_put(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    _restore_cipher_by_uuid(&uuid, &headers, &mut conn, &nt).await
}

#[put("/ciphers/<uuid>/restore-admin")]
async fn restore_cipher_put_admin(uuid: String, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    _restore_cipher_by_uuid(&uuid, &headers, &mut conn, &nt).await
}

#[put("/ciphers/restore", data = "<data>")]
async fn restore_cipher_selected(
    data: JsonUpcase<Value>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    _restore_multiple_ciphers(data, &headers, &mut conn, &nt).await
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct MoveCipherData {
    FolderId: Option<String>,
    Ids: Vec<String>,
}

#[post("/ciphers/move", data = "<data>")]
async fn move_cipher_selected(
    data: JsonUpcase<MoveCipherData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner().data;
    let user_uuid = headers.user.uuid;

    if let Some(ref folder_id) = data.FolderId {
        match Folder::find_by_uuid(folder_id, &mut conn).await {
            Some(folder) => {
                if folder.user_uuid != user_uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist"),
        }
    }

    for uuid in data.Ids {
        let cipher = match Cipher::find_by_uuid(&uuid, &mut conn).await {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        if !cipher.is_accessible_to_user(&user_uuid, &mut conn).await {
            err!("Cipher is not accessible by user")
        }

        // Move cipher
        cipher.move_to_folder(data.FolderId.clone(), &user_uuid, &mut conn).await?;

        nt.send_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &[user_uuid.clone()], &headers.device.uuid).await;
    }

    Ok(())
}

#[put("/ciphers/move", data = "<data>")]
async fn move_cipher_selected_put(
    data: JsonUpcase<MoveCipherData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    move_cipher_selected(data, headers, conn, nt).await
}

#[derive(FromForm)]
struct OrganizationId {
    #[field(name = "organizationId")]
    org_id: String,
}

#[post("/ciphers/purge?<organization..>", data = "<data>")]
async fn delete_all(
    organization: Option<OrganizationId>,
    data: JsonUpcase<PasswordData>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
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
            match UserOrganization::find_by_user_and_org(&user.uuid, &org_data.org_id, &mut conn).await {
                None => err!("You don't have permission to purge the organization vault"),
                Some(user_org) => {
                    if user_org.atype == UserOrgType::Owner {
                        Cipher::delete_all_by_organization(&org_data.org_id, &mut conn).await?;
                        nt.send_user_update(UpdateType::SyncVault, &user).await;

                        log_event(
                            EventType::OrganizationPurgedVault as i32,
                            &org_data.org_id,
                            org_data.org_id.clone(),
                            user.uuid,
                            headers.device.atype,
                            &headers.ip.ip,
                            &mut conn,
                        )
                        .await;

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
            for cipher in Cipher::find_owned_by_user(&user.uuid, &mut conn).await {
                cipher.delete(&mut conn).await?;
            }

            // Delete folders
            for f in Folder::find_by_user(&user.uuid, &mut conn).await {
                f.delete(&mut conn).await?;
            }

            user.update_revision(&mut conn).await?;
            nt.send_user_update(UpdateType::SyncVault, &user).await;
            Ok(())
        }
    }
}

async fn _delete_cipher_by_uuid(
    uuid: &str,
    headers: &Headers,
    conn: &mut DbConn,
    soft_delete: bool,
    nt: &Notify<'_>,
) -> EmptyResult {
    let mut cipher = match Cipher::find_by_uuid(uuid, conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn).await {
        err!("Cipher can't be deleted by user")
    }

    if soft_delete {
        cipher.deleted_at = Some(Utc::now().naive_utc());
        cipher.save(conn).await?;
        nt.send_cipher_update(
            UpdateType::SyncCipherUpdate,
            &cipher,
            &cipher.update_users_revision(conn).await,
            &headers.device.uuid,
        )
        .await;
    } else {
        cipher.delete(conn).await?;
        nt.send_cipher_update(
            UpdateType::SyncCipherDelete,
            &cipher,
            &cipher.update_users_revision(conn).await,
            &headers.device.uuid,
        )
        .await;
    }

    if let Some(org_uuid) = cipher.organization_uuid {
        let event_type = match soft_delete {
            true => EventType::CipherSoftDeleted as i32,
            false => EventType::CipherDeleted as i32,
        };

        log_event(
            event_type,
            &cipher.uuid,
            org_uuid,
            headers.user.uuid.clone(),
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }

    Ok(())
}

async fn _delete_multiple_ciphers(
    data: JsonUpcase<Value>,
    headers: Headers,
    mut conn: DbConn,
    soft_delete: bool,
    nt: Notify<'_>,
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
        if let error @ Err(_) = _delete_cipher_by_uuid(uuid, &headers, &mut conn, soft_delete, &nt).await {
            return error;
        };
    }

    Ok(())
}

async fn _restore_cipher_by_uuid(uuid: &str, headers: &Headers, conn: &mut DbConn, nt: &Notify<'_>) -> JsonResult {
    let mut cipher = match Cipher::find_by_uuid(uuid, conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn).await {
        err!("Cipher can't be restored by user")
    }

    cipher.deleted_at = None;
    cipher.save(conn).await?;

    nt.send_cipher_update(
        UpdateType::SyncCipherUpdate,
        &cipher,
        &cipher.update_users_revision(conn).await,
        &headers.device.uuid,
    )
    .await;
    if let Some(org_uuid) = &cipher.organization_uuid {
        log_event(
            EventType::CipherRestored as i32,
            &cipher.uuid.clone(),
            String::from(org_uuid),
            headers.user.uuid.clone(),
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }

    Ok(Json(cipher.to_json(&headers.host, &headers.user.uuid, None, CipherSyncType::User, conn).await))
}

async fn _restore_multiple_ciphers(
    data: JsonUpcase<Value>,
    headers: &Headers,
    conn: &mut DbConn,
    nt: &Notify<'_>,
) -> JsonResult {
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
        match _restore_cipher_by_uuid(uuid, headers, conn, nt).await {
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

async fn _delete_cipher_attachment_by_id(
    uuid: &str,
    attachment_id: &str,
    headers: &Headers,
    conn: &mut DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    let attachment = match Attachment::find_by_id(attachment_id, conn).await {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist"),
    };

    if attachment.cipher_uuid != uuid {
        err!("Attachment from other cipher")
    }

    let cipher = match Cipher::find_by_uuid(uuid, conn).await {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if !cipher.is_write_accessible_to_user(&headers.user.uuid, conn).await {
        err!("Cipher cannot be deleted by user")
    }

    // Delete attachment
    attachment.delete(conn).await?;
    nt.send_cipher_update(
        UpdateType::SyncCipherUpdate,
        &cipher,
        &cipher.update_users_revision(conn).await,
        &headers.device.uuid,
    )
    .await;
    if let Some(org_uuid) = cipher.organization_uuid {
        log_event(
            EventType::CipherAttachmentDeleted as i32,
            &cipher.uuid,
            org_uuid,
            headers.user.uuid.clone(),
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }
    Ok(())
}

/// This will hold all the necessary data to improve a full sync of all the ciphers
/// It can be used during the `Cipher::to_json()` call.
/// It will prevent the so called N+1 SQL issue by running just a few queries which will hold all the data needed.
/// This will not improve the speed of a single cipher.to_json() call that much, so better not to use it for those calls.
pub struct CipherSyncData {
    pub cipher_attachments: HashMap<String, Vec<Attachment>>,
    pub cipher_folders: HashMap<String, String>,
    pub cipher_favorites: HashSet<String>,
    pub cipher_collections: HashMap<String, Vec<String>>,
    pub user_organizations: HashMap<String, UserOrganization>,
    pub user_collections: HashMap<String, CollectionUser>,
    pub user_collections_groups: HashMap<String, CollectionGroup>,
    pub user_group_full_access_for_organizations: HashSet<String>,
}

#[derive(Eq, PartialEq)]
pub enum CipherSyncType {
    User,
    Organization,
}

impl CipherSyncData {
    pub async fn new(user_uuid: &str, sync_type: CipherSyncType, conn: &mut DbConn) -> Self {
        let cipher_folders: HashMap<String, String>;
        let cipher_favorites: HashSet<String>;
        match sync_type {
            // User Sync supports Folders and Favorits
            CipherSyncType::User => {
                // Generate a HashMap with the Cipher UUID as key and the Folder UUID as value
                cipher_folders = FolderCipher::find_by_user(user_uuid, conn).await.into_iter().collect();

                // Generate a HashSet of all the Cipher UUID's which are marked as favorite
                cipher_favorites = Favorite::get_all_cipher_uuid_by_user(user_uuid, conn).await.into_iter().collect();
            }
            // Organization Sync does not support Folders and Favorits.
            // If these are set, it will cause issues in the web-vault.
            CipherSyncType::Organization => {
                cipher_folders = HashMap::with_capacity(0);
                cipher_favorites = HashSet::with_capacity(0);
            }
        }

        // Generate a list of Cipher UUID's containing a Vec with one or more Attachment records
        let user_org_uuids = UserOrganization::get_org_uuid_by_user(user_uuid, conn).await;
        let attachments = Attachment::find_all_by_user_and_orgs(user_uuid, &user_org_uuids, conn).await;
        let mut cipher_attachments: HashMap<String, Vec<Attachment>> = HashMap::with_capacity(attachments.len());
        for attachment in attachments {
            cipher_attachments.entry(attachment.cipher_uuid.clone()).or_default().push(attachment);
        }

        // Generate a HashMap with the Cipher UUID as key and one or more Collection UUID's
        let user_cipher_collections = Cipher::get_collections_with_cipher_by_user(user_uuid.to_string(), conn).await;
        let mut cipher_collections: HashMap<String, Vec<String>> =
            HashMap::with_capacity(user_cipher_collections.len());
        for (cipher, collection) in user_cipher_collections {
            cipher_collections.entry(cipher).or_default().push(collection);
        }

        // Generate a HashMap with the Organization UUID as key and the UserOrganization record
        let user_organizations: HashMap<String, UserOrganization> = UserOrganization::find_by_user(user_uuid, conn)
            .await
            .into_iter()
            .map(|uo| (uo.org_uuid.clone(), uo))
            .collect();

        // Generate a HashMap with the User_Collections UUID as key and the CollectionUser record
        let user_collections: HashMap<String, CollectionUser> = CollectionUser::find_by_user(user_uuid, conn)
            .await
            .into_iter()
            .map(|uc| (uc.collection_uuid.clone(), uc))
            .collect();

        // Generate a HashMap with the collections_uuid as key and the CollectionGroup record
        let user_collections_groups: HashMap<String, CollectionGroup> = CollectionGroup::find_by_user(user_uuid, conn)
            .await
            .into_iter()
            .map(|collection_group| (collection_group.collections_uuid.clone(), collection_group))
            .collect();

        // Get all organizations that the user has full access to via group assignement
        let user_group_full_access_for_organizations: HashSet<String> =
            Group::gather_user_organizations_full_access(user_uuid, conn).await.into_iter().collect();

        Self {
            cipher_attachments,
            cipher_folders,
            cipher_favorites,
            cipher_collections,
            user_organizations,
            user_collections,
            user_collections_groups,
            user_group_full_access_for_organizations,
        }
    }
}
