use std::{path::Path, sync::LazyLock, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use num_traits::{FromPrimitive, ToPrimitive};
use rocket::{
    form::Form,
    fs::{NamedFile, TempFile},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult, JsonResult, Notify, UpdateType},
    auth::{Headers, Host, SendHeaders},
    config::PathType,
    db::{
        DbConn, DbPool,
        models::{
            Cipher, CipherId, Device, OrgPolicy, OrgPolicyType, Send, SendAuthType, SendFileId, SendId, SendType,
            UserId,
        },
    },
    util::{FeatureFlagFilter, NumberOrString, parse_experimental_client_feature_flags, save_temp_file},
};

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";
static ANON_PUSH_DEVICE: LazyLock<Device> = LazyLock::new(|| {
    let dt = DateTime::UNIX_EPOCH.naive_utc();
    Device {
        uuid: String::from("00000000-0000-0000-0000-000000000000").into(),
        created_at: dt,
        updated_at: dt,
        user_uuid: String::from("00000000-0000-0000-0000-000000000000").into(),
        name: String::new(),
        atype: 14, // 14 == Unknown Browser
        push_uuid: Some(String::from("00000000-0000-0000-0000-000000000000").into()),
        push_token: None,
        refresh_token: String::new(),
        twofactor_remember: None,
    }
});

// The max file size allowed by Bitwarden clients and add an extra 5% to avoid issues
pub(crate) const SIZE_525_MB: i64 = 550_502_400;

pub fn routes() -> Vec<rocket::Route> {
    routes![
        get_sends,
        get_send,
        post_send,
        post_access,
        post_access_file,
        put_send,
        delete_send,
        put_remove_password,
        download_send,
        post_send_file_v2,
        post_send_file_v2_data
    ]
}

pub async fn purge_sends(pool: DbPool) {
    debug!("Purging sends");
    if let Ok(conn) = pool.get().await {
        Send::purge(&conn).await;
    } else {
        error!("Failed to get DB connection while purging sends");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendData {
    r#type: i32,
    pub key: String,
    password: Option<String>,
    max_access_count: Option<NumberOrString>,
    expiration_date: Option<DateTime<Utc>>,
    deletion_date: DateTime<Utc>,
    disabled: bool,
    hide_email: Option<bool>,
    auth_type: Option<i32>,
    emails: Option<String>,

    // Data field
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
    data: Option<Value>,
    file_length: Option<NumberOrString>,

    // Used for key rotations
    pub id: Option<SendId>,
}

/// Enforces the `Disable Send` policy. A non-owner/admin user belonging to
/// an org with this policy enabled isn't allowed to create new Sends or
/// modify existing ones, but is allowed to delete them.
///
/// Ref: https://bitwarden.com/help/article/policies/#disable-send
///
/// There is also a Vaultwarden-specific `sends_allowed` config setting that
/// controls this policy globally.
async fn enforce_disable_send_policy(headers: &Headers, conn: &DbConn) -> EmptyResult {
    let user_id = &headers.user.uuid;
    if !CONFIG.sends_allowed()
        || OrgPolicy::is_applicable_to_user(user_id, OrgPolicyType::DisableSend, None, conn).await
    {
        err!("Due to an Enterprise Policy, you are only able to delete an existing Send.")
    }
    Ok(())
}

/// Enforces the `DisableHideEmail` option of the `Send Options` policy.
/// A non-owner/admin user belonging to an org with this option enabled isn't
/// allowed to hide their email address from the recipient of a Bitwarden Send,
/// but is allowed to remove this option from an existing Send.
///
/// Ref: https://bitwarden.com/help/article/policies/#send-options
async fn enforce_disable_hide_email_policy(data: &SendData, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let user_id = &headers.user.uuid;
    let hide_email = data.hide_email.unwrap_or(false);
    if hide_email && OrgPolicy::is_hide_email_disabled(user_id, conn).await {
        err!(
            "Due to an Enterprise Policy, you are not allowed to hide your email address \
              from recipients when creating or editing a Send."
        )
    }
    Ok(())
}

fn create_send(data: SendData, user_id: UserId) -> ApiResult<Send> {
    let data_val = if data.r#type == SendType::Text as i32 {
        data.text
    } else if data.r#type == SendType::File as i32 {
        data.file
    } else if data.r#type == SendType::Item as i32 {
        Some(serde_json::to_value(parse_item_data(data.data)?)?)
    } else {
        err!("Invalid Send type")
    };

    let data_str = if let Some(mut d) = data_val {
        d.as_object_mut().and_then(|o| o.remove("response"));
        serde_json::to_string(&d)?
    } else {
        err!("Send data not provided");
    };

    if data.deletion_date > Utc::now() + TimeDelta::try_days(31).unwrap() {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }

    let mut send = Send::new(data.r#type, data.name, data_str, data.key, data.deletion_date.naive_utc());
    send.user_uuid = Some(user_id);
    send.notes = data.notes;
    send.max_access_count = match data.max_access_count {
        Some(m) => Some(m.into_i32()?),
        _ => None,
    };
    send.expiration_date = data.expiration_date.map(|d| d.naive_utc());
    send.disabled = data.disabled;
    send.hide_email = data.hide_email;
    send.atype = data.r#type;

    apply_send_auth(&mut send, data.auth_type, data.emails.as_deref(), data.password)?;
    enforce_mail_enabled_for_email_auth(&send)?;
    enforce_email_auth_for_item_send(&send)?;

    Ok(send)
}

const ITEM_SENDS_FEATURE_FLAG: &str = "pm-34203-temporary-item-sharing";

/// Item Sends (sharing a vault item through a temporary link) are opt-in through the client feature flag.
pub fn item_sends_enabled() -> bool {
    parse_experimental_client_feature_flags(&CONFIG.experimental_client_feature_flags(), &FeatureFlagFilter::ValidOnly)
        .contains_key(ITEM_SENDS_FEATURE_FLAG)
}

/// Whether a Send can be shown to its owner or a recipient, Item Sends are hidden while the feature is disabled.
pub fn send_visible(send: &Send) -> bool {
    send.atype != SendType::Item as i32 || item_sends_enabled()
}

/// Data of an Item Send. The vault item is encrypted client side into a single opaque blob, the item id
/// is kept in clear so the server can check that the sender is allowed to share it.
///
/// Upstream: https://github.com/bitwarden/server/blob/main/src/Core/Tools/Models/Data/SendItemData.cs
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendItemData {
    encryption_version: i32,
    data: String,
    metadata: SendItemMetadata,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendItemMetadata {
    item_id: CipherId,
}

impl SendItemData {
    const ENCRYPTION_VERSION: i32 = 1;
    const MAX_DATA_LENGTH: usize = 500_000;
}

fn parse_item_data(data: Option<Value>) -> ApiResult<SendItemData> {
    if !item_sends_enabled() {
        err!("Item Sends are not enabled on this server")
    }
    let Some(data) = data else {
        err!("Send data not provided")
    };
    let Ok(item) = serde_json::from_value::<SendItemData>(data) else {
        err!("Invalid Item Send data")
    };
    if item.encryption_version != SendItemData::ENCRYPTION_VERSION {
        err!("Unsupported Item Send encryption version")
    }
    if item.data.is_empty() || item.data.len() > SendItemData::MAX_DATA_LENGTH {
        err!("Invalid Item Send data")
    }
    Ok(item)
}

fn stored_item_id(send: &Send) -> Option<CipherId> {
    serde_json::from_str::<SendItemData>(&send.data).ok().map(|d| d.metadata.item_id)
}

fn enforce_email_auth_for_item_send(send: &Send) -> EmptyResult {
    if send.atype == SendType::Item as i32 && send.auth_type != SendAuthType::Email as i32 {
        err!("Item Sends require email verification")
    }
    Ok(())
}

/// A user can only share an item they own, or an organization item they can edit and see the password of.
/// Deleted, archived and SSH key items can't be shared.
///
/// Upstream: https://github.com/bitwarden/server/blob/main/src/Core/Tools/SendFeatures/Services/SendValidationService.cs
async fn enforce_item_shareable(item_id: &CipherId, user_id: &UserId, conn: &DbConn) -> EmptyResult {
    const SSH_KEY_TYPE: i32 = 5;

    let Some(cipher) = Cipher::find_by_uuid(item_id, conn).await else {
        err!("Item not found.")
    };
    let can_share = if cipher.user_uuid.as_ref() == Some(user_id) {
        true
    } else if cipher.organization_uuid.is_some() {
        // (read_only, hide_passwords, manage)
        matches!(cipher.get_access_restrictions(user_id, None, conn).await, Some((false, false, _)))
    } else {
        false
    };
    if !can_share
        || cipher.deleted_at.is_some()
        || cipher.atype == SSH_KEY_TYPE
        || cipher.get_archived_at(user_id, conn).await.is_some()
    {
        err!("Item not found.")
    }
    Ok(())
}

/// Splits a comma separated list of emails, trimming and lowercasing each entry and dropping empty ones.
/// Returns `None` when no address is left.
fn normalize_emails(emails: Option<&str>) -> Option<String> {
    let emails: Vec<String> = emails?.split(',').map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()).collect();
    (!emails.is_empty()).then(|| emails.join(","))
}

/// Applies the requested access control to a Send, used for both creation and updates.
///
/// When `authType` is missing (older clients) it is inferred from the other fields, like upstream does.
/// The stored `auth_type` is always derived from the resulting state, so a Send never claims a
/// protection it doesn't actually enforce.
///
/// Upstream: https://github.com/bitwarden/server/blob/main/src/Api/Tools/Models/Request/SendRequestModel.cs
fn apply_send_auth(
    send: &mut Send,
    auth_type: Option<i32>,
    emails: Option<&str>,
    password: Option<String>,
) -> EmptyResult {
    let auth_type = match auth_type.map(SendAuthType::from_i32) {
        Some(None) => err!("Invalid authType"),
        Some(t) => t,
        None => None,
    };
    let emails = normalize_emails(emails);
    let password = password.filter(|p| !p.is_empty());

    match auth_type {
        Some(SendAuthType::Email) => {
            let Some(emails) = emails else {
                err!("Email verification requires at least one email address")
            };
            send.emails = Some(emails);
            send.set_password(None);
        }
        Some(SendAuthType::Password) => {
            send.emails = None;
            // Editing a password protected Send doesn't resend the password, keep the existing one
            if let Some(password) = password {
                send.set_password(Some(&password));
            } else if send.password_hash.is_none() {
                err!("A password is required")
            }
        }
        Some(SendAuthType::None) => {
            send.emails = None;
            send.set_password(None);
        }
        // Unlike upstream, an email protected Send is kept as is when no emails are provided, clients
        // without `authType` don't know about emails so they can't have intentionally removed them.
        None => {
            if emails.is_some() {
                send.emails = emails;
                send.set_password(None);
            } else if let Some(password) = password {
                send.emails = None;
                send.set_password(Some(&password));
            }
        }
    }

    send.auth_type = send.effective_auth_type() as i32;
    Ok(())
}

fn enforce_mail_enabled_for_email_auth(send: &Send) -> EmptyResult {
    if send.emails.is_some() && !CONFIG.mail_enabled() {
        err!("Email verification for Sends requires email to be enabled on this server")
    }
    Ok(())
}

#[get("/sends")]
async fn get_sends(headers: Headers, conn: DbConn) -> Json<Value> {
    let sends = Send::find_by_user(&headers.user.uuid, &conn);
    let sends_json: Vec<Value> = sends.await.iter().filter(|s| send_visible(s)).map(Send::to_json).collect();

    Json(json!({
      "data": sends_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/sends/<send_id>")]
async fn get_send(send_id: SendId, headers: Headers, conn: DbConn) -> JsonResult {
    if let Some(send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await
        && send_visible(&send)
    {
        Ok(Json(send.to_json()))
    } else {
        err!("Send not found", "Invalid send uuid or does not belong to user")
    }
}

#[post("/sends", data = "<data>")]
async fn post_send(data: Json<SendData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.into_inner();
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    if data.r#type == SendType::File as i32 {
        err!("File sends should use /api/sends/file/v2")
    }

    let mut send = create_send(data, headers.user.uuid.clone())?;
    if let Some(item_id) = stored_item_id(&send) {
        enforce_item_shareable(&item_id, &headers.user.uuid, &conn).await?;
    }
    send.save(&conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendCreate,
        &send,
        &send.update_users_revision(&conn).await,
        &headers.device,
        &conn,
    )
    .await;

    Ok(Json(send.to_json()))
}

#[derive(FromForm)]
struct UploadDataV2<'f> {
    data: TempFile<'f>,
}

// Upstream: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Tools/Controllers/SendsController.cs#L165
#[post("/sends/file/v2", data = "<data>")]
async fn post_send_file_v2(data: Json<SendData>, headers: Headers, conn: DbConn) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data = data.into_inner();

    if data.r#type != SendType::File as i32 {
        err!("Send content is not a file");
    }

    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let file_length = if let Some(m) = &data.file_length {
        m.into_i64()?
    } else {
        err!("Invalid send length")
    };
    if file_length < 0 {
        err!("Send size can't be negative")
    }

    let size_limit = match CONFIG.user_send_limit() {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let Some(already_used) = Send::size_by_user(&headers.user.uuid, &conn).await else {
                err!("Existing sends overflow")
            };
            let Some(left) = limit_kb.checked_mul(1024).and_then(|l| l.checked_sub(already_used)) else {
                err!("Send size overflow");
            };
            if left <= 0 {
                err!("Send storage limit reached! Delete some sends to free up space")
            }
            i64::clamp(left, 0, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    if file_length > size_limit {
        err!("Send storage limit exceeded with this file");
    }

    let mut send = create_send(data, headers.user.uuid)?;

    let file_id = crate::crypto::generate_send_file_id();

    let mut data_value: Value = serde_json::from_str(&send.data)?;
    if let Some(o) = data_value.as_object_mut() {
        o.insert(String::from("id"), Value::String(file_id.clone()));
        o.insert(String::from("size"), Value::Number(file_length.into()));
        o.insert(String::from("sizeName"), Value::String(crate::util::get_display_size(file_length)));
    }
    send.data = serde_json::to_string(&data_value)?;
    send.save(&conn).await?;

    Ok(Json(json!({
        "fileUploadType": 0, // 0 == Direct | 1 == Azure
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{file_id}", send.uuid),
        "sendResponse": send.to_json()
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendFileData {
    id: SendFileId,
    size: u64,
    fileName: String,
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Tools/Controllers/SendsController.cs#L195
#[post("/sends/<send_id>/file/<file_id>", format = "multipart/form-data", data = "<data>", rank = 2)]
async fn post_send_file_v2_data(
    send_id: SendId,
    file_id: SendFileId,
    data: Form<UploadDataV2<'_>>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data = data.into_inner();

    let Some(send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await else {
        err!("Send not found. Unable to save the file.", "Invalid send uuid or does not belong to user.")
    };

    if send.atype != SendType::File as i32 {
        err!("Send is not a file type send.");
    }

    let Ok(send_data) = serde_json::from_str::<SendFileData>(&send.data) else {
        err!("Unable to decode send data as json.")
    };

    match data.data.raw_name() {
        Some(raw_file_name)
            if raw_file_name.dangerous_unsafe_unsanitized_raw() == send_data.fileName
            // be less strict only if using CLI, cf. https://github.com/dani-garcia/vaultwarden/issues/5614
            || (headers.device.is_cli() && send_data.fileName.ends_with(raw_file_name.dangerous_unsafe_unsanitized_raw().as_str())
            ) => {}
        Some(raw_file_name) => err!(
            "Send file name does not match.",
            format!(
                "Expected file name '{}' got '{}'",
                send_data.fileName.escape_debug(),
                raw_file_name.dangerous_unsafe_unsanitized_raw().as_str().escape_debug()
            )
        ),
        _ => err!("Send file name does not match or is not provided."),
    }

    if file_id != send_data.id {
        err!("Send file does not match send data.", format!("Expected id {} got {file_id}", send_data.id));
    }

    let Some(size) = data.data.len().to_u64() else {
        err!("Send file size overflow.");
    };

    if size != send_data.size {
        err!("Send file size does not match.", format!("Expected a file size of {} got {size}", send_data.size));
    }

    let file_path = format!("{send_id}/{file_id}");

    save_temp_file(&PathType::Sends, &file_path, data.data, false).await?;

    nt.send_send_update(
        UpdateType::SyncSendCreate,
        &send,
        &send.update_users_revision(&conn).await,
        &headers.device,
        &conn,
    )
    .await;

    Ok(())
}

#[post("/sends/access")]
async fn post_access(headers: SendHeaders, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    let Some(mut send) = Send::find_by_uuid(&headers.send_id, &conn).await else {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    };
    if !send.is_accessible() || !send_visible(&send) {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    // Files are incremented during the download
    if (send.atype == SendType::Text as i32 || send.atype == SendType::Item as i32)
        && !send.register_access(&conn).await?
    {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    process_access(send, conn, nt).await
}

async fn process_access(send: Send, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&conn).await,
        &ANON_PUSH_DEVICE,
        &conn,
    )
    .await;

    Ok(Json(send.to_json_access(&conn).await))
}

#[post("/sends/access/file/<file_id>", rank = 1)]
async fn post_access_file(
    file_id: SendFileId,
    headers: SendHeaders,
    host: Host,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let Some(mut send) = Send::find_by_uuid(&headers.send_id, &conn).await else {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    };
    if !send.is_accessible() {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    check_send_file_id(&send, &file_id)?;
    if !send.register_access(&conn).await? {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    process_access_file(send, file_id, host, conn, nt).await
}

fn check_send_file_id(send: &Send, file_id: &SendFileId) -> EmptyResult {
    if send.atype != SendType::File as i32 {
        err!("Send is not a file type send.");
    }
    match serde_json::from_str::<SendFileData>(&send.data) {
        Ok(data) if &data.id == file_id => Ok(()),
        _ => err_code!(SEND_INACCESSIBLE_MSG, 404),
    }
}

async fn process_access_file(send: Send, file_id: SendFileId, host: Host, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&conn).await,
        &ANON_PUSH_DEVICE,
        &conn,
    )
    .await;

    Ok(Json(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": download_url(&host, &send.uuid, &file_id).await?,
    })))
}

async fn download_url(host: &Host, send_id: &SendId, file_id: &SendFileId) -> Result<String, crate::Error> {
    let operator = CONFIG.opendal_operator_for_path_type(&PathType::Sends)?;

    if crate::storage::is_fs_operator(&operator) {
        let token_claims = crate::auth::generate_send_claims(send_id, file_id);
        let token = crate::auth::encode_jwt(&token_claims);

        Ok(format!("{}/api/sends/{send_id}/{file_id}?t={token}", host.host))
    } else {
        Ok(operator.presign_read(&format!("{send_id}/{file_id}"), Duration::from_mins(5)).await?.uri().to_string())
    }
}

#[get("/sends/<send_id>/<file_id>?<t>")]
async fn download_send(send_id: SendId, file_id: SendFileId, t: &str) -> Option<NamedFile> {
    if let Ok(claims) = crate::auth::decode_send(t)
        && claims.sub == format!("{send_id}/{file_id}")
    {
        return NamedFile::open(Path::new(&CONFIG.sends_folder()).join(send_id).join(file_id)).await.ok();
    }
    None
}

#[put("/sends/<send_id>", data = "<data>")]
async fn put_send(send_id: SendId, data: Json<SendData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.into_inner();
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let Some(mut send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await else {
        err!("Send not found", "Send send_id is invalid or does not belong to user")
    };

    update_send_from_data(&mut send, data, &headers, &conn, &nt, UpdateType::SyncSendUpdate).await?;

    Ok(Json(send.to_json()))
}

async fn update_send_from_data(
    send: &mut Send,
    data: SendData,
    headers: &Headers,
    conn: &DbConn,
    nt: &Notify<'_>,
    ut: UpdateType,
) -> EmptyResult {
    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    if send.atype != data.r#type {
        err!("Sends can't change type")
    }

    if data.deletion_date > Utc::now() + TimeDelta::try_days(31).unwrap() {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }

    // When updating a file Send, we receive nulls in the File field, as it's immutable,
    // so we only need to update the data field in the Text case
    if data.r#type == SendType::Text as i32 {
        let data_str = if let Some(mut d) = data.text {
            d.as_object_mut().and_then(|d| d.remove("response"));
            serde_json::to_string(&d)?
        } else {
            err!("Send data not provided");
        };
        send.data = data_str;
    } else if data.r#type == SendType::Item as i32 {
        let item = parse_item_data(data.data)?;
        // Only check access to the item when it changes
        if stored_item_id(send).as_ref() != Some(&item.metadata.item_id) {
            enforce_item_shareable(&item.metadata.item_id, &headers.user.uuid, conn).await?;
        }
        send.data = serde_json::to_string(&item)?;
    }

    send.name = data.name;
    send.akey = data.key;
    send.deletion_date = data.deletion_date.naive_utc();
    send.notes = data.notes;
    send.max_access_count = match data.max_access_count {
        Some(m) => Some(m.into_i32()?),
        _ => None,
    };
    send.expiration_date = data.expiration_date.map(|d| d.naive_utc());
    send.hide_email = data.hide_email;
    send.disabled = data.disabled;

    apply_send_auth(send, data.auth_type, data.emails.as_deref(), data.password)?;
    enforce_mail_enabled_for_email_auth(send)?;
    enforce_email_auth_for_item_send(send)?;

    send.save(conn).await?;
    if ut != UpdateType::None {
        nt.send_send_update(ut, send, &send.update_users_revision(conn).await, &headers.device, conn).await;
    }
    Ok(())
}

#[delete("/sends/<send_id>")]
async fn delete_send(send_id: SendId, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let Some(send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await else {
        err!("Send not found", "Invalid send uuid, or does not belong to user")
    };

    send.delete(&conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendDelete,
        &send,
        &send.update_users_revision(&conn).await,
        &headers.device,
        &conn,
    )
    .await;

    Ok(())
}

#[put("/sends/<send_id>/remove-password")]
async fn put_remove_password(send_id: SendId, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let Some(mut send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await else {
        err!("Send not found", "Invalid send uuid, or does not belong to user")
    };

    send.set_password(None);
    send.auth_type = send.effective_auth_type() as i32;
    send.save(&conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&conn).await,
        &headers.device,
        &conn,
    )
    .await;

    Ok(Json(send.to_json()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_send() -> Send {
        Send::new(
            SendType::Text as i32,
            String::from("name"),
            String::from("{}"),
            String::from("key"),
            Utc::now().naive_utc(),
        )
    }

    const EMAIL: i32 = SendAuthType::Email as i32;
    const PASSWORD: i32 = SendAuthType::Password as i32;
    const NONE: i32 = SendAuthType::None as i32;

    #[test]
    fn test_normalize_emails() {
        assert_eq!(normalize_emails(Some(" A@x.com, ,b@X.com ,")).as_deref(), Some("a@x.com,b@x.com"));
        assert_eq!(normalize_emails(Some(" , ")), None);
        assert_eq!(normalize_emails(Some("")), None);
        assert_eq!(normalize_emails(None), None);
    }

    #[test]
    fn test_email_auth_requires_an_email() {
        let mut send = new_send();
        assert!(apply_send_auth(&mut send, Some(EMAIL), Some(" , "), None).is_err());
        assert!(apply_send_auth(&mut send, Some(EMAIL), None, None).is_err());
    }

    #[test]
    fn test_email_auth_clears_password() {
        let mut send = new_send();
        apply_send_auth(&mut send, Some(PASSWORD), None, Some(String::from("secret"))).unwrap();
        apply_send_auth(&mut send, Some(EMAIL), Some("A@x.com"), Some(String::from("secret"))).unwrap();
        assert_eq!(send.auth_type, EMAIL);
        assert_eq!(send.emails.as_deref(), Some("a@x.com"));
        assert!(send.password_hash.is_none());
    }

    #[test]
    fn test_password_auth() {
        let mut send = new_send();
        assert!(apply_send_auth(&mut send, Some(PASSWORD), None, None).is_err());

        apply_send_auth(&mut send, Some(PASSWORD), Some("a@x.com"), Some(String::from("secret"))).unwrap();
        assert_eq!(send.auth_type, PASSWORD);
        assert!(send.emails.is_none());

        // Edits don't resend the password, the existing one is kept
        apply_send_auth(&mut send, Some(PASSWORD), None, None).unwrap();
        assert_eq!(send.auth_type, PASSWORD);
        assert!(send.check_password("secret"));
    }

    #[test]
    fn test_none_auth_clears_everything() {
        let mut send = new_send();
        apply_send_auth(&mut send, Some(EMAIL), Some("a@x.com"), None).unwrap();
        apply_send_auth(&mut send, Some(NONE), Some("a@x.com"), Some(String::from("secret"))).unwrap();
        assert_eq!(send.auth_type, NONE);
        assert!(send.emails.is_none());
        assert!(send.password_hash.is_none());
    }

    #[test]
    fn test_missing_auth_type_is_inferred() {
        let mut send = new_send();
        apply_send_auth(&mut send, None, None, Some(String::from("secret"))).unwrap();
        assert_eq!(send.auth_type, PASSWORD);

        apply_send_auth(&mut send, None, Some("a@x.com"), None).unwrap();
        assert_eq!(send.auth_type, EMAIL);
        assert!(send.password_hash.is_none());

        // Clients without authType don't know about emails, an email protected Send stays protected
        apply_send_auth(&mut send, None, None, None).unwrap();
        assert_eq!(send.auth_type, EMAIL);
        assert_eq!(send.emails.as_deref(), Some("a@x.com"));
    }

    #[test]
    fn test_item_send_data_roundtrip() {
        let mut send = new_send();
        send.atype = SendType::Item as i32;
        send.data = String::from(r#"{"encryptionVersion":1,"data":"blob","metadata":{"itemId":"item-id"}}"#);
        assert_eq!(stored_item_id(&send).as_deref().map(String::as_str), Some("item-id"));

        // Other Send types don't have an item
        assert!(stored_item_id(&new_send()).is_none());
    }

    #[test]
    fn test_item_send_requires_email_auth() {
        let mut send = new_send();
        send.atype = SendType::Item as i32;
        apply_send_auth(&mut send, Some(PASSWORD), None, Some(String::from("secret"))).unwrap();
        assert!(enforce_email_auth_for_item_send(&send).is_err());

        apply_send_auth(&mut send, Some(EMAIL), Some("a@x.com"), None).unwrap();
        assert!(enforce_email_auth_for_item_send(&send).is_ok());

        // Text Sends aren't affected
        assert!(enforce_email_auth_for_item_send(&new_send()).is_ok());
    }

    #[test]
    fn test_invalid_auth_type() {
        let mut send = new_send();
        assert!(apply_send_auth(&mut send, Some(42), None, None).is_err());
    }
}
