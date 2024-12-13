use std::path::Path;

use chrono::{DateTime, TimeDelta, Utc};
use num_traits::ToPrimitive;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::fs::TempFile;
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, Notify, UpdateType},
    auth::{ClientIp, Headers, Host},
    db::{models::*, DbConn, DbPool},
    util::{NumberOrString, SafeString},
    CONFIG,
};

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";

// The max file size allowed by Bitwarden clients and add an extra 5% to avoid issues
const SIZE_525_MB: i64 = 550_502_400;

pub fn routes() -> Vec<rocket::Route> {
    routes![
        get_sends,
        get_send,
        post_send,
        post_send_file,
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
    if let Ok(mut conn) = pool.get().await {
        Send::purge(&mut conn).await;
    } else {
        error!("Failed to get DB connection while purging sends")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendData {
    r#type: i32,
    key: String,
    password: Option<String>,
    max_access_count: Option<NumberOrString>,
    expiration_date: Option<DateTime<Utc>>,
    deletion_date: DateTime<Utc>,
    disabled: bool,
    hide_email: Option<bool>,

    // Data field
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
    file_length: Option<NumberOrString>,

    // Used for key rotations
    pub id: Option<String>,
}

/// Enforces the `Disable Send` policy. A non-owner/admin user belonging to
/// an org with this policy enabled isn't allowed to create new Sends or
/// modify existing ones, but is allowed to delete them.
///
/// Ref: https://bitwarden.com/help/article/policies/#disable-send
///
/// There is also a Vaultwarden-specific `sends_allowed` config setting that
/// controls this policy globally.
async fn enforce_disable_send_policy(headers: &Headers, conn: &mut DbConn) -> EmptyResult {
    let user_uuid = &headers.user.uuid;
    if !CONFIG.sends_allowed()
        || OrgPolicy::is_applicable_to_user(user_uuid, OrgPolicyType::DisableSend, None, conn).await
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
async fn enforce_disable_hide_email_policy(data: &SendData, headers: &Headers, conn: &mut DbConn) -> EmptyResult {
    let user_uuid = &headers.user.uuid;
    let hide_email = data.hide_email.unwrap_or(false);
    if hide_email && OrgPolicy::is_hide_email_disabled(user_uuid, conn).await {
        err!(
            "Due to an Enterprise Policy, you are not allowed to hide your email address \
              from recipients when creating or editing a Send."
        )
    }
    Ok(())
}

fn create_send(data: SendData, user_uuid: String) -> ApiResult<Send> {
    let data_val = if data.r#type == SendType::Text as i32 {
        data.text
    } else if data.r#type == SendType::File as i32 {
        data.file
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
    send.user_uuid = Some(user_uuid);
    send.notes = data.notes;
    send.max_access_count = match data.max_access_count {
        Some(m) => Some(m.into_i32()?),
        _ => None,
    };
    send.expiration_date = data.expiration_date.map(|d| d.naive_utc());
    send.disabled = data.disabled;
    send.hide_email = data.hide_email;
    send.atype = data.r#type;

    send.set_password(data.password.as_deref());

    Ok(send)
}

#[get("/sends")]
async fn get_sends(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let sends = Send::find_by_user(&headers.user.uuid, &mut conn);
    let sends_json: Vec<Value> = sends.await.iter().map(|s| s.to_json()).collect();

    Json(json!({
      "data": sends_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/sends/<uuid>")]
async fn get_send(uuid: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    match Send::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await {
        Some(send) => Ok(Json(send.to_json())),
        None => err!("Send not found", "Invalid uuid or does not belong to user"),
    }
}

#[post("/sends", data = "<data>")]
async fn post_send(data: Json<SendData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let data: SendData = data.into_inner();
    enforce_disable_hide_email_policy(&data, &headers, &mut conn).await?;

    if data.r#type == SendType::File as i32 {
        err!("File sends should use /api/sends/file")
    }

    let mut send = create_send(data, headers.user.uuid)?;
    send.save(&mut conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendCreate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &headers.device.uuid,
        &mut conn,
    )
    .await;

    Ok(Json(send.to_json()))
}

#[derive(FromForm)]
struct UploadData<'f> {
    model: Json<SendData>,
    data: TempFile<'f>,
}

#[derive(FromForm)]
struct UploadDataV2<'f> {
    data: TempFile<'f>,
}

// @deprecated Mar 25 2021: This method has been deprecated in favor of direct uploads (v2).
// This method still exists to support older clients, probably need to remove it sometime.
// Upstream: https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L164-L167
#[post("/sends/file", format = "multipart/form-data", data = "<data>")]
async fn post_send_file(data: Form<UploadData<'_>>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let UploadData {
        model,
        mut data,
    } = data.into_inner();
    let model = model.into_inner();

    let Some(size) = data.len().to_i64() else {
        err!("Invalid send size");
    };
    if size < 0 {
        err!("Send size can't be negative")
    }

    enforce_disable_hide_email_policy(&model, &headers, &mut conn).await?;

    let size_limit = match CONFIG.user_send_limit() {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let Some(already_used) = Send::size_by_user(&headers.user.uuid, &mut conn).await else {
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

    if size > size_limit {
        err!("Send storage limit exceeded with this file");
    }

    let mut send = create_send(model, headers.user.uuid)?;
    if send.atype != SendType::File as i32 {
        err!("Send content is not a file");
    }

    let file_id = crate::crypto::generate_send_id();
    let folder_path = tokio::fs::canonicalize(&CONFIG.sends_folder()).await?.join(&send.uuid);
    let file_path = folder_path.join(&file_id);
    tokio::fs::create_dir_all(&folder_path).await?;

    if let Err(_err) = data.persist_to(&file_path).await {
        data.move_copy_to(file_path).await?
    }

    let mut data_value: Value = serde_json::from_str(&send.data)?;
    if let Some(o) = data_value.as_object_mut() {
        o.insert(String::from("id"), Value::String(file_id));
        o.insert(String::from("size"), Value::Number(size.into()));
        o.insert(String::from("sizeName"), Value::String(crate::util::get_display_size(size)));
    }
    send.data = serde_json::to_string(&data_value)?;

    // Save the changes in the database
    send.save(&mut conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendCreate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &headers.device.uuid,
        &mut conn,
    )
    .await;

    Ok(Json(send.to_json()))
}

// Upstream: https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L190
#[post("/sends/file/v2", data = "<data>")]
async fn post_send_file_v2(data: Json<SendData>, headers: Headers, mut conn: DbConn) -> JsonResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let data = data.into_inner();

    if data.r#type != SendType::File as i32 {
        err!("Send content is not a file");
    }

    enforce_disable_hide_email_policy(&data, &headers, &mut conn).await?;

    let file_length = match &data.file_length {
        Some(m) => m.into_i64()?,
        _ => err!("Invalid send length"),
    };
    if file_length < 0 {
        err!("Send size can't be negative")
    }

    let size_limit = match CONFIG.user_send_limit() {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let Some(already_used) = Send::size_by_user(&headers.user.uuid, &mut conn).await else {
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

    let file_id = crate::crypto::generate_send_id();

    let mut data_value: Value = serde_json::from_str(&send.data)?;
    if let Some(o) = data_value.as_object_mut() {
        o.insert(String::from("id"), Value::String(file_id.clone()));
        o.insert(String::from("size"), Value::Number(file_length.into()));
        o.insert(String::from("sizeName"), Value::String(crate::util::get_display_size(file_length)));
    }
    send.data = serde_json::to_string(&data_value)?;
    send.save(&mut conn).await?;

    Ok(Json(json!({
        "fileUploadType": 0, // 0 == Direct | 1 == Azure
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{}", send.uuid, file_id),
        "sendResponse": send.to_json()
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendFileData {
    id: String,
    size: u64,
    fileName: String,
}

// https://github.com/bitwarden/server/blob/66f95d1c443490b653e5a15d32977e2f5a3f9e32/src/Api/Tools/Controllers/SendsController.cs#L250
#[post("/sends/<send_uuid>/file/<file_id>", format = "multipart/form-data", data = "<data>")]
async fn post_send_file_v2_data(
    send_uuid: &str,
    file_id: &str,
    data: Form<UploadDataV2<'_>>,
    headers: Headers,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let mut data = data.into_inner();

    let Some(send) = Send::find_by_uuid_and_user(send_uuid, &headers.user.uuid, &mut conn).await else {
        err!("Send not found. Unable to save the file.", "Invalid uuid or does not belong to user.")
    };

    if send.atype != SendType::File as i32 {
        err!("Send is not a file type send.");
    }

    let Ok(send_data) = serde_json::from_str::<SendFileData>(&send.data) else {
        err!("Unable to decode send data as json.")
    };

    match data.data.raw_name() {
        Some(raw_file_name) if raw_file_name.dangerous_unsafe_unsanitized_raw() == send_data.fileName => (),
        Some(raw_file_name) => err!(
            "Send file name does not match.",
            format!(
                "Expected file name '{}' got '{}'",
                send_data.fileName,
                raw_file_name.dangerous_unsafe_unsanitized_raw()
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

    let folder_path = tokio::fs::canonicalize(&CONFIG.sends_folder()).await?.join(send_uuid);
    let file_path = folder_path.join(file_id);

    // Check if the file already exists, if that is the case do not overwrite it
    if tokio::fs::metadata(&file_path).await.is_ok() {
        err!("Send file has already been uploaded.", format!("File {file_path:?} already exists"))
    }

    tokio::fs::create_dir_all(&folder_path).await?;

    if let Err(_err) = data.data.persist_to(&file_path).await {
        data.data.move_copy_to(file_path).await?
    }

    nt.send_send_update(
        UpdateType::SyncSendCreate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &headers.device.uuid,
        &mut conn,
    )
    .await;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessData {
    pub password: Option<String>,
}

#[post("/sends/access/<access_id>", data = "<data>")]
async fn post_access(
    access_id: &str,
    data: Json<SendAccessData>,
    mut conn: DbConn,
    ip: ClientIp,
    nt: Notify<'_>,
) -> JsonResult {
    let Some(mut send) = Send::find_by_access_id(access_id, &mut conn).await else {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    };

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            err_code!(SEND_INACCESSIBLE_MSG, 404);
        }
    }

    if let Some(expiration) = send.expiration_date {
        if Utc::now().naive_utc() >= expiration {
            err_code!(SEND_INACCESSIBLE_MSG, 404)
        }
    }

    if Utc::now().naive_utc() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }

    if send.password_hash.is_some() {
        match data.into_inner().password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password", format!("IP: {}.", ip.ip)),
            None => err_code!("Password not provided", format!("IP: {}.", ip.ip), 401),
        }
    }

    // Files are incremented during the download
    if send.atype == SendType::Text as i32 {
        send.access_count += 1;
    }

    send.save(&mut conn).await?;

    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &String::from("00000000-0000-0000-0000-000000000000"),
        &mut conn,
    )
    .await;

    Ok(Json(send.to_json_access(&mut conn).await))
}

#[post("/sends/<send_id>/access/file/<file_id>", data = "<data>")]
async fn post_access_file(
    send_id: &str,
    file_id: &str,
    data: Json<SendAccessData>,
    host: Host,
    mut conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    let Some(mut send) = Send::find_by_uuid(send_id, &mut conn).await else {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    };

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            err_code!(SEND_INACCESSIBLE_MSG, 404)
        }
    }

    if let Some(expiration) = send.expiration_date {
        if Utc::now().naive_utc() >= expiration {
            err_code!(SEND_INACCESSIBLE_MSG, 404)
        }
    }

    if Utc::now().naive_utc() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }

    if send.password_hash.is_some() {
        match data.into_inner().password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password."),
            None => err_code!("Password not provided", 401),
        }
    }

    send.access_count += 1;

    send.save(&mut conn).await?;

    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &String::from("00000000-0000-0000-0000-000000000000"),
        &mut conn,
    )
    .await;

    let token_claims = crate::auth::generate_send_claims(send_id, file_id);
    let token = crate::auth::encode_jwt(&token_claims);
    Ok(Json(json!({
        "object": "send-fileDownload",
        "id": file_id,
        "url": format!("{}/api/sends/{}/{}?t={}", &host.host, send_id, file_id, token)
    })))
}

#[get("/sends/<send_id>/<file_id>?<t>")]
async fn download_send(send_id: SafeString, file_id: SafeString, t: &str) -> Option<NamedFile> {
    if let Ok(claims) = crate::auth::decode_send(t) {
        if claims.sub == format!("{send_id}/{file_id}") {
            return NamedFile::open(Path::new(&CONFIG.sends_folder()).join(send_id).join(file_id)).await.ok();
        }
    }
    None
}

#[put("/sends/<uuid>", data = "<data>")]
async fn put_send(uuid: &str, data: Json<SendData>, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let data: SendData = data.into_inner();
    enforce_disable_hide_email_policy(&data, &headers, &mut conn).await?;

    let Some(mut send) = Send::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await else {
        err!("Send not found", "Send uuid is invalid or does not belong to user")
    };

    update_send_from_data(&mut send, data, &headers, &mut conn, &nt, UpdateType::SyncSendUpdate).await?;

    Ok(Json(send.to_json()))
}

pub async fn update_send_from_data(
    send: &mut Send,
    data: SendData,
    headers: &Headers,
    conn: &mut DbConn,
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

    // Only change the value if it's present
    if let Some(password) = data.password {
        send.set_password(Some(&password));
    }

    send.save(conn).await?;
    if ut != UpdateType::None {
        nt.send_send_update(ut, send, &send.update_users_revision(conn).await, &headers.device.uuid, conn).await;
    }
    Ok(())
}

#[delete("/sends/<uuid>")]
async fn delete_send(uuid: &str, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let Some(send) = Send::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await else {
        err!("Send not found", "Invalid send uuid, or does not belong to user")
    };

    send.delete(&mut conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendDelete,
        &send,
        &send.update_users_revision(&mut conn).await,
        &headers.device.uuid,
        &mut conn,
    )
    .await;

    Ok(())
}

#[put("/sends/<uuid>/remove-password")]
async fn put_remove_password(uuid: &str, headers: Headers, mut conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &mut conn).await?;

    let Some(mut send) = Send::find_by_uuid_and_user(uuid, &headers.user.uuid, &mut conn).await else {
        err!("Send not found", "Invalid send uuid, or does not belong to user")
    };

    send.set_password(None);
    send.save(&mut conn).await?;
    nt.send_send_update(
        UpdateType::SyncSendUpdate,
        &send,
        &send.update_users_revision(&mut conn).await,
        &headers.device.uuid,
        &mut conn,
    )
    .await;

    Ok(Json(send.to_json()))
}
