use std::{path::Path, sync::LazyLock, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use num_traits::ToPrimitive;
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
        models::{Device, OrgPolicy, OrgPolicyType, Send, SendFileId, SendId, SendType, UserId},
    },
    util::{NumberOrString, save_temp_file},
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
    emails: Option<String>,

    // Data field
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
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
        err!(crate::i18n::send_delete_only_policy(&headers.locale))
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
        err!(crate::i18n::send_hide_email_policy_forbidden(&headers.locale))
    }
    Ok(())
}

fn create_send(data: SendData, user_id: UserId) -> ApiResult<Send> {
    let data_val = if data.r#type == SendType::Text as i32 {
        data.text
    } else if data.r#type == SendType::File as i32 {
        data.file
    } else {
        err!(crate::i18n::send_invalid_type(&CONFIG.default_locale()))
    };

    let data_str = if let Some(mut d) = data_val {
        d.as_object_mut().and_then(|o| o.remove("response"));
        serde_json::to_string(&d)?
    } else {
        err!(crate::i18n::send_data_not_provided(&CONFIG.default_locale()));
    };

    if data.deletion_date > Utc::now() + TimeDelta::try_days(31).unwrap() {
        err!(crate::i18n::send_deletion_date_too_far(&CONFIG.default_locale()));
    }

    if data.emails.is_some() {
        err!(crate::i18n::send_email_verification_not_supported(&CONFIG.default_locale()));
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

    send.set_password(data.password.as_deref());

    Ok(send)
}

#[get("/sends")]
async fn get_sends(headers: Headers, conn: DbConn) -> Json<Value> {
    let sends = Send::find_by_user(&headers.user.uuid, &conn);
    let sends_json: Vec<Value> = sends.await.iter().map(Send::to_json).collect();

    Json(json!({
      "data": sends_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/sends/<send_id>")]
async fn get_send(send_id: SendId, headers: Headers, conn: DbConn) -> JsonResult {
    if let Some(send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await {
        Ok(Json(send.to_json()))
    } else {
        err!(crate::i18n::send_not_found(&headers.locale), crate::i18n::send_invalid_uuid_or_not_owned(&headers.locale))
    }
}

#[post("/sends", data = "<data>")]
async fn post_send(data: Json<SendData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.into_inner();
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    if data.r#type == SendType::File as i32 {
        err!(crate::i18n::send_file_use_v2(&headers.locale))
    }

    let mut send = create_send(data, headers.user.uuid)?;
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
        err!(crate::i18n::send_content_not_file(&headers.locale));
    }

    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let file_length = if let Some(m) = &data.file_length {
        m.into_i64()?
    } else {
        err!(crate::i18n::send_invalid_length(&headers.locale))
    };
    if file_length < 0 {
        err!(crate::i18n::send_size_negative(&headers.locale))
    }

    let size_limit = match CONFIG.user_send_limit() {
        Some(0) => err!(crate::i18n::send_file_uploads_disabled(&headers.locale)),
        Some(limit_kb) => {
            let Some(already_used) = Send::size_by_user(&headers.user.uuid, &conn).await else {
                err!(crate::i18n::send_existing_overflow(&headers.locale))
            };
            let Some(left) = limit_kb.checked_mul(1024).and_then(|l| l.checked_sub(already_used)) else {
                err!(crate::i18n::send_size_overflow(&headers.locale));
            };
            if left <= 0 {
                err!(crate::i18n::send_storage_limit_reached(&headers.locale))
            }
            i64::clamp(left, 0, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    if file_length > size_limit {
        err!(crate::i18n::send_storage_limit_exceeded_file(&headers.locale));
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
        err!(
            crate::i18n::send_not_found_unable_save_file(&headers.locale),
            crate::i18n::send_invalid_uuid_or_not_owned(&headers.locale)
        )
    };

    if send.atype != SendType::File as i32 {
        err!(crate::i18n::send_not_file_type(&headers.locale));
    }

    let Ok(send_data) = serde_json::from_str::<SendFileData>(&send.data) else {
        err!(crate::i18n::send_unable_decode_json(&headers.locale))
    };

    match data.data.raw_name() {
        Some(raw_file_name)
            if raw_file_name.dangerous_unsafe_unsanitized_raw() == send_data.fileName
            // be less strict only if using CLI, cf. https://github.com/dani-garcia/vaultwarden/issues/5614
            || (headers.device.is_cli() && send_data.fileName.ends_with(raw_file_name.dangerous_unsafe_unsanitized_raw().as_str())
            ) => {}
        Some(raw_file_name) => err!(
            crate::i18n::send_file_name_mismatch(&headers.locale),
            format!(
                "Expected file name '{}' got '{}'",
                send_data.fileName.escape_debug(),
                raw_file_name.dangerous_unsafe_unsanitized_raw().as_str().escape_debug()
            )
        ),
        _ => err!(crate::i18n::send_file_name_missing_or_mismatch(&headers.locale)),
    }

    if file_id != send_data.id {
        err!(
            crate::i18n::send_file_mismatch_data(&headers.locale),
            format!("Expected id {} got {file_id}", send_data.id)
        );
    }

    let Some(size) = data.data.len().to_u64() else {
        err!(crate::i18n::send_file_size_overflow(&headers.locale));
    };

    if size != send_data.size {
        err!(
            crate::i18n::send_file_size_mismatch(&headers.locale),
            format!("Expected a file size of {} got {size}", send_data.size)
        );
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
    if !send.is_accessible() {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    // Files are incremented during the download
    if send.atype == SendType::Text as i32 && !send.register_access(&conn).await? {
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
        err!(crate::i18n::send_not_file_type(&CONFIG.default_locale()));
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
        err!(
            crate::i18n::send_not_found(&headers.locale),
            crate::i18n::send_invalid_send_id_or_not_owned(&headers.locale)
        )
    };

    if data.emails.is_some() {
        err!(crate::i18n::send_email_verification_not_supported(&headers.locale));
    }

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
        err!(crate::i18n::send_not_owned_by_user(&headers.locale))
    }

    if send.atype != data.r#type {
        err!(crate::i18n::send_cannot_change_type(&headers.locale))
    }

    if data.deletion_date > Utc::now() + TimeDelta::try_days(31).unwrap() {
        err!(crate::i18n::send_deletion_date_too_far(&headers.locale));
    }

    // When updating a file Send, we receive nulls in the File field, as it's immutable,
    // so we only need to update the data field in the Text case
    if data.r#type == SendType::Text as i32 {
        let data_str = if let Some(mut d) = data.text {
            d.as_object_mut().and_then(|d| d.remove("response"));
            serde_json::to_string(&d)?
        } else {
            err!(crate::i18n::send_data_not_provided(&headers.locale));
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
        nt.send_send_update(ut, send, &send.update_users_revision(conn).await, &headers.device, conn).await;
    }
    Ok(())
}

#[delete("/sends/<send_id>")]
async fn delete_send(send_id: SendId, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let Some(send) = Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await else {
        err!(crate::i18n::send_not_found(&headers.locale), crate::i18n::send_invalid_uuid_or_not_owned(&headers.locale))
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
        err!(crate::i18n::send_not_found(&headers.locale), crate::i18n::send_invalid_uuid_or_not_owned(&headers.locale))
    };

    send.set_password(None);
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
