use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::fs::TempFile;
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, JsonUpcase, Notify, NumberOrString, UpdateType},
    auth::{ClientIp, Headers, Host},
    db::{models::*, DbConn, DbPool},
    util::SafeString,
    CONFIG,
};

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";

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
        download_send
    ]
}

pub async fn purge_sends(pool: DbPool) {
    debug!("Purging sends");
    if let Ok(conn) = pool.get().await {
        Send::purge(&conn).await;
    } else {
        error!("Failed to get DB connection while purging sends")
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct SendData {
    Type: i32,
    Key: String,
    Password: Option<String>,
    MaxAccessCount: Option<NumberOrString>,
    ExpirationDate: Option<DateTime<Utc>>,
    DeletionDate: DateTime<Utc>,
    Disabled: bool,
    HideEmail: Option<bool>,

    // Data field
    Name: String,
    Notes: Option<String>,
    Text: Option<Value>,
    File: Option<Value>,
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
    let user_uuid = &headers.user.uuid;
    let policy_type = OrgPolicyType::DisableSend;
    if !CONFIG.sends_allowed() || OrgPolicy::is_applicable_to_user(user_uuid, policy_type, conn).await {
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
    let user_uuid = &headers.user.uuid;
    let hide_email = data.HideEmail.unwrap_or(false);
    if hide_email && OrgPolicy::is_hide_email_disabled(user_uuid, conn).await {
        err!(
            "Due to an Enterprise Policy, you are not allowed to hide your email address \
              from recipients when creating or editing a Send."
        )
    }
    Ok(())
}

fn create_send(data: SendData, user_uuid: String) -> ApiResult<Send> {
    let data_val = if data.Type == SendType::Text as i32 {
        data.Text
    } else if data.Type == SendType::File as i32 {
        data.File
    } else {
        err!("Invalid Send type")
    };

    let data_str = if let Some(mut d) = data_val {
        d.as_object_mut().and_then(|o| o.remove("Response"));
        serde_json::to_string(&d)?
    } else {
        err!("Send data not provided");
    };

    if data.DeletionDate > Utc::now() + Duration::days(31) {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }

    let mut send = Send::new(data.Type, data.Name, data_str, data.Key, data.DeletionDate.naive_utc());
    send.user_uuid = Some(user_uuid);
    send.notes = data.Notes;
    send.max_access_count = match data.MaxAccessCount {
        Some(m) => Some(m.into_i32()?),
        _ => None,
    };
    send.expiration_date = data.ExpirationDate.map(|d| d.naive_utc());
    send.disabled = data.Disabled;
    send.hide_email = data.HideEmail;
    send.atype = data.Type;

    send.set_password(data.Password.as_deref());

    Ok(send)
}

#[get("/sends")]
async fn get_sends(headers: Headers, conn: DbConn) -> Json<Value> {
    let sends = Send::find_by_user(&headers.user.uuid, &conn);
    let sends_json: Vec<Value> = sends.await.iter().map(|s| s.to_json()).collect();

    Json(json!({
      "Data": sends_json,
      "Object": "list",
      "ContinuationToken": null
    }))
}

#[get("/sends/<uuid>")]
async fn get_send(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let send = match Send::find_by_uuid(&uuid, &conn).await {
        Some(send) => send,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    Ok(Json(send.to_json()))
}

#[post("/sends", data = "<data>")]
async fn post_send(data: JsonUpcase<SendData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.into_inner().data;
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    if data.Type == SendType::File as i32 {
        err!("File sends should use /api/sends/file")
    }

    let mut send = create_send(data, headers.user.uuid)?;
    send.save(&conn).await?;
    nt.send_send_update(UpdateType::SyncSendCreate, &send, &send.update_users_revision(&conn).await).await;

    Ok(Json(send.to_json()))
}

#[derive(FromForm)]
struct UploadData<'f> {
    model: Json<crate::util::UpCase<SendData>>,
    data: TempFile<'f>,
}

#[post("/sends/file", format = "multipart/form-data", data = "<data>")]
async fn post_send_file(data: Form<UploadData<'_>>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let UploadData {
        model,
        mut data,
    } = data.into_inner();
    let model = model.into_inner().data;

    enforce_disable_hide_email_policy(&model, &headers, &conn).await?;

    // Get the file length and add an extra 5% to avoid issues
    const SIZE_525_MB: u64 = 550_502_400;

    let size_limit = match CONFIG.user_attachment_limit() {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let left = (limit_kb * 1024) - Attachment::size_by_user(&headers.user.uuid, &conn).await;
            if left <= 0 {
                err!("Attachment storage limit reached! Delete some attachments to free up space")
            }
            std::cmp::Ord::max(left as u64, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    let mut send = create_send(model, headers.user.uuid)?;
    if send.atype != SendType::File as i32 {
        err!("Send content is not a file");
    }

    // There seems to be a bug somewhere regarding uploading attachments using the Android Client (Maybe iOS too?)
    // See: https://github.com/dani-garcia/vaultwarden/issues/2644
    // Since all other clients seem to match TempFile::File and not TempFile::Buffered lets catch this and return an error for now.
    // We need to figure out how to solve this, but for now it's better to not accept these attachments since they will be broken.
    if let TempFile::Buffered {
        content: _,
    } = &data
    {
        err!("Error reading send file data. Please try an other client.");
    }

    let size = data.len();
    if size > size_limit {
        err!("Attachment storage limit exceeded with this file");
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
        o.insert(String::from("Id"), Value::String(file_id));
        o.insert(String::from("Size"), Value::Number(size.into()));
        o.insert(String::from("SizeName"), Value::String(crate::util::get_display_size(size as i32)));
    }
    send.data = serde_json::to_string(&data_value)?;

    // Save the changes in the database
    send.save(&conn).await?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn).await).await;

    Ok(Json(send.to_json()))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendAccessData {
    pub Password: Option<String>,
}

#[post("/sends/access/<access_id>", data = "<data>")]
async fn post_access(access_id: String, data: JsonUpcase<SendAccessData>, conn: DbConn, ip: ClientIp) -> JsonResult {
    let mut send = match Send::find_by_access_id(&access_id, &conn).await {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, 404),
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
        match data.into_inner().data.Password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password", format!("IP: {}.", ip.ip)),
            None => err_code!("Password not provided", format!("IP: {}.", ip.ip), 401),
        }
    }

    // Files are incremented during the download
    if send.atype == SendType::Text as i32 {
        send.access_count += 1;
    }

    send.save(&conn).await?;

    Ok(Json(send.to_json_access(&conn).await))
}

#[post("/sends/<send_id>/access/file/<file_id>", data = "<data>")]
async fn post_access_file(
    send_id: String,
    file_id: String,
    data: JsonUpcase<SendAccessData>,
    host: Host,
    conn: DbConn,
) -> JsonResult {
    let mut send = match Send::find_by_uuid(&send_id, &conn).await {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, 404),
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
        match data.into_inner().data.Password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password."),
            None => err_code!("Password not provided", 401),
        }
    }

    send.access_count += 1;

    send.save(&conn).await?;

    let token_claims = crate::auth::generate_send_claims(&send_id, &file_id);
    let token = crate::auth::encode_jwt(&token_claims);
    Ok(Json(json!({
        "Object": "send-fileDownload",
        "Id": file_id,
        "Url": format!("{}/api/sends/{}/{}?t={}", &host.host, send_id, file_id, token)
    })))
}

#[get("/sends/<send_id>/<file_id>?<t>")]
async fn download_send(send_id: SafeString, file_id: SafeString, t: String) -> Option<NamedFile> {
    if let Ok(claims) = crate::auth::decode_send(&t) {
        if claims.sub == format!("{}/{}", send_id, file_id) {
            return NamedFile::open(Path::new(&CONFIG.sends_folder()).join(send_id).join(file_id)).await.ok();
        }
    }
    None
}

#[put("/sends/<id>", data = "<data>")]
async fn put_send(
    id: String,
    data: JsonUpcase<SendData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.into_inner().data;
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let mut send = match Send::find_by_uuid(&id, &conn).await {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    if send.atype != data.Type {
        err!("Sends can't change type")
    }

    // When updating a file Send, we receive nulls in the File field, as it's immutable,
    // so we only need to update the data field in the Text case
    if data.Type == SendType::Text as i32 {
        let data_str = if let Some(mut d) = data.Text {
            d.as_object_mut().and_then(|d| d.remove("Response"));
            serde_json::to_string(&d)?
        } else {
            err!("Send data not provided");
        };
        send.data = data_str;
    }

    if data.DeletionDate > Utc::now() + Duration::days(31) {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }
    send.name = data.Name;
    send.akey = data.Key;
    send.deletion_date = data.DeletionDate.naive_utc();
    send.notes = data.Notes;
    send.max_access_count = match data.MaxAccessCount {
        Some(m) => Some(m.into_i32()?),
        _ => None,
    };
    send.expiration_date = data.ExpirationDate.map(|d| d.naive_utc());
    send.hide_email = data.HideEmail;
    send.disabled = data.Disabled;

    // Only change the value if it's present
    if let Some(password) = data.Password {
        send.set_password(Some(&password));
    }

    send.save(&conn).await?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn).await).await;

    Ok(Json(send.to_json()))
}

#[delete("/sends/<id>")]
async fn delete_send(id: String, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let send = match Send::find_by_uuid(&id, &conn).await {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    send.delete(&conn).await?;
    nt.send_send_update(UpdateType::SyncSendDelete, &send, &send.update_users_revision(&conn).await).await;

    Ok(())
}

#[put("/sends/<id>/remove-password")]
async fn put_remove_password(id: String, headers: Headers, conn: DbConn, nt: Notify<'_>) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn).await?;

    let mut send = match Send::find_by_uuid(&id, &conn).await {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    send.set_password(None);
    send.save(&conn).await?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn).await).await;

    Ok(Json(send.to_json()))
}
