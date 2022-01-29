use std::{io::Read, path::Path};

use chrono::{DateTime, Duration, Utc};
use multipart::server::{save::SavedData, Multipart, SaveResult};
use rocket::{http::ContentType, response::NamedFile, Data};
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult, JsonResult, JsonUpcase, Notify, NumberOrString, UpdateType},
    auth::{Headers, Host},
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

pub fn purge_sends(pool: DbPool) {
    debug!("Purging sends");
    if let Ok(conn) = pool.get() {
        Send::purge(&conn);
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
fn enforce_disable_send_policy(headers: &Headers, conn: &DbConn) -> EmptyResult {
    let user_uuid = &headers.user.uuid;
    let policy_type = OrgPolicyType::DisableSend;
    if !CONFIG.sends_allowed() || OrgPolicy::is_applicable_to_user(user_uuid, policy_type, conn) {
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
fn enforce_disable_hide_email_policy(data: &SendData, headers: &Headers, conn: &DbConn) -> EmptyResult {
    let user_uuid = &headers.user.uuid;
    let hide_email = data.HideEmail.unwrap_or(false);
    if hide_email && OrgPolicy::is_hide_email_disabled(user_uuid, conn) {
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
fn get_sends(headers: Headers, conn: DbConn) -> Json<Value> {
    let sends = Send::find_by_user(&headers.user.uuid, &conn);
    let sends_json: Vec<Value> = sends.iter().map(|s| s.to_json()).collect();

    Json(json!({
      "Data": sends_json,
      "Object": "list",
      "ContinuationToken": null
    }))
}

#[get("/sends/<uuid>")]
fn get_send(uuid: String, headers: Headers, conn: DbConn) -> JsonResult {
    let send = match Send::find_by_uuid(&uuid, &conn) {
        Some(send) => send,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    Ok(Json(send.to_json()))
}

#[post("/sends", data = "<data>")]
fn post_send(data: JsonUpcase<SendData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn)?;

    let data: SendData = data.into_inner().data;
    enforce_disable_hide_email_policy(&data, &headers, &conn)?;

    if data.Type == SendType::File as i32 {
        err!("File sends should use /api/sends/file")
    }

    let mut send = create_send(data, headers.user.uuid)?;
    send.save(&conn)?;
    nt.send_send_update(UpdateType::SyncSendCreate, &send, &send.update_users_revision(&conn));

    Ok(Json(send.to_json()))
}

#[post("/sends/file", format = "multipart/form-data", data = "<data>")]
fn post_send_file(data: Data, content_type: &ContentType, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn)?;

    let boundary = content_type.params().next().expect("No boundary provided").1;

    let mut mpart = Multipart::with_body(data.open(), boundary);

    // First entry is the SendData JSON
    let mut model_entry = match mpart.read_entry()? {
        Some(e) if &*e.headers.name == "model" => e,
        Some(_) => err!("Invalid entry name"),
        None => err!("No model entry present"),
    };

    let mut buf = String::new();
    model_entry.data.read_to_string(&mut buf)?;
    let data = serde_json::from_str::<crate::util::UpCase<SendData>>(&buf)?;
    enforce_disable_hide_email_policy(&data.data, &headers, &conn)?;

    // Get the file length and add an extra 5% to avoid issues
    const SIZE_525_MB: u64 = 550_502_400;

    let size_limit = match CONFIG.user_attachment_limit() {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let left = (limit_kb * 1024) - Attachment::size_by_user(&headers.user.uuid, &conn);
            if left <= 0 {
                err!("Attachment storage limit reached! Delete some attachments to free up space")
            }
            std::cmp::Ord::max(left as u64, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    // Create the Send
    let mut send = create_send(data.data, headers.user.uuid)?;
    let file_id = crate::crypto::generate_send_id();

    if send.atype != SendType::File as i32 {
        err!("Send content is not a file");
    }

    let file_path = Path::new(&CONFIG.sends_folder()).join(&send.uuid).join(&file_id);

    // Read the data entry and save the file
    let mut data_entry = match mpart.read_entry()? {
        Some(e) if &*e.headers.name == "data" => e,
        Some(_) => err!("Invalid entry name"),
        None => err!("No model entry present"),
    };

    let size = match data_entry.data.save().memory_threshold(0).size_limit(size_limit).with_path(&file_path) {
        SaveResult::Full(SavedData::File(_, size)) => size as i32,
        SaveResult::Full(other) => {
            std::fs::remove_file(&file_path).ok();
            err!(format!("Attachment is not a file: {:?}", other));
        }
        SaveResult::Partial(_, reason) => {
            std::fs::remove_file(&file_path).ok();
            err!(format!("Attachment storage limit exceeded with this file: {:?}", reason));
        }
        SaveResult::Error(e) => {
            std::fs::remove_file(&file_path).ok();
            err!(format!("Error: {:?}", e));
        }
    };

    // Set ID and sizes
    let mut data_value: Value = serde_json::from_str(&send.data)?;
    if let Some(o) = data_value.as_object_mut() {
        o.insert(String::from("Id"), Value::String(file_id));
        o.insert(String::from("Size"), Value::Number(size.into()));
        o.insert(String::from("SizeName"), Value::String(crate::util::get_display_size(size)));
    }
    send.data = serde_json::to_string(&data_value)?;

    // Save the changes in the database
    send.save(&conn)?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn));

    Ok(Json(send.to_json()))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendAccessData {
    pub Password: Option<String>,
}

#[post("/sends/access/<access_id>", data = "<data>")]
fn post_access(access_id: String, data: JsonUpcase<SendAccessData>, conn: DbConn) -> JsonResult {
    let mut send = match Send::find_by_access_id(&access_id, &conn) {
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
            Some(_) => err!("Invalid password."),
            None => err_code!("Password not provided", 401),
        }
    }

    // Files are incremented during the download
    if send.atype == SendType::Text as i32 {
        send.access_count += 1;
    }

    send.save(&conn)?;

    Ok(Json(send.to_json_access(&conn)))
}

#[post("/sends/<send_id>/access/file/<file_id>", data = "<data>")]
fn post_access_file(
    send_id: String,
    file_id: String,
    data: JsonUpcase<SendAccessData>,
    host: Host,
    conn: DbConn,
) -> JsonResult {
    let mut send = match Send::find_by_uuid(&send_id, &conn) {
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

    send.save(&conn)?;

    let token_claims = crate::auth::generate_send_claims(&send_id, &file_id);
    let token = crate::auth::encode_jwt(&token_claims);
    Ok(Json(json!({
        "Object": "send-fileDownload",
        "Id": file_id,
        "Url": format!("{}/api/sends/{}/{}?t={}", &host.host, send_id, file_id, token)
    })))
}

#[get("/sends/<send_id>/<file_id>?<t>")]
fn download_send(send_id: SafeString, file_id: SafeString, t: String) -> Option<NamedFile> {
    if let Ok(claims) = crate::auth::decode_send(&t) {
        if claims.sub == format!("{}/{}", send_id, file_id) {
            return NamedFile::open(Path::new(&CONFIG.sends_folder()).join(send_id).join(file_id)).ok();
        }
    }
    None
}

#[put("/sends/<id>", data = "<data>")]
fn put_send(id: String, data: JsonUpcase<SendData>, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn)?;

    let data: SendData = data.into_inner().data;
    enforce_disable_hide_email_policy(&data, &headers, &conn)?;

    let mut send = match Send::find_by_uuid(&id, &conn) {
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

    send.save(&conn)?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn));

    Ok(Json(send.to_json()))
}

#[delete("/sends/<id>")]
fn delete_send(id: String, headers: Headers, conn: DbConn, nt: Notify) -> EmptyResult {
    let send = match Send::find_by_uuid(&id, &conn) {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    send.delete(&conn)?;
    nt.send_send_update(UpdateType::SyncSendDelete, &send, &send.update_users_revision(&conn));

    Ok(())
}

#[put("/sends/<id>/remove-password")]
fn put_remove_password(id: String, headers: Headers, conn: DbConn, nt: Notify) -> JsonResult {
    enforce_disable_send_policy(&headers, &conn)?;

    let mut send = match Send::find_by_uuid(&id, &conn) {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.user_uuid.as_ref() != Some(&headers.user.uuid) {
        err!("Send is not owned by user")
    }

    send.set_password(None);
    send.save(&conn)?;
    nt.send_send_update(UpdateType::SyncSendUpdate, &send, &send.update_users_revision(&conn));

    Ok(Json(send.to_json()))
}
