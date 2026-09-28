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
    auth::{ClientVersion, Headers, Host, SendHeaders},
    config::PathType,
    db::{
        DbConn, DbPool,
        models::{
            Device, DeviceType, OrgPolicy, OrgPolicyType, Send, SendAuthType, SendFileId, SendId, SendType, UserId,
            normalize_emails,
        },
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
    auth_type: Option<i32>,
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
    // Item Sends: `{ encryptionVersion, data }`, the whole shared item encrypted client side
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

/// Max length of the encrypted blob of an Item Send, the same limit as the Bitwarden server
const ITEM_DATA_MAX_LEN: usize = 500_000;
/// Max recipients of an email verified Send
const SEND_EMAILS_MAX: usize = 50;

/// Whether temporary item sharing (`pm-34203-temporary-item-sharing`) is enabled on this server
pub fn item_sharing_enabled() -> bool {
    crate::util::parse_experimental_client_feature_flags(
        &CONFIG.experimental_client_feature_flags(),
        &crate::util::FeatureFlagFilter::ValidOnly,
    )
    .contains_key("pm-34203-temporary-item-sharing")
}

/// Whether this client version is recent enough for Item Sends and the SDK Sends API.
/// A client that does not tell its version is treated as too old.
pub fn client_version_supports_item_sharing(client_version: Option<&ClientVersion>) -> bool {
    let Ok(min) = semver::Version::parse(&CONFIG.item_sharing_min_client_version()) else {
        return false;
    };
    client_version.is_some_and(|v| v.0 >= min)
}

/// Whether Item Sends can be listed to this client. An unknown Send type fails the whole sync of the
/// Android app (its Send type enum has no fallback), and the mobile apps follow their own release
/// train, so they never get Item Sends whatever version they report.
pub fn client_supports_item_sends(device_type: i32, client_version: Option<&ClientVersion>) -> bool {
    const MOBILE: [i32; 3] = [DeviceType::Android as i32, DeviceType::Ios as i32, DeviceType::AndroidAmazon as i32];
    item_sharing_enabled() && client_version_supports_item_sharing(client_version) && !MOBILE.contains(&device_type)
}

/// Validates the encrypted blob of an Item Send and keeps only the fields the server stores.
fn item_data_str(data: Option<&Value>) -> ApiResult<String> {
    let Some(d) = data else {
        err!("Send data not provided")
    };
    let blob = d.get("data").or_else(|| d.get("Data")).and_then(Value::as_str).unwrap_or_default();
    if blob.is_empty() {
        err!("Item Sends need the encrypted item data")
    }
    if blob.len() > ITEM_DATA_MAX_LEN {
        err!("The shared item is too large")
    }
    let version =
        d.get("encryptionVersion").or_else(|| d.get("EncryptionVersion")).and_then(Value::as_i64).unwrap_or(1);
    Ok(serde_json::to_string(&json!({ "encryptionVersion": version, "data": blob }))?)
}

fn set_send_emails(send: &mut Send, emails: &[String], current: Option<&[String]>) -> EmptyResult {
    // Keeping the current recipients doesn't need mail: a key rotation re-saves every Send after other
    // writes, and must not fail halfway because email was switched off after the Send was created
    let unchanged = current.is_some_and(|c| {
        let (mut a, mut b) = (c.to_vec(), emails.to_vec());
        a.sort_unstable();
        b.sort_unstable();
        a == b
    });
    if !unchanged && !CONFIG.mail_enabled() {
        err!("Email verified Sends need email to be configured on this server")
    }
    if emails.len() > SEND_EMAILS_MAX {
        err!(format!("A Send can be verified by at most {SEND_EMAILS_MAX} emails"))
    }
    if emails.iter().any(|e| e.len() > 254 || !e.contains('@')) {
        err!("Invalid email address")
    }
    send.set_auth_emails(Some(&emails.join(",")))
}

/// Applies the requested access control, following the Bitwarden server: `authType` decides, and a
/// request carrying the type without its secret keeps the current one (the SDK edits that way when
/// the auth is not being changed). An existing email gate is never dropped implicitly: only an
/// explicit `authType` does it, unlike the Bitwarden server, which clears it for older clients.
fn apply_send_auth(
    send: &mut Send,
    auth_type: Option<i32>,
    password: Option<&str>,
    emails: Option<&str>,
    current_emails: Option<&[String]>,
) -> EmptyResult {
    let requested_emails = emails.map(normalize_emails).filter(|e| !e.is_empty());
    match auth_type.map(SendAuthType::from_i32) {
        Some(None) => err!("Invalid Send auth type"),
        Some(Some(SendAuthType::Email)) => {
            let Some(list) = requested_emails.or_else(|| current_emails.map(<[String]>::to_vec)) else {
                err!("Email verified Sends need at least one email")
            };
            set_send_emails(send, &list, current_emails)?;
        }
        Some(Some(SendAuthType::Password)) => {
            if password.is_none() && send.password_hash.is_none() {
                err!("Password protected Sends need a password")
            }
            send.set_auth_emails(None)?;
            if let Some(p) = password {
                send.set_password(Some(p));
            }
        }
        Some(Some(SendAuthType::None)) => {
            send.set_auth_emails(None)?;
            send.set_password(None);
        }
        // Clients from before the SDK Sends API don't send `authType`
        None => {
            if let Some(list) = requested_emails {
                set_send_emails(send, &list, current_emails)?;
            } else if let Some(p) = password {
                send.set_auth_emails(None)?;
                send.set_password(Some(p));
            } else if let Some(list) = current_emails {
                set_send_emails(send, list, Some(list))?;
            }
        }
    }

    if send.atype == SendType::Item as i32 && send.auth_emails().is_none() {
        err!("Item Sends require email verification")
    }
    Ok(())
}

fn create_send(data: SendData, user_id: UserId) -> ApiResult<Send> {
    let data_str = match SendType::from_i32(data.r#type) {
        Some(send_type @ (SendType::Text | SendType::File)) => {
            let data_val = if send_type == SendType::Text {
                data.text
            } else {
                data.file
            };
            let Some(mut d) = data_val else {
                err!("Send data not provided");
            };
            d.as_object_mut().and_then(|o| o.remove("response"));
            serde_json::to_string(&d)?
        }
        Some(SendType::Item) => {
            if !item_sharing_enabled() {
                err!("Item Sends are not enabled on this server")
            }
            item_data_str(data.data.as_ref())?
        }
        None => err!("Invalid Send type"),
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

    // A client could put the server side email list inside its own data: start from none
    send.set_auth_emails(None)?;
    apply_send_auth(&mut send, data.auth_type, data.password.as_deref(), data.emails.as_deref(), None)?;

    Ok(send)
}

#[get("/sends")]
async fn get_sends(headers: Headers, client_version: Option<ClientVersion>, conn: DbConn) -> Json<Value> {
    let show_items = client_supports_item_sends(headers.device.atype, client_version.as_ref());
    let sends = Send::find_by_user(&headers.user.uuid, &conn).await;
    let sends_json: Vec<Value> =
        sends.iter().filter(|s| show_items || s.atype != SendType::Item as i32).map(Send::to_json).collect();

    Json(json!({
      "data": sends_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/sends/<send_id>")]
async fn get_send(
    send_id: SendId,
    headers: Headers,
    client_version: Option<ClientVersion>,
    conn: DbConn,
) -> JsonResult {
    match Send::find_by_uuid_and_user(&send_id, &headers.user.uuid, &conn).await {
        Some(send)
            if send.atype != SendType::Item as i32
                || client_supports_item_sends(headers.device.atype, client_version.as_ref()) =>
        {
            Ok(Json(send.to_json()))
        }
        _ => err!("Send not found", "Invalid send uuid or does not belong to user"),
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
    if !send.is_accessible() || (send.atype == SendType::Item as i32 && !item_sharing_enabled()) {
        err_code!(SEND_INACCESSIBLE_MSG, 404)
    }
    // Files are incremented during the download, text and item Sends here
    if send.atype != SendType::File as i32 && !send.register_access(&conn).await? {
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

    // The email list lives inside `data`, which a Text or Item update replaces
    let current_emails = send.auth_emails();

    // When updating a file Send, we receive nulls in the File field, as it's immutable,
    // so we only need to update the data field in the Text and Item cases
    if data.r#type == SendType::Text as i32 {
        let data_str = if let Some(mut d) = data.text {
            d.as_object_mut().and_then(|d| d.remove("response"));
            serde_json::to_string(&d)?
        } else {
            err!("Send data not provided");
        };
        send.data = data_str;
    } else if data.r#type == SendType::Item as i32 {
        if !item_sharing_enabled() {
            err!("Item Sends are not enabled on this server")
        }
        if data.data.is_some() {
            send.data = item_data_str(data.data.as_ref())?;
        }
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

    apply_send_auth(send, data.auth_type, data.password.as_deref(), data.emails.as_deref(), current_emails.as_deref())?;

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

    fn new_send(atype: SendType) -> Send {
        let deletion = (Utc::now() + TimeDelta::try_days(1).unwrap()).naive_utc();
        Send::new(atype as i32, "2.name".into(), r#"{"text":"2.t"}"#.into(), "2.key".into(), deletion)
    }

    #[test]
    fn item_data_is_validated_and_trimmed_to_known_fields() {
        let stored =
            item_data_str(Some(&json!({"encryptionVersion": 1, "data": "blob", "vwAuthEmails": "x@y.z"}))).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), json!({"encryptionVersion": 1, "data": "blob"}));

        assert!(item_data_str(None).is_err());
        assert!(item_data_str(Some(&json!({"encryptionVersion": 1, "data": ""}))).is_err());
        let too_big = "a".repeat(ITEM_DATA_MAX_LEN + 1);
        assert!(item_data_str(Some(&json!({"data": too_big}))).is_err());
    }

    #[test]
    fn password_auth_needs_a_password_unless_one_exists() {
        let mut send = new_send(SendType::Text);
        assert!(apply_send_auth(&mut send, Some(SendAuthType::Password as i32), None, None, None).is_err());

        apply_send_auth(&mut send, Some(SendAuthType::Password as i32), Some("hash"), None, None).unwrap();
        let hash = send.password_hash.clone();
        assert!(hash.is_some());

        // The SDK edits with the type and no secret to keep the current password
        apply_send_auth(&mut send, Some(SendAuthType::Password as i32), None, None, None).unwrap();
        assert_eq!(send.password_hash, hash);
    }

    #[test]
    fn explicit_none_removes_the_password() {
        let mut send = new_send(SendType::Text);
        send.set_password(Some("hash"));
        apply_send_auth(&mut send, Some(SendAuthType::None as i32), None, None, None).unwrap();
        assert!(send.password_hash.is_none());
    }

    #[test]
    fn older_clients_keep_the_password_when_they_send_none() {
        let mut send = new_send(SendType::Text);
        send.set_password(Some("hash"));
        apply_send_auth(&mut send, None, None, None, None).unwrap();
        assert!(send.password_hash.is_some());
    }

    #[test]
    fn unknown_auth_type_is_refused() {
        let mut send = new_send(SendType::Text);
        assert!(apply_send_auth(&mut send, Some(9), None, None, None).is_err());
    }

    #[test]
    fn item_sends_can_not_drop_email_verification() {
        let mut send = new_send(SendType::Item);
        assert!(apply_send_auth(&mut send, Some(SendAuthType::None as i32), None, None, None).is_err());
        assert!(apply_send_auth(&mut send, Some(SendAuthType::Password as i32), Some("hash"), None, None).is_err());
        assert!(apply_send_auth(&mut send, None, None, None, None).is_err());
    }

    #[test]
    fn email_verified_sends_need_mail() {
        // The test config has no SMTP: an email verified Send would be impossible to open
        let mut send = new_send(SendType::Text);
        assert!(!CONFIG.mail_enabled());
        assert!(apply_send_auth(&mut send, Some(SendAuthType::Email as i32), None, Some("a@x.com"), None).is_err());
    }

    #[test]
    fn keeping_the_recipients_needs_no_mail() {
        // A key rotation re-saves every Send: switching email off later must not make it fail halfway
        assert!(!CONFIG.mail_enabled());
        let current = || Some(vec!["a@x.com".to_owned(), "b@x.com".to_owned()]);
        let email = Some(SendAuthType::Email as i32);
        let mut send = new_send(SendType::Text);
        assert!(apply_send_auth(&mut send, email, None, Some("b@x.com, A@x.com"), current().as_deref()).is_ok());
        assert!(apply_send_auth(&mut send, email, None, None, current().as_deref()).is_ok());
        assert!(apply_send_auth(&mut send, None, None, None, current().as_deref()).is_ok());
        assert_eq!(send.auth_emails(), current());
        // Changing the recipients still needs mail
        assert!(apply_send_auth(&mut send, email, None, Some("a@x.com"), current().as_deref()).is_err());
        assert!(apply_send_auth(&mut send, None, None, Some("c@x.com"), current().as_deref()).is_err());
    }

    #[test]
    fn min_client_version_gate() {
        let v = |s: &str| ClientVersion(semver::Version::parse(s).unwrap());
        assert!(!client_version_supports_item_sharing(None));
        assert!(!client_version_supports_item_sharing(Some(&v("2026.9.3"))));
        assert!(client_version_supports_item_sharing(Some(&v("2026.10.0"))));
        assert!(client_version_supports_item_sharing(Some(&v("2027.1.0"))));
    }
}
