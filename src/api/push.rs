use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method,
};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::{
    api::{ApiResult, EmptyResult, UpdateType},
    db::models::{Cipher, Device, Folder, Send, User},
    http_client::make_http_request,
    util::format_date,
    CONFIG,
};

use once_cell::sync::Lazy;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct AuthPushToken {
    access_token: String,
    expires_in: i32,
}

#[derive(Debug)]
struct LocalAuthPushToken {
    access_token: String,
    valid_until: Instant,
}

async fn get_auth_push_token() -> ApiResult<String> {
    static PUSH_TOKEN: Lazy<RwLock<LocalAuthPushToken>> = Lazy::new(|| {
        RwLock::new(LocalAuthPushToken {
            access_token: String::new(),
            valid_until: Instant::now(),
        })
    });
    let push_token = PUSH_TOKEN.read().await;

    if push_token.valid_until.saturating_duration_since(Instant::now()).as_secs() > 0 {
        debug!("Auth Push token still valid, no need for a new one");
        return Ok(push_token.access_token.clone());
    }
    drop(push_token); // Drop the read lock now

    let installation_id = CONFIG.push_installation_id();
    let client_id = format!("installation.{installation_id}");
    let client_secret = CONFIG.push_installation_key();

    let params = [
        ("grant_type", "client_credentials"),
        ("scope", "api.push"),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
    ];

    let res = match make_http_request(Method::POST, &format!("{}/connect/token", CONFIG.push_identity_uri()))?
        .form(&params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => err!(format!("Error getting push token from bitwarden server: {e}")),
    };

    let json_pushtoken = match res.json::<AuthPushToken>().await {
        Ok(r) => r,
        Err(e) => err!(format!("Unexpected push token received from bitwarden server: {e}")),
    };

    let mut push_token = PUSH_TOKEN.write().await;
    push_token.valid_until = Instant::now()
        .checked_add(Duration::new((json_pushtoken.expires_in / 2) as u64, 0)) // Token valid for half the specified time
        .unwrap();

    push_token.access_token = json_pushtoken.access_token;

    debug!("Token still valid for {}", push_token.valid_until.saturating_duration_since(Instant::now()).as_secs());
    Ok(push_token.access_token.clone())
}

pub async fn register_push_device(device: &mut Device, conn: &mut crate::db::DbConn) -> EmptyResult {
    if !CONFIG.push_enabled() || !device.is_push_device() || device.is_registered() {
        return Ok(());
    }

    if device.push_token.is_none() {
        warn!("Skipping the registration of the device {} because the push_token field is empty.", device.uuid);
        warn!("To get rid of this message you need to clear the app data and reconnect the device.");
        return Ok(());
    }

    debug!("Registering Device {}", device.uuid);

    // generate a random push_uuid so we know the device is registered
    device.push_uuid = Some(uuid::Uuid::new_v4().to_string());

    //Needed to register a device for push to bitwarden :
    let data = json!({
        "userId": device.user_uuid,
        "deviceId": device.push_uuid,
        "identifier": device.uuid,
        "type": device.atype,
        "pushToken": device.push_token
    });

    let auth_push_token = get_auth_push_token().await?;
    let auth_header = format!("Bearer {}", &auth_push_token);

    if let Err(e) = make_http_request(Method::POST, &(CONFIG.push_relay_uri() + "/push/register"))?
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, auth_header)
        .json(&data)
        .send()
        .await?
        .error_for_status()
    {
        err!(format!("An error occurred while proceeding registration of a device: {e}"));
    }

    if let Err(e) = device.save(conn).await {
        err!(format!("An error occurred while trying to save the (registered) device push uuid: {e}"));
    }

    Ok(())
}

pub async fn unregister_push_device(push_uuid: Option<String>) -> EmptyResult {
    if !CONFIG.push_enabled() || push_uuid.is_none() {
        return Ok(());
    }
    let auth_push_token = get_auth_push_token().await?;

    let auth_header = format!("Bearer {}", &auth_push_token);

    match make_http_request(Method::DELETE, &(CONFIG.push_relay_uri() + "/push/" + &push_uuid.unwrap()))?
        .header(AUTHORIZATION, auth_header)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => err!(format!("An error occurred during device unregistration: {e}")),
    };
    Ok(())
}

pub async fn push_cipher_update(
    ut: UpdateType,
    cipher: &Cipher,
    acting_device_uuid: &String,
    conn: &mut crate::db::DbConn,
) {
    // We shouldn't send a push notification on cipher update if the cipher belongs to an organization, this isn't implemented in the upstream server too.
    if cipher.organization_uuid.is_some() {
        return;
    };
    let user_uuid = match &cipher.user_uuid {
        Some(c) => c,
        None => {
            debug!("Cipher has no uuid");
            return;
        }
    };

    if Device::check_user_has_push_device(user_uuid, conn).await {
        send_to_push_relay(json!({
            "userId": user_uuid,
            "organizationId": (),
            "deviceId": acting_device_uuid,
            "identifier": acting_device_uuid,
            "type": ut as i32,
            "payload": {
                "Id": cipher.uuid,
                "UserId": cipher.user_uuid,
                "OrganizationId": (),
                "RevisionDate": format_date(&cipher.updated_at)
            }
        }))
        .await;
    }
}

pub fn push_logout(user: &User, acting_device_uuid: Option<String>) {
    let acting_device_uuid: Value = acting_device_uuid.map(|v| v.into()).unwrap_or_else(|| Value::Null);

    tokio::task::spawn(send_to_push_relay(json!({
        "userId": user.uuid,
        "organizationId": (),
        "deviceId": acting_device_uuid,
        "identifier": acting_device_uuid,
        "type": UpdateType::LogOut as i32,
        "payload": {
            "UserId": user.uuid,
            "Date": format_date(&user.updated_at)
        }
    })));
}

pub fn push_user_update(ut: UpdateType, user: &User) {
    tokio::task::spawn(send_to_push_relay(json!({
        "userId": user.uuid,
        "organizationId": (),
        "deviceId": (),
        "identifier": (),
        "type": ut as i32,
        "payload": {
            "UserId": user.uuid,
            "Date": format_date(&user.updated_at)
        }
    })));
}

pub async fn push_folder_update(
    ut: UpdateType,
    folder: &Folder,
    acting_device_uuid: &String,
    conn: &mut crate::db::DbConn,
) {
    if Device::check_user_has_push_device(&folder.user_uuid, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": folder.user_uuid,
            "organizationId": (),
            "deviceId": acting_device_uuid,
            "identifier": acting_device_uuid,
            "type": ut as i32,
            "payload": {
                "Id": folder.uuid,
                "UserId": folder.user_uuid,
                "RevisionDate": format_date(&folder.updated_at)
            }
        })));
    }
}

pub async fn push_send_update(ut: UpdateType, send: &Send, acting_device_uuid: &String, conn: &mut crate::db::DbConn) {
    if let Some(s) = &send.user_uuid {
        if Device::check_user_has_push_device(s, conn).await {
            tokio::task::spawn(send_to_push_relay(json!({
                "userId": send.user_uuid,
                "organizationId": (),
                "deviceId": acting_device_uuid,
                "identifier": acting_device_uuid,
                "type": ut as i32,
                "payload": {
                    "Id": send.uuid,
                    "UserId": send.user_uuid,
                    "RevisionDate": format_date(&send.revision_date)
                }
            })));
        }
    }
}

async fn send_to_push_relay(notification_data: Value) {
    if !CONFIG.push_enabled() {
        return;
    }

    let auth_push_token = match get_auth_push_token().await {
        Ok(s) => s,
        Err(e) => {
            debug!("Could not get the auth push token: {}", e);
            return;
        }
    };

    let auth_header = format!("Bearer {}", &auth_push_token);

    let req = match make_http_request(Method::POST, &(CONFIG.push_relay_uri() + "/push/send")) {
        Ok(r) => r,
        Err(e) => {
            error!("An error occurred while sending a send update to the push relay: {}", e);
            return;
        }
    };

    if let Err(e) = req
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, &auth_header)
        .json(&notification_data)
        .send()
        .await
    {
        error!("An error occurred while sending a send update to the push relay: {}", e);
    };
}

pub async fn push_auth_request(user_uuid: String, auth_request_uuid: String, conn: &mut crate::db::DbConn) {
    if Device::check_user_has_push_device(user_uuid.as_str(), conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user_uuid,
            "organizationId": (),
            "deviceId": null,
            "identifier": null,
            "type": UpdateType::AuthRequest as i32,
            "payload": {
                "Id": auth_request_uuid,
                "UserId": user_uuid,
            }
        })));
    }
}

pub async fn push_auth_response(
    user_uuid: String,
    auth_request_uuid: String,
    approving_device_uuid: String,
    conn: &mut crate::db::DbConn,
) {
    if Device::check_user_has_push_device(user_uuid.as_str(), conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user_uuid,
            "organizationId": (),
            "deviceId": approving_device_uuid,
            "identifier": approving_device_uuid,
            "type": UpdateType::AuthRequestResponse as i32,
            "payload": {
                "Id": auth_request_uuid,
                "UserId": user_uuid,
            }
        })));
    }
}
