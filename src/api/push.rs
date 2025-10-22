use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method,
};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::{
    api::{ApiResult, EmptyResult, UpdateType},
    db::{
        models::{AuthRequestId, Cipher, Device, DeviceId, Folder, PushId, Send, User, UserId},
        DbConn,
    },
    http_client::make_http_request,
    util::{format_date, get_uuid},
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

async fn get_auth_api_token() -> ApiResult<String> {
    static API_TOKEN: Lazy<RwLock<LocalAuthPushToken>> = Lazy::new(|| {
        RwLock::new(LocalAuthPushToken {
            access_token: String::new(),
            valid_until: Instant::now(),
        })
    });
    let api_token = API_TOKEN.read().await;

    if api_token.valid_until.saturating_duration_since(Instant::now()).as_secs() > 0 {
        debug!("Auth Push token still valid, no need for a new one");
        return Ok(api_token.access_token.clone());
    }
    drop(api_token); // Drop the read lock now

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

    let mut api_token = API_TOKEN.write().await;
    api_token.valid_until = Instant::now()
        .checked_add(Duration::new((json_pushtoken.expires_in / 2) as u64, 0)) // Token valid for half the specified time
        .unwrap();

    api_token.access_token = json_pushtoken.access_token;

    debug!("Token still valid for {}", api_token.valid_until.saturating_duration_since(Instant::now()).as_secs());
    Ok(api_token.access_token.clone())
}

pub async fn register_push_device(device: &mut Device, conn: &DbConn) -> EmptyResult {
    if !CONFIG.push_enabled() || !device.is_push_device() {
        return Ok(());
    }

    if device.push_token.is_none() {
        warn!("Skipping the registration of the device {:?} because the push_token field is empty.", device.uuid);
        warn!("To get rid of this message you need to logout, clear the app data and login again on the device.");
        return Ok(());
    }

    debug!("Registering Device {:?}", device.push_uuid);

    // Generate a random push_uuid so if it doesn't already have one
    if device.push_uuid.is_none() {
        device.push_uuid = Some(PushId(get_uuid()));
    }

    //Needed to register a device for push to bitwarden :
    let data = json!({
        "deviceId": device.push_uuid, // Unique UUID per user/device
        "pushToken": device.push_token,
        "userId": device.user_uuid,
        "type": device.atype,
        "identifier": device.uuid,    // Unique UUID of the device/app, determined by the device/app it self currently registering
        // "organizationIds:" [] // TODO: This is not yet implemented by Vaultwarden!
        "installationId": CONFIG.push_installation_id(),
    });

    let auth_api_token = get_auth_api_token().await?;
    let auth_header = format!("Bearer {auth_api_token}");

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

pub async fn unregister_push_device(push_id: &Option<PushId>) -> EmptyResult {
    if !CONFIG.push_enabled() || push_id.is_none() {
        return Ok(());
    }
    let auth_api_token = get_auth_api_token().await?;

    let auth_header = format!("Bearer {auth_api_token}");

    match make_http_request(
        Method::POST,
        &format!("{}/push/delete/{}", CONFIG.push_relay_uri(), push_id.as_ref().unwrap()),
    )?
    .header(AUTHORIZATION, auth_header)
    .send()
    .await
    {
        Ok(r) => r,
        Err(e) => err!(format!("An error occurred during device unregistration: {e}")),
    };
    Ok(())
}

pub async fn push_cipher_update(ut: UpdateType, cipher: &Cipher, device: &Device, conn: &DbConn) {
    // We shouldn't send a push notification on cipher update if the cipher belongs to an organization, this isn't implemented in the upstream server too.
    if cipher.organization_uuid.is_some() {
        return;
    };
    let Some(user_id) = &cipher.user_uuid else {
        debug!("Cipher has no uuid");
        return;
    };

    if Device::check_user_has_push_device(user_id, conn).await {
        send_to_push_relay(json!({
            "userId": user_id,
            "organizationId": null,
            "deviceId": device.push_uuid, // Should be the records unique uuid of the acting device (unique uuid per user/device)
            "identifier": device.uuid, // Should be the acting device id (aka uuid per device/app)
            "type": ut as i32,
            "payload": {
                "id": cipher.uuid,
                "userId": cipher.user_uuid,
                "organizationId": null,
                "collectionIds": null,
                "revisionDate": format_date(&cipher.updated_at)
            },
            "clientType": null,
            "installationId": null
        }))
        .await;
    }
}

pub async fn push_logout(user: &User, acting_device_id: Option<DeviceId>, conn: &DbConn) {
    let acting_device_id: Value = acting_device_id.map(|v| v.to_string().into()).unwrap_or_else(|| Value::Null);

    if Device::check_user_has_push_device(&user.uuid, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user.uuid,
            "organizationId": (),
            "deviceId": acting_device_id,
            "identifier": acting_device_id,
            "type": UpdateType::LogOut as i32,
            "payload": {
                "userId": user.uuid,
                "date": format_date(&user.updated_at)
            },
            "clientType": null,
            "installationId": null
        })));
    }
}

pub async fn push_user_update(ut: UpdateType, user: &User, push_uuid: &Option<PushId>, conn: &DbConn) {
    if Device::check_user_has_push_device(&user.uuid, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user.uuid,
            "organizationId": null,
            "deviceId": push_uuid,
            "identifier": null,
            "type": ut as i32,
            "payload": {
                "userId": user.uuid,
                "date": format_date(&user.updated_at)
            },
            "clientType": null,
            "installationId": null
        })));
    }
}

pub async fn push_folder_update(ut: UpdateType, folder: &Folder, device: &Device, conn: &DbConn) {
    if Device::check_user_has_push_device(&folder.user_uuid, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": folder.user_uuid,
            "organizationId": null,
            "deviceId": device.push_uuid, // Should be the records unique uuid of the acting device (unique uuid per user/device)
            "identifier": device.uuid, // Should be the acting device id (aka uuid per device/app)
            "type": ut as i32,
            "payload": {
                "id": folder.uuid,
                "userId": folder.user_uuid,
                "revisionDate": format_date(&folder.updated_at)
            },
            "clientType": null,
            "installationId": null
        })));
    }
}

pub async fn push_send_update(ut: UpdateType, send: &Send, device: &Device, conn: &DbConn) {
    if let Some(s) = &send.user_uuid {
        if Device::check_user_has_push_device(s, conn).await {
            tokio::task::spawn(send_to_push_relay(json!({
                "userId": send.user_uuid,
                "organizationId": null,
                "deviceId": device.push_uuid, // Should be the records unique uuid of the acting device (unique uuid per user/device)
                "identifier": device.uuid, // Should be the acting device id (aka uuid per device/app)
                "type": ut as i32,
                "payload": {
                    "id": send.uuid,
                    "userId": send.user_uuid,
                    "revisionDate": format_date(&send.revision_date)
                },
                "clientType": null,
                "installationId": null
            })));
        }
    }
}

async fn send_to_push_relay(notification_data: Value) {
    if !CONFIG.push_enabled() {
        return;
    }

    let auth_api_token = match get_auth_api_token().await {
        Ok(s) => s,
        Err(e) => {
            debug!("Could not get the auth push token: {e}");
            return;
        }
    };

    let auth_header = format!("Bearer {auth_api_token}");

    let req = match make_http_request(Method::POST, &(CONFIG.push_relay_uri() + "/push/send")) {
        Ok(r) => r,
        Err(e) => {
            error!("An error occurred while sending a send update to the push relay: {e}");
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
        error!("An error occurred while sending a send update to the push relay: {e}");
    };
}

pub async fn push_auth_request(user_id: &UserId, auth_request_id: &str, device: &Device, conn: &DbConn) {
    if Device::check_user_has_push_device(user_id, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user_id,
            "organizationId": null,
            "deviceId": device.push_uuid, // Should be the records unique uuid of the acting device (unique uuid per user/device)
            "identifier": device.uuid, // Should be the acting device id (aka uuid per device/app)
            "type": UpdateType::AuthRequest as i32,
            "payload": {
                "userId": user_id,
                "id": auth_request_id,
            },
            "clientType": null,
            "installationId": null
        })));
    }
}

pub async fn push_auth_response(user_id: &UserId, auth_request_id: &AuthRequestId, device: &Device, conn: &DbConn) {
    if Device::check_user_has_push_device(user_id, conn).await {
        tokio::task::spawn(send_to_push_relay(json!({
            "userId": user_id,
            "organizationId": null,
            "deviceId": device.push_uuid, // Should be the records unique uuid of the acting device (unique uuid per user/device)
            "identifier": device.uuid, // Should be the acting device id (aka uuid per device/app)
            "type": UpdateType::AuthRequestResponse as i32,
            "payload": {
                "userId": user_id,
                "id": auth_request_id,
            },
            "clientType": null,
            "installationId": null
        })));
    }
}
