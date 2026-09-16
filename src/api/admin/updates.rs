//! Admin-authenticated bridge to the host updater. Docker access stays outside Vaultwarden.
use reqwest::Method;
use rocket::serde::json::Json;
use serde_json::Value;

use super::AdminToken;
use crate::{CONFIG, api::JsonResult};

#[get("/updates/status")]
pub(super) async fn update_status(_token: AdminToken) -> JsonResult {
    updater_request(Method::GET, "/status", None).await
}

#[post("/updates/start", format = "json")]
pub(super) async fn start_update(_token: AdminToken) -> JsonResult {
    updater_request(Method::POST, "/update", Some(json!({}))).await
}

async fn updater_request(method: Method, path: &str, body: Option<Value>) -> JsonResult {
    if CONFIG.disable_admin_token() {
        err_code!("Docker updates require admin authentication.", 403);
    }
    let Some(socket) = CONFIG.updater_socket() else {
        err_code!("The host updater has not been configured.", 503);
    };
    send_request(socket, method, path, body).await
}

#[cfg(unix)]
async fn send_request(socket: String, method: Method, path: &str, body: Option<Value>) -> JsonResult {
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut request = client.request(method, format!("http://localhost{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let Ok(response) = request.send().await else {
        err_code!("Cannot reach the host updater. Check its service and socket permissions.", 503);
    };
    let status = response.status();
    let data: Value = response.json().await?;
    if !status.is_success() {
        let message = data.get("error").and_then(Value::as_str).unwrap_or("The host updater rejected the request.");
        err_code!(message, status.as_u16());
    }
    Ok(Json(data))
}

#[cfg(not(unix))]
async fn send_request(_socket: String, _method: Method, _path: &str, _body: Option<Value>) -> JsonResult {
    err_code!("The host updater requires a Unix socket.", 503);
}
