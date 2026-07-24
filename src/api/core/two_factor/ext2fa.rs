use std::net::IpAddr;

use reqwest::Method;

use crate::{CONFIG, http_client::make_http_request};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecondFactorData {
    pub id: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetaData {
    pub username: String,
    pub device_name: String,
    pub ip_addr: IpAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthRequest {
    pub id: String,
    pub meta_data: MetaData,
    pub second_factor_data: SecondFactorData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthValidate {
    pub id: String,
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthResponse {
    pub ok: bool,
    pub description: Option<String>,
}

fn build_url(path: &str) -> String {
    let base = CONFIG.ext2fa_url();
    if base.ends_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

/// Create a new 2FA request at the configured external 2FA service.
pub async fn ext2fa_request(req: &AuthRequest) -> Result<AuthResponse, crate::Error> {
    let url = build_url("request");

    let resp = make_http_request(Method::POST, &url)?
        .json(req)
        .send()
        .await?
        .error_for_status()?
        .json::<AuthResponse>()
        .await?;

    Ok(resp)
}

/// Validate a 2FA code against the configured external 2FA service.
pub async fn ext2fa_validate(req: &AuthValidate) -> Result<AuthResponse, crate::Error> {
    let url = build_url("validate");

    let resp = make_http_request(Method::POST, &url)?
        .json(req)
        .send()
        .await?
        .error_for_status()?
        .json::<AuthResponse>()
        .await?;

    Ok(resp)
}
