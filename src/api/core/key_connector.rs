use rocket::Route;
use rocket::serde::json::Json;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::DbConn,
};

pub fn routes() -> Vec<Route> {
    routes![post_set_key_connector_key, post_convert_to_key_connector, get_confirmation_details,]
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPairData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetKeyConnectorKeyData {
    key: String,
    keys: KeyPairData,
    kdf: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    #[allow(dead_code)]
    org_identifier: String,
}

// Called by the client to finish provisioning a new SSO user whose master key
// was just stored on the key connector.
#[post("/accounts/set-key-connector-key", data = "<data>")]
async fn post_set_key_connector_key(data: Json<SetKeyConnectorKeyData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.key_connector_enabled() {
        err!("Key Connector is not enabled on this server");
    }

    let data = data.into_inner();
    let mut user = headers.user;

    user.client_kdf_type = data.kdf;
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;

    user.akey = data.key;
    user.private_key = Some(data.keys.encrypted_private_key);
    user.public_key = Some(data.keys.public_key);

    // Key connector users don't have a master password
    user.password_hash = Vec::new();
    user.uses_key_connector = true;

    user.save(&conn).await
}

// Migrates an existing password user to the key connector. The client has already
// uploaded the current master key to the connector at this point.
#[post("/accounts/convert-to-key-connector")]
async fn post_convert_to_key_connector(headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.key_connector_enabled() {
        err!("Key Connector is not enabled on this server");
    }

    let mut user = headers.user;
    user.password_hash = Vec::new();
    user.password_hint = None;
    user.uses_key_connector = true;

    user.save(&conn).await
}

#[get("/accounts/key-connector/confirmation-details/<_org_identifier>")]
fn get_confirmation_details(_org_identifier: &str, _headers: Headers) -> JsonResult {
    if !CONFIG.key_connector_enabled() {
        err!("Key Connector is not enabled on this server");
    }

    // SSO (and therefore the key connector) is global, so there is no real org to look up
    Ok(Json(serde_json::json!({
        "OrganizationName": CONFIG.key_connector_org_name(),
        "Object": "keyConnectorUserDecryptionOptionConfirmationDetails"
    })))
}

pub fn key_connector_user_decryption_option() -> Value {
    serde_json::json!({ "KeyConnectorUrl": CONFIG.key_connector_url() })
}
