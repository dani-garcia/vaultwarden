//
// Management endpoints for the per-organization SCIM api key. These live
// under /api (not /scim) and require an interactive admin session plus
// password or OTP re-authentication, mirroring the existing organization
// api-key rotation endpoints.
//
// The plaintext token is returned exactly once, from the generate/rotate
// call. Only its sha256 digest is stored.
//
use rocket::{Route, serde::json::Json};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult, PasswordOrOtpData, core::log_event},
    auth::AdminHeaders,
    crypto,
    db::{
        DbConn,
        models::{EventType, OrganizationId, ScimApiKey},
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![generate_scim_key, delete_scim_key, scim_status]
}

fn check_scim_enabled() -> EmptyResult {
    if !CONFIG.scim_enabled() {
        err!("SCIM support is disabled")
    }
    Ok(())
}

// Records a SCIM token management action in the org event log under the acting
// admin's own identity (this is an interactive, re-authenticated admin action,
// not a SCIM-driven one, so it does not use the synthetic SCIM actor). The org
// itself is the event source; OrganizationUpdated is the closest existing type,
// matching how the admin panel logs org-level configuration changes.
async fn log_scim_key_event(headers: &AdminHeaders, org_id: &OrganizationId, conn: &DbConn) {
    log_event(
        EventType::OrganizationUpdated as i32,
        org_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
}

// The single place a SCIM token is minted. Generates the secret, replaces any
// existing key row (rotation: the previous token stops working immediately),
// and returns the full bearer token plus the stored row. The integration
// tests call this too, so the minted format and the guard's verification
// cannot drift apart.
pub(crate) async fn mint_scim_token(
    org_id: &OrganizationId,
    conn: &DbConn,
) -> Result<(String, ScimApiKey), crate::Error> {
    // 256-bit secret; the stored digest can only be brute-forced, not inverted.
    let secret = crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD);
    let key_hash = crypto::sha256_hex(secret.as_bytes());

    ScimApiKey::delete_all_by_organization(org_id, conn).await?;
    let scim_key = ScimApiKey::new(org_id.clone(), key_hash);
    scim_key.save(conn).await?;

    Ok((format!("scim_v1.{org_id}.{secret}"), scim_key))
}

#[post("/organizations/<org_id>/scim/api-key", data = "<data>")]
async fn generate_scim_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    check_scim_enabled()?;
    data.into_inner().validate(&headers.user, true, &conn).await?;

    let (token, scim_key) = mint_scim_token(&org_id, &conn).await?;
    log_scim_key_event(&headers, &org_id, &conn).await;

    Ok(Json(json!({
        "object": "scim-api-key",
        "token": token,
        "scimBaseUrl": format!("{}/scim/v2/{org_id}", CONFIG.domain()),
        "revisionDate": format_date(&scim_key.revision_date),
    })))
}

#[delete("/organizations/<org_id>/scim/api-key", data = "<data>")]
async fn delete_scim_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    data.into_inner().validate(&headers.user, true, &conn).await?;

    ScimApiKey::delete_all_by_organization(&org_id, &conn).await?;
    log_scim_key_event(&headers, &org_id, &conn).await;
    Ok(())
}

#[get("/organizations/<org_id>/scim/status")]
async fn scim_status(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let scim_key = ScimApiKey::find_by_org(&org_id, &conn).await;
    Ok(Json(json!({
        "object": "scim-status",
        "scimEnabled": CONFIG.scim_enabled(),
        "keyConfigured": scim_key.is_some(),
        "keyEnabled": scim_key.as_ref().is_some_and(|k| k.enabled),
        "createdAt": scim_key.as_ref().map(|k| format_date(&k.created_at)),
        "revisionDate": scim_key.as_ref().map(|k| format_date(&k.revision_date)),
    })))
}
