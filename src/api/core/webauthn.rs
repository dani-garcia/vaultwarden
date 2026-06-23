use rocket::{http::Status, serde::json::Json};
use serde_json::Value;
use webauthn_rs::prelude::{Passkey, PasskeyRegistration};
use webauthn_rs_proto::UserVerificationPolicy;

use crate::{
    api::{
        ApiResult, JsonResult, PasswordOrOtpData,
        core::two_factor::webauthn::{RegisterPublicKeyCredentialCopy, WEBAUTHN},
    },
    auth::Headers,
    db::{
        DbConn,
        models::{TwoFactor, TwoFactorType, WebauthnCredential, WebauthnCredentialId},
    },
};

pub fn routes() -> Vec<rocket::Route> {
    routes![get_webauthn, post_webauthn, post_webauthn_attestation_options, post_webauthn_delete]
}

#[get("/webauthn")]
async fn get_webauthn(headers: Headers, conn: DbConn) -> Json<Value> {
    let user = headers.user;

    let data: Vec<WebauthnCredential> = WebauthnCredential::find_all_by_user(&user.uuid, &conn).await;
    let data = data
        .into_iter()
        .map(|wac| {
            json!({
                "id": wac.uuid,
                "name": wac.name,
                "prfStatus": wac.get_prf_status() as u8,
                "encryptedUserKey": wac.encrypted_user_key,
                "encryptedPublicKey": wac.encrypted_public_key,
                "object": "webauthnCredential",
            })
        })
        .collect::<Value>();

    Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    }))
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    let all_creds: Vec<WebauthnCredential> = WebauthnCredential::find_all_by_user(&user.uuid, &conn).await;
    let existing_cred_ids: Vec<_> = all_creds
        .into_iter()
        .filter_map(|wac| {
            let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;
            Some(passkey.cred_id().to_owned())
        })
        .collect();

    let user_uuid = uuid::Uuid::parse_str(&user.uuid).expect("Failed to parse user UUID");

    let (mut challenge, state) =
        WEBAUTHN.start_passkey_registration(user_uuid, &user.email, user.display_name(), Some(existing_cred_ids))?;

    // For passkey login, we need discoverable credentials (resident keys)
    // and require user verification.
    // start_passkey_registration() defaults to require_resident_key=false, but passkey login
    // requires the credential to be discoverable (resident) so the authenticator can find it
    // without the server providing allowCredentials.
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
        asc.require_resident_key = true;
        asc.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }

    // Persist the registration state in the database (same pattern as 2FA webauthn)
    TwoFactor::new(user.uuid, TwoFactorType::WebauthnPasskeyRegisterChallenge, serde_json::to_string(&state)?)
        .save(&conn)
        .await?;

    let mut options = serde_json::to_value(challenge.public_key)?;
    options["status"] = "ok".into();
    options["errorMessage"] = "".into();

    Ok(Json(json!({
        "options": options,
        "object": "webauthnCredentialCreateOptions"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnLoginCredentialCreateRequest {
    device_response: RegisterPublicKeyCredentialCopy,
    name: String,
    supports_prf: bool,
    encrypted_user_key: Option<String>,
    encrypted_public_key: Option<String>,
    encrypted_private_key: Option<String>,
}

#[post("/webauthn", data = "<data>")]
async fn post_webauthn(
    data: Json<WebAuthnLoginCredentialCreateRequest>,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    let data: WebAuthnLoginCredentialCreateRequest = data.into_inner();
    let user = headers.user;

    // Retrieve and delete the saved challenge state from the database
    let type_ = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let credential = match TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await {
        Some(tf) => {
            let state: PasskeyRegistration = serde_json::from_str(&tf.data)?;
            tf.delete(&conn).await?;
            WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state)?
        }
        None => err!("No registration challenge found. Please try again."),
    };

    WebauthnCredential::new(
        user.uuid,
        data.name,
        serde_json::to_string(&credential)?,
        data.supports_prf,
        data.encrypted_user_key,
        data.encrypted_public_key,
        data.encrypted_private_key,
    )
    .save(&conn)
    .await?;

    Ok(Status::Ok)
}

#[post("/webauthn/<uuid>/delete", data = "<data>")]
async fn post_webauthn_delete(
    data: Json<PasswordOrOtpData>,
    uuid: &str,
    headers: Headers,
    conn: DbConn,
) -> ApiResult<Status> {
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    WebauthnCredential::delete_by_uuid_and_user(&WebauthnCredentialId::from(uuid.to_string()), &user.uuid, &conn)
        .await?;

    Ok(Status::Ok)
}
