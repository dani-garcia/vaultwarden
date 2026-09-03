use std::sync::LazyLock;

use rocket::{http::Status, serde::json::Json};
use serde_json::Value;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Passkey, PasskeyRegistration},
};
use webauthn_rs_proto::{COSEAlgorithm, UserVerificationPolicy, options::PubKeyCredParams};

use crate::{
    CONFIG,
    api::{ApiResult, JsonResult, PasswordOrOtpData, core::two_factor::webauthn::RegisterPublicKeyCredentialCopy},
    auth::Headers,
    db::{
        DbConn,
        models::{TwoFactor, TwoFactorType, WebauthnCredential, WebauthnCredentialId, WebauthnCredentialPrfStatus},
    },
};

pub static WEBAUTHN_PASSWORDLESS: LazyLock<Webauthn> = LazyLock::new(|| {
    let domain = CONFIG.domain();
    let domain_origin = CONFIG.domain_origin();
    let rp_id = url::Url::parse(&domain).map(|u| u.domain().map(str::to_owned)).ok().flatten().unwrap_or_default();
    let rp_origin = url::Url::parse(&domain_origin).unwrap();

    let mut webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("Creating WebauthnBuilder failed")
        .rp_name(&domain)
        .timeout(tokio::time::Duration::from_mins(1));

    for origin in [
        "chrome-extension://nngceckbapebfimnlniiiahkandclblb", // Chrome Web Store
        "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh", // Edge Add-ons
    ] {
        let origin = url::Url::parse(origin).expect("origin should parse");
        webauthn = webauthn.append_allowed_origin(&origin);
    }

    webauthn.build().expect("Building Webauthn failed")
});

pub fn routes() -> Vec<rocket::Route> {
    routes![get_webauthn, post_webauthn, post_webauthn_attestation_options, post_webauthn_delete]
}

pub fn webauthn_prf_option(wac: &WebauthnCredential, pascal_case: bool) -> Option<Value> {
    if !matches!(wac.get_prf_status(), WebauthnCredentialPrfStatus::Enabled) {
        return None;
    }

    let passkey: Passkey = serde_json::from_str(&wac.credential).ok()?;

    if pascal_case {
        Some(json!({
            "CredentialId": passkey.cred_id().to_owned(),
            "Transports": [],
            "EncryptedPrivateKey": wac.encrypted_private_key.as_ref()?,
            "EncryptedUserKey": wac.encrypted_user_key.as_ref()?,
        }))
    } else {
        Some(json!({
            "credentialId": passkey.cred_id().to_owned(),
            "transports": [],
            "encryptedPrivateKey": wac.encrypted_private_key.as_ref()?,
            "encryptedUserKey": wac.encrypted_user_key.as_ref()?,
        }))
    }
}

#[get("/webauthn")]
async fn get_webauthn(headers: Headers, conn: DbConn) -> JsonResult {
    if !CONFIG.passkey_login_allowed() {
        // The web vault will query this endpoint whether passkey login is allowed or not, so we should return an empty list instead of an error.
        return Ok(Json(json!({
            "object": "list",
            "data": [],
            "continuationToken": null
        })));
    }

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

    Ok(Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    })))
}

#[post("/webauthn/attestation-options", data = "<data>")]
async fn post_webauthn_attestation_options(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    if !CONFIG.passkey_login_allowed() {
        err!("Passkey login is not allowed")
    }

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

    let (mut challenge, state) = WEBAUTHN_PASSWORDLESS.start_passkey_registration(
        user_uuid,
        &user.email,
        user.display_name(),
        Some(existing_cred_ids),
    )?;

    // For passkey login, we need discoverable credentials (resident keys).
    // start_passkey_registration() defaults to require_resident_key=false, but passkey login
    // requires the credential to be discoverable (resident) so the authenticator can find it
    // without the server providing allowCredentials.
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Preferred;
        asc.require_resident_key = true;
        asc.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
    }

    // Safely clear the extensions field to match Bitwarden behavior
    if let Some(exts) = challenge.public_key.extensions.as_mut() {
        exts.cred_props = None;
        exts.uvm = None;
        exts.cred_protect = None;
        exts.hmac_create_secret = None;
        exts.min_pin_length = None;
    }

    // Set algorithms list to {ES,RS,PS}{256,384,512},EDDSA to match Bitwarden behavior
    challenge.public_key.pub_key_cred_params = vec![
        PubKeyCredParams {
            alg: COSEAlgorithm::ES256 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::ES384 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::ES512 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::RS256 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::RS384 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::RS512 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::PS256 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::PS384 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::PS512 as i64,
            type_: "public-key".to_owned(),
        },
        PubKeyCredParams {
            alg: COSEAlgorithm::EDDSA as i64,
            type_: "public-key".to_owned(),
        },
    ];

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
    if !CONFIG.passkey_login_allowed() {
        err!("Passkey login is not allowed")
    }

    let data: WebAuthnLoginCredentialCreateRequest = data.into_inner();
    let user = headers.user;

    // Retrieve and delete the saved challenge state from the database
    let type_ = TwoFactorType::WebauthnPasskeyRegisterChallenge as i32;
    let credential = if let Some(tf) = TwoFactor::find_by_user_and_type(&user.uuid, type_, &conn).await {
        let state: PasskeyRegistration = serde_json::from_str(&tf.data)?;
        tf.delete(&conn).await?;
        WEBAUTHN_PASSWORDLESS.finish_passkey_registration(&data.device_response.into(), &state)?
    } else {
        err!("No registration challenge found. Please try again.")
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
    if !CONFIG.passkey_login_allowed() {
        err!("Passkey login is not allowed")
    }

    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    data.validate(&user, false, &conn).await?;

    WebauthnCredential::delete_by_uuid_and_user(&WebauthnCredentialId::from(uuid.to_owned()), &user.uuid, &conn)
        .await?;

    Ok(Status::Ok)
}
