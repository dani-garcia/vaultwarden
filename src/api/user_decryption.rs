//! `UserDecryptionOptions` (login) and `userDecryption` (sync) payloads for Bitwarden-compatible clients.
//!
//! References: Bitwarden `UserDecryptionOptionsBuilder`, `TrustedDeviceUserDecryptionOption`, and
//! `libs/common/.../user-decryption-options.response.ts` in bitwarden/clients.

use serde_json::{Value, json};

use crate::CONFIG;
use crate::db::DbConn;
use crate::db::models::{Device, Membership, SsoUser, User};

pub async fn build_sync_user_decryption(user: &User, device: &Device, conn: &DbConn) -> Value {
    let with_trusted =
        CONFIG.sso_enabled() && (CONFIG.sso_only() || SsoUser::find_by_user(&user.uuid, conn).await.is_some());
    build_token_user_decryption_options(user, device, with_trusted, conn).await
}

// Bitwarden only builds trusted-device options when SSO Identity context exists (authorization_code grant).
// Do not return the Trusted information if there is no master password (otherwise onboarding does not allow setting one)
pub async fn build_token_user_decryption_options(
    user: &User,
    device: &Device,
    with_trusted: bool,
    conn: &DbConn,
) -> Value {
    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "kdf": {
                "kdfType": user.client_kdf_type,
                "iterations": user.client_kdf_iter,
                "memory": user.client_kdf_memory,
                "parallelism": user.client_kdf_parallelism
            },
            "masterKeyEncryptedUserKey": user.akey,
            "masterKeyWrappedUserKey": user.akey,
            "salt": user.email
        })
    } else {
        Value::Null
    };

    let mut out = json!({
        "hasMasterPassword": has_master_password,
        "masterPasswordUnlock": master_password_unlock,
        "userKeyId": user.key_id,
        "object": "userDecryptionOptions"
    });

    if with_trusted && CONFIG.sso_trusted_device_encryption() && has_master_password {
        let mut trusted = json!({
            "hasAdminApproval": false,
            "hasLoginApprovingDevice": has_login_approving_device(user, device, conn).await,
            "hasManageResetPasswordPermission": is_owner_admin(user, conn).await,
            "isTdeOffboarding": false,
        });

        if let Some(key) = device.encrypted_user_key.as_ref() {
            trusted["encryptedUserKey"] = json!(key);
            trusted["EncryptedUserKey"] = json!(key);
        }

        if let Some(key) = device.encrypted_private_key.as_ref() {
            trusted["encryptedPrivateKey"] = json!(key);
            trusted["EncryptedPrivateKey"] = json!(key);
        }

        out["trustedDeviceOption"] = trusted.clone();
        out["TrustedDeviceOption"] = trusted;
    }

    out
}

// Details on trusted settings:
//  https://github.com/bitwarden/clients/blob/web-v2026.4.2/libs/auth/src/common/models/domain/user-decryption-options.ts#L114
async fn is_owner_admin(user: &User, conn: &DbConn) -> bool {
    Membership::find_confirmed_by_user(&user.uuid, conn).await.iter().any(|m| m.is_owner() || m.is_admin())
}

async fn has_login_approving_device(user: &User, device: &Device, conn: &DbConn) -> bool {
    Device::find_by_user(&user.uuid, conn).await.iter().any(|d| d.uuid != device.uuid && d.can_approve_trusted_login())
}
