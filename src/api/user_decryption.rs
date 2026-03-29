//! `UserDecryptionOptions` (login) and `userDecryption` (sync) payloads for Bitwarden-compatible clients.
//!
//! References: Bitwarden `UserDecryptionOptionsBuilder`, `TrustedDeviceUserDecryptionOption`, and
//! `libs/common/.../user-decryption-options.response.ts` in bitwarden/clients.

use serde_json::{json, Value};

use crate::db::models::{Device, Membership, SsoUser, User, UserId};
use crate::db::DbConn;
use crate::CONFIG;

/// Device types that may approve “login with device” / trusted-device flows (see Bitwarden `LoginApprovingClientTypes`).
pub fn device_type_can_approve_trusted_login(atype: i32) -> bool {
    !matches!(atype, 21..=25) // SDK, Server, CLIs
}

async fn has_login_approving_device(user_uuid: &UserId, current: &Device, conn: &DbConn) -> bool {
    let devices = Device::find_by_user(user_uuid, conn).await;
    devices.iter().any(|d| {
        d.uuid != current.uuid
            && device_type_can_approve_trusted_login(d.atype)
    })
}

fn has_valid_reset_password_key(m: &Membership) -> bool {
    m.reset_password_key.as_ref().is_some_and(|s| !s.trim().is_empty())
}

/// Owner or Admin (Vaultwarden does not persist custom-role JSON for `manageResetPassword` on members).
fn membership_has_manage_reset_password(m: &Membership) -> bool {
    matches!(m.atype, 0 | 1)
}

async fn aggregate_trusted_device_flags(user: &User, device: &Device, conn: &DbConn) -> (bool, bool, bool) {
    let members = Membership::find_confirmed_by_user(&user.uuid, conn).await;
    let has_admin_approval = members.iter().any(has_valid_reset_password_key);
    let has_manage_reset = members.iter().any(membership_has_manage_reset_password);
    let has_login_approving = has_login_approving_device(&user.uuid, device, conn).await;
    (has_admin_approval, has_manage_reset, has_login_approving)
}

/// Sync may be called long after SSO login; include TDE hints for users linked to SSO.
async fn user_in_sso_context(user_uuid: &UserId, conn: &DbConn) -> bool {
    if !CONFIG.sso_enabled() {
        return false;
    }
    SsoUser::find_by_user(user_uuid, conn).await.is_some()
}

fn trusted_device_option_token(
    has_admin_approval: bool,
    has_login_approving_device: bool,
    has_manage_reset_password_permission: bool,
    is_tde_offboarding: bool,
    device: &Device,
) -> Value {
    let (enc_priv, enc_user) = if device.is_trusted() {
        (
            device
                .encrypted_private_key
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| json!(s))
                .unwrap_or(Value::Null),
            device
                .encrypted_user_key
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| json!(s))
                .unwrap_or(Value::Null),
        )
    } else {
        (Value::Null, Value::Null)
    };

    json!({
        "HasAdminApproval": has_admin_approval,
        "HasLoginApprovingDevice": has_login_approving_device,
        "HasManageResetPasswordPermission": has_manage_reset_password_permission,
        "IsTdeOffboarding": is_tde_offboarding,
        "EncryptedPrivateKey": enc_priv,
        "EncryptedUserKey": enc_user,
    })
}

fn trusted_device_option_sync(
    has_admin_approval: bool,
    has_login_approving_device: bool,
    has_manage_reset_password_permission: bool,
    is_tde_offboarding: bool,
    device: &Device,
) -> Value {
    let (enc_priv, enc_user) = if device.is_trusted() {
        (
            device
                .encrypted_private_key
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| json!(s))
                .unwrap_or(Value::Null),
            device
                .encrypted_user_key
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| json!(s))
                .unwrap_or(Value::Null),
        )
    } else {
        (Value::Null, Value::Null)
    };

    json!({
        "hasAdminApproval": has_admin_approval,
        "hasLoginApprovingDevice": has_login_approving_device,
        "hasManageResetPasswordPermission": has_manage_reset_password_permission,
        "isTdeOffboarding": is_tde_offboarding,
        "encryptedPrivateKey": enc_priv,
        "encryptedUserKey": enc_user,
    })
}

/// `UserDecryptionOptions` for `POST /identity/connect/token` (PascalCase, Bitwarden Identity).
pub async fn build_token_user_decryption_options(
    user: &User,
    device: &Device,
    conn: &DbConn,
    sso_login: bool,
) -> Value {
    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let mut out = json!({
        "HasMasterPassword": has_master_password,
        "MasterPasswordUnlock": master_password_unlock,
        "Object": "userDecryptionOptions"
    });

    // Bitwarden only builds trusted-device options when SSO Identity context exists (authorization_code grant).
    if !sso_login {
        return out;
    }

    let is_tde_active = CONFIG.sso_trusted_device_encryption();
    let is_tde_offboarding = !has_master_password && device.is_trusted() && !is_tde_active;

    if !is_tde_active && !is_tde_offboarding {
        return out;
    }

    let (ha, hm, hl) = aggregate_trusted_device_flags(user, device, conn).await;
    out["TrustedDeviceOption"] = trusted_device_option_token(ha, hl, hm, is_tde_offboarding, device);
    out
}

/// `userDecryption` object on full sync (camelCase nested keys; see `GET /sync`).
pub async fn build_sync_user_decryption(user: &User, device: &Device, conn: &DbConn) -> Value {
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
        "masterPasswordUnlock": master_password_unlock,
    });

    if !user_in_sso_context(&user.uuid, conn).await {
        return out;
    }

    let is_tde_active = CONFIG.sso_trusted_device_encryption();
    let is_tde_offboarding = !has_master_password && device.is_trusted() && !is_tde_active;

    if !is_tde_active && !is_tde_offboarding {
        return out;
    }

    let (ha, hm, hl) = aggregate_trusted_device_flags(user, device, conn).await;
    out["trustedDeviceOption"] = trusted_device_option_sync(ha, hl, hm, is_tde_offboarding, device);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_type_approver_excludes_cli_and_server() {
        assert!(device_type_can_approve_trusted_login(14));
        assert!(!device_type_can_approve_trusted_login(22));
        assert!(!device_type_can_approve_trusted_login(23));
    }
}
