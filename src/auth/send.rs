use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

use chrono::{TimeDelta, Utc};

use rocket::request::{FromRequest, Outcome, Request};

use crate::{
    CONFIG,
    api::ApiResult,
    auth,
    auth::{BasicJwtClaims, ClientIp},
    crypto,
    db::{
        DbConn,
        models::{Send, SendAuthType, SendId},
    },
    error::{Error, ErrorKind},
    mail,
};

/// A verification code sent to one recipient of an email verified Send
struct SendOtp {
    /// `None` once too many wrong tries burned it. The entry stays until it expires, so the resend
    /// cooldown still counts from `created` and wrong tries can't be used to skip it.
    code: Option<String>,
    created: i64,
    expires: i64,
    failed_attempts: u64,
}

/// Pending codes, keyed by Send and email. They live minutes, so they are kept in memory: a restart
/// only makes the recipient ask for a new code, and no table is needed.
static SEND_OTPS: LazyLock<Mutex<HashMap<(SendId, String), SendOtp>>> = LazyLock::new(Default::default);

/// Minimum seconds between two codes for the same recipient of the same Send, so a leaked link can't
/// be used to flood the recipient's inbox
const OTP_RESEND_COOLDOWN_SECS: i64 = 30;

/// Registers a new code for this recipient and returns it, or `None` while the last one, burned or not,
/// is younger than `OTP_RESEND_COOLDOWN_SECS`.
fn reserve_send_otp(send_id: &SendId, email: &str) -> Option<String> {
    let now = Utc::now().timestamp();
    let key = (send_id.clone(), email.to_owned());
    let mut otps = SEND_OTPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    otps.retain(|_, o| o.expires > now);
    if otps.get(&key).is_some_and(|o| now - o.created < OTP_RESEND_COOLDOWN_SECS) {
        return None;
    }
    let code = crypto::generate_email_token(CONFIG.email_token_size());
    let expires = now + i64::try_from(CONFIG.email_expiration_time()).unwrap_or(600);
    otps.insert(
        key,
        SendOtp {
            code: Some(code.clone()),
            created: now,
            expires,
            failed_attempts: 0,
        },
    );
    Some(code)
}

/// Mails a new code in the background. It is not awaited on purpose: allowed and unknown emails must get
/// the same answer, in the same time, even when the mail server fails, so a failure is only logged.
fn issue_send_otp(send_id: &SendId, email: &str) {
    let Some(code) = reserve_send_otp(send_id, email) else {
        return;
    };
    let key = (send_id.clone(), email.to_owned());
    tokio::task::spawn(async move {
        if let Err(e) = mail::send_send_otp(&key.1, &code).await {
            error!("Error sending the verification code of Send {} to {}: {e:#?}", key.0, key.1);
            // Let the recipient ask again right away, unless a newer code already replaced this one
            let mut otps = SEND_OTPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if otps.get(&key).is_some_and(|o| o.code.as_deref() == Some(code.as_str())) {
                otps.remove(&key);
            }
        }
    });
}

/// Checks a code. A valid code is consumed; after `EMAIL_ATTEMPTS_LIMIT` wrong ones the pending code
/// is burned and the recipient must ask for a new one, which the resend cooldown still applies to.
fn verify_send_otp(send_id: &SendId, email: &str, code: &str) -> bool {
    let now = Utc::now().timestamp();
    let key = (send_id.clone(), email.to_owned());
    let mut otps = SEND_OTPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(otp) = otps.get_mut(&key) else {
        return false;
    };
    if otp.expires <= now {
        otps.remove(&key);
        return false;
    }
    let Some(expected) = &otp.code else {
        return false;
    };
    if crypto::ct_eq(expected, code) {
        otps.remove(&key);
        return true;
    }
    otp.failed_attempts += 1;
    if otp.failed_attempts >= CONFIG.email_attempts_limit() {
        otp.code = None;
    }
    false
}

fn generate_send_access_claims(send_id: &SendId) -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: auth::JWT_SEND_ISSUER.to_string(),
        sub: format!("{send_id}"),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTokens {
    pub access_claims: BasicJwtClaims,
}

impl SendTokens {
    pub fn as_send_id(access_id: &str) -> Option<SendId> {
        data_encoding::BASE64URL_NOPAD
            .decode(access_id.as_bytes())
            .ok()
            .and_then(|uuid_vec| uuid::Uuid::from_slice(&uuid_vec).ok().map(|u| SendId::from(u.to_string())))
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "access_token": self.access_claims.token(),
            "expires_in": self.access_claims.expires_in(),
            "token_type": "Bearer",
            "scope": "api.send.access",
        })
    }

    fn expected_error(msg: &str, error_type: &str) -> ApiResult<SendTokens> {
        let err = json!({
            "kind": "expected_server",
            "error": "invalid_request",
            "send_access_error_type": error_type,
        });

        Err(Error::new_msg(msg).with_kind(ErrorKind::Json(err)).silent())
    }

    fn invalid_error(msg: &str, error_type: &str, silent: bool) -> ApiResult<SendTokens> {
        let err = json!({
            "kind": "expected_server",
            "error": "invalid_grant",
            "send_access_error_type": error_type,
        });

        Err(Error::new_msg(msg).with_kind(ErrorKind::Json(err)).with_code(404).with_silent(silent))
    }

    pub async fn generate_tokens(
        access_id: &str,
        password: Option<String>,
        email: Option<String>,
        otp: Option<String>,
        ip: &ClientIp,
        conn: &DbConn,
    ) -> ApiResult<SendTokens> {
        let Some(send_id) = Self::as_send_id(access_id) else {
            return Self::invalid_error(&format!("Can't convert {access_id}"), "send_id_invalid", false);
        };

        let Some(send) = Send::find_by_uuid(&send_id, conn).await else {
            return Self::invalid_error(&format!("Can't find {send_id}"), "send_id_invalid", false);
        };

        if let Some(max_access_count) = send.max_access_count
            && send.access_count >= max_access_count
        {
            return Self::invalid_error(&format!("Send {send_id}, max access reached"), "send_id_invalid", true);
        }

        if !send.is_accessible() {
            return Self::invalid_error(&format!("Send {send_id}, not accessible"), "send_id_invalid", true);
        }

        let mut verified_email = None;
        if send.auth_type() == SendAuthType::Email {
            if !CONFIG.mail_enabled() {
                return Self::invalid_error(
                    &format!("Send {send_id} needs email verification, but email is not configured"),
                    "send_id_invalid",
                    false,
                );
            }
            let allowed = send.auth_emails().unwrap_or_default();
            let Some(email) = email.map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) else {
                return Self::expected_error("Email is required", "email_required");
            };
            // Like the Bitwarden server, every failure below gets the same answer as "code sent",
            // so the link alone does not reveal which emails may open the Send
            if !allowed.contains(&email) {
                warn!("Send {send_id}, email not allowed, from {}", ip.ip);
                return Self::expected_error("Email and OTP are required", "email_and_otp_required");
            }
            match otp.map(|o| o.trim().to_owned()).filter(|o| !o.is_empty()) {
                None => {
                    issue_send_otp(&send_id, &email);
                    return Self::expected_error("Email and OTP are required", "email_and_otp_required");
                }
                Some(code) => {
                    if !verify_send_otp(&send_id, &email, &code) {
                        warn!("Send {send_id}, invalid email verification code from {}", ip.ip);
                        return Self::expected_error("Email and OTP are required", "email_and_otp_required");
                    }
                    verified_email = Some(email);
                }
            }
        }

        if send.password_hash.is_some() {
            match password {
                Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
                Some(_) => {
                    return Self::invalid_error(
                        &format!("Send {send_id}, Invalid password from {}", ip.ip),
                        "password_hash_b64_invalid",
                        false,
                    );
                }
                None => return Self::expected_error("Password required", "password_hash_b64_required"),
            }
        }

        // Audit trail of who opened an email verified Send. The access itself is counted when the
        // content is requested, like upstream: getting a token only checks the limit
        if let Some(email) = verified_email {
            info!("Send {send_id} opened by {email} from {}", ip.ip);
        }

        Ok(Self {
            access_claims: generate_send_access_claims(&send_id),
        })
    }
}

pub struct SendHeaders {
    pub send_id: SendId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SendHeaders {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();

        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };

        // Check JWT token is valid and get send_id
        let Ok(claims) = auth::decode_send(access_token) else {
            err_handler!("Invalid claim")
        };

        Outcome::Success(SendHeaders {
            send_id: claims.sub.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plant(send_id: &SendId, email: &str, code: &str, expires_in: i64) {
        let now = Utc::now().timestamp();
        SEND_OTPS.lock().unwrap().insert(
            (send_id.clone(), email.to_owned()),
            SendOtp {
                code: Some(code.to_owned()),
                created: now,
                expires: now + expires_in,
                failed_attempts: 0,
            },
        );
    }

    #[test]
    fn valid_code_opens_once() {
        let id = SendId::from("otp-once".to_string());
        plant(&id, "a@x.com", "123456", 600);
        assert!(verify_send_otp(&id, "a@x.com", "123456"));
        assert!(!verify_send_otp(&id, "a@x.com", "123456"), "a code is single use");
    }

    #[test]
    fn code_is_bound_to_send_and_email() {
        let id = SendId::from("otp-bound".to_string());
        plant(&id, "a@x.com", "123456", 600);
        assert!(!verify_send_otp(&id, "b@x.com", "123456"));
        assert!(!verify_send_otp(&SendId::from("otp-other".to_string()), "a@x.com", "123456"));
        assert!(verify_send_otp(&id, "a@x.com", "123456"));
    }

    #[test]
    fn wrong_codes_burn_the_pending_code() {
        let id = SendId::from("otp-burn".to_string());
        plant(&id, "a@x.com", "123456", 600);
        for _ in 0..CONFIG.email_attempts_limit() {
            assert!(!verify_send_otp(&id, "a@x.com", "000000"));
        }
        assert!(!verify_send_otp(&id, "a@x.com", "123456"), "after the attempts limit the right code is gone too");
    }

    #[test]
    fn burned_code_keeps_the_resend_cooldown() {
        let id = SendId::from("otp-cooldown".to_string());
        plant(&id, "a@x.com", "123456", 600);
        for _ in 0..CONFIG.email_attempts_limit() {
            assert!(!verify_send_otp(&id, "a@x.com", "000000"));
        }
        assert_eq!(reserve_send_otp(&id, "a@x.com"), None, "wrong tries must not skip the cooldown");
        // Another recipient of the same Send has its own cooldown
        assert!(reserve_send_otp(&id, "b@x.com").is_some());
        assert_eq!(reserve_send_otp(&id, "b@x.com"), None);
    }

    #[test]
    fn expired_code_is_refused() {
        let id = SendId::from("otp-expired".to_string());
        plant(&id, "a@x.com", "123456", -1);
        assert!(!verify_send_otp(&id, "a@x.com", "123456"));
    }
}
