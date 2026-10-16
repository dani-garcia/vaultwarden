use chrono::{TimeDelta, Utc};
use num_traits::FromPrimitive;

use rocket::request::{FromRequest, Outcome, Request};

use crate::{
    CONFIG,
    api::ApiResult,
    auth,
    auth::{BasicJwtClaims, ClientIp},
    crypto,
    db::{
        DbConn,
        models::{Send, SendAccessOtp, SendAuthType, SendId},
    },
    error::{Error, ErrorKind},
    mail,
};

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

    fn expected_error<T>(msg: &str, error_type: &str) -> ApiResult<T> {
        let err = json!({
            "kind": "expected_server",
            "error": "invalid_request",
            "send_access_error_type": error_type,
        });

        Err(Error::new_msg(msg).with_kind(ErrorKind::Json(err)).silent())
    }

    fn invalid_error<T>(msg: &str, error_type: &str, silent: bool) -> ApiResult<T> {
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

        // Rely on the stored auth type and fail closed if the Send doesn't hold what it requires
        match SendAuthType::from_i32(send.auth_type) {
            Some(SendAuthType::Email) => Self::verify_email_otp(&send, email, otp, conn).await?,
            Some(SendAuthType::Password) => match password {
                Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
                Some(_) => {
                    return Self::invalid_error(
                        &format!("Send {send_id}, Invalid password from {}", ip.ip),
                        "password_hash_b64_invalid",
                        false,
                    );
                }
                None => return Self::expected_error("Password required", "password_hash_b64_required"),
            },
            Some(SendAuthType::None) if send.password_hash.is_none() && send.emails.is_none() => {}
            _ => {
                return Self::invalid_error(
                    &format!("Send {send_id}, inconsistent access settings"),
                    "send_id_invalid",
                    false,
                );
            }
        }

        Ok(Self {
            access_claims: generate_send_access_claims(&send_id),
        })
    }
}

impl SendTokens {
    /// Email verification: the first request (without `otp`) emails a code to the recipient, the
    /// second one exchanges it for an access token.
    ///
    /// Unlisted emails get the same response as listed ones and no email is sent, so the list of
    /// recipients can't be enumerated.
    ///
    /// Upstream: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/RequestValidators/SendAccess/SendEmailOtpRequestValidator.cs
    async fn verify_email_otp(send: &Send, email: Option<String>, otp: Option<String>, conn: &DbConn) -> ApiResult<()> {
        let Some(allowed_emails) = send.emails.as_deref() else {
            return Self::invalid_error(&format!("Send {}, no emails to verify", send.uuid), "send_id_invalid", false);
        };
        if !CONFIG.mail_enabled() {
            return Self::invalid_error(
                &format!("Send {}, email verification without mail enabled", send.uuid),
                "send_id_invalid",
                false,
            );
        }

        let Some(email) = email.map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) else {
            return Self::expected_error("Email required", "email_required");
        };
        if !allowed_emails.split(',').any(|e| e == email) {
            return Self::expected_error("Email and OTP required", "email_and_otp_required");
        }

        let stored = SendAccessOtp::find(&send.uuid, &email, conn).await;
        let Some(code) = otp.map(|o| o.trim().to_owned()).filter(|o| !o.is_empty()) else {
            if stored.as_ref().is_none_or(SendAccessOtp::can_resend) {
                let code = crypto::generate_email_token(CONFIG.email_token_size());
                let new_otp = SendAccessOtp::new(send.uuid.clone(), email.clone(), code.clone());
                new_otp.save(conn).await?;
                if let Err(e) = mail::send_send_access_otp(&email, &code).await {
                    new_otp.delete(conn).await.ok();
                    return Err(e);
                }
            }
            return Self::expected_error("Email and OTP required", "email_and_otp_required");
        };

        let Some(stored) = stored else {
            return Self::expected_error("Email and OTP required", "email_and_otp_required");
        };
        if stored.is_expired() || stored.attempts >= SendAccessOtp::MAX_ATTEMPTS {
            stored.delete(conn).await?;
            return Self::expected_error("Email and OTP required", "email_and_otp_required");
        }
        if !crypto::ct_eq(&code, &stored.code) {
            stored.increment_attempts(conn).await?;
            return Self::expected_error("Email and OTP required", "email_and_otp_required");
        }

        // Codes are single use
        stored.delete(conn).await?;
        Ok(())
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
