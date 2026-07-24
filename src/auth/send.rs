use chrono::{TimeDelta, Utc};

use rocket::request::{FromRequest, Outcome, Request};

use crate::{
    api::ApiResult,
    auth,
    auth::{BasicJwtClaims, ClientIp},
    db::{
        DbConn,
        models::{Send, SendId},
    },
    error::{Error, ErrorKind},
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
        ip: &ClientIp,
        conn: &DbConn,
    ) -> ApiResult<SendTokens> {
        let Some(send_id) = Self::as_send_id(access_id) else {
            return Self::invalid_error(&format!("Can't convert {access_id}"), "send_id_invalid", false);
        };

        let Some(mut send) = Send::find_by_uuid(&send_id, conn).await else {
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

        if !send.register_access(conn).await? {
            return Self::invalid_error(&format!("Send {send_id}, max access reached"), "send_id_invalid", true);
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
