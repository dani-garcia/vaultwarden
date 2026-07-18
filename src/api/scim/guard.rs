//
// Request guard for the /scim/v2/<org_id> endpoints.
//
// The credential is a per-organization static bearer token of the form
//   scim_v1.<org_uuid>.<secret>
// as configured in the IdP (Entra ID sends a static "Secret Token"; it cannot
// drive an OAuth flow, which rules out the short-lived organization api-key
// JWT used by /api/public). Only the sha256 digest of the secret is stored.
//
// Failure behaviour: every rejection logs its specific cause via err_handler!
// (target "auth", server log only) and surfaces to the caller as a bare 401
// that the scim catcher turns into one fixed SCIM error body. Rate limiting
// runs before any parsing so unauthenticated floods are cut off first.
//
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};

use crate::{
    CONFIG,
    auth::ClientIp,
    db::{
        DbConn,
        models::{OrganizationId, ScimApiKey},
    },
    ratelimit,
};

// Digest compared when no key row exists, so a miss costs the same ct_eq as a
// hit. The DB lookup itself still dominates timing; this is hygiene, not a
// timing-safety guarantee.
const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// Handlers must scope every query to token.org_uuid, never to a path or body
// value.
pub struct ScimToken {
    pub org_uuid: OrganizationId,
}

impl ScimToken {
    // Splits "scim_v1.<org_uuid>.<secret>" into (org_uuid, secret).
    fn parse_token(token: &str) -> Option<(&str, &str)> {
        let rest = token.strip_prefix("scim_v1.")?;
        let (org_uuid, secret) = rest.split_once('.')?;
        if org_uuid.is_empty() || secret.is_empty() {
            return None;
        }
        Some((org_uuid, secret))
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ScimToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Outcome::Success(ip) = ClientIp::from_request(request).await else {
            err_handler!("Error getting Client IP")
        };

        // Rate limit before any parsing or database work.
        if ratelimit::check_limit_scim(&ip.ip).is_err() {
            warn!(target: "auth", "SCIM rate limit exceeded. IP: {}", ip.ip);
            return Outcome::Error((Status::TooManyRequests, "Too many requests"));
        }

        if !CONFIG.scim_enabled() {
            err_handler!("SCIM is disabled")
        }

        let Some(auth_header) = request.headers().get_one("Authorization") else {
            err_handler!("No access token provided")
        };
        let Some(bearer) = auth_header.strip_prefix("Bearer ") else {
            err_handler!("No access token provided")
        };

        let Some((token_org, secret)) = Self::parse_token(bearer) else {
            err_handler!("Malformed SCIM token")
        };

        // The org embedded in the token must match the org in the request
        // path, before any database work. Route shape is /v2/<org_id>/...,
        // so the org id is path parameter index 1.
        let Some(Ok(path_org)) = request.param::<OrganizationId>(1) else {
            err_handler!("Missing org_id in path")
        };
        if token_org != &*path_org {
            err_handler!("SCIM token does not match the requested organization", format!("IP: {}", ip.ip))
        }

        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };

        let org_uuid: OrganizationId = token_org.to_owned().into();
        let Some(scim_key) = ScimApiKey::find_active_by_org(&org_uuid, &conn).await else {
            // Burn an equivalent comparison so a missing key row does not
            // return faster than a wrong secret.
            let _ = crate::crypto::ct_eq(DUMMY_DIGEST, crate::crypto::sha256_hex(secret.as_bytes()));
            err_handler!("No active SCIM api key for organization", format!("IP: {}. Organization: {org_uuid}", ip.ip))
        };
        if !scim_key.check_valid_secret(secret) {
            err_handler!("Invalid SCIM token secret", format!("IP: {}. Organization: {org_uuid}", ip.ip))
        }

        Outcome::Success(ScimToken {
            org_uuid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_valid() {
        let parsed = ScimToken::parse_token("scim_v1.11111111-2222-3333-4444-555555555555.some-secret-value");
        assert_eq!(parsed, Some(("11111111-2222-3333-4444-555555555555", "some-secret-value")));
    }

    #[test]
    fn parse_token_secret_may_contain_dots() {
        // Only the first dot after the org uuid separates; the secret keeps the rest.
        let parsed = ScimToken::parse_token("scim_v1.org-uuid.part1.part2");
        assert_eq!(parsed, Some(("org-uuid", "part1.part2")));
    }

    #[test]
    fn parse_token_rejects_bad_shapes() {
        assert_eq!(ScimToken::parse_token(""), None);
        assert_eq!(ScimToken::parse_token("scim_v1."), None);
        assert_eq!(ScimToken::parse_token("scim_v1.orgonly"), None);
        assert_eq!(ScimToken::parse_token("scim_v1..secret"), None);
        assert_eq!(ScimToken::parse_token("scim_v1.org."), None);
        assert_eq!(ScimToken::parse_token("scim_v2.org.secret"), None);
        assert_eq!(ScimToken::parse_token("Bearer scim_v1.org.secret"), None);
    }
}
