use std::time::Duration;

use chrono::{NaiveDateTime, Utc};
use diesel::{
    deserialize::FromSql,
    expression::AsExpression,
    prelude::*,
    serialize::{Output, ToSql},
    sql_types::Text,
};

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{DbConn, DbPool, schema::sso_auth},
    error::MapResult,
    sso::{OIDCCode, OIDCCodeChallenge, OIDCIdentifier, OIDCState, SSO_AUTH_EXPIRATION},
};

#[derive(AsExpression, Clone, Debug, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct OIDCCodeResponseError {
    pub error: String,
    pub error_description: Option<String>,
}

impl_FromToSqlText!(OIDCCodeResponseError);

#[derive(AsExpression, Clone, Debug, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct OIDCAuthenticatedUser {
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_in: Option<Duration>,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
}

impl OIDCAuthenticatedUser {
    pub fn should_skip_2fa(&self) -> bool {
        let skip_mode = CONFIG.sso_2fa_skip();
        let acr = CONFIG.sso_2fa_acr();
        let amr_values = CONFIG.sso_2fa_amr_vec();

        Self::should_skip_2fa_with(&skip_mode, self.acr.as_deref(), self.amr.as_deref(), &acr, &amr_values)
    }

    fn should_skip_2fa_with(
        skip_mode: &str,
        user_acr: Option<&str>,
        user_amr: Option<&[String]>,
        configured_acr: &str,
        configured_amr: &[String],
    ) -> bool {
        match skip_mode {
            "true" => true,
            "auto" => {
                (!configured_acr.is_empty() && user_acr == Some(configured_acr))
                    || user_amr.is_some_and(|methods| {
                        methods.iter().any(|method| {
                            configured_amr.contains(method)
                                && (method != "otp" || methods.iter().any(|other| other == "pwd"))
                        })
                    })
            }
            _ => false,
        }
    }
}

impl_FromToSqlText!(OIDCAuthenticatedUser);

#[cfg(test)]
mod tests {
    use super::OIDCAuthenticatedUser;

    #[test]
    fn two_factor_skip_modes_are_respected() {
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with("false", None, None, "mfa", &[]));
        assert!(OIDCAuthenticatedUser::should_skip_2fa_with("true", None, None, "", &[]));
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with("invalid", Some("mfa"), None, "mfa", &[]));
    }

    #[test]
    fn auto_mode_matches_configured_acr_exactly() {
        assert!(OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            Some("urn:example:mfa"),
            None,
            "urn:example:mfa",
            &[]
        ));
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            Some("urn:example:loa:2"),
            None,
            "urn:example:mfa",
            &[]
        ));
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            Some("URN:EXAMPLE:MFA"),
            None,
            "urn:example:mfa",
            &[]
        ));
    }

    #[test]
    fn auto_mode_matches_configured_amr_exactly() {
        let accepted_amr = vec!["mfa".to_owned()];
        let otp_only_amr = vec!["otp".to_owned()];
        let password_and_otp_amr = vec!["pwd".to_owned(), "otp".to_owned()];

        assert!(OIDCAuthenticatedUser::should_skip_2fa_with("auto", None, Some(&accepted_amr), "", &accepted_amr));
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            None,
            Some(&otp_only_amr),
            "",
            &["otp".to_owned()]
        ));
        assert!(OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            None,
            Some(&password_and_otp_amr),
            "",
            &["otp".to_owned()]
        ));
        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with("auto", None, None, "", &accepted_amr));
    }

    #[test]
    fn auto_mode_matches_configured_passwordless_methods() {
        let passkey_amr = vec!["webauthn".to_owned()];

        assert!(OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            None,
            Some(&passkey_amr),
            "",
            &["fido2".to_owned(), "webauthn".to_owned(), "hwk".to_owned()]
        ));
    }

    #[test]
    fn empty_configured_claims_do_not_skip_two_factor() {
        let returned_amr = vec!["mfa".to_owned()];

        assert!(!OIDCAuthenticatedUser::should_skip_2fa_with(
            "auto",
            Some("urn:example:mfa"),
            Some(&returned_amr),
            "",
            &[]
        ));
    }
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = sso_auth)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(state))]
pub struct SsoAuth {
    pub state: OIDCState,
    pub client_challenge: OIDCCodeChallenge,
    pub nonce: String,
    pub redirect_uri: String,
    pub code_response: Option<OIDCCode>,
    pub code_response_error: Option<OIDCCodeResponseError>,
    pub auth_response: Option<OIDCAuthenticatedUser>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub binding_hash: Option<String>,
}

/// Local methods
impl SsoAuth {
    pub fn new(
        state: OIDCState,
        client_challenge: OIDCCodeChallenge,
        nonce: String,
        redirect_uri: String,
        binding_hash: Option<String>,
    ) -> Self {
        let now = Utc::now().naive_utc();

        SsoAuth {
            state,
            client_challenge,
            nonce,
            redirect_uri,
            created_at: now,
            updated_at: now,
            code_response: None,
            code_response_error: None,
            auth_response: None,
            binding_hash,
        }
    }
}

/// Database methods
impl SsoAuth {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(sso_auth::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving SSO auth")
            }
            postgresql, sqlite {
                diesel::insert_into(sso_auth::table)
                    .values(self)
                    .on_conflict(sso_auth::state)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving SSO auth")
            }
        }
    }

    pub async fn find(state: &OIDCState, conn: &DbConn) -> Option<Self> {
        let oldest = Utc::now().naive_utc() - *SSO_AUTH_EXPIRATION;
        conn.run(move |conn| {
            sso_auth::table
                .filter(sso_auth::state.eq(state))
                .filter(sso_auth::created_at.ge(oldest))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_code(code: &OIDCCode, conn: &DbConn) -> Option<Self> {
        let oldest = Utc::now().naive_utc() - *SSO_AUTH_EXPIRATION;
        db_run! { conn: {
            sso_auth::table
                .filter(sso_auth::code_response.eq(code))
                .filter(sso_auth::created_at.ge(oldest))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(sso_auth::table.filter(sso_auth::state.eq(self.state)))
                .execute(conn)
                .map_res("Error deleting sso_auth")
        })
        .await
    }

    pub async fn delete_expired(pool: DbPool) -> EmptyResult {
        debug!("Purging expired sso_auth");
        if let Ok(conn) = pool.get().await {
            let oldest = Utc::now().naive_utc() - *SSO_AUTH_EXPIRATION;
            conn.run(move |conn| {
                diesel::delete(sso_auth::table.filter(sso_auth::created_at.lt(oldest)))
                    .execute(conn)
                    .map_res("Error deleting expired SSO nonce")
            })
            .await
        } else {
            err!("Failed to get DB connection while purging expired sso_auth")
        }
    }
}
