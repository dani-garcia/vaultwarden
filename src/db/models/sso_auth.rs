use chrono::{NaiveDateTime, Utc};
use std::time::Duration;

use crate::api::EmptyResult;
use crate::db::schema::sso_auth;
use crate::db::{DbConn, DbPool};
use crate::error::MapResult;
use crate::sso::{OIDCCode, OIDCCodeChallenge, OIDCIdentifier, OIDCState, SSO_AUTH_EXPIRATION};

use diesel::deserialize::FromSql;
use diesel::expression::AsExpression;
use diesel::prelude::*;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::Text;

#[derive(AsExpression, Clone, Debug, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = Text)]
pub enum OIDCCodeWrapper {
    Ok {
        code: OIDCCode,
    },
    Error {
        error: String,
        error_description: Option<String>,
    },
}

impl_FromToSqlText!(OIDCCodeWrapper);

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
}

impl_FromToSqlText!(OIDCAuthenticatedUser);

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = sso_auth)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(state))]
pub struct SsoAuth {
    pub state: OIDCState,
    pub client_challenge: OIDCCodeChallenge,
    pub nonce: String,
    pub redirect_uri: String,
    pub code_response: Option<OIDCCodeWrapper>,
    pub auth_response: Option<OIDCAuthenticatedUser>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// Local methods
impl SsoAuth {
    pub fn new(state: OIDCState, client_challenge: OIDCCodeChallenge, nonce: String, redirect_uri: String) -> Self {
        let now = Utc::now().naive_utc();

        SsoAuth {
            state,
            client_challenge,
            nonce,
            redirect_uri,
            created_at: now,
            updated_at: now,
            code_response: None,
            auth_response: None,
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
        db_run! { conn: {
            sso_auth::table
                .filter(sso_auth::state.eq(state))
                .filter(sso_auth::created_at.ge(oldest))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! {conn: {
            diesel::delete(sso_auth::table.filter(sso_auth::state.eq(self.state)))
                .execute(conn)
                .map_res("Error deleting sso_auth")
        }}
    }

    pub async fn delete_expired(pool: DbPool) -> EmptyResult {
        debug!("Purging expired sso_auth");
        if let Ok(conn) = pool.get().await {
            let oldest = Utc::now().naive_utc() - *SSO_AUTH_EXPIRATION;
            db_run! { conn: {
                diesel::delete(sso_auth::table.filter(sso_auth::created_at.lt(oldest)))
                    .execute(conn)
                    .map_res("Error deleting expired SSO nonce")
            }}
        } else {
            err!("Failed to get DB connection while purging expired sso_auth")
        }
    }
}
