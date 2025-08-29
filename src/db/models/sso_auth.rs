use chrono::{NaiveDateTime, Utc};
use std::time::Duration;

use crate::api::EmptyResult;
use crate::db::{DbConn, DbPool};
use crate::error::MapResult;
use crate::sso::{OIDCCode, OIDCCodeChallenge, OIDCIdentifier, OIDCState, SSO_AUTH_EXPIRATION};

use diesel::deserialize::FromSql;
use diesel::expression::AsExpression;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::{Json, Text};

#[derive(AsExpression, Clone, Debug, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = Text)]
#[diesel(sql_type = Json)]
pub enum OIDCCodeWrapper {
    Ok {
        code: OIDCCode,
    },
    Error {
        error: String,
        error_description: Option<String>,
    },
}

#[cfg(sqlite)]
impl ToSql<Text, diesel::sqlite::Sqlite> for OIDCCodeWrapper {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
        serde_json::to_string(self)
            .map(|str| {
                out.set_value(str);
                diesel::serialize::IsNull::No
            })
            .map_err(Into::into)
    }
}

#[cfg(sqlite)]
impl<B: diesel::backend::Backend> FromSql<Text, B> for OIDCCodeWrapper
where
    String: FromSql<Text, B>,
{
    fn from_sql(bytes: B::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        <String as FromSql<Text, B>>::from_sql(bytes).and_then(|str| serde_json::from_str(&str).map_err(Into::into))
    }
}

#[cfg(postgresql)]
impl FromSql<Json, diesel::pg::Pg> for OIDCCodeWrapper {
    fn from_sql(value: diesel::pg::PgValue<'_>) -> diesel::deserialize::Result<Self> {
        serde_json::from_slice(value.as_bytes()).map_err(|_| "Invalid Json".into())
    }
}

#[cfg(postgresql)]
impl ToSql<Json, diesel::pg::Pg> for OIDCCodeWrapper {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> diesel::serialize::Result {
        serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
    }
}

#[cfg(mysql)]
impl FromSql<Json, diesel::mysql::Mysql> for OIDCCodeWrapper {
    fn from_sql(value: diesel::mysql::MysqlValue<'_>) -> diesel::deserialize::Result<Self> {
        serde_json::from_slice(value.as_bytes()).map_err(|_| "Invalid Json".into())
    }
}

#[cfg(mysql)]
impl ToSql<Json, diesel::mysql::Mysql> for OIDCCodeWrapper {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> diesel::serialize::Result {
        serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
    }
}

#[derive(AsExpression, Clone, Debug, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = Text)]
#[diesel(sql_type = Json)]
pub struct OIDCAuthenticatedUser {
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_in: Option<Duration>,
    pub identifier: OIDCIdentifier,
    pub email: String,
    pub email_verified: Option<bool>,
    pub user_name: Option<String>,
}

#[cfg(sqlite)]
impl ToSql<Text, diesel::sqlite::Sqlite> for OIDCAuthenticatedUser {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
        serde_json::to_string(self)
            .map(|str| {
                out.set_value(str);
                diesel::serialize::IsNull::No
            })
            .map_err(Into::into)
    }
}

#[cfg(sqlite)]
impl<B: diesel::backend::Backend> FromSql<Text, B> for OIDCAuthenticatedUser
where
    String: FromSql<Text, B>,
{
    fn from_sql(bytes: B::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        <String as FromSql<Text, B>>::from_sql(bytes).and_then(|str| serde_json::from_str(&str).map_err(Into::into))
    }
}

#[cfg(postgresql)]
impl FromSql<Json, diesel::pg::Pg> for OIDCAuthenticatedUser {
    fn from_sql(value: diesel::pg::PgValue<'_>) -> diesel::deserialize::Result<Self> {
        serde_json::from_slice(value.as_bytes()).map_err(|_| "Invalid Json".into())
    }
}

#[cfg(postgresql)]
impl ToSql<Json, diesel::pg::Pg> for OIDCAuthenticatedUser {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> diesel::serialize::Result {
        serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
    }
}

#[cfg(mysql)]
impl FromSql<Json, diesel::mysql::Mysql> for OIDCAuthenticatedUser {
    fn from_sql(value: diesel::mysql::MysqlValue<'_>) -> diesel::deserialize::Result<Self> {
        serde_json::from_slice(value.as_bytes()).map_err(|_| "Invalid Json".into())
    }
}

#[cfg(mysql)]
impl ToSql<Json, diesel::mysql::Mysql> for OIDCAuthenticatedUser {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> diesel::serialize::Result {
        serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
    }
}

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = sso_auth)]
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
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(sso_auth::table)
                    .values(SsoAuthDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving SSO auth")
            }
            postgresql {
                let value = SsoAuthDb::to_db(self);
                diesel::insert_into(sso_auth::table)
                    .values(&value)
                    .on_conflict(sso_auth::state)
                    .do_update()
                    .set(&value)
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
                .first::<SsoAuthDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
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
