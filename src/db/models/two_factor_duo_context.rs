use chrono::Utc;

use crate::{api::EmptyResult, db::DbConn, error::MapResult};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = twofactor_duo_ctx)]
    #[diesel(primary_key(state))]
    pub struct TwoFactorDuoContext {
        pub state: String,
        pub user_email: String,
        pub nonce: String,
        pub exp: i64,
    }
}

impl TwoFactorDuoContext {
    pub async fn find_by_state(state: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! {
            conn: {
                twofactor_duo_ctx::table
                    .filter(twofactor_duo_ctx::state.eq(state))
                    .first::<TwoFactorDuoContextDb>(conn)
                    .ok()
                    .from_db()
            }
        }
    }

    pub async fn save(state: &str, user_email: &str, nonce: &str, ttl: i64, conn: &mut DbConn) -> EmptyResult {
        // A saved context should never be changed, only created or deleted.
        let exists = Self::find_by_state(state, conn).await;
        if exists.is_some() {
            return Ok(());
        };

        let exp = Utc::now().timestamp() + ttl;

        db_run! {
            conn: {
                diesel::insert_into(twofactor_duo_ctx::table)
                    .values((
                        twofactor_duo_ctx::state.eq(state),
                        twofactor_duo_ctx::user_email.eq(user_email),
                        twofactor_duo_ctx::nonce.eq(nonce),
                        twofactor_duo_ctx::exp.eq(exp)
                ))
                .execute(conn)
                .map_res("Error saving context to twofactor_duo_ctx")
            }
        }
    }

    pub async fn find_expired(conn: &mut DbConn) -> Vec<Self> {
        let now = Utc::now().timestamp();
        db_run! {
            conn: {
                twofactor_duo_ctx::table
                    .filter(twofactor_duo_ctx::exp.lt(now))
                    .load::<TwoFactorDuoContextDb>(conn)
                    .expect("Error finding expired contexts in twofactor_duo_ctx")
                    .from_db()
            }
        }
    }

    pub async fn delete(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! {
            conn: {
                diesel::delete(
                    twofactor_duo_ctx::table
                    .filter(twofactor_duo_ctx::state.eq(&self.state)))
                    .execute(conn)
                    .map_res("Error deleting from twofactor_duo_ctx")
            }
        }
    }

    pub async fn purge_expired_duo_contexts(conn: &mut DbConn) {
        for context in Self::find_expired(conn).await {
            context.delete(conn).await.ok();
        }
    }
}
