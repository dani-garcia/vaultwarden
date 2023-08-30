use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;

db_object! {
    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = sso_nonce)]
    #[diesel(primary_key(nonce))]
    pub struct SsoNonce {
        pub nonce: String,
    }
}

/// Local methods
impl SsoNonce {
    pub fn new(nonce: String) -> Self {
        Self {
            nonce,
        }
    }
}

/// Database methods
impl SsoNonce {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(sso_nonce::table)
                    .values(SsoNonceDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving SSO device")
            }
            postgresql {
                let value = SsoNonceDb::to_db(self);
                diesel::insert_into(sso_nonce::table)
                    .values(&value)
                    .execute(conn)
                    .map_res("Error saving SSO nonce")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(sso_nonce::table.filter(sso_nonce::nonce.eq(self.nonce)))
                .execute(conn)
                .map_res("Error deleting SSO nonce")
        }}
    }

    pub async fn find(nonce: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            sso_nonce::table
                .filter(sso_nonce::nonce.eq(nonce))
                .first::<SsoNonceDb>(conn)
                .ok()
                .from_db()
        }}
    }
}
