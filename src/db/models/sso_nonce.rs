use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;

use super::Organization;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "sso_nonce"]
    #[belongs_to(Organization, foreign_key = "org_uuid")]
    #[primary_key(uuid)]
    pub struct SsoNonce {
        pub uuid: String,
        pub org_uuid: String,
        pub nonce: String,
    }
}

/// Local methods
impl SsoNonce {
    pub fn new(org_uuid: String, nonce: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            org_uuid,
            nonce,
        }
    }
}

/// Database methods
impl SsoNonce {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(sso_nonce::table)
                    .values(SsoNonceDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving device")
            }
            postgresql {
                let value = SsoNonceDb::to_db(self);
                diesel::insert_into(sso_nonce::table)
                    .values(&value)
                    .on_conflict(sso_nonce::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving SSO nonce")
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(sso_nonce::table.filter(sso_nonce::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting SSO nonce")
        }}
    }

    pub fn find_by_org_and_nonce(org_uuid: &str, nonce: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            sso_nonce::table
                .filter(sso_nonce::org_uuid.eq(org_uuid))
                .filter(sso_nonce::nonce.eq(nonce))
                .first::<SsoNonceDb>(conn)
                .ok()
                .from_db()
        }}
    }
}
