use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;

use super::User;

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "twofactor"]
    #[belongs_to(User, foreign_key = "user_uuid")]
    #[primary_key(uuid)]
    pub struct TwoFactor {
        pub uuid: String,
        pub user_uuid: String,
        pub atype: i32,
        pub enabled: bool,
        pub data: String,
        pub last_used: i32,
    }
}

#[allow(dead_code)]
#[derive(num_derive::FromPrimitive)]
pub enum TwoFactorType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,

    // These are implementation details
    U2fRegisterChallenge = 1000,
    U2fLoginChallenge = 1001,
    EmailVerificationChallenge = 1002,
}

/// Local methods
impl TwoFactor {
    pub fn new(user_uuid: String, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            user_uuid,
            atype: atype as i32,
            enabled: true,
            data,
            last_used: 0,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Enabled": self.enabled,
            "Key": "", // This key and value vary
            "Object": "twoFactorAuthenticator" // This value varies
        })
    }

    pub fn to_json_provider(&self) -> Value {
        json!({
            "Enabled": self.enabled,
            "Type": self.atype,
            "Object": "twoFactorProvider"
        })
    }
}

/// Database methods
impl TwoFactor {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: 
            sqlite, mysql {
                diesel::replace_into(twofactor::table)
                    .values(TwoFactorDb::to_db(self))
                    .execute(conn)
                    .map_res("Error saving twofactor")        
            }
            postgresql {
                let value = TwoFactorDb::to_db(self);
                // We need to make sure we're not going to violate the unique constraint on user_uuid and atype.
                // This happens automatically on other DBMS backends due to replace_into(). PostgreSQL does
                // not support multiple constraints on ON CONFLICT clauses.
                diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq(&self.user_uuid)).filter(twofactor::atype.eq(&self.atype)))
                    .execute(conn)
                    .map_res("Error deleting twofactor for insert")?;

                diesel::insert_into(twofactor::table)
                    .values(&value)
                    .on_conflict(twofactor::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving twofactor")            
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor::table.filter(twofactor::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting twofactor")
        }}
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.lt(1000)) // Filter implementation types
                .load::<TwoFactorDb>(conn)
                .expect("Error loading twofactor")
                .from_db()
        }}
    }

    pub fn find_by_user_and_type(user_uuid: &str, atype: i32, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.eq(atype))
                .first::<TwoFactorDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting twofactors")
        }}
    }
}
