use serde_json::Value;

use super::User;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "twofactor"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[primary_key(uuid)]
pub struct TwoFactor {
    pub uuid: String,
    pub user_uuid: String,
    pub type_: i32,
    pub enabled: bool,
    pub data: String,
}

#[allow(dead_code)]
#[derive(FromPrimitive, ToPrimitive)]
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
}

/// Local methods
impl TwoFactor {
    pub fn new(user_uuid: String, type_: TwoFactorType, data: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            user_uuid,
            type_: type_ as i32,
            enabled: true,
            data,
        }
    }

    pub fn check_totp_code(&self, totp_code: u64) -> bool {
        let totp_secret = self.data.as_bytes();

        use data_encoding::BASE32;
        use oath::{totp_raw_now, HashType};

        let decoded_secret = match BASE32.decode(totp_secret) {
            Ok(s) => s,
            Err(_) => return false
        };

        let generated = totp_raw_now(&decoded_secret, 6, 0, 30, &HashType::SHA1);
        generated == totp_code
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Enabled": self.enabled,
            "Key": "", // This key and value vary
            "Object": "twoFactorAuthenticator" // This value varies
        })
    }

    pub fn to_json_list(&self) -> Value {
        json!({
            "Enabled": self.enabled,
            "Type": self.type_,
            "Object": "twoFactorProvider"
        })
    }
}

use diesel;
use diesel::prelude::*;
use crate::db::DbConn;
use crate::db::schema::twofactor;

/// Database methods
impl TwoFactor {
    pub fn save(&self, conn: &DbConn) -> QueryResult<usize> {
        diesel::replace_into(twofactor::table)
            .values(self)
            .execute(&**conn)
    }

    pub fn delete(self, conn: &DbConn) -> QueryResult<usize> {
        diesel::delete(
            twofactor::table.filter(
                twofactor::uuid.eq(self.uuid)
            )
        ).execute(&**conn)
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        twofactor::table
            .filter(twofactor::user_uuid.eq(user_uuid))
            .load::<Self>(&**conn).expect("Error loading twofactor")
    }

    pub fn find_by_user_and_type(user_uuid: &str, type_: i32, conn: &DbConn) -> Option<Self> {
        twofactor::table
            .filter(twofactor::user_uuid.eq(user_uuid))
            .filter(twofactor::type_.eq(type_))
            .first::<Self>(&**conn).ok()
    }
    
    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> QueryResult<usize> {
        diesel::delete(
            twofactor::table.filter(
                twofactor::user_uuid.eq(user_uuid)
            )
        ).execute(&**conn)
    }
}
