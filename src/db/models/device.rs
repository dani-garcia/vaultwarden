use chrono::{NaiveDateTime, Utc};

use super::User;
use crate::CONFIG;

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "devices"]
    #[changeset_options(treat_none_as_null="true")]
    #[belongs_to(User, foreign_key = "user_uuid")]
    #[primary_key(uuid)]
    pub struct Device {
        pub uuid: String,
        pub created_at: NaiveDateTime,
        pub updated_at: NaiveDateTime,

        pub user_uuid: String,

        pub name: String,
        // https://github.com/bitwarden/core/tree/master/src/Core/Enums
        pub atype: i32,
        pub push_token: Option<String>,

        pub refresh_token: String,

        pub twofactor_remember: Option<String>,
    }
}

/// Local methods
impl Device {
    pub fn new(uuid: String, user_uuid: String, name: String, atype: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_token: None,
            refresh_token: String::new(),
            twofactor_remember: None,
        }
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use crate::crypto;
        use data_encoding::BASE64;

        let twofactor_remember = BASE64.encode(&crypto::get_random(vec![0u8; 180]));
        self.twofactor_remember = Some(twofactor_remember.clone());

        twofactor_remember
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    pub fn refresh_tokens(&mut self, user: &super::User, orgs: Vec<super::UserOrganization>) -> (String, i64) {
        // If there is no refresh token, we create one
        if self.refresh_token.is_empty() {
            use crate::crypto;
            use data_encoding::BASE64URL;

            self.refresh_token = BASE64URL.encode(&crypto::get_random_64());
        }

        // Update the expiration of the device and the last update date
        let time_now = Utc::now().naive_utc();
        self.updated_at = time_now;

        let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == 0).map(|o| o.org_uuid.clone()).collect();
        let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == 1).map(|o| o.org_uuid.clone()).collect();
        let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == 2).map(|o| o.org_uuid.clone()).collect();
        let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == 3).map(|o| o.org_uuid.clone()).collect();

        // Create the JWT claims struct, to send to the client
        use crate::auth::{encode_jwt, LoginJWTClaims, DEFAULT_VALIDITY, JWT_LOGIN_ISSUER};
        let claims = LoginJWTClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + *DEFAULT_VALIDITY).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid.to_string(),

            premium: true,
            name: user.name.to_string(),
            email: user.email.to_string(),
            email_verified: !CONFIG.mail_enabled() || user.verified_at.is_some(),

            orgowner,
            orgadmin,
            orguser,
            orgmanager,

            sstamp: user.security_stamp.to_string(),
            device: self.uuid.to_string(),
            scope: vec!["api".into(), "offline_access".into()],
            amr: vec!["Application".into()],
        };

        (encode_jwt(&claims), DEFAULT_VALIDITY.num_seconds())
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Device {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn: 
            sqlite, mysql {
                crate::util::retry(
                    || diesel::replace_into(devices::table).values(DeviceDb::to_db(self)).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql {
                let value = DeviceDb::to_db(self);
                crate::util::retry(
                    || diesel::insert_into(devices::table).values(&value).on_conflict(devices::uuid).do_update().set(&value).execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(devices::table.filter(devices::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing device")
        }}
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for device in Self::find_by_user(user_uuid, &conn) {
            device.delete(&conn)?;
        }
        Ok(())
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_refresh_token(refresh_token: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::refresh_token.eq(refresh_token))
                .first::<DeviceDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .load::<DeviceDb>(conn)
                .expect("Error loading devices")
                .from_db()
        }}
    }
}
