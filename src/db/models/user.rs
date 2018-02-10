use chrono::{NaiveDate, NaiveDateTime, Utc};
use time::Duration;
use serde_json::Value as JsonValue;

use uuid::Uuid;

use CONFIG;

#[derive(Queryable, Insertable, Identifiable)]
#[table_name = "users"]
#[primary_key(uuid)]
pub struct User {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub email: String,
    pub name: String,

    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub password_iterations: i32,
    pub password_hint: Option<String>,

    pub key: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_recover: Option<String>,
    pub security_stamp: String,
}

/// Local methods
impl User {
    pub fn new(mail: String, key: String, password: String) -> User {
        let now = Utc::now().naive_utc();
        let email = mail.to_lowercase();

        use crypto;

        let iterations = CONFIG.password_iterations;
        let salt = crypto::get_random_64();
        let password_hash = crypto::hash_password(password.as_bytes(), &salt, iterations as u32);

        User {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            name: email.clone(),
            email,
            key,

            password_hash,
            salt,
            password_iterations: iterations,

            security_stamp: Uuid::new_v4().to_string(),

            password_hint: None,
            private_key: None,
            public_key: None,
            totp_secret: None,
            totp_recover: None,
        }
    }

    pub fn check_valid_password(&self, password: &str) -> bool {
        use crypto;

        crypto::verify_password_hash(password.as_bytes(),
                                     &self.salt,
                                     &self.password_hash,
                                     self.password_iterations as u32)
    }

    pub fn set_password(&mut self, password: &str) {
        use crypto;
        self.password_hash = crypto::hash_password(password.as_bytes(),
                                                   &self.salt,
                                                   self.password_iterations as u32);
        self.reset_security_stamp();
    }

    pub fn reset_security_stamp(&mut self) {
        self.security_stamp = Uuid::new_v4().to_string();
    }

    pub fn check_totp_code(&self, totp_code: Option<u64>) -> bool {
        if let Some(ref totp_secret) = self.totp_secret {
            if let Some(code) = totp_code {
                // Validate totp
                use data_encoding::BASE32;
                use oath::{totp_raw_now, HashType};

                let decoded_secret = match BASE32.decode(totp_secret.as_bytes()) {
                    Ok(s) => s,
                    Err(e) => return false
                };

                let generated = totp_raw_now(&decoded_secret, 6, 0, 30, &HashType::SHA1);
                generated == code
            } else {
                false
            }
        } else {
            true
        }
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "Name": self.name,
            "Email": self.email,
            "EmailVerified": true,
            "Premium": true,
            "MasterPasswordHint": self.password_hint,
            "Culture": "en-US",
            "TwoFactorEnabled": self.totp_secret.is_some(),
            "Key": self.key,
            "PrivateKey": self.private_key,
            "SecurityStamp": self.security_stamp,
            "Organizations": [],
            "Object": "profile"
        })
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::users;

/// Database methods
impl User {
    pub fn save(&self, conn: &DbConn) -> bool {
        // TODO: Update modified date

        match diesel::replace_into(users::table) // Insert or update
            .values(self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn find_by_mail(mail: &str, conn: &DbConn) -> Option<User> {
        let lower_mail = mail.to_lowercase();
        users::table
            .filter(users::email.eq(lower_mail))
            .first::<User>(&**conn).ok()
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<User> {
        users::table
            .filter(users::uuid.eq(uuid))
            .first::<User>(&**conn).ok()
    }
}
