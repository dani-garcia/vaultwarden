use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use crypto;
use CONFIG;


#[derive(Debug, Identifiable, Queryable, Insertable)]
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
    
    #[column_name = "totp_secret"]
    _totp_secret: Option<String>,
    pub totp_recover: Option<String>,

    pub security_stamp: String,

    pub equivalent_domains: String,
    pub excluded_globals: String,
    
    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
}

/// Local methods
impl User {
    pub const CLIENT_KDF_TYPE_DEFAULT: i32 = 0; // PBKDF2: 0
    pub const CLIENT_KDF_ITER_DEFAULT: i32 = 5_000;

    pub fn new(mail: String) -> Self {
        let now = Utc::now().naive_utc();
        let email = mail.to_lowercase();

        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            name: email.clone(),
            email,
            key: String::new(),

            password_hash: Vec::new(),
            salt: crypto::get_random_64(),
            password_iterations: CONFIG.password_iterations,

            security_stamp: Uuid::new_v4().to_string(),

            password_hint: None,
            private_key: None,
            public_key: None,
            
            _totp_secret: None,
            totp_recover: None,

            equivalent_domains: "[]".to_string(),
            excluded_globals: "[]".to_string(),
            
            client_kdf_type: Self::CLIENT_KDF_TYPE_DEFAULT,
            client_kdf_iter: Self::CLIENT_KDF_ITER_DEFAULT,
        }
    }

    pub fn check_valid_password(&self, password: &str) -> bool {
        crypto::verify_password_hash(password.as_bytes(),
                                     &self.salt,
                                     &self.password_hash,
                                     self.password_iterations as u32)
    }

    pub fn check_valid_recovery_code(&self, recovery_code: &str) -> bool {
        if let Some(ref totp_recover) = self.totp_recover {
            recovery_code == totp_recover.to_lowercase()
        } else {
            false
        }
    }

    pub fn set_password(&mut self, password: &str) {
        self.password_hash = crypto::hash_password(password.as_bytes(),
                                                   &self.salt,
                                                   self.password_iterations as u32);
        self.reset_security_stamp();
    }

    pub fn reset_security_stamp(&mut self) {
        self.security_stamp = Uuid::new_v4().to_string();
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::{users, invitations};

/// Database methods
impl User {
    pub fn to_json(&self, conn: &DbConn) -> JsonValue {
        use super::UserOrganization;
        use super::TwoFactor;

        let orgs = UserOrganization::find_by_user(&self.uuid, conn);
        let orgs_json: Vec<JsonValue> = orgs.iter().map(|c| c.to_json(&conn)).collect();

        let twofactor_enabled = !TwoFactor::find_by_user(&self.uuid, conn).is_empty();

        json!({
            "Id": self.uuid,
            "Name": self.name,
            "Email": self.email,
            "EmailVerified": true,
            "Premium": true,
            "MasterPasswordHint": self.password_hint,
            "Culture": "en-US",
            "TwoFactorEnabled": twofactor_enabled,
            "Key": self.key,
            "PrivateKey": self.private_key,
            "SecurityStamp": self.security_stamp,
            "Organizations": orgs_json,
            "Object": "profile"
        })
    }


    pub fn save(&mut self, conn: &DbConn) -> bool {
        self.updated_at = Utc::now().naive_utc();

        match diesel::replace_into(users::table) // Insert or update
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(users::table.filter(
            users::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn update_uuid_revision(uuid: &str, conn: &DbConn) {
        if let Some(mut user) = User::find_by_uuid(&uuid, conn) {
            if user.update_revision(conn).is_err(){
                println!("Warning: Failed to update revision for {}", user.email);
            };
        };
    }

    pub fn update_revision(&mut self, conn: &DbConn) -> QueryResult<()> {
        self.updated_at = Utc::now().naive_utc();
        diesel::update(
            users::table.filter(
                users::uuid.eq(&self.uuid)
            )
        )
        .set(users::updated_at.eq(&self.updated_at))
        .execute(&**conn).and(Ok(()))
    }

    pub fn find_by_mail(mail: &str, conn: &DbConn) -> Option<Self> {
        let lower_mail = mail.to_lowercase();
        users::table
            .filter(users::email.eq(lower_mail))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        users::table
            .filter(users::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }
}

#[derive(Debug, Identifiable, Queryable, Insertable)]
#[table_name = "invitations"]
#[primary_key(email)]
pub struct Invitation {
    pub email: String,
}

impl Invitation {
    pub fn new(email: String) -> Self {
        Self {
            email
        }
    }

    pub fn save(&mut self, conn: &DbConn) -> QueryResult<()> {
        diesel::replace_into(invitations::table)
        .values(&*self)
        .execute(&**conn)
        .and(Ok(()))
    }

    pub fn delete(self, conn: &DbConn) -> QueryResult<()> {
        diesel::delete(invitations::table.filter(
        invitations::email.eq(self.email)))
        .execute(&**conn)
        .and(Ok(()))
    }

    pub fn find_by_mail(mail: &str, conn: &DbConn) -> Option<Self> {
        let lower_mail = mail.to_lowercase();
        invitations::table
            .filter(invitations::email.eq(lower_mail))
            .first::<Self>(&**conn).ok()
    }

    pub fn take(mail: &str, conn: &DbConn) -> bool {
        CONFIG.invitations_allowed &&
        match Self::find_by_mail(mail, &conn) {
            Some(invitation) => invitation.delete(&conn).is_ok(),
            None => false
        }
    }
}