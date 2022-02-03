use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use super::{Organization, User};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "sends"]
    #[changeset_options(treat_none_as_null="true")]
    #[belongs_to(User, foreign_key = "user_uuid")]
    #[belongs_to(Organization, foreign_key = "organization_uuid")]
    #[primary_key(uuid)]
    pub struct Send {
        pub uuid: String,

        pub user_uuid: Option<String>,
        pub organization_uuid: Option<String>,


        pub name: String,
        pub notes: Option<String>,

        pub atype: i32,
        pub data: String,
        pub akey: String,
        pub password_hash: Option<Vec<u8>>,
        password_salt: Option<Vec<u8>>,
        password_iter: Option<i32>,

        pub max_access_count: Option<i32>,
        pub access_count: i32,

        pub creation_date: NaiveDateTime,
        pub revision_date: NaiveDateTime,
        pub expiration_date: Option<NaiveDateTime>,
        pub deletion_date: NaiveDateTime,

        pub disabled: bool,
        pub hide_email: Option<bool>,
    }
}

#[derive(Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum SendType {
    Text = 0,
    File = 1,
}

impl Send {
    pub fn new(atype: i32, name: String, data: String, akey: String, deletion_date: NaiveDateTime) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            user_uuid: None,
            organization_uuid: None,

            name,
            notes: None,

            atype,
            data,
            akey,
            password_hash: None,
            password_salt: None,
            password_iter: None,

            max_access_count: None,
            access_count: 0,

            creation_date: now,
            revision_date: now,
            expiration_date: None,
            deletion_date,

            disabled: false,
            hide_email: None,
        }
    }

    pub fn set_password(&mut self, password: Option<&str>) {
        const PASSWORD_ITER: i32 = 100_000;

        if let Some(password) = password {
            self.password_iter = Some(PASSWORD_ITER);
            let salt = crate::crypto::get_random_64();
            let hash = crate::crypto::hash_password(password.as_bytes(), &salt, PASSWORD_ITER as u32);
            self.password_salt = Some(salt);
            self.password_hash = Some(hash);
        } else {
            self.password_iter = None;
            self.password_salt = None;
            self.password_hash = None;
        }
    }

    pub fn check_password(&self, password: &str) -> bool {
        match (&self.password_hash, &self.password_salt, self.password_iter) {
            (Some(hash), Some(salt), Some(iter)) => {
                crate::crypto::verify_password_hash(password.as_bytes(), salt, hash, iter as u32)
            }
            _ => false,
        }
    }

    pub fn creator_identifier(&self, conn: &DbConn) -> Option<String> {
        if let Some(hide_email) = self.hide_email {
            if hide_email {
                return None;
            }
        }

        if let Some(user_uuid) = &self.user_uuid {
            if let Some(user) = User::find_by_uuid(user_uuid, conn) {
                return Some(user.email);
            }
        }

        None
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;
        use data_encoding::BASE64URL_NOPAD;
        use uuid::Uuid;

        let data: Value = serde_json::from_str(&self.data).unwrap_or_default();

        json!({
            "Id": self.uuid,
            "AccessId": BASE64URL_NOPAD.encode(Uuid::parse_str(&self.uuid).unwrap_or_default().as_bytes()),
            "Type": self.atype,

            "Name": self.name,
            "Notes": self.notes,
            "Text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "File": if self.atype == SendType::File as i32 { Some(&data) } else { None },

            "Key": self.akey,
            "MaxAccessCount": self.max_access_count,
            "AccessCount": self.access_count,
            "Password": self.password_hash.as_deref().map(|h| BASE64URL_NOPAD.encode(h)),
            "Disabled": self.disabled,
            "HideEmail": self.hide_email,

            "RevisionDate": format_date(&self.revision_date),
            "ExpirationDate": self.expiration_date.as_ref().map(format_date),
            "DeletionDate": format_date(&self.deletion_date),
            "Object": "send",
        })
    }

    pub fn to_json_access(&self, conn: &DbConn) -> Value {
        use crate::util::format_date;

        let data: Value = serde_json::from_str(&self.data).unwrap_or_default();

        json!({
            "Id": self.uuid,
            "Type": self.atype,

            "Name": self.name,
            "Text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "File": if self.atype == SendType::File as i32 { Some(&data) } else { None },

            "ExpirationDate": self.expiration_date.as_ref().map(format_date),
            "CreatorIdentifier": self.creator_identifier(conn),
            "Object": "send-access",
        })
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

impl Send {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);
        self.revision_date = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(sends::table)
                    .values(SendDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(sends::table)
                            .filter(sends::uuid.eq(&self.uuid))
                            .set(SendDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving send")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving send")
            }
            postgresql {
                let value = SendDb::to_db(self);
                diesel::insert_into(sends::table)
                    .values(&value)
                    .on_conflict(sends::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving send")
            }
        }
    }

    pub fn delete(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);

        if self.atype == SendType::File as i32 {
            std::fs::remove_dir_all(std::path::Path::new(&crate::CONFIG.sends_folder()).join(&self.uuid)).ok();
        }

        db_run! { conn: {
            diesel::delete(sends::table.filter(sends::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting send")
        }}
    }

    /// Purge all sends that are past their deletion date.
    pub fn purge(conn: &DbConn) {
        for send in Self::find_by_past_deletion_date(conn) {
            send.delete(conn).ok();
        }
    }

    pub fn update_users_revision(&self, conn: &DbConn) -> Vec<String> {
        let mut user_uuids = Vec::new();
        match &self.user_uuid {
            Some(user_uuid) => {
                User::update_uuid_revision(user_uuid, conn);
                user_uuids.push(user_uuid.clone())
            }
            None => {
                // Belongs to Organization, not implemented
            }
        };
        user_uuids
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for send in Self::find_by_user(user_uuid, conn) {
            send.delete(conn)?;
        }
        Ok(())
    }

    pub fn find_by_access_id(access_id: &str, conn: &DbConn) -> Option<Self> {
        use data_encoding::BASE64URL_NOPAD;
        use uuid::Uuid;

        let uuid_vec = match BASE64URL_NOPAD.decode(access_id.as_bytes()) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let uuid = match Uuid::from_slice(&uuid_vec) {
            Ok(u) => u.to_string(),
            Err(_) => return None,
        };

        Self::find_by_uuid(&uuid, conn)
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::uuid.eq(uuid))
                .first::<SendDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::user_uuid.eq(user_uuid))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::organization_uuid.eq(org_uuid))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }

    pub fn find_by_past_deletion_date(conn: &DbConn) -> Vec<Self> {
        let now = Utc::now().naive_utc();
        db_run! {conn: {
            sends::table
                .filter(sends::deletion_date.lt(now))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }
}
