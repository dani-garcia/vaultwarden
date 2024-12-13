use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use crate::util::LowerCase;

use super::User;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = sends)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
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
            let salt = crate::crypto::get_random_bytes::<64>().to_vec();
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

    pub async fn creator_identifier(&self, conn: &mut DbConn) -> Option<String> {
        if let Some(hide_email) = self.hide_email {
            if hide_email {
                return None;
            }
        }

        if let Some(user_uuid) = &self.user_uuid {
            if let Some(user) = User::find_by_uuid(user_uuid, conn).await {
                return Some(user.email);
            }
        }

        None
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;
        use data_encoding::BASE64URL_NOPAD;
        use uuid::Uuid;

        let mut data = serde_json::from_str::<LowerCase<Value>>(&self.data).map(|d| d.data).unwrap_or_default();

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
            data["size"] = Value::String(size.to_string());
        }

        json!({
            "id": self.uuid,
            "accessId": BASE64URL_NOPAD.encode(Uuid::parse_str(&self.uuid).unwrap_or_default().as_bytes()),
            "type": self.atype,

            "name": self.name,
            "notes": self.notes,
            "text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.atype == SendType::File as i32 { Some(&data) } else { None },

            "key": self.akey,
            "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count,
            "password": self.password_hash.as_deref().map(|h| BASE64URL_NOPAD.encode(h)),
            "disabled": self.disabled,
            "hideEmail": self.hide_email,

            "revisionDate": format_date(&self.revision_date),
            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "deletionDate": format_date(&self.deletion_date),
            "object": "send",
        })
    }

    pub async fn to_json_access(&self, conn: &mut DbConn) -> Value {
        use crate::util::format_date;

        let mut data = serde_json::from_str::<LowerCase<Value>>(&self.data).map(|d| d.data).unwrap_or_default();

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
            data["size"] = Value::String(size.to_string());
        }

        json!({
            "id": self.uuid,
            "type": self.atype,

            "name": self.name,
            "text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.atype == SendType::File as i32 { Some(&data) } else { None },

            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "creatorIdentifier": self.creator_identifier(conn).await,
            "object": "send-access",
        })
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;
use crate::util::NumberOrString;

impl Send {
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
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

    pub async fn delete(&self, conn: &mut DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

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
    pub async fn purge(conn: &mut DbConn) {
        for send in Self::find_by_past_deletion_date(conn).await {
            send.delete(conn).await.ok();
        }
    }

    pub async fn update_users_revision(&self, conn: &mut DbConn) -> Vec<String> {
        let mut user_uuids = Vec::new();
        match &self.user_uuid {
            Some(user_uuid) => {
                User::update_uuid_revision(user_uuid, conn).await;
                user_uuids.push(user_uuid.clone())
            }
            None => {
                // Belongs to Organization, not implemented
            }
        };
        user_uuids
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for send in Self::find_by_user(user_uuid, conn).await {
            send.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_access_id(access_id: &str, conn: &mut DbConn) -> Option<Self> {
        use data_encoding::BASE64URL_NOPAD;
        use uuid::Uuid;

        let Ok(uuid_vec) = BASE64URL_NOPAD.decode(access_id.as_bytes()) else {
            return None;
        };

        let uuid = match Uuid::from_slice(&uuid_vec) {
            Ok(u) => u.to_string(),
            Err(_) => return None,
        };

        Self::find_by_uuid(&uuid, conn).await
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::uuid.eq(uuid))
                .first::<SendDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::uuid.eq(uuid))
                .filter(sends::user_uuid.eq(user_uuid))
                .first::<SendDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::user_uuid.eq(user_uuid))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }

    pub async fn size_by_user(user_uuid: &str, conn: &mut DbConn) -> Option<i64> {
        let sends = Self::find_by_user(user_uuid, conn).await;

        #[derive(serde::Deserialize)]
        struct FileData {
            #[serde(rename = "size", alias = "Size")]
            size: NumberOrString,
        }

        let mut total: i64 = 0;
        for send in sends {
            if send.atype == SendType::File as i32 {
                if let Ok(size) =
                    serde_json::from_str::<FileData>(&send.data).map_err(Into::into).and_then(|d| d.size.into_i64())
                {
                    total = total.checked_add(size)?;
                };
            }
        }

        Some(total)
    }

    pub async fn find_by_org(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! {conn: {
            sends::table
                .filter(sends::organization_uuid.eq(org_uuid))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }

    pub async fn find_by_past_deletion_date(conn: &mut DbConn) -> Vec<Self> {
        let now = Utc::now().naive_utc();
        db_run! {conn: {
            sends::table
                .filter(sends::deletion_date.lt(now))
                .load::<SendDb>(conn).expect("Error loading sends").from_db()
        }}
    }
}
