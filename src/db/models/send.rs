use std::path::Path;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use data_encoding::BASE64URL_NOPAD;
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use macros::{IdFromParam, UuidFromParam};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    CONFIG,
    api::EmptyResult,
    config::PathType,
    db::{
        DbConn, DbPool,
        schema::{sends, sends_otp},
    },
    error::MapResult,
    util::{LowerCase, NumberOrString, format_date},
};

use super::{OrganizationId, User, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = sends)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Send {
    pub uuid: SendId,

    pub user_uuid: Option<UserId>,
    pub organization_uuid: Option<OrganizationId>,

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
    pub emails: Option<String>,

    pub creation_date: NaiveDateTime,
    pub revision_date: NaiveDateTime,
    pub expiration_date: Option<NaiveDateTime>,
    pub deletion_date: NaiveDateTime,

    pub disabled: bool,
    pub hide_email: Option<bool>,
}

#[derive(Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum SendType {
    Text = 0,
    File = 1,
}

enum SendAuthType {
    #[allow(dead_code)]
    // Send requires email OTP verification
    Email = 0,
    // Send requires a password
    Password = 1,
    // Send requires no auth
    None = 2,
}

impl Send {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        atype: i32,
        user_uuid: UserId,
        name: String,
        notes: Option<String>,
        data: String,
        akey: String,
        max_access_count: Option<i32>,
        emails: Option<String>,
        expiration_date: Option<NaiveDateTime>,
        deletion_date: NaiveDateTime,
        disabled: bool,
        hide_email: Option<bool>,
    ) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: SendId::from(crate::util::get_uuid()),
            user_uuid: Some(user_uuid),
            organization_uuid: None,
            name,
            notes,
            atype,
            data,
            akey,
            password_hash: None,
            password_salt: None,
            password_iter: None,

            max_access_count,
            access_count: 0,
            emails: emails.map(|e| e.to_lowercase()),

            creation_date: now,
            revision_date: now,
            expiration_date,
            deletion_date,

            disabled,
            hide_email,
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
                crate::crypto::verify_password_hash(password.as_bytes(), salt, hash, iter.cast_unsigned())
            }
            _ => false,
        }
    }

    pub async fn creator_identifier(&self, conn: &DbConn) -> Option<String> {
        if let Some(hide_email) = self.hide_email
            && hide_email
        {
            return None;
        }

        if let Some(user_uuid) = &self.user_uuid
            && let Some(user) = User::find_by_uuid(user_uuid, conn).await
        {
            return Some(user.email);
        }

        None
    }

    pub fn to_json(&self) -> Value {
        let mut data = serde_json::from_str::<LowerCase<Value>>(&self.data).map(|d| d.data).unwrap_or_default();

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(Value::as_i64) {
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
            "authType": if self.password_hash.is_some() { SendAuthType::Password } else if self.emails.is_some() { SendAuthType::Email } else { SendAuthType::None } as i32,
            "disabled": self.disabled,
            "hideEmail": self.hide_email.unwrap_or(false),
            "emails": self.emails,

            "revisionDate": format_date(&self.revision_date),
            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "deletionDate": format_date(&self.deletion_date),
            "object": "send",
        })
    }

    pub async fn to_json_access(&self, conn: &DbConn) -> Value {
        let mut data = serde_json::from_str::<LowerCase<Value>>(&self.data).map(|d| d.data).unwrap_or_default();

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(Value::as_i64) {
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

impl Send {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        self.revision_date = Utc::now().naive_utc();

        db_run! { conn:
            mysql {
                diesel::insert_into(sends::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving send")
            }
            postgresql, sqlite {
                diesel::insert_into(sends::table)
                    .values(&*self)
                    .on_conflict(sends::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving send")
            }
        }
    }

    /// Registers an access, incrementing `access_count` only while below `max_access_count`.
    /// Returns false when the limit was already reached. The check and the increment are a single
    /// statement, otherwise concurrent accesses can both pass the check and exceed the limit.
    pub async fn register_access(&mut self, conn: &DbConn) -> Result<bool, crate::Error> {
        self.update_users_revision(conn).await;

        let revision_date = Utc::now().naive_utc();
        let uuid = self.uuid.clone();
        let updated = conn
            .run(move |conn| {
                diesel::update(sends::table)
                    .filter(sends::uuid.eq(uuid))
                    .filter(
                        sends::max_access_count
                            .is_null()
                            .or(sends::access_count.nullable().lt(sends::max_access_count)),
                    )
                    .set((sends::access_count.eq(sends::access_count + 1), sends::revision_date.eq(revision_date)))
                    .execute(conn)
            })
            .await?;

        if updated == 0 {
            return Ok(false);
        }

        self.access_count += 1;
        self.revision_date = revision_date;
        Ok(true)
    }

    /// Whether the Send is currently within its validity window: not disabled, not past its
    /// expiration date, and not past its deletion date. Does not consider `max_access_count`
    /// (consumed at token issuance) or the password.
    pub fn is_accessible(&self) -> bool {
        let now = Utc::now().naive_utc();
        if self.disabled {
            return false;
        }
        if let Some(expiration) = self.expiration_date
            && now >= expiration
        {
            return false;
        }
        now < self.deletion_date
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

        if self.atype == SendType::File as i32 {
            let operator = CONFIG.opendal_operator_for_path_type(&PathType::Sends)?;
            operator.delete_with(&self.uuid).recursive(true).await.ok();
        }

        conn.run(move |conn| {
            diesel::delete(sends::table.filter(sends::uuid.eq(&self.uuid))).execute(conn).map_res("Error deleting send")
        })
        .await
    }

    /// Purge all sends that are past their deletion date.
    pub async fn purge(conn: &DbConn) {
        for send in Self::find_by_past_deletion_date(conn).await {
            send.delete(conn).await.ok();
        }
    }

    pub async fn update_users_revision(&self, conn: &DbConn) -> Vec<UserId> {
        let mut user_uuids = Vec::new();
        if let Some(user_uuid) = &self.user_uuid {
            User::update_uuid_revision(user_uuid, conn).await;
            user_uuids.push(user_uuid.clone());
        } else {
            // Belongs to Organization, not implemented
        }
        user_uuids
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        for send in Self::find_by_user(user_uuid, conn).await {
            send.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_access_id(access_id: &str, conn: &DbConn) -> Option<Self> {
        let Ok(uuid_vec) = BASE64URL_NOPAD.decode(access_id.as_bytes()) else {
            return None;
        };

        let uuid = match Uuid::from_slice(&uuid_vec) {
            Ok(u) => SendId::from(u.to_string()),
            Err(_) => return None,
        };

        Self::find_by_uuid(&uuid, conn).await
    }

    pub async fn find_by_uuid(uuid: &SendId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| sends::table.filter(sends::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_uuid_and_user(uuid: &SendId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            sends::table.filter(sends::uuid.eq(uuid)).filter(sends::user_uuid.eq(user_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            sends::table.filter(sends::user_uuid.eq(user_uuid)).load::<Self>(conn).expect("Error loading sends")
        })
        .await
    }

    pub async fn size_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<i64> {
        #[derive(serde::Deserialize)]
        struct FileData {
            #[serde(rename = "size", alias = "Size")]
            size: NumberOrString,
        }

        let sends = Self::find_by_user(user_uuid, conn).await;
        let mut total: i64 = 0;
        for send in sends {
            if send.atype == SendType::File as i32
                && let Ok(size) =
                    serde_json::from_str::<FileData>(&send.data).map_err(Into::into).and_then(|d| d.size.into_i64())
            {
                total = total.checked_add(size)?;
            }
        }

        Some(total)
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            sends::table.filter(sends::organization_uuid.eq(org_uuid)).load::<Self>(conn).expect("Error loading sends")
        })
        .await
    }

    pub async fn find_by_past_deletion_date(conn: &DbConn) -> Vec<Self> {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            sends::table.filter(sends::deletion_date.lt(now)).load::<Self>(conn).expect("Error loading sends")
        })
        .await
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct SendId(String);

impl AsRef<Path> for SendId {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

#[derive(
    Clone, Debug, AsRef, Deref, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct SendFileId(String);

impl AsRef<Path> for SendFileId {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = sends_otp)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(send_uuid, email))]
pub struct SendOTP {
    pub send_uuid: SendId,
    pub email: String,

    pub code: String,

    pub creation_date: NaiveDateTime,
    pub revision_date: NaiveDateTime,
    pub expiration_date: NaiveDateTime,
}

impl SendOTP {
    pub fn new(send_id: SendId, email: &str, code: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            send_uuid: send_id,
            email: email.to_lowercase(),
            code,
            creation_date: now,
            revision_date: now,
            expiration_date: now + TimeDelta::try_minutes(5).unwrap(),
        }
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(sends_otp::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set((
                        sends_otp::code.eq(&self.code),
                        sends_otp::expiration_date.eq(self.expiration_date),
                        sends_otp::revision_date.eq(Utc::now().naive_utc()),
                    ))
                    .execute(conn)
                    .map_res("Error saving send_otp")
            }
            postgresql, sqlite {
                diesel::insert_into(sends_otp::table)
                    .values(&*self)
                    .on_conflict((sends_otp::send_uuid, sends_otp::email))
                    .do_update()
                    .set((
                        sends_otp::code.eq(&self.code),
                        sends_otp::expiration_date.eq(self.expiration_date),
                        sends_otp::revision_date.eq(Utc::now().naive_utc()),
                    ))
                    .execute(conn)
                    .map_res("Error saving send_otp")
            }
        }
    }

    pub async fn find_with_send(uuid: &SendId, email: Option<&String>, conn: &DbConn) -> Option<(Send, Option<Self>)> {
        if let Some(mail) = email.map(|e| e.to_lowercase()) {
            conn.run(move |conn| {
                sends::table
                    .left_join(sends_otp::table.on(sends::uuid.eq(sends_otp::send_uuid).and(sends_otp::email.eq(mail))))
                    .select(<(Send, Option<Self>)>::as_select())
                    .filter(sends::uuid.eq(uuid))
                    .first::<(Send, Option<Self>)>(conn)
                    .ok()
            })
            .await
        } else {
            Send::find_by_uuid(uuid, conn).await.map(|s| (s, None))
        }
    }

    pub async fn delete_expired(pool: DbPool) -> EmptyResult {
        debug!("Purging expired sends_otp");
        if let Ok(conn) = pool.get().await {
            conn.run(move |conn| {
                diesel::delete(sends_otp::table.filter(sends_otp::expiration_date.lt(Utc::now().naive_utc())))
                    .execute(conn)
                    .map_res("Error deleting expired Sends OTP")
            })
            .await
        } else {
            err!("Failed to get DB connection while purging expired sends_otp")
        }
    }
}
