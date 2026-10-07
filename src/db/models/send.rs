use std::path::Path;

use chrono::{NaiveDateTime, Utc};
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
    db::{DbConn, schema::sends},
    error::MapResult,
    util::{LowerCase, NumberOrString, format_date},
};

use super::{OrganizationId, User, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
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
    // A shared vault item, encrypted client side as a single blob (temporary item sharing)
    Item = 2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum SendAuthType {
    // Send requires email OTP verification
    Email = 0,
    // Send requires a password
    Password = 1,
    // Send requires no auth
    None = 2,
}

/// Key inside `sends.data` holding the normalized, comma separated list of emails allowed to
/// access an email verified Send. It lives inside `data` instead of a new column so the feature
/// needs no schema change, and it is stripped before `data` is sent to any client.
const AUTH_EMAILS_KEY: &str = "vwAuthEmails";

/// Normalizes a comma separated email list: trimmed, lowercased, deduplicated, empty entries dropped.
pub fn normalize_emails(emails: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in emails.split(',').map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) {
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

impl Send {
    pub fn new(atype: i32, name: String, data: String, akey: String, deletion_date: NaiveDateTime) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: SendId::from(crate::util::get_uuid()),
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

    fn access_id(&self) -> String {
        BASE64URL_NOPAD.encode(Uuid::parse_str(&self.uuid).unwrap_or_default().as_bytes())
    }

    /// The emails allowed to access this Send through email OTP verification, if any.
    pub fn auth_emails(&self) -> Option<Vec<String>> {
        let data = serde_json::from_str::<Value>(&self.data).ok()?;
        let emails = normalize_emails(data.get(AUTH_EMAILS_KEY)?.as_str()?);
        (!emails.is_empty()).then_some(emails)
    }

    /// Stores (or removes, with `None` or an empty list) the emails allowed to access this Send.
    /// Setting emails clears the password: the two auth methods are mutually exclusive.
    pub fn set_auth_emails(&mut self, emails: Option<&str>) -> EmptyResult {
        let mut data = serde_json::from_str::<Value>(&self.data).unwrap_or_else(|_| json!({}));
        let Some(obj) = data.as_object_mut() else {
            err!("Invalid Send data")
        };
        let emails = emails.map(normalize_emails).unwrap_or_default();
        if emails.is_empty() {
            obj.remove(AUTH_EMAILS_KEY);
        } else {
            obj.insert(AUTH_EMAILS_KEY.to_owned(), Value::String(emails.join(",")));
            self.set_password(None);
        }
        self.data = serde_json::to_string(&data)?;
        Ok(())
    }

    pub fn auth_type(&self) -> SendAuthType {
        // Item Sends are always email verified, matching the Bitwarden server
        if self.atype == SendType::Item as i32 || self.auth_emails().is_some() {
            SendAuthType::Email
        } else if self.password_hash.is_some() {
            SendAuthType::Password
        } else {
            SendAuthType::None
        }
    }

    /// The `data` column as sent to clients: keys lowercased and the server side auth list removed.
    fn client_data(&self) -> Value {
        let mut data = serde_json::from_str::<LowerCase<Value>>(&self.data).map(|d| d.data).unwrap_or_default();
        if let Some(obj) = data.as_object_mut() {
            obj.remove(AUTH_EMAILS_KEY);
        }

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(Value::as_i64) {
            data["size"] = Value::String(size.to_string());
        }
        data
    }

    pub fn to_json(&self) -> Value {
        let data = self.client_data();

        json!({
            "id": self.uuid,
            "accessId": self.access_id(),
            "type": self.atype,

            "name": self.name,
            "notes": self.notes,
            "text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.atype == SendType::File as i32 { Some(&data) } else { None },
            "data": if self.atype == SendType::Item as i32 { Some(&data) } else { None },

            "key": self.akey,
            "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count,
            "password": self.password_hash.as_deref().map(|h| BASE64URL_NOPAD.encode(h)),
            "emails": self.auth_emails().map(|e| e.join(",")),
            "authType": self.auth_type() as i32,
            "disabled": self.disabled,
            "hideEmail": self.hide_email.unwrap_or(false),

            "revisionDate": format_date(&self.revision_date),
            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "deletionDate": format_date(&self.deletion_date),
            "object": "send",
        })
    }

    pub async fn to_json_access(&self, conn: &DbConn) -> Value {
        let data = self.client_data();

        json!({
            "id": self.access_id(),
            "type": self.atype,
            "authType": self.auth_type() as i32,

            "name": self.name,
            "text": if self.atype == SendType::Text as i32 { Some(&data) } else { None },
            "file": if self.atype == SendType::File as i32 { Some(&data) } else { None },
            "data": if self.atype == SendType::Item as i32 { Some(&data) } else { None },

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
    /// (counted on each access) or the password.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn new_send(atype: SendType, data: &str) -> Send {
        let deletion = Utc::now().naive_utc() + chrono::TimeDelta::try_days(1).unwrap();
        Send::new(atype as i32, "2.name".into(), data.into(), "2.key".into(), deletion)
    }

    #[test]
    fn normalize_emails_trims_lowercases_and_dedups() {
        assert_eq!(normalize_emails(" A@x.com, b@Y.com,,a@x.com , "), vec!["a@x.com", "b@y.com"]);
        assert!(normalize_emails(" , ").is_empty());
    }

    #[test]
    fn auth_emails_round_trip_and_clear_password() {
        let mut send = new_send(SendType::Text, r#"{"text":"2.t","hidden":false}"#);
        send.set_password(Some("hash"));
        send.set_auth_emails(Some("B@y.com, a@x.com")).unwrap();

        assert_eq!(send.auth_emails(), Some(vec!["b@y.com".to_string(), "a@x.com".to_string()]));
        assert!(send.password_hash.is_none(), "email and password auth are exclusive");
        assert_eq!(send.auth_type(), SendAuthType::Email);

        send.set_auth_emails(None).unwrap();
        assert_eq!(send.auth_emails(), None);
        assert_eq!(send.auth_type(), SendAuthType::None);
        assert!(!send.data.contains(AUTH_EMAILS_KEY));
    }

    #[test]
    fn email_list_never_reaches_clients() {
        let mut send = new_send(SendType::Text, r#"{"text":"2.t","hidden":false}"#);
        send.set_auth_emails(Some("a@x.com")).unwrap();

        let json = send.to_json();
        assert_eq!(json["emails"], "a@x.com");
        assert_eq!(json["authType"], SendAuthType::Email as i32);
        assert!(json["text"].get(AUTH_EMAILS_KEY).is_none());
        assert_eq!(json["text"]["text"], "2.t");
    }

    #[test]
    fn item_send_json_carries_data_and_is_email_verified() {
        let send = new_send(SendType::Item, r#"{"encryptionVersion":1,"data":"{\"id\":\"c\"}"}"#);

        let json = send.to_json();
        assert_eq!(json["type"], 2);
        assert!(json["text"].is_null() && json["file"].is_null());
        assert_eq!(json["data"]["encryptionVersion"], 1);
        assert_eq!(json["data"]["data"], "{\"id\":\"c\"}");
        assert_eq!(send.auth_type(), SendAuthType::Email, "Item Sends are always email verified");
    }

    #[test]
    fn password_auth_type() {
        let mut send = new_send(SendType::Text, r#"{"text":"2.t"}"#);
        assert_eq!(send.auth_type(), SendAuthType::None);
        send.set_password(Some("hash"));
        assert_eq!(send.auth_type(), SendAuthType::Password);
    }
}
