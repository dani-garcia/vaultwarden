use chrono::{NaiveDateTime, Utc};
use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::User;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "ciphers"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[primary_key(uuid)]
pub struct Cipher {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: String,
    pub folder_uuid: Option<String>,
    pub organization_uuid: Option<String>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    */
    pub type_: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,

    pub data: String,

    pub favorite: bool,
}

/// Local methods
impl Cipher {
    pub fn new(user_uuid: String, type_: i32, name: String, favorite: bool) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,

            user_uuid,
            folder_uuid: None,
            organization_uuid: None,

            type_,
            favorite,
            name,

            notes: None,
            fields: None,

            data: String::new(),
        }
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::ciphers;

/// Database methods
impl Cipher {
    pub fn to_json(&self, host: &str, conn: &DbConn) -> JsonValue {
        use serde_json;
        use util::format_date;
        use super::Attachment;

        let attachments = Attachment::find_by_cipher(&self.uuid, conn);
        let attachments_json: Vec<JsonValue> = attachments.iter().map(|c| c.to_json(host)).collect();

        let fields_json: JsonValue = if let Some(ref fields) = self.fields {
            serde_json::from_str(fields).unwrap()
        } else { JsonValue::Null };

        let mut data_json: JsonValue = serde_json::from_str(&self.data).unwrap();

        // TODO: ******* Backwards compat start **********
        // To remove backwards compatibility, just remove this entire section
        // and remove the compat code from ciphers::update_cipher_from_data
        if self.type_ == 1 && data_json["Uris"].is_array() {
            let uri = data_json["Uris"][0]["uri"].clone();
            data_json["Uri"] = uri;
        }
        // TODO: ******* Backwards compat end **********

        let mut json_object = json!({
            "Id": self.uuid,
            "Type": self.type_,
            "RevisionDate": format_date(&self.updated_at),
            "FolderId": self.folder_uuid,
            "Favorite": self.favorite,
            "OrganizationId": self.organization_uuid,
            "Attachments": attachments_json,
            "OrganizationUseTotp": false,

            "Name": self.name,
            "Notes": self.notes,
            "Fields": fields_json,

            "Data": data_json,

            "Object": "cipher",
            "Edit": true,
        });

        let key = match self.type_ {
            1 => "Login",
            2 => "SecureNote",
            3 => "Card",
            4 => "Identity",
            _ => panic!("Wrong type"),
        };

        json_object[key] = data_json;
        json_object
    }

    pub fn save(&mut self, conn: &DbConn) -> bool {
        self.updated_at = Utc::now().naive_utc();

        match diesel::replace_into(ciphers::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(ciphers::table.filter(
            ciphers::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        ciphers::table
            .filter(ciphers::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
            .filter(ciphers::user_uuid.eq(user_uuid))
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
            .filter(ciphers::organization_uuid.eq(org_uuid))
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    pub fn find_by_folder(folder_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
            .filter(ciphers::folder_uuid.eq(folder_uuid))
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }
}
