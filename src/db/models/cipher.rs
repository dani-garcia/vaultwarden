use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use super::{
    Attachment, CollectionCipher, FolderCipher, Organization, User, UserOrgStatus, UserOrgType, UserOrganization,
};

#[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
#[table_name = "ciphers"]
#[changeset_options(treat_none_as_null="true")]
#[belongs_to(User, foreign_key = "user_uuid")]
#[belongs_to(Organization, foreign_key = "organization_uuid")]
#[primary_key(uuid)]
pub struct Cipher {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    */
    pub atype: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,

    pub data: String,

    pub favorite: bool,
    pub password_history: Option<String>,
    pub deleted_at: Option<NaiveDateTime>,
}

/// Local methods
impl Cipher {
    pub fn new(atype: i32, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            created_at: now,
            updated_at: now,

            user_uuid: None,
            organization_uuid: None,

            atype,
            favorite: false,
            name,

            notes: None,
            fields: None,

            data: String::new(),
            password_history: None,
            deleted_at: None,
        }
    }
}

use crate::db::schema::*;
use crate::db::DbConn;
use diesel::prelude::*;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Cipher {
    pub fn to_json(&self, host: &str, user_uuid: &str, conn: &DbConn) -> Value {
        use crate::util::format_date;

        let attachments = Attachment::find_by_cipher(&self.uuid, conn);
        let attachments_json: Vec<Value> = attachments.iter().map(|c| c.to_json(host)).collect();

        let fields_json = self.fields.as_ref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
        let password_history_json = self.password_history.as_ref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);

        // Get the data or a default empty value to avoid issues with the mobile apps
        let mut data_json: Value = serde_json::from_str(&self.data).unwrap_or_else(|_| json!({
            "Fields":null,
            "Name": self.name,
            "Notes":null,
            "Password":null,
            "PasswordHistory":null,
            "PasswordRevisionDate":null,
            "Response":null,
            "Totp":null,
            "Uris":null,
            "Username":null
        }));

        // TODO: ******* Backwards compat start **********
        // To remove backwards compatibility, just remove this entire section
        // and remove the compat code from ciphers::update_cipher_from_data
        if self.atype == 1 && data_json["Uris"].is_array() {
            let uri = data_json["Uris"][0]["Uri"].clone();
            data_json["Uri"] = uri;
        }
        // TODO: ******* Backwards compat end **********

        let mut json_object = json!({
            "Id": self.uuid,
            "Type": self.atype,
            "RevisionDate": format_date(&self.updated_at),
            "DeletedDate": self.deleted_at.map_or(Value::Null, |d| Value::String(format_date(&d))),
            "FolderId": self.get_folder_uuid(&user_uuid, &conn),
            "Favorite": self.favorite,
            "OrganizationId": self.organization_uuid,
            "Attachments": attachments_json,
            "OrganizationUseTotp": true,
            "CollectionIds": self.get_collections(user_uuid, &conn),

            "Name": self.name,
            "Notes": self.notes,
            "Fields": fields_json,

            "Data": data_json,

            "Object": "cipher",
            "Edit": true,

            "PasswordHistory": password_history_json,
        });

        let key = match self.atype {
            1 => "Login",
            2 => "SecureNote",
            3 => "Card",
            4 => "Identity",
            _ => panic!("Wrong type"),
        };

        json_object[key] = data_json;
        json_object
    }

    pub fn update_users_revision(&self, conn: &DbConn) -> Vec<String> {
        let mut user_uuids = Vec::new();
        match self.user_uuid {
            Some(ref user_uuid) => {
                User::update_uuid_revision(&user_uuid, conn);
                user_uuids.push(user_uuid.clone())
            }
            None => {
                // Belongs to Organization, need to update affected users
                if let Some(ref org_uuid) = self.organization_uuid {
                    UserOrganization::find_by_cipher_and_org(&self.uuid, &org_uuid, conn)
                        .iter()
                        .for_each(|user_org| {
                            User::update_uuid_revision(&user_org.user_uuid, conn);
                            user_uuids.push(user_org.user_uuid.clone())
                        });
                }
            }
        };
        user_uuids
    }

    #[cfg(feature = "postgresql")]
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);
        self.updated_at = Utc::now().naive_utc();

        diesel::insert_into(ciphers::table)
            .values(&*self)
            .on_conflict(ciphers::uuid)
            .do_update()
            .set(&*self)
            .execute(&**conn)
            .map_res("Error saving cipher")
    }

    #[cfg(not(feature = "postgresql"))]
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);
        self.updated_at = Utc::now().naive_utc();

        diesel::replace_into(ciphers::table)
            .values(&*self)
            .execute(&**conn)
            .map_res("Error saving cipher")
    }

    pub fn delete(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);

        FolderCipher::delete_all_by_cipher(&self.uuid, &conn)?;
        CollectionCipher::delete_all_by_cipher(&self.uuid, &conn)?;
        Attachment::delete_all_by_cipher(&self.uuid, &conn)?;

        diesel::delete(ciphers::table.filter(ciphers::uuid.eq(&self.uuid)))
            .execute(&**conn)
            .map_res("Error deleting cipher")
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for cipher in Self::find_by_org(org_uuid, &conn) {
            cipher.delete(&conn)?;
        }
        Ok(())
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for cipher in Self::find_owned_by_user(user_uuid, &conn) {
            cipher.delete(&conn)?;
        }
        Ok(())
    }

    pub fn move_to_folder(&self, folder_uuid: Option<String>, user_uuid: &str, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(user_uuid, &conn);

        match (self.get_folder_uuid(&user_uuid, &conn), folder_uuid) {
            // No changes
            (None, None) => Ok(()),
            (Some(ref old), Some(ref new)) if old == new => Ok(()),

            // Add to folder
            (None, Some(new)) => FolderCipher::new(&new, &self.uuid).save(&conn),

            // Remove from folder
            (Some(old), None) => match FolderCipher::find_by_folder_and_cipher(&old, &self.uuid, &conn) {
                Some(old) => old.delete(&conn),
                None => err!("Couldn't move from previous folder"),
            },

            // Move to another folder
            (Some(old), Some(new)) => {
                if let Some(old) = FolderCipher::find_by_folder_and_cipher(&old, &self.uuid, &conn) {
                    old.delete(&conn)?;
                }
                FolderCipher::new(&new, &self.uuid).save(&conn)
            }
        }
    }

    pub fn is_write_accessible_to_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        ciphers::table
            .filter(ciphers::uuid.eq(&self.uuid))
            .left_join(
                users_organizations::table.on(ciphers::organization_uuid
                    .eq(users_organizations::org_uuid.nullable())
                    .and(users_organizations::user_uuid.eq(user_uuid))),
            )
            .left_join(ciphers_collections::table)
            .left_join(
                users_collections::table
                    .on(ciphers_collections::collection_uuid.eq(users_collections::collection_uuid)),
            )
            .filter(ciphers::user_uuid.eq(user_uuid).or(
                // Cipher owner
                users_organizations::access_all.eq(true).or(
                    // access_all in Organization
                    users_organizations::atype.le(UserOrgType::Admin as i32).or(
                        // Org admin or owner
                        users_collections::user_uuid.eq(user_uuid).and(
                            users_collections::read_only.eq(false), //R/W access to collection
                        ),
                    ),
                ),
            ))
            .select(ciphers::all_columns)
            .first::<Self>(&**conn)
            .ok()
            .is_some()
    }

    pub fn is_accessible_to_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        ciphers::table
            .filter(ciphers::uuid.eq(&self.uuid))
            .left_join(
                users_organizations::table.on(ciphers::organization_uuid
                    .eq(users_organizations::org_uuid.nullable())
                    .and(users_organizations::user_uuid.eq(user_uuid))),
            )
            .left_join(ciphers_collections::table)
            .left_join(
                users_collections::table
                    .on(ciphers_collections::collection_uuid.eq(users_collections::collection_uuid)),
            )
            .filter(ciphers::user_uuid.eq(user_uuid).or(
                // Cipher owner
                users_organizations::access_all.eq(true).or(
                    // access_all in Organization
                    users_organizations::atype.le(UserOrgType::Admin as i32).or(
                        // Org admin or owner
                        users_collections::user_uuid.eq(user_uuid), // Access to Collection
                    ),
                ),
            ))
            .select(ciphers::all_columns)
            .first::<Self>(&**conn)
            .ok()
            .is_some()
    }

    pub fn get_folder_uuid(&self, user_uuid: &str, conn: &DbConn) -> Option<String> {
        folders_ciphers::table
            .inner_join(folders::table)
            .filter(folders::user_uuid.eq(&user_uuid))
            .filter(folders_ciphers::cipher_uuid.eq(&self.uuid))
            .select(folders_ciphers::folder_uuid)
            .first::<String>(&**conn)
            .ok()
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        ciphers::table
            .filter(ciphers::uuid.eq(uuid))
            .first::<Self>(&**conn)
            .ok()
    }

    // Find all ciphers accessible to user
    pub fn find_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
        .left_join(users_organizations::table.on(
            ciphers::organization_uuid.eq(users_organizations::org_uuid.nullable()).and(
                users_organizations::user_uuid.eq(user_uuid).and(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
            )
        ))
        .left_join(ciphers_collections::table.on(
            ciphers::uuid.eq(ciphers_collections::cipher_uuid)
        ))
        .left_join(users_collections::table.on(
            ciphers_collections::collection_uuid.eq(users_collections::collection_uuid)
        ))
        .filter(ciphers::user_uuid.eq(user_uuid).or( // Cipher owner
            users_organizations::access_all.eq(true).or( // access_all in Organization
                users_organizations::atype.le(UserOrgType::Admin as i32).or( // Org admin or owner
                    users_collections::user_uuid.eq(user_uuid).and( // Access to Collection
                        users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                    )
                )
            )
        ))
        .select(ciphers::all_columns)
        .distinct()
        .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    // Find all ciphers directly owned by user
    pub fn find_owned_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
        .filter(ciphers::user_uuid.eq(user_uuid))
        .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    pub fn count_owned_by_user(user_uuid: &str, conn: &DbConn) -> i64 {
        ciphers::table
        .filter(ciphers::user_uuid.eq(user_uuid))
        .count()
        .first::<i64>(&**conn)
        .ok()
        .unwrap_or(0)
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        ciphers::table
            .filter(ciphers::organization_uuid.eq(org_uuid))
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    pub fn count_by_org(org_uuid: &str, conn: &DbConn) -> i64 {
        ciphers::table
            .filter(ciphers::organization_uuid.eq(org_uuid))
            .count()
            .first::<i64>(&**conn)
            .ok()
            .unwrap_or(0)
    }

    pub fn find_by_folder(folder_uuid: &str, conn: &DbConn) -> Vec<Self> {
        folders_ciphers::table.inner_join(ciphers::table)
            .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
            .select(ciphers::all_columns)
            .load::<Self>(&**conn).expect("Error loading ciphers")
    }

    pub fn get_collections(&self, user_id: &str, conn: &DbConn) -> Vec<String> {
        ciphers_collections::table
        .inner_join(collections::table.on(
            collections::uuid.eq(ciphers_collections::collection_uuid)
        ))
        .inner_join(users_organizations::table.on(
            users_organizations::org_uuid.eq(collections::org_uuid).and(
                users_organizations::user_uuid.eq(user_id)
            )
        ))
        .left_join(users_collections::table.on(
            users_collections::collection_uuid.eq(ciphers_collections::collection_uuid).and(
                users_collections::user_uuid.eq(user_id)
            )
        ))
        .filter(ciphers_collections::cipher_uuid.eq(&self.uuid))
        .filter(users_collections::user_uuid.eq(user_id).or( // User has access to collection
            users_organizations::access_all.eq(true).or( // User has access all
                users_organizations::atype.le(UserOrgType::Admin as i32) // User is admin or owner
            )
        ))
        .select(ciphers_collections::collection_uuid)
        .load::<String>(&**conn).unwrap_or_default()
    }
}
