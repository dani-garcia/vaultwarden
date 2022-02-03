use chrono::{Duration, NaiveDateTime, Utc};
use serde_json::Value;

use crate::CONFIG;

use super::{
    Attachment, CollectionCipher, Favorite, FolderCipher, Organization, User, UserOrgStatus, UserOrgType,
    UserOrganization,
};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations, AsChangeset)]
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

        pub password_history: Option<String>,
        pub deleted_at: Option<NaiveDateTime>,
        pub reprompt: Option<i32>,
    }
}

#[allow(dead_code)]
pub enum RepromptType {
    None = 0,
    Password = 1, // not currently used in server
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
            name,

            notes: None,
            fields: None,

            data: String::new(),
            password_history: None,
            deleted_at: None,
            reprompt: None,
        }
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Cipher {
    pub fn to_json(&self, host: &str, user_uuid: &str, conn: &DbConn) -> Value {
        use crate::util::format_date;

        let attachments = Attachment::find_by_cipher(&self.uuid, conn);
        // When there are no attachments use null instead of an empty array
        let attachments_json = if attachments.is_empty() {
            Value::Null
        } else {
            attachments.iter().map(|c| c.to_json(host)).collect()
        };

        let fields_json = self.fields.as_ref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
        let password_history_json =
            self.password_history.as_ref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);

        let (read_only, hide_passwords) = match self.get_access_restrictions(user_uuid, conn) {
            Some((ro, hp)) => (ro, hp),
            None => {
                error!("Cipher ownership assertion failure");
                (true, true)
            }
        };

        // Get the type_data or a default to an empty json object '{}'.
        // If not passing an empty object, mobile clients will crash.
        let mut type_data_json: Value = serde_json::from_str(&self.data).unwrap_or_else(|_| json!({}));

        // NOTE: This was marked as *Backwards Compatibilty Code*, but as of January 2021 this is still being used by upstream
        // Set the first element of the Uris array as Uri, this is needed several (mobile) clients.
        if self.atype == 1 {
            if type_data_json["Uris"].is_array() {
                let uri = type_data_json["Uris"][0]["Uri"].clone();
                type_data_json["Uri"] = uri;
            } else {
                // Upstream always has an Uri key/value
                type_data_json["Uri"] = Value::Null;
            }
        }

        // Clone the type_data and add some default value.
        let mut data_json = type_data_json.clone();

        // NOTE: This was marked as *Backwards Compatibilty Code*, but as of January 2021 this is still being used by upstream
        // data_json should always contain the following keys with every atype
        data_json["Fields"] = json!(fields_json);
        data_json["Name"] = json!(self.name);
        data_json["Notes"] = json!(self.notes);
        data_json["PasswordHistory"] = json!(password_history_json);

        // There are three types of cipher response models in upstream
        // Bitwarden: "cipherMini", "cipher", and "cipherDetails" (in order
        // of increasing level of detail). vaultwarden currently only
        // supports the "cipherDetails" type, though it seems like the
        // Bitwarden clients will ignore extra fields.
        //
        // Ref: https://github.com/bitwarden/server/blob/master/src/Core/Models/Api/Response/CipherResponseModel.cs
        let mut json_object = json!({
            "Object": "cipherDetails",
            "Id": self.uuid,
            "Type": self.atype,
            "RevisionDate": format_date(&self.updated_at),
            "DeletedDate": self.deleted_at.map_or(Value::Null, |d| Value::String(format_date(&d))),
            "FolderId": self.get_folder_uuid(user_uuid, conn),
            "Favorite": self.is_favorite(user_uuid, conn),
            "Reprompt": self.reprompt.unwrap_or(RepromptType::None as i32),
            "OrganizationId": self.organization_uuid,
            "Attachments": attachments_json,
            // We have UseTotp set to true by default within the Organization model.
            // This variable together with UsersGetPremium is used to show or hide the TOTP counter.
            "OrganizationUseTotp": true,

            // This field is specific to the cipherDetails type.
            "CollectionIds": self.get_collections(user_uuid, conn),

            "Name": self.name,
            "Notes": self.notes,
            "Fields": fields_json,

            "Data": data_json,

            // These values are true by default, but can be false if the
            // cipher belongs to a collection where the org owner has enabled
            // the "Read Only" or "Hide Passwords" restrictions for the user.
            "Edit": !read_only,
            "ViewPassword": !hide_passwords,

            "PasswordHistory": password_history_json,

            // All Cipher types are included by default as null, but only the matching one will be populated
            "Login": null,
            "SecureNote": null,
            "Card": null,
            "Identity": null,
        });

        let key = match self.atype {
            1 => "Login",
            2 => "SecureNote",
            3 => "Card",
            4 => "Identity",
            _ => panic!("Wrong type"),
        };

        json_object[key] = type_data_json;
        json_object
    }

    pub fn update_users_revision(&self, conn: &DbConn) -> Vec<String> {
        let mut user_uuids = Vec::new();
        match self.user_uuid {
            Some(ref user_uuid) => {
                User::update_uuid_revision(user_uuid, conn);
                user_uuids.push(user_uuid.clone())
            }
            None => {
                // Belongs to Organization, need to update affected users
                if let Some(ref org_uuid) = self.organization_uuid {
                    UserOrganization::find_by_cipher_and_org(&self.uuid, org_uuid, conn).iter().for_each(|user_org| {
                        User::update_uuid_revision(&user_org.user_uuid, conn);
                        user_uuids.push(user_org.user_uuid.clone())
                    });
                }
            }
        };
        user_uuids
    }

    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(ciphers::table)
                    .values(CipherDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(ciphers::table)
                            .filter(ciphers::uuid.eq(&self.uuid))
                            .set(CipherDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving cipher")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving cipher")
            }
            postgresql {
                let value = CipherDb::to_db(self);
                diesel::insert_into(ciphers::table)
                    .values(&value)
                    .on_conflict(ciphers::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving cipher")
            }
        }
    }

    pub fn delete(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn);

        FolderCipher::delete_all_by_cipher(&self.uuid, conn)?;
        CollectionCipher::delete_all_by_cipher(&self.uuid, conn)?;
        Attachment::delete_all_by_cipher(&self.uuid, conn)?;
        Favorite::delete_all_by_cipher(&self.uuid, conn)?;

        db_run! { conn: {
            diesel::delete(ciphers::table.filter(ciphers::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting cipher")
        }}
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for cipher in Self::find_by_org(org_uuid, conn) {
            cipher.delete(conn)?;
        }
        Ok(())
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for cipher in Self::find_owned_by_user(user_uuid, conn) {
            cipher.delete(conn)?;
        }
        Ok(())
    }

    /// Purge all ciphers that are old enough to be auto-deleted.
    pub fn purge_trash(conn: &DbConn) {
        if let Some(auto_delete_days) = CONFIG.trash_auto_delete_days() {
            let now = Utc::now().naive_utc();
            let dt = now - Duration::days(auto_delete_days);
            for cipher in Self::find_deleted_before(&dt, conn) {
                cipher.delete(conn).ok();
            }
        }
    }

    pub fn move_to_folder(&self, folder_uuid: Option<String>, user_uuid: &str, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn);

        match (self.get_folder_uuid(user_uuid, conn), folder_uuid) {
            // No changes
            (None, None) => Ok(()),
            (Some(ref old), Some(ref new)) if old == new => Ok(()),

            // Add to folder
            (None, Some(new)) => FolderCipher::new(&new, &self.uuid).save(conn),

            // Remove from folder
            (Some(old), None) => match FolderCipher::find_by_folder_and_cipher(&old, &self.uuid, conn) {
                Some(old) => old.delete(conn),
                None => err!("Couldn't move from previous folder"),
            },

            // Move to another folder
            (Some(old), Some(new)) => {
                if let Some(old) = FolderCipher::find_by_folder_and_cipher(&old, &self.uuid, conn) {
                    old.delete(conn)?;
                }
                FolderCipher::new(&new, &self.uuid).save(conn)
            }
        }
    }

    /// Returns whether this cipher is directly owned by the user.
    pub fn is_owned_by_user(&self, user_uuid: &str) -> bool {
        self.user_uuid.is_some() && self.user_uuid.as_ref().unwrap() == user_uuid
    }

    /// Returns whether this cipher is owned by an org in which the user has full access.
    pub fn is_in_full_access_org(&self, user_uuid: &str, conn: &DbConn) -> bool {
        if let Some(ref org_uuid) = self.organization_uuid {
            if let Some(user_org) = UserOrganization::find_by_user_and_org(user_uuid, org_uuid, conn) {
                return user_org.has_full_access();
            }
        }

        false
    }

    /// Returns the user's access restrictions to this cipher. A return value
    /// of None means that this cipher does not belong to the user, and is
    /// not in any collection the user has access to. Otherwise, the user has
    /// access to this cipher, and Some(read_only, hide_passwords) represents
    /// the access restrictions.
    pub fn get_access_restrictions(&self, user_uuid: &str, conn: &DbConn) -> Option<(bool, bool)> {
        // Check whether this cipher is directly owned by the user, or is in
        // a collection that the user has full access to. If so, there are no
        // access restrictions.
        if self.is_owned_by_user(user_uuid) || self.is_in_full_access_org(user_uuid, conn) {
            return Some((false, false));
        }

        db_run! {conn: {
            // Check whether this cipher is in any collections accessible to the
            // user. If so, retrieve the access flags for each collection.
            let rows = ciphers::table
                .filter(ciphers::uuid.eq(&self.uuid))
                .inner_join(ciphers_collections::table.on(
                    ciphers::uuid.eq(ciphers_collections::cipher_uuid)))
                .inner_join(users_collections::table.on(
                    ciphers_collections::collection_uuid.eq(users_collections::collection_uuid)
                        .and(users_collections::user_uuid.eq(user_uuid))))
                .select((users_collections::read_only, users_collections::hide_passwords))
                .load::<(bool, bool)>(conn)
                .expect("Error getting access restrictions");

            if rows.is_empty() {
                // This cipher isn't in any collections accessible to the user.
                return None;
            }

            // A cipher can be in multiple collections with inconsistent access flags.
            // For example, a cipher could be in one collection where the user has
            // read-only access, but also in another collection where the user has
            // read/write access. For a flag to be in effect for a cipher, upstream
            // requires all collections the cipher is in to have that flag set.
            // Therefore, we do a boolean AND of all values in each of the `read_only`
            // and `hide_passwords` columns. This could ideally be done as part of the
            // query, but Diesel doesn't support a min() or bool_and() function on
            // booleans and this behavior isn't portable anyway.
            let mut read_only = true;
            let mut hide_passwords = true;
            for (ro, hp) in rows.iter() {
                read_only &= ro;
                hide_passwords &= hp;
            }

            Some((read_only, hide_passwords))
        }}
    }

    pub fn is_write_accessible_to_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        match self.get_access_restrictions(user_uuid, conn) {
            Some((read_only, _hide_passwords)) => !read_only,
            None => false,
        }
    }

    pub fn is_accessible_to_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        self.get_access_restrictions(user_uuid, conn).is_some()
    }

    // Returns whether this cipher is a favorite of the specified user.
    pub fn is_favorite(&self, user_uuid: &str, conn: &DbConn) -> bool {
        Favorite::is_favorite(&self.uuid, user_uuid, conn)
    }

    // Sets whether this cipher is a favorite of the specified user.
    pub fn set_favorite(&self, favorite: Option<bool>, user_uuid: &str, conn: &DbConn) -> EmptyResult {
        match favorite {
            None => Ok(()), // No change requested.
            Some(status) => Favorite::set_favorite(status, &self.uuid, user_uuid, conn),
        }
    }

    pub fn get_folder_uuid(&self, user_uuid: &str, conn: &DbConn) -> Option<String> {
        db_run! {conn: {
            folders_ciphers::table
                .inner_join(folders::table)
                .filter(folders::user_uuid.eq(&user_uuid))
                .filter(folders_ciphers::cipher_uuid.eq(&self.uuid))
                .select(folders_ciphers::folder_uuid)
                .first::<String>(conn)
                .ok()
        }}
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! {conn: {
            ciphers::table
                .filter(ciphers::uuid.eq(uuid))
                .first::<CipherDb>(conn)
                .ok()
                .from_db()
        }}
    }

    // Find all ciphers accessible or visible to the specified user.
    //
    // "Accessible" means the user has read access to the cipher, either via
    // direct ownership or via collection access.
    //
    // "Visible" usually means the same as accessible, except when an org
    // owner/admin sets their account to have access to only selected
    // collections in the org (presumably because they aren't interested in
    // the other collections in the org). In this case, if `visible_only` is
    // true, then the non-interesting ciphers will not be returned. As a
    // result, those ciphers will not appear in "My Vault" for the org
    // owner/admin, but they can still be accessed via the org vault view.
    pub fn find_by_user(user_uuid: &str, visible_only: bool, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            let mut query = ciphers::table
                .left_join(ciphers_collections::table.on(
                    ciphers::uuid.eq(ciphers_collections::cipher_uuid)
                ))
                .left_join(users_organizations::table.on(
                    ciphers::organization_uuid.eq(users_organizations::org_uuid.nullable())
                        .and(users_organizations::user_uuid.eq(user_uuid))
                        .and(users_organizations::status.eq(UserOrgStatus::Confirmed as i32))
                ))
                .left_join(users_collections::table.on(
                    ciphers_collections::collection_uuid.eq(users_collections::collection_uuid)
                        // Ensure that users_collections::user_uuid is NULL for unconfirmed users.
                        .and(users_organizations::user_uuid.eq(users_collections::user_uuid))
                ))
                .filter(ciphers::user_uuid.eq(user_uuid)) // Cipher owner
                .or_filter(users_organizations::access_all.eq(true)) // access_all in org
                .or_filter(users_collections::user_uuid.eq(user_uuid)) // Access to collection
                .into_boxed();

            if !visible_only {
                query = query.or_filter(
                    users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin/owner
                );
            }

            query
                .select(ciphers::all_columns)
                .distinct()
                .load::<CipherDb>(conn).expect("Error loading ciphers").from_db()
        }}
    }

    // Find all ciphers visible to the specified user.
    pub fn find_by_user_visible(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        Self::find_by_user(user_uuid, true, conn)
    }

    // Find all ciphers directly owned by the specified user.
    pub fn find_owned_by_user(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            ciphers::table
                .filter(
                    ciphers::user_uuid.eq(user_uuid)
                    .and(ciphers::organization_uuid.is_null())
                )
                .load::<CipherDb>(conn).expect("Error loading ciphers").from_db()
        }}
    }

    pub fn count_owned_by_user(user_uuid: &str, conn: &DbConn) -> i64 {
        db_run! {conn: {
            ciphers::table
                .filter(ciphers::user_uuid.eq(user_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            ciphers::table
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .load::<CipherDb>(conn).expect("Error loading ciphers").from_db()
        }}
    }

    pub fn count_by_org(org_uuid: &str, conn: &DbConn) -> i64 {
        db_run! {conn: {
            ciphers::table
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub fn find_by_folder(folder_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            folders_ciphers::table.inner_join(ciphers::table)
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .select(ciphers::all_columns)
                .load::<CipherDb>(conn).expect("Error loading ciphers").from_db()
        }}
    }

    /// Find all ciphers that were deleted before the specified datetime.
    pub fn find_deleted_before(dt: &NaiveDateTime, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            ciphers::table
                .filter(ciphers::deleted_at.lt(dt))
                .load::<CipherDb>(conn).expect("Error loading ciphers").from_db()
        }}
    }

    pub fn get_collections(&self, user_id: &str, conn: &DbConn) -> Vec<String> {
        db_run! {conn: {
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
            .load::<String>(conn).unwrap_or_default()
        }}
    }
}
