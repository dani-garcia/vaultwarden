use std::borrow::Cow;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        EmptyResult,
        core::{CipherData, CipherSyncData, CipherSyncType},
    },
    db::{
        DbConn,
        schema::{
            ciphers, ciphers_collections, collections, collections_groups, folders, folders_ciphers, groups,
            groups_users, users_collections, users_organizations,
        },
    },
    error::MapResult,
    util::LowerCase,
};
use macros::UuidFromParam;

use super::{
    Archive, Attachment, CollectionCipher, CollectionId, Favorite, FolderCipher, FolderId, Group, Membership,
    MembershipStatus, MembershipType, OrganizationId, User, UserId,
    organization::{ORG_ADMIN_ATYPES, custom_membership_with_edit_any_collection},
};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = ciphers)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Cipher {
    pub uuid: CipherId,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: Option<UserId>,
    pub organization_uuid: Option<OrganizationId>,

    pub key: Option<String>,

    // See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/Vault/Enums/CipherType.cs
    // Login = 1,
    // SecureNote = 2,
    // Card = 3,
    // Identity = 4,
    // SSHKey = 5
    // BankAccount = 6,
    // DriversLicense = 7,
    // Passport = 8,
    pub atype: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,

    pub data: String,

    pub password_history: Option<String>,
    pub deleted_at: Option<NaiveDateTime>,
    pub reprompt: Option<i32>,
}

pub enum RepromptType {
    None = 0,
    Password = 1,
}

/// Whether `membership` holds organization-wide authority over its organization's ciphers.
///
/// Upstream gates every administrative cipher route on `CanEditCipherAsAdminAsync`,
/// `CanDeleteOrRestoreCipherAsAdminAsync` or `CanEditAllCiphersAsync`. All three first require
/// Owner, Admin or `Edit any collection`, and then resolve through `CanEditAllCiphersAsync` --
/// which is that very same set, because Vaultwarden always serializes
/// `allowAdminAccessToAllCollectionItems = true`. So all three reduce to this one predicate, and
/// the per-cipher fallbacks they contain for restricted admins are unreachable here.
///
/// Deliberately narrower than upstream's `ViewAllCollections` (which guards
/// `GET /ciphers/<id>/admin` and additionally admits `Delete any collection`): honouring that would
/// hand cipher *contents* to a permission that upstream's own `CanAccessAllCiphersAsync` -- and
/// therefore `GET /ciphers/organization-details` here -- deliberately keeps away from them. Where
/// the two upstream answers disagree, this takes the stricter one.
pub fn may_administer_org_ciphers(membership: &Membership) -> bool {
    // `has_full_access()` is exactly "confirmed, and Owner/Admin or Custom holding
    // `Edit any collection`".
    membership.has_full_access()
}

/// Which authorization a cipher operation runs under.
///
/// Vaultwarden serves the organization's administrative cipher routes (`/ciphers/<id>/admin` and
/// friends) from the same handlers as the regular vault routes, so the handlers state the scope
/// explicitly and every authorization call site shows which one it uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherAccessScope {
    /// The regular vault routes. Only ownership and the caller's per-collection/group assignments
    /// count. `Edit any collection` deliberately does not widen `/sync`, `GET /ciphers` or the
    /// non-admin `GET|PUT /ciphers/<id>`, so a Custom member holding it still sees exactly the
    /// ciphers they are assigned to.
    User,
    /// The organization's administrative cipher routes, where a member with organization-wide
    /// cipher authority reaches every cipher of that organization.
    OrganizationAdmin,
}

impl CipherAccessScope {
    /// Whether `membership` reaches every cipher of its organization in this scope.
    ///
    /// Owner and Admin qualify in both scopes, which is the behaviour Vaultwarden has always had.
    /// `Edit any collection` is administrative authority only, so it qualifies in
    /// [`Self::OrganizationAdmin`] alone.
    fn grants_org_wide_cipher_access(self, membership: &Membership) -> bool {
        match self {
            Self::User => membership.atype >= MembershipType::Admin,
            Self::OrganizationAdmin => may_administer_org_ciphers(membership),
        }
    }

    /// The scope a request asks for, for the one route that states it: the v2 attachment create.
    ///
    /// Upstream's `PostAttachment` branches on the request's `adminRequest` flag -- `true`
    /// authorizes with `CanEditCipherAsAdminAsync` and answers with a `CipherMiniResponse`,
    /// anything else authorizes and answers as the regular vault route.
    ///
    /// The flag only selects *which* predicate is evaluated, never what it answers:
    /// [`Self::OrganizationAdmin`] still requires the caller to hold organization-wide cipher
    /// authority, so a member without it gains nothing by setting the flag.
    pub fn requested(admin_request: Option<bool>) -> Self {
        if admin_request == Some(true) {
            Self::OrganizationAdmin
        } else {
            Self::User
        }
    }

    /// The scope for a route that cannot be told which one to use, resolved from the caller's own
    /// membership in the cipher's organization.
    ///
    /// The second leg of the v2 attachment upload is a bare file POST with no `adminRequest` field,
    /// so upstream's `PostFileForExistingAttachment` recomputes the administrative context from the
    /// caller instead (`orgAdmin = CanEditCipherAsAdminAsync(...)`). Nothing from the request feeds
    /// into this, so that route cannot be talked into an administrative scope.
    pub fn for_member(membership: Option<&Membership>) -> Self {
        if membership.is_some_and(may_administer_org_ciphers) {
            Self::OrganizationAdmin
        } else {
            Self::User
        }
    }
}

/// Local methods
impl Cipher {
    pub fn new(atype: i32, name: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: CipherId(crate::util::get_uuid()),
            created_at: now,
            updated_at: now,

            user_uuid: None,
            organization_uuid: None,

            key: None,

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

    pub fn validate_cipher_data(cipher_data: &[CipherData]) -> EmptyResult {
        let mut validation_errors = serde_json::Map::new();
        let max_note_size = CONFIG._max_note_size();
        let max_note_size_msg =
            format!("The field Notes exceeds the maximum encrypted value length of {max_note_size} characters.");
        for (index, cipher) in cipher_data.iter().enumerate() {
            // Validate the note size and if it is exceeded return a warning
            if let Some(note) = &cipher.notes
                && note.len() > max_note_size
            {
                validation_errors
                    .insert(format!("Ciphers[{index}].Notes"), serde_json::to_value([&max_note_size_msg]).unwrap());
            }

            // Validate the password history if it contains `null` values and if so, return a warning
            if let Some(Value::Array(password_history)) = &cipher.password_history {
                for pwh in password_history {
                    if let Value::Object(pwo) = pwh
                        && pwo.get("password").is_some_and(|p| !p.is_string())
                    {
                        validation_errors.insert(
                            format!("Ciphers[{index}].Notes"),
                            serde_json::to_value([
                                "The password history contains a `null` value. Only strings are allowed.",
                            ])
                            .unwrap(),
                        );
                        break;
                    }
                }
            }
        }

        if !validation_errors.is_empty() {
            let err_json = json!({
                "message": "The model state is invalid.",
                "validationErrors" : validation_errors,
                "object": "error"
            });
            err_json!(err_json, "Import validation errors")
        }

        Ok(())
    }
}

/// Database methods
impl Cipher {
    pub async fn to_json(
        &self,
        host: &str,
        user_uuid: &UserId,
        cipher_sync_data: Option<&CipherSyncData>,
        sync_type: CipherSyncType,
        conn: &DbConn,
    ) -> Result<Value, crate::Error> {
        self.to_json_scoped(host, user_uuid, cipher_sync_data, sync_type, CipherAccessScope::User, conn).await
    }

    /// [`Cipher::to_json`] for one of the organization's administrative cipher routes.
    ///
    /// Same response shape those handlers have always produced; only the access flags differ. They
    /// are resolved with [`CipherAccessScope::OrganizationAdmin`], so a member acting with
    /// organization-wide cipher authority is reported as able to edit the cipher -- which is
    /// exactly what the route authorized. Resolving them as `User` would answer a successfully
    /// authorized admin request with `edit: false` and log an ownership assertion failure.
    pub async fn to_json_org_admin(
        &self,
        host: &str,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Result<Value, crate::Error> {
        self.to_json_scoped(host, user_uuid, None, CipherSyncType::User, CipherAccessScope::OrganizationAdmin, conn)
            .await
    }

    async fn to_json_scoped(
        &self,
        host: &str,
        user_uuid: &UserId,
        cipher_sync_data: Option<&CipherSyncData>,
        sync_type: CipherSyncType,
        scope: CipherAccessScope,
        conn: &DbConn,
    ) -> Result<Value, crate::Error> {
        use crate::util::{format_date, validate_and_format_date};

        let mut attachments_json: Value = Value::Null;
        if let Some(cipher_sync_data) = cipher_sync_data {
            if let Some(attachments) = cipher_sync_data.cipher_attachments.get(&self.uuid)
                && !attachments.is_empty()
            {
                let mut attachments_json_vec = vec![];
                for attachment in attachments {
                    attachments_json_vec.push(attachment.to_json(host).await?);
                }
                attachments_json = Value::Array(attachments_json_vec);
            }
        } else {
            let attachments = Attachment::find_by_cipher(&self.uuid, conn).await;
            if !attachments.is_empty() {
                let mut attachments_json_vec = vec![];
                for attachment in attachments {
                    attachments_json_vec.push(attachment.to_json(host).await?);
                }
                attachments_json = Value::Array(attachments_json_vec);
            }
        }

        // We don't need these values at all for Organizational syncs
        // Skip any other database calls if this is the case and just return false.
        let (read_only, hide_passwords, _) = if sync_type == CipherSyncType::User {
            if let Some((ro, hp, mn)) = self.get_access_restrictions(user_uuid, scope, cipher_sync_data, conn).await {
                (ro, hp, mn)
            } else {
                error!("Cipher ownership assertion failure");
                (true, true, false)
            }
        } else {
            (false, false, false)
        };

        let fields_json: Vec<_> = self
            .fields
            .as_ref()
            .and_then(|s| {
                serde_json::from_str::<Vec<LowerCase<Value>>>(s)
                    .inspect_err(|e| warn!("Error parsing fields {e:?} for {}", self.uuid))
                    .ok()
            })
            .map(|d| {
                d.into_iter()
                    .map(|mut f| {
                        // Check if the `type` key is a number, strings break some clients
                        // The fallback type is the hidden type `1`. this should prevent accidental data disclosure
                        // If not try to convert the string value to a number and fallback to `1`
                        // If it is both not a number and not a string, fallback to `1`
                        match f.data.get("type") {
                            Some(t) if t.is_number() => {}
                            Some(t) if t.is_string() => {
                                let type_num = &t.as_str().unwrap_or("1").parse::<u8>().unwrap_or(1);
                                f.data["type"] = json!(type_num);
                            }
                            _ => {
                                f.data["type"] = json!(1);
                            }
                        }
                        f.data
                    })
                    .collect()
            })
            .unwrap_or_default();

        let password_history_json: Vec<_> = self
            .password_history
            .as_ref()
            .and_then(|s| {
                serde_json::from_str::<Vec<LowerCase<Value>>>(s)
                    .inspect_err(|e| warn!("Error parsing password history {e:?} for {}", self.uuid))
                    .ok()
            })
            .map(|d| {
                // Check every password history item if they are valid and return it.
                // If a password field has the type `null` skip it, it breaks newer Bitwarden clients
                // A second check is done to verify the lastUsedDate exists and is a valid DateTime string, if not the epoch start time will be used
                d.into_iter()
                    .filter_map(|d| match d.data.get("password") {
                        Some(p) if p.is_string() => Some(d.data),
                        _ => None,
                    })
                    .map(|mut d| {
                        let lud = if let Some(l) = d.get("lastUsedDate").and_then(|l| l.as_str()) {
                            validate_and_format_date(l)
                        } else {
                            "1970-01-01T00:00:00.000000Z".to_owned()
                        };
                        d["lastUsedDate"] = json!(lud);
                        d
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Get the type_data or a default to an empty json object '{}'.
        // If not passing an empty object, mobile clients will crash.
        let mut type_data_json = serde_json::from_str::<LowerCase<Value>>(&self.data)
            .inspect_err(|_| warn!("Error parsing data field for {}", self.uuid))
            .map_or_else(|_| Value::Object(serde_json::Map::new()), |d| d.data);

        // NOTE: This was marked as *Backwards Compatibility Code*, but as of January 2021 this is still being used by upstream
        // Set the first element of the Uris array as Uri, this is needed several (mobile) clients.
        if self.atype == 1 {
            // Upstream always has an `uri` key/value
            type_data_json["uri"] = Value::Null;
            if let Some(uris) = type_data_json["uris"].as_array_mut()
                && !uris.is_empty()
            {
                // Fix uri match values first, they are only allowed to be a number or null
                // If it is a string, convert it to an int or null if that fails
                for uri in &mut *uris {
                    if uri["match"].is_string() {
                        let match_value = match uri["match"].as_str().unwrap_or_default().parse::<u8>() {
                            Ok(n) => json!(n),
                            _ => Value::Null,
                        };
                        uri["match"] = match_value;
                    }
                }
                type_data_json["uri"] = uris[0]["uri"].clone();
            }

            // Check if `passwordRevisionDate` is a valid date, else convert it
            if let Some(pw_revision) = type_data_json["passwordRevisionDate"].as_str() {
                type_data_json["passwordRevisionDate"] = json!(validate_and_format_date(pw_revision));
            }
        }

        // Fix secure note issues when data is invalid
        // This breaks at least the native mobile clients
        if self.atype == 2 {
            match type_data_json {
                Value::Object(ref t) if t.get("type").is_some_and(Value::is_number) => {}
                _ => {
                    type_data_json = json!({"type": 0});
                }
            }
        }

        // Fix invalid SSH Entries
        // This breaks at least the native mobile client if invalid
        // The only way to fix this is by setting type_data_json to `null`
        // Opening this ssh-key in the mobile client will probably crash the client, but you can edit, save and afterwards delete it
        if self.atype == 5
            && (type_data_json["keyFingerprint"].as_str().is_none_or(str::is_empty)
                || type_data_json["privateKey"].as_str().is_none_or(str::is_empty)
                || type_data_json["publicKey"].as_str().is_none_or(str::is_empty))
        {
            warn!("Error parsing ssh-key, mandatory fields are invalid for {}", self.uuid);
            type_data_json = Value::Null;
        }

        let collection_ids = if let Some(cipher_sync_data) = cipher_sync_data {
            if let Some(cipher_collections) = cipher_sync_data.cipher_collections.get(&self.uuid) {
                Cow::from(cipher_collections)
            } else {
                Cow::from(Vec::new())
            }
        } else {
            Cow::from(self.get_admin_collections(user_uuid.clone(), conn).await)
        };

        // There are three types of cipher response models in upstream
        // Bitwarden: "cipherMini", "cipher", and "cipherDetails" (in order
        // of increasing level of detail). vaultwarden currently only
        // supports the "cipherDetails" type, though it seems like the
        // Bitwarden clients will ignore extra fields.
        //
        // Ref: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Vault/Models/Response/CipherResponseModel.cs#L14
        let mut json_object = json!({
            "object": "cipherDetails",
            "id": self.uuid,
            "type": self.atype,
            "creationDate": format_date(&self.created_at),
            "revisionDate": format_date(&self.updated_at),
            "deletedDate": self.deleted_at.map_or(Value::Null, |d| Value::String(format_date(&d))),
            "reprompt": self.reprompt.filter(|r| *r == RepromptType::None as i32 || *r == RepromptType::Password as i32).unwrap_or(RepromptType::None as i32),
            "organizationId": self.organization_uuid,
            "key": self.key,
            "attachments": attachments_json,
            // We have UseTotp set to true by default within the Organization model.
            // This variable together with UsersGetPremium is used to show or hide the TOTP counter.
            "organizationUseTotp": true,

            // This field is specific to the cipherDetails type.
            "collectionIds": collection_ids,

            "name": self.name,
            "notes": self.notes,
            "fields": fields_json,

            "passwordHistory": password_history_json,

            // All Cipher types are included by default as null, but only the matching one will be populated
            "login": null,
            "secureNote": null,
            "card": null,
            "identity": null,
            "sshKey": null,
            "bankAccount": null,
            "driversLicense": null,
            "passport": null,
        });

        // These values are only needed for user/default syncs
        // Not during an organizational sync like `get_org_details`
        // Skip adding these fields in that case
        if sync_type == CipherSyncType::User {
            json_object["folderId"] = json!(if let Some(cipher_sync_data) = cipher_sync_data {
                cipher_sync_data.cipher_folders.get(&self.uuid).cloned()
            } else {
                self.get_folder_uuid(user_uuid, conn).await
            });
            json_object["favorite"] = json!(if let Some(cipher_sync_data) = cipher_sync_data {
                cipher_sync_data.cipher_favorites.contains(&self.uuid)
            } else {
                self.is_favorite(user_uuid, conn).await
            });
            json_object["archivedDate"] = json!(if let Some(cipher_sync_data) = cipher_sync_data {
                cipher_sync_data.cipher_archives.get(&self.uuid).map_or(Value::Null, |d| Value::String(format_date(d)))
            } else {
                self.get_archived_at(user_uuid, conn).await.map_or(Value::Null, |d| Value::String(format_date(&d)))
            });
            // These values are true by default, but can be false if the
            // cipher belongs to a collection or group where the org owner has enabled
            // the "Read Only" or "Hide Passwords" restrictions for the user.
            json_object["edit"] = json!(!read_only);
            json_object["viewPassword"] = json!(!hide_passwords);
            // The new key used by clients since v2025.6.0
            json_object["permissions"] = json!({
                "delete": !read_only,
                "restore": !read_only,
            });
        }

        let key = match self.atype {
            1 => "login",
            2 => "secureNote",
            3 => "card",
            4 => "identity",
            5 => "sshKey",
            6 => "bankAccount",
            7 => "driversLicense",
            8 => "passport",
            _ => err!(format!("Cipher {} has an invalid type {}", self.uuid, self.atype)),
        };

        json_object[key] = type_data_json;
        Ok(json_object)
    }

    pub async fn update_users_revision(&self, conn: &DbConn) -> Vec<UserId> {
        let mut user_uuids = Vec::new();
        match self.user_uuid {
            Some(ref user_uuid) => {
                User::update_uuid_revision(user_uuid, conn).await;
                user_uuids.push(user_uuid.clone());
            }
            None => {
                // Belongs to Organization, need to update affected users
                if let Some(ref org_uuid) = self.organization_uuid {
                    // users having access to the collection
                    let mut collection_users = Membership::find_by_cipher_and_org(&self.uuid, org_uuid, conn).await;
                    if CONFIG.org_groups_enabled() {
                        // members of a group having access to the collection
                        let group_users =
                            Membership::find_by_cipher_and_org_with_group(&self.uuid, org_uuid, conn).await;
                        collection_users.extend(group_users);
                    }
                    for member in collection_users {
                        User::update_uuid_revision(&member.user_uuid, conn).await;
                        user_uuids.push(member.user_uuid.clone());
                    }
                }
            }
        }
        user_uuids
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            mysql {
                diesel::insert_into(ciphers::table)
                    .values(&*self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving cipher")
            }
            postgresql, sqlite {
                diesel::insert_into(ciphers::table)
                    .values(&*self)
                    .on_conflict(ciphers::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving cipher")
            }
        }
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

        FolderCipher::delete_all_by_cipher(&self.uuid, conn).await?;
        CollectionCipher::delete_all_by_cipher(&self.uuid, conn).await?;
        Attachment::delete_all_by_cipher(&self.uuid, conn).await?;
        Favorite::delete_all_by_cipher(&self.uuid, conn).await?;

        conn.run(move |conn| {
            diesel::delete(ciphers::table.filter(ciphers::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting cipher")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        // TODO: Optimize this by executing a DELETE directly on the database, instead of first fetching.
        for cipher in Self::find_by_org(org_uuid, conn).await {
            cipher.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        for cipher in Self::find_owned_by_user(user_uuid, conn).await {
            cipher.delete(conn).await?;
        }
        Ok(())
    }

    /// Purge all ciphers that are old enough to be auto-deleted.
    pub async fn purge_trash(conn: &DbConn) {
        if let Some(auto_delete_days) = CONFIG.trash_auto_delete_days() {
            let now = Utc::now().naive_utc();
            let dt = now - TimeDelta::try_days(auto_delete_days).unwrap();
            for cipher in Self::find_deleted_before(&dt, conn).await {
                cipher.delete(conn).await.ok();
            }
        }
    }

    pub async fn move_to_folder(
        &self,
        folder_uuid: Option<FolderId>,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;

        match (self.get_folder_uuid(user_uuid, conn).await, folder_uuid) {
            // No changes
            (None, None) => Ok(()),
            (Some(ref old_folder), Some(ref new_folder)) if old_folder == new_folder => Ok(()),

            // Add to folder
            (None, Some(new_folder)) => FolderCipher::new(new_folder, self.uuid.clone()).save(conn).await,

            // Remove from folder
            (Some(old_folder), None) => {
                if let Some(old_folder) = FolderCipher::find_by_folder_and_cipher(&old_folder, &self.uuid, conn).await {
                    old_folder.delete(conn).await
                } else {
                    err!("Couldn't move from previous folder")
                }
            }

            // Move to another folder
            (Some(old_folder), Some(new_folder)) => {
                if let Some(old_folder) = FolderCipher::find_by_folder_and_cipher(&old_folder, &self.uuid, conn).await {
                    old_folder.delete(conn).await?;
                }
                FolderCipher::new(new_folder, self.uuid.clone()).save(conn).await
            }
        }
    }

    /// Returns whether this cipher is directly owned by the user.
    pub fn is_owned_by_user(&self, user_uuid: &UserId) -> bool {
        self.user_uuid.is_some() && self.user_uuid.as_ref().unwrap() == user_uuid
    }

    /// Returns whether this cipher is owned by an org in which the user reaches every cipher by
    /// role, for the given [`CipherAccessScope`].
    async fn is_in_full_access_org(
        &self,
        user_uuid: &UserId,
        scope: CipherAccessScope,
        cipher_sync_data: Option<&CipherSyncData>,
        conn: &DbConn,
    ) -> bool {
        if let Some(ref org_uuid) = self.organization_uuid {
            if let Some(cipher_sync_data) = cipher_sync_data {
                if let Some(cached_member) = cipher_sync_data.members.get(org_uuid) {
                    return scope.grants_org_wide_cipher_access(cached_member);
                }
            } else if let Some(member) = Membership::find_confirmed_by_user_and_org(user_uuid, org_uuid, conn).await {
                return scope.grants_org_wide_cipher_access(&member);
            }
        }
        false
    }

    /// Returns whether this cipher is owned by an group in which the user has full access.
    async fn is_in_full_access_group(
        &self,
        user_uuid: &UserId,
        cipher_sync_data: Option<&CipherSyncData>,
        conn: &DbConn,
    ) -> bool {
        if !CONFIG.org_groups_enabled() {
            return false;
        }
        if let Some(ref org_uuid) = self.organization_uuid {
            if let Some(cipher_sync_data) = cipher_sync_data {
                return cipher_sync_data.user_group_full_access_for_organizations.contains(org_uuid);
            }
            return Group::is_in_full_access_group(user_uuid, org_uuid, conn).await;
        }
        false
    }

    /// Returns the user's access restrictions to this cipher. A return value
    /// of None means that this cipher does not belong to the user, and is
    /// not in any collection the user has access to. Otherwise, the user has
    /// access to this cipher, and Some(read_only, hide_passwords, manage) represents
    /// the access restrictions.
    pub async fn get_access_restrictions(
        &self,
        user_uuid: &UserId,
        scope: CipherAccessScope,
        cipher_sync_data: Option<&CipherSyncData>,
        conn: &DbConn,
    ) -> Option<(bool, bool, bool)> {
        // Security: central fail-closed check binding cipher -> organization -> *confirmed* membership.
        // It denies access from assignment rows that outlived a revoke (or are still only
        // invited/accepted) and from cross-organization assignments another path might have persisted.
        // The sync path (cipher_sync_data is Some) is left to the caller: it is built only from confirmed
        // memberships and evaluated below against that cached data.
        if cipher_sync_data.is_none()
            && let Some(ref org_uuid) = self.organization_uuid
            && Membership::find_confirmed_by_user_and_org(user_uuid, org_uuid, conn).await.is_none()
        {
            return None;
        }

        // Check whether this cipher is directly owned by the user, or is in
        // a collection that the user has full access to. If so, there are no
        // access restrictions.
        if self.is_owned_by_user(user_uuid)
            || self.is_in_full_access_org(user_uuid, scope, cipher_sync_data, conn).await
            || self.is_in_full_access_group(user_uuid, cipher_sync_data, conn).await
        {
            return Some((false, false, true));
        }

        let rows = if let Some(cipher_sync_data) = cipher_sync_data {
            let mut rows: Vec<(bool, bool, bool)> = Vec::new();
            if let Some(collections) = cipher_sync_data.cipher_collections.get(&self.uuid) {
                for collection in collections {
                    // User permissions
                    if let Some(cu) = cipher_sync_data.user_collections.get(collection) {
                        rows.push((cu.read_only, cu.hide_passwords, cu.manage));
                    // Group permissions
                    } else if let Some(cg) = cipher_sync_data.user_collections_groups.get(collection) {
                        rows.push((cg.read_only, cg.hide_passwords, cg.manage));
                    }
                }
            }
            rows
        } else {
            let user_permissions = self.get_user_collections_access_flags(user_uuid, conn).await;
            if user_permissions.is_empty() {
                self.get_group_collections_access_flags(user_uuid, conn).await
            } else {
                user_permissions
            }
        };

        if rows.is_empty() {
            // This cipher isn't in any collections accessible to the user.
            return None;
        }

        // A cipher can be in multiple collections with inconsistent access flags.
        // Also, user permission overrule group permissions
        // and only user permissions are returned by the code above.
        //
        // For example, a cipher could be in one collection where the user has
        // read-only access, but also in another collection where the user has
        // read/write access. For a flag to be in effect for a cipher, upstream
        // requires all collections the cipher is in to have that flag set.
        // Therefore, we do a boolean AND of all values in each of the `read_only`
        // and `hide_passwords` columns. This could ideally be done as part of the
        // query, but Diesel doesn't support a min() or bool_and() function on
        // booleans and this behavior isn't portable anyway.
        //
        // The only exception is for the `manage` flag, that needs a boolean OR!
        let mut read_only = true;
        let mut hide_passwords = true;
        let mut manage = false;
        for (ro, hp, mn) in &rows {
            read_only &= ro;
            hide_passwords &= hp;
            manage |= mn;
        }

        Some((read_only, hide_passwords, manage))
    }

    async fn get_user_collections_access_flags(&self, user_uuid: &UserId, conn: &DbConn) -> Vec<(bool, bool, bool)> {
        let cipher_uuid = self.uuid.clone();
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            // Check whether this cipher is in any collections accessible to the
            // user. If so, retrieve the access flags for each collection.
            //
            // Security: bind the assignment to a *confirmed* membership in the same organization as both
            // the cipher and the collection, so a row left behind by a revoke, or pointing at another
            // organization's collection, grants nothing. Defense in depth.
            ciphers::table
                .filter(ciphers::uuid.eq(cipher_uuid))
                .inner_join(ciphers_collections::table.on(ciphers::uuid.eq(ciphers_collections::cipher_uuid)))
                .inner_join(
                    collections::table.on(collections::uuid
                        .eq(ciphers_collections::collection_uuid)
                        .and(collections::org_uuid.nullable().eq(ciphers::organization_uuid))),
                )
                .inner_join(
                    users_collections::table.on(ciphers_collections::collection_uuid
                        .eq(users_collections::collection_uuid)
                        .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                )
                .inner_join(
                    users_organizations::table.on(users_organizations::user_uuid
                        .eq(user_uuid)
                        .and(users_organizations::org_uuid.eq(collections::org_uuid))
                        .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                )
                .select((users_collections::read_only, users_collections::hide_passwords, users_collections::manage))
                .load::<(bool, bool, bool)>(conn)
                .expect("Error getting user access restrictions")
        })
        .await
    }

    async fn get_group_collections_access_flags(&self, user_uuid: &UserId, conn: &DbConn) -> Vec<(bool, bool, bool)> {
        if !CONFIG.org_groups_enabled() {
            return Vec::new();
        }
        let cipher_uuid = self.uuid.clone();
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            // Security: bind the group assignment to a *confirmed* membership and require cipher,
            // collection, group and membership to share one organization. The `collections` join is what
            // stops a cross-organization collection<->group assignment reaching foreign ciphers.
            ciphers::table
                .filter(ciphers::uuid.eq(cipher_uuid))
                .inner_join(ciphers_collections::table.on(ciphers::uuid.eq(ciphers_collections::cipher_uuid)))
                .inner_join(
                    collections_groups::table
                        .on(collections_groups::collections_uuid.eq(ciphers_collections::collection_uuid)),
                )
                .inner_join(groups_users::table.on(groups_users::groups_uuid.eq(collections_groups::groups_uuid)))
                .inner_join(
                    users_organizations::table.on(users_organizations::uuid
                        .eq(groups_users::users_organizations_uuid)
                        .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                )
                .inner_join(
                    groups::table.on(groups::uuid
                        .eq(collections_groups::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .inner_join(
                    collections::table.on(collections::uuid
                        .eq(ciphers_collections::collection_uuid)
                        .and(collections::org_uuid.eq(groups::organizations_uuid))
                        .and(collections::org_uuid.nullable().eq(ciphers::organization_uuid))),
                )
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .select((collections_groups::read_only, collections_groups::hide_passwords, collections_groups::manage))
                .load::<(bool, bool, bool)>(conn)
                .expect("Error getting group access restrictions")
        })
        .await
    }

    pub async fn is_write_accessible_to_user(
        &self,
        user_uuid: &UserId,
        scope: CipherAccessScope,
        conn: &DbConn,
    ) -> bool {
        match self.get_access_restrictions(user_uuid, scope, None, conn).await {
            Some((read_only, _hide_passwords, manage)) => !read_only || manage,
            None => false,
        }
    }

    // used for checking if collection can be edited (only if user has access to a collection they
    // can write to and also passwords are not hidden to prevent privilege escalation)
    pub async fn is_in_editable_collection_by_user(
        &self,
        user_uuid: &UserId,
        scope: CipherAccessScope,
        conn: &DbConn,
    ) -> bool {
        match self.get_access_restrictions(user_uuid, scope, None, conn).await {
            Some((read_only, hide_passwords, manage)) => (!read_only && !hide_passwords) || manage,
            None => false,
        }
    }

    pub async fn is_accessible_to_user(&self, user_uuid: &UserId, scope: CipherAccessScope, conn: &DbConn) -> bool {
        self.get_access_restrictions(user_uuid, scope, None, conn).await.is_some()
    }

    // Returns whether this cipher is a favorite of the specified user.
    pub async fn is_favorite(&self, user_uuid: &UserId, conn: &DbConn) -> bool {
        Favorite::is_favorite(&self.uuid, user_uuid, conn).await
    }

    // Sets whether this cipher is a favorite of the specified user.
    pub async fn set_favorite(&self, favorite: Option<bool>, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        match favorite {
            None => Ok(()), // No change requested.
            Some(status) => Favorite::set_favorite(status, &self.uuid, user_uuid, conn).await,
        }
    }

    pub async fn get_archived_at(&self, user_uuid: &UserId, conn: &DbConn) -> Option<NaiveDateTime> {
        Archive::get_archived_at(&self.uuid, user_uuid, conn).await
    }

    pub async fn set_archived_at(&self, archived_at: NaiveDateTime, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        Archive::save(user_uuid, &self.uuid, archived_at, conn).await
    }

    pub async fn unarchive(&self, user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        Archive::delete_by_cipher(user_uuid, &self.uuid, conn).await
    }

    pub async fn get_folder_uuid(&self, user_uuid: &UserId, conn: &DbConn) -> Option<FolderId> {
        conn.run(move |conn| {
            folders_ciphers::table
                .inner_join(folders::table)
                .filter(folders::user_uuid.eq(&user_uuid))
                .filter(folders_ciphers::cipher_uuid.eq(&self.uuid))
                .select(folders_ciphers::folder_uuid)
                .first::<FolderId>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_uuid(uuid: &CipherId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| ciphers::table.filter(ciphers::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_uuid_and_org(
        cipher_uuid: &CipherId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            ciphers::table
                .filter(ciphers::uuid.eq(cipher_uuid))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    // Find all ciphers accessible or visible to the specified user.
    //
    // "Accessible" means the user has read access to the cipher, either via
    // direct ownership, collection or via group access.
    //
    // "Visible" usually means the same as accessible, except when an org
    // owner/admin sets their account or group to have access to only selected
    // collections in the org (presumably because they aren't interested in
    // the other collections in the org). In this case, if `visible_only` is
    // true, then the non-interesting ciphers will not be returned. As a
    // result, those ciphers will not appear in "My Vault" for the org
    // owner/admin, but they can still be accessed via the org vault view.
    pub async fn find_by_user(
        user_uuid: &UserId,
        visible_only: bool,
        cipher_uuids: &Vec<CipherId>,
        conn: &DbConn,
    ) -> Vec<Self> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                let mut query = ciphers::table
                    .left_join(ciphers_collections::table.on(ciphers::uuid.eq(ciphers_collections::cipher_uuid)))
                    .left_join(
                        users_organizations::table.on(ciphers::organization_uuid
                            .eq(users_organizations::org_uuid.nullable())
                            .and(users_organizations::user_uuid.eq(user_uuid))
                            .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                    )
                    .left_join(
                        users_collections::table.on(ciphers_collections::collection_uuid
                            .eq(users_collections::collection_uuid)
                            // Ensure that users_collections::user_uuid is NULL for unconfirmed users.
                            .and(users_organizations::user_uuid.eq(users_collections::user_uuid))),
                    )
                    .left_join(
                        groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                    )
                    .left_join(
                        groups::table.on(groups::uuid
                            .eq(groups_users::groups_uuid)
                            // Ensure that group and membership belong to the same org
                            .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                    )
                    .left_join(
                        collections_groups::table.on(collections_groups::collections_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(collections_groups::groups_uuid.eq(groups::uuid))),
                    )
                    .filter(ciphers::user_uuid.eq(user_uuid)) // Cipher owner
                    .or_filter(users_collections::user_uuid.eq(user_uuid)) // Access to collection
                    .or_filter(groups::access_all.eq(true)) // Access via groups
                    .or_filter(collections_groups::collections_uuid.is_not_null()) // Access via groups
                    .into_boxed();

                if !visible_only {
                    // Administrative organization scope, separate from the normal user vault.
                    query = query.or_filter(
                        custom_membership_with_edit_any_collection()
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)),
                    );
                }

                // Only filter for one specific cipher
                if !cipher_uuids.is_empty() {
                    query = query.filter(ciphers::uuid.eq_any(cipher_uuids));
                }

                query.select(ciphers::all_columns).distinct().load::<Self>(conn).expect("Error loading ciphers")
            })
            .await
        } else {
            conn.run(move |conn| {
                let mut query = ciphers::table
                    .left_join(ciphers_collections::table.on(ciphers::uuid.eq(ciphers_collections::cipher_uuid)))
                    .left_join(
                        users_organizations::table.on(ciphers::organization_uuid
                            .eq(users_organizations::org_uuid.nullable())
                            .and(users_organizations::user_uuid.eq(user_uuid))
                            .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                    )
                    .left_join(
                        users_collections::table.on(ciphers_collections::collection_uuid
                            .eq(users_collections::collection_uuid)
                            // Ensure that users_collections::user_uuid is NULL for unconfirmed users.
                            .and(users_organizations::user_uuid.eq(users_collections::user_uuid))),
                    )
                    .filter(ciphers::user_uuid.eq(user_uuid)) // Cipher owner
                    .or_filter(users_collections::user_uuid.eq(user_uuid)) // Access to collection
                    .into_boxed();

                if !visible_only {
                    // Administrative organization scope, separate from the normal user vault.
                    query = query.or_filter(
                        custom_membership_with_edit_any_collection()
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)),
                    );
                }

                // Only filter for one specific cipher
                if !cipher_uuids.is_empty() {
                    query = query.filter(ciphers::uuid.eq_any(cipher_uuids));
                }

                query.select(ciphers::all_columns).distinct().load::<Self>(conn).expect("Error loading ciphers")
            })
            .await
        }
    }

    // Find all ciphers visible to the specified user.
    pub async fn find_by_user_visible(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        Self::find_by_user(user_uuid, true, &vec![], conn).await
    }

    pub async fn find_by_user_and_ciphers(
        user_uuid: &UserId,
        cipher_uuids: &Vec<CipherId>,
        conn: &DbConn,
    ) -> Vec<Self> {
        Self::find_by_user(user_uuid, true, cipher_uuids, conn).await
    }

    pub async fn find_by_user_and_cipher(user_uuid: &UserId, cipher_uuid: &CipherId, conn: &DbConn) -> Option<Self> {
        Self::find_by_user(user_uuid, true, &vec![cipher_uuid.clone()], conn).await.pop()
    }

    // Find all ciphers directly owned by the specified user.
    pub async fn find_owned_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            ciphers::table
                .filter(ciphers::user_uuid.eq(user_uuid).and(ciphers::organization_uuid.is_null()))
                .load::<Self>(conn)
                .expect("Error loading ciphers")
        })
        .await
    }

    pub async fn count_owned_by_user(user_uuid: &UserId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            ciphers::table.filter(ciphers::user_uuid.eq(user_uuid)).count().first::<i64>(conn).ok().unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            ciphers::table
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading ciphers")
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            ciphers::table.filter(ciphers::organization_uuid.eq(org_uuid)).count().first::<i64>(conn).ok().unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_folder(folder_uuid: &FolderId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            folders_ciphers::table
                .inner_join(ciphers::table)
                .filter(folders_ciphers::folder_uuid.eq(folder_uuid))
                .select(ciphers::all_columns)
                .load::<Self>(conn)
                .expect("Error loading ciphers")
        })
        .await
    }

    /// Find all ciphers that were deleted before the specified datetime.
    pub async fn find_deleted_before(dt: &NaiveDateTime, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            ciphers::table.filter(ciphers::deleted_at.lt(dt)).load::<Self>(conn).expect("Error loading ciphers")
        })
        .await
    }

    pub async fn get_collections(&self, user_uuid: UserId, conn: &DbConn) -> Vec<CollectionId> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(&self.uuid))
                    .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                    .left_join(
                        users_organizations::table.on(users_organizations::org_uuid
                            .eq(collections::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                    )
                    .left_join(
                        groups::table.on(groups::uuid
                            .eq(groups_users::groups_uuid)
                            .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                    )
                    .left_join(
                        collections_groups::table.on(collections_groups::collections_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(collections_groups::groups_uuid.eq(groups::uuid))),
                    )
                    .filter(
                        custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                            .or(users_collections::user_uuid
                                .eq(user_uuid) // User has access to collection
                                .and(users_collections::read_only.eq(false)))
                            .or(groups::access_all.eq(true)) // Access via groups
                            .or(collections_groups::collections_uuid
                                .is_not_null() // Access via groups
                                .and(collections_groups::read_only.eq(false))),
                    )
                    .select(ciphers_collections::collection_uuid)
                    .load::<CollectionId>(conn)
                    .unwrap_or_default()
            })
            .await
        } else {
            conn.run(move |conn| {
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(&self.uuid))
                    .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                    .inner_join(
                        users_organizations::table.on(users_organizations::org_uuid
                            .eq(collections::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .filter(
                        custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                            .or(users_collections::user_uuid
                                .eq(user_uuid) // User has access to collection
                                .and(users_collections::read_only.eq(false))),
                    )
                    .select(ciphers_collections::collection_uuid)
                    .load::<CollectionId>(conn)
                    .unwrap_or_default()
            })
            .await
        }
    }

    pub async fn get_admin_collections(&self, user_uuid: UserId, conn: &DbConn) -> Vec<CollectionId> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(&self.uuid))
                    .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                    .left_join(
                        users_organizations::table.on(users_organizations::org_uuid
                            .eq(collections::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)),
                    )
                    .left_join(
                        groups::table.on(groups::uuid
                            .eq(groups_users::groups_uuid)
                            .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                    )
                    .left_join(
                        collections_groups::table.on(collections_groups::collections_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(collections_groups::groups_uuid.eq(groups::uuid))),
                    )
                    .filter(
                        custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                            .or(users_collections::user_uuid
                                .eq(user_uuid) // User has access to collection
                                .and(users_collections::read_only.eq(false)))
                            .or(groups::access_all.eq(true)) // Access via groups
                            .or(collections_groups::collections_uuid
                                .is_not_null() // Access via groups
                                .and(collections_groups::read_only.eq(false)))
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)), // User is admin or owner
                    )
                    .select(ciphers_collections::collection_uuid)
                    .load::<CollectionId>(conn)
                    .unwrap_or_default()
            })
            .await
        } else {
            conn.run(move |conn| {
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(&self.uuid))
                    .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                    .inner_join(
                        users_organizations::table.on(users_organizations::org_uuid
                            .eq(collections::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(ciphers_collections::collection_uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .filter(
                        custom_membership_with_edit_any_collection() // Custom "Edit any collection" (successor of access_all)
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // or org admin/owner
                            .or(users_collections::user_uuid
                                .eq(user_uuid) // User has access to collection
                                .and(users_collections::read_only.eq(false)))
                            .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)), // User is admin or owner
                    )
                    .select(ciphers_collections::collection_uuid)
                    .load::<CollectionId>(conn)
                    .unwrap_or_default()
            })
            .await
        }
    }

    /// Return a Vec with (cipher_uuid, collection_uuid)
    /// This is used during a full sync so we only need one query for all collections accessible.
    pub async fn get_collections_with_cipher_by_user(
        user_uuid: UserId,
        conn: &DbConn,
    ) -> Vec<(CipherId, CollectionId)> {
        conn.run(move |conn| {
            ciphers_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(collections::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                )
                .left_join(
                    users_collections::table.on(users_collections::collection_uuid
                        .eq(ciphers_collections::collection_uuid)
                        .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                )
                .left_join(groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)))
                .left_join(
                    groups::table.on(groups::uuid
                        .eq(groups_users::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .left_join(
                    collections_groups::table.on(collections_groups::collections_uuid
                        .eq(ciphers_collections::collection_uuid)
                        .and(collections_groups::groups_uuid.eq(groups::uuid))),
                )
                .or_filter(users_collections::user_uuid.eq(user_uuid)) // User has access to collection
                .or_filter(custom_membership_with_edit_any_collection()) // Custom "Edit any collection" (successor of access_all)
                .or_filter(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)) // User is admin or owner
                .or_filter(groups::access_all.eq(true)) //Access via group
                .or_filter(collections_groups::collections_uuid.is_not_null()) //Access via group
                .select(ciphers_collections::all_columns)
                .distinct()
                .load::<(CipherId, CollectionId)>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn get_collections_with_cipher_by_organization(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<(CipherId, CollectionId)> {
        conn.run(move |conn| {
            ciphers_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(ciphers_collections::all_columns)
                .load::<(CipherId, CollectionId)>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// The organization's ciphers that have no collection assignment — upstream's
    /// `GetUnassignedOrganizationCiphers`.
    pub async fn find_unassigned_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            ciphers::table
                .left_join(ciphers_collections::table.on(ciphers_collections::cipher_uuid.eq(ciphers::uuid)))
                .filter(ciphers::organization_uuid.eq(org_uuid))
                .filter(ciphers::user_uuid.is_null())
                .filter(ciphers_collections::cipher_uuid.is_null())
                .select(ciphers::all_columns)
                .load::<Self>(conn)
                .unwrap_or_default()
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
pub struct CipherId(String);

#[cfg(test)]
mod tests {
    use super::CipherAccessScope;
    use crate::db::models::{Membership, MembershipStatus as Status, MembershipType, OrganizationId, UserId};

    const OWNER: i32 = MembershipType::Owner as i32;
    const ADMIN: i32 = MembershipType::Admin as i32;
    const USER: i32 = MembershipType::User as i32;
    const CUSTOM: i32 = MembershipType::Custom as i32;
    /// An `atype` this build cannot interpret: a future build, a partial rollback or a hand-edited row.
    const UNKNOWN: i32 = 99;

    /// `atype` is a raw `i32` and the permission flag is set regardless of the role on purpose, so the
    /// tests can cover a stale flag and a role this build does not know.
    fn membership(atype: i32, status: Status, edit_any_collection: bool) -> Membership {
        let mut member = Membership::new(
            UserId::from(String::from("test-user")),
            OrganizationId::from(String::from("test-org")),
            None,
        );
        member.atype = atype;
        member.status = status as i32;
        member.edit_any_collection = edit_any_collection;
        member
    }

    fn confirmed(atype: i32, edit_any_collection: bool) -> Membership {
        membership(atype, Status::Confirmed, edit_any_collection)
    }

    /// Who reaches *every* cipher of an organization, in each of the two scopes.
    ///
    /// The regular vault scope answers by role alone; the administrative scope additionally admits a
    /// confirmed Custom member holding `Edit any collection` -- upstream's `CanEditAllCiphersAsync`,
    /// which every `/ciphers/.../admin` route resolves through.
    #[test]
    fn cipher_access_scope_matrix() {
        // (case, atype, status, edit_any_collection, regular vault scope, administrative scope)
        let cases = [
            ("Owner", OWNER, Status::Confirmed, false, true, true),
            ("Admin", ADMIN, Status::Confirmed, false, true, true),
            // The role this change adds: administrative authority, and nothing beyond it.
            ("Custom + EditAny", CUSTOM, Status::Confirmed, true, false, true),
            ("Custom without EditAny", CUSTOM, Status::Confirmed, false, false, false),
            ("User", USER, Status::Confirmed, false, false, false),
            // A permission flag is only meaningful on a Custom membership, so one left behind by a
            // role change grants nothing.
            ("User with a stale EditAny flag", USER, Status::Confirmed, true, false, false),
            // The permission only activates once the membership is confirmed.
            ("Custom + EditAny, invited", CUSTOM, Status::Invited, true, false, false),
            ("Custom + EditAny, accepted", CUSTOM, Status::Accepted, true, false, false),
            ("Custom + EditAny, revoked", CUSTOM, Status::Revoked, true, false, false),
            // A role this build cannot interpret holds nothing, in either scope.
            ("unknown role", UNKNOWN, Status::Confirmed, true, false, false),
        ];

        for (case, atype, status, edit_any_collection, user_scope, admin_scope) in cases {
            let member = membership(atype, status, edit_any_collection);

            assert_eq!(
                CipherAccessScope::User.grants_org_wide_cipher_access(&member),
                user_scope,
                "{case}: regular vault scope"
            );
            assert_eq!(
                CipherAccessScope::OrganizationAdmin.grants_org_wide_cipher_access(&member),
                admin_scope,
                "{case}: administrative scope"
            );
            // A route picks which scope it runs under, so the administrative one must never be the
            // narrower of the two -- the worst case of picking it is the regular answer.
            assert!(!user_scope || admin_scope, "{case}: this row expects the administrative scope to narrow");
        }
    }

    /// The regression this separation exists for. The administrative authority above must not leak
    /// into the regular vault routes, so `/sync`, `GET /ciphers` and the non-admin
    /// `GET|PUT /ciphers/<id>` keep answering from the member's own collection assignments.
    #[test]
    fn edit_any_collection_does_not_widen_the_regular_vault_scope() {
        let member = confirmed(CUSTOM, true);

        assert!(!CipherAccessScope::User.grants_org_wide_cipher_access(&member));
        // The two scopes must genuinely disagree for this member; that difference *is* the fix.
        assert_ne!(
            CipherAccessScope::User.grants_org_wide_cipher_access(&member),
            CipherAccessScope::OrganizationAdmin.grants_org_wide_cipher_access(&member)
        );
    }

    // ---- Scope selection for the two attachment flows ----

    /// The v2 attachment *create* is the one route upstream lets the request pick the flow for
    /// (`adminRequest`), so the mapping is pinned here together with the one member it changes the
    /// answer for.
    #[test]
    fn admin_request_scope_selection() {
        assert_eq!(CipherAccessScope::requested(Some(true)), CipherAccessScope::OrganizationAdmin);
        assert_eq!(CipherAccessScope::requested(Some(false)), CipherAccessScope::User);
        assert_eq!(CipherAccessScope::requested(None), CipherAccessScope::User);

        let member = confirmed(CUSTOM, true);
        assert!(CipherAccessScope::requested(Some(true)).grants_org_wide_cipher_access(&member));
        assert!(!CipherAccessScope::requested(Some(false)).grants_org_wide_cipher_access(&member));
        assert!(!CipherAccessScope::requested(None).grants_org_wide_cipher_access(&member));
    }

    /// The flag must not be usable as a privilege escalation: it picks which predicate runs, and the
    /// administrative one still asks whether this member actually holds the authority.
    #[test]
    fn admin_request_flag_cannot_be_abused_for_escalation() {
        let scope = CipherAccessScope::requested(Some(true));
        assert_eq!(scope, CipherAccessScope::OrganizationAdmin);

        let escalation_attempts = [
            confirmed(USER, false),
            // A plain User carrying a stale `edit_any_collection` flag.
            confirmed(USER, true),
            confirmed(CUSTOM, false),
            membership(CUSTOM, Status::Invited, true),
            membership(CUSTOM, Status::Accepted, true),
            membership(CUSTOM, Status::Revoked, true),
            membership(UNKNOWN, Status::Confirmed, true),
        ];

        for member in &escalation_attempts {
            assert!(
                !scope.grants_org_wide_cipher_access(member),
                "atype {} / status {} must not reach org ciphers via adminRequest",
                member.atype,
                member.status
            );
        }
    }

    /// The v2 upload leg carries no `adminRequest`, so its scope comes from the membership alone and
    /// nothing in the request can talk that route into an administrative scope.
    #[test]
    fn upload_scope_is_resolved_from_the_membership() {
        // (case, membership, scope)
        let cases = [
            ("Custom + EditAny", confirmed(CUSTOM, true), CipherAccessScope::OrganizationAdmin),
            ("Owner", confirmed(OWNER, false), CipherAccessScope::OrganizationAdmin),
            ("Custom without EditAny", confirmed(CUSTOM, false), CipherAccessScope::User),
            ("User with a stale EditAny flag", confirmed(USER, true), CipherAccessScope::User),
            ("revoked Custom + EditAny", membership(CUSTOM, Status::Revoked, true), CipherAccessScope::User),
            ("unknown role", membership(UNKNOWN, Status::Confirmed, true), CipherAccessScope::User),
        ];

        for (case, member, expected) in cases {
            assert_eq!(CipherAccessScope::for_member(Some(&member)), expected, "{case}");
        }
        // No membership at all, e.g. a personal cipher.
        assert_eq!(CipherAccessScope::for_member(None), CipherAccessScope::User);
    }
}

/// The scope decision as the database actually answers it.
///
/// The tests above pin the predicate; this one pins the query path that consumes it. It is the only
/// place that shows a Custom member holding `Edit any collection` reaching a cipher they have no
/// assignment for -- and not reaching it in the regular vault scope.
#[cfg(all(test, sqlite))]
mod db_scope_tests {
    use super::{Cipher, CipherAccessScope};
    use crate::db::models::UserId;
    use crate::db::test_db::{TestDb, block_on};

    /// Two organizations, and one cipher in each.
    ///
    /// `u_custom` is a confirmed Custom member of org 1 holding `Edit any collection`, with **no**
    /// `users_collections` row and no group -- exactly the member whose administrative reach is not
    /// backed by an assignment. `u_assigned` is the plain User the collection is actually assigned
    /// to, so the fixture proves the cipher is reachable at all. `u_revoked` holds the same Custom
    /// permission with a revoked membership.
    const FIXTURE: &str = "
        INSERT INTO collections (uuid, org_uuid, name) VALUES
            ('col1', 'org1', 'c'),
            ('col2', 'org2', 'c');
        INSERT INTO ciphers (uuid, created_at, updated_at, organization_uuid, atype, name, data) VALUES
            ('cipher1', '2026-01-01 00:00:00', '2026-01-01 00:00:00', 'org1', 1, 'n', '{}'),
            ('cipher2', '2026-01-01 00:00:00', '2026-01-01 00:00:00', 'org2', 1, 'n', '{}');
        INSERT INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES
            ('cipher1', 'col1'),
            ('cipher2', 'col2');
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, akey, status, atype, edit_any_collection) VALUES
            ('m_custom',   'u_custom',   'org1', '', 2, 4, TRUE),
            ('m_revoked',  'u_revoked',  'org1', '', -1, 4, TRUE),
            ('m_assigned', 'u_assigned', 'org1', '', 2, 2, FALSE);
        INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage) VALUES
            ('u_assigned', 'col1', FALSE, FALSE, FALSE);
    ";

    /// Only the tables the cipher access queries join.
    const SCHEMA: &str = "
        CREATE TABLE collections (
            uuid TEXT NOT NULL PRIMARY KEY,
            org_uuid TEXT NOT NULL,
            name TEXT NOT NULL,
            external_id TEXT
        );
        CREATE TABLE ciphers (
            uuid TEXT NOT NULL PRIMARY KEY,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            user_uuid TEXT,
            organization_uuid TEXT,
            key TEXT,
            atype INTEGER NOT NULL,
            name TEXT NOT NULL,
            notes TEXT,
            fields TEXT,
            data TEXT NOT NULL,
            password_history TEXT,
            deleted_at DATETIME,
            reprompt INTEGER
        );
        CREATE TABLE ciphers_collections (
            cipher_uuid TEXT NOT NULL,
            collection_uuid TEXT NOT NULL,
            PRIMARY KEY (cipher_uuid, collection_uuid)
        );
        CREATE TABLE users_collections (
            user_uuid TEXT NOT NULL,
            collection_uuid TEXT NOT NULL,
            read_only BOOLEAN NOT NULL DEFAULT FALSE,
            hide_passwords BOOLEAN NOT NULL DEFAULT FALSE,
            manage BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (user_uuid, collection_uuid)
        );
        CREATE TABLE users_organizations (
            uuid TEXT NOT NULL PRIMARY KEY,
            user_uuid TEXT NOT NULL,
            org_uuid TEXT NOT NULL,
            invited_by_email TEXT,
            akey TEXT NOT NULL,
            status INTEGER NOT NULL,
            atype INTEGER NOT NULL,
            reset_password_key TEXT,
            external_id TEXT,
            manage_users BOOLEAN NOT NULL DEFAULT FALSE,
            manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
            manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
            create_new_collections BOOLEAN NOT NULL DEFAULT FALSE,
            edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
            delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
            access_event_logs BOOLEAN NOT NULL DEFAULT FALSE,
            access_import_export BOOLEAN NOT NULL DEFAULT FALSE,
            access_reports BOOLEAN NOT NULL DEFAULT FALSE
        );
    ";

    /// A cipher in `org_uuid`, matching the seeded row of the same id.
    fn cipher(uuid: &str, org_uuid: &str) -> Cipher {
        let mut cipher = Cipher::new(1, String::from("n"));
        cipher.uuid = uuid.to_owned().into();
        cipher.organization_uuid = Some(org_uuid.to_owned().into());
        cipher.data = String::from("{}");
        cipher
    }

    #[test]
    fn cipher_scope_is_enforced_against_the_database() {
        let db = TestDb::new(&format!("{SCHEMA}{FIXTURE}"));

        let own_org = cipher("cipher1", "org1");
        let other_org = cipher("cipher2", "org2");
        let custom: UserId = String::from("u_custom").into();
        let revoked: UserId = String::from("u_revoked").into();
        let assigned: UserId = String::from("u_assigned").into();

        // `DbConn` has to be created *and* dropped inside the runtime: its `Drop` uses
        // `spawn_blocking` to return the connection to the pool.
        block_on(async {
            let conn = db.conn();
            // The fixture is meaningful: the cipher is reachable through a real assignment.
            assert!(
                own_org.is_accessible_to_user(&assigned, CipherAccessScope::User, &conn).await,
                "the assigned member must reach the cipher, otherwise this fixture proves nothing"
            );

            // Custom + `Edit any collection`, with no assignment of its own: administrative reach...
            assert!(
                own_org.is_accessible_to_user(&custom, CipherAccessScope::OrganizationAdmin, &conn).await,
                "Custom + EditAny must reach an unassigned org cipher on the administrative routes"
            );
            assert!(
                own_org.is_write_accessible_to_user(&custom, CipherAccessScope::OrganizationAdmin, &conn).await,
                "administrative reach includes writing"
            );

            // ...and nothing at all in the regular vault, which is what `/sync` and `GET /ciphers`
            // answer from. A query that resolved the scope from the membership instead of from the
            // route would make this true and hand the member the whole organization vault.
            assert!(
                !own_org.is_accessible_to_user(&custom, CipherAccessScope::User, &conn).await,
                "Custom + EditAny must not reach an unassigned org cipher in the regular vault scope"
            );
            assert!(
                !own_org.is_write_accessible_to_user(&custom, CipherAccessScope::User, &conn).await,
                "Custom + EditAny must not write an unassigned org cipher in the regular vault scope"
            );

            // A revoked membership holds the same flag and reaches nothing, in either scope.
            for scope in [CipherAccessScope::User, CipherAccessScope::OrganizationAdmin] {
                assert!(
                    !own_org.is_accessible_to_user(&revoked, scope, &conn).await,
                    "a revoked membership must not reach org ciphers in any scope"
                );
            }

            // Another organization's cipher stays out of reach even in the administrative scope:
            // the authority is bound to the organization the membership belongs to.
            for scope in [CipherAccessScope::User, CipherAccessScope::OrganizationAdmin] {
                assert!(
                    !other_org.is_accessible_to_user(&custom, scope, &conn).await,
                    "a cipher of another organization must never be reachable"
                );
            }
        });
    }
}
