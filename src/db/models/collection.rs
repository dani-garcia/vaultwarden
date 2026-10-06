use std::collections::{HashMap, HashSet};

use derive_more::{AsRef, Deref, Display, From};
use diesel::{
    dsl::{count, count_star},
    prelude::*,
    result::{DatabaseErrorKind, Error as DieselError},
};
use serde_json::Value;
use tokio::time::{Duration, sleep};

use crate::{
    CONFIG,
    api::EmptyResult,
    db::{
        DbConn,
        schema::{
            ciphers_collections, collections, collections_groups, groups, groups_users, users_collections,
            users_organizations,
        },
    },
    error::MapResult,
};
use macros::UuidFromParam;

use super::{
    CipherId, CollectionGroup, GroupUser, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy,
    OrganizationId, User, UserId,
};

// See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/AdminConsole/Entities/Collection.cs
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = collections)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Collection {
    pub uuid: CollectionId,
    pub org_uuid: OrganizationId,
    pub name: String,
    pub external_id: Option<String>,
    /// The member whose "My Items" collection (upstream's `DefaultUserCollection`) this is, `None` for a shared one.
    pub default_user_uuid: Option<UserId>,
    /// The email address of the former owner of a My Items collection that was turned into a shared one.
    pub default_user_collection_email: Option<String>,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = users_collections)]
#[diesel(primary_key(user_uuid, collection_uuid))]
pub struct CollectionUser {
    pub user_uuid: UserId,
    pub collection_uuid: CollectionId,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = ciphers_collections)]
#[diesel(primary_key(cipher_uuid, collection_uuid))]
pub struct CollectionCipher {
    pub cipher_uuid: CipherId,
    pub collection_uuid: CollectionId,
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: OrganizationId, name: String, external_id: Option<String>) -> Self {
        let mut new_model = Self {
            uuid: CollectionId(crate::util::get_uuid()),
            org_uuid,
            name,
            external_id: None,
            default_user_uuid: None,
            default_user_collection_email: None,
        };

        new_model.set_external_id(external_id);
        new_model
    }

    pub fn is_default_user_collection(&self) -> bool {
        self.default_user_uuid.is_some()
    }

    /// Like upstream, an item that is only in shared collections can't be put (back) into a My Items collection.
    /// `current_collections` are the item's collections the acting user sees, before the change. Neither can an
    /// item of another member's My Items, which the acting user may administer but doesn't see:
    /// `cipher_my_items` are all the My Items collections the item is in.
    pub fn check_cipher_assignment(
        &self,
        current_collections: &HashSet<CollectionId>,
        cipher_my_items: &HashSet<CollectionId>,
    ) -> EmptyResult {
        if !self.is_default_user_collection() {
            return Ok(());
        }
        if !current_collections.is_empty() && !current_collections.contains(&self.uuid) {
            err!(
                "The cipher(s) cannot be assigned to a default collection when only assigned to non-default collections."
            )
        }
        if cipher_my_items.iter().any(|c| *c != self.uuid) {
            err!(
                "The cipher(s) cannot be assigned to a default collection when in another member's default collection."
            )
        }
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "externalId": self.external_id,
            "id": self.uuid,
            "organizationId": self.org_uuid,
            "name": self.name,
            // Collection types are either 0: SharedCollection or 1: DefaultUserCollection ("My Items").
            // See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/AdminConsole/Enums/CollectionType.cs
            "type": i32::from(self.is_default_user_collection()),
            // Set when a My Items collection outlived its owner's membership, the clients show it as the name.
            "defaultUserCollectionEmail": self.default_user_collection_email,
            "object": "collection",
        })
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        match external_id {
            Some(external_id) => {
                if external_id.is_empty() {
                    self.external_id = None;
                } else {
                    self.external_id = Some(external_id);
                }
            }
            None => self.external_id = None,
        }
    }

    pub async fn to_json_details(
        &self,
        user_uuid: &UserId,
        cipher_sync_data: Option<&crate::api::core::CipherSyncData>,
        conn: &DbConn,
    ) -> Value {
        let (read_only, hide_passwords, manage) = if let Some(cipher_sync_data) = cipher_sync_data {
            match cipher_sync_data.members.get(&self.org_uuid) {
                // Only for Manager types Bitwarden returns true for the manage option
                // Owners and Admins always have true. Users are not able to have full access
                Some(m) if m.has_full_access() => (false, false, m.atype >= MembershipType::Manager),
                Some(m) => {
                    // Only let a manager manage collections when the have full read/write access.
                    // The owner of a My Items collection, its only member, manages it whatever their type, like upstream.
                    let is_manager = m.atype == MembershipType::Manager || self.is_default_user_collection();
                    if let Some(cu) = cipher_sync_data.user_collections.get(&self.uuid) {
                        (
                            cu.read_only,
                            cu.hide_passwords,
                            is_manager && (cu.manage || (!cu.read_only && !cu.hide_passwords)),
                        )
                    } else if let Some(cg) = cipher_sync_data.user_collections_groups.get(&self.uuid) {
                        (
                            cg.read_only,
                            cg.hide_passwords,
                            is_manager && (cg.manage || (!cg.read_only && !cg.hide_passwords)),
                        )
                    } else {
                        (false, false, false)
                    }
                }
                _ => (true, true, false),
            }
        } else {
            match Membership::find_confirmed_by_user_and_org(user_uuid, &self.org_uuid, conn).await {
                Some(m) if m.has_full_access() => (false, false, m.atype >= MembershipType::Manager),
                Some(m) if m.atype == MembershipType::Manager && self.is_manageable_by_user(user_uuid, conn).await => {
                    (false, false, true)
                }
                Some(m) => {
                    let is_manager = m.atype == MembershipType::Manager || self.is_default_user_collection();
                    let read_only = !self.is_writable_by_user(user_uuid, conn).await;
                    let hide_passwords = self.hide_passwords_for_user(user_uuid, conn).await;
                    (read_only, hide_passwords, is_manager && !read_only && !hide_passwords)
                }
                _ => (true, true, false),
            }
        };

        let mut json_object = self.to_json();
        json_object["object"] = json!("collectionDetails");
        json_object["readOnly"] = json!(read_only);
        json_object["hidePasswords"] = json!(hide_passwords);
        json_object["manage"] = json!(manage);
        json_object
    }

    pub async fn can_access_collection(member: &Membership, col_id: &CollectionId, conn: &DbConn) -> bool {
        member.has_status(MembershipStatus::Confirmed)
            && (member.has_full_access()
                || CollectionUser::has_access_to_collection_by_user(col_id, &member.user_uuid, conn).await
                || (CONFIG.org_groups_enabled()
                    && (GroupUser::has_full_access_by_member(&member.org_uuid, &member.uuid, conn).await
                        || GroupUser::has_access_to_collection_by_member(col_id, &member.uuid, conn).await)))
    }
}

/// Database methods
impl Collection {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

        if self.is_default_user_collection() {
            // Only ever updated here. They are created by `create_default_user_collections()`: on MySQL, the upsert
            // below also fires on the unique `(org_uuid, default_user_uuid)` index and would overwrite the member's
            // existing My Items collection.
            return conn
                .run(move |conn| {
                    diesel::update(collections::table.filter(collections::uuid.eq(&self.uuid)))
                        .set(self)
                        .execute(conn)
                        .map_res("Error saving collection")
                })
                .await;
        }

        db_run! { conn:
            mysql {
                diesel::insert_into(collections::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving collection")
            }
            postgresql, sqlite {
                diesel::insert_into(collections::table)
                    .values(self)
                    .on_conflict(collections::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving collection")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        CollectionCipher::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionUser::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionGroup::delete_all_by_collection(&self.uuid, &self.org_uuid, conn).await?;

        conn.run(move |conn| {
            diesel::delete(collections::table.filter(collections::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting collection")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in Self::find_by_organization(org_uuid, conn).await {
            collection.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn update_users_revision(&self, conn: &DbConn) {
        if let Some(owner) = &self.default_user_uuid {
            if Membership::find_confirmed_by_user_and_org(owner, &self.org_uuid, conn).await.is_some() {
                User::update_uuid_revision(owner, conn).await;
            }
            return;
        }
        for member in &Membership::find_by_collection_and_org(&self.uuid, &self.org_uuid, conn).await {
            User::update_uuid_revision(&member.user_uuid, conn).await;
        }
    }

    pub async fn find_by_uuid(uuid: &CollectionId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| collections::table.filter(collections::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_user_uuid(user_uuid: UserId, conn: &DbConn) -> Vec<Self> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
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
                        collections_groups::table.on(collections_groups::groups_uuid
                            .eq(groups_users::groups_uuid)
                            .and(collections_groups::collections_uuid.eq(collections::uuid))),
                    )
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(
                        users_collections::user_uuid
                            .eq(user_uuid)
                            // access_all never reaches another member's My Items collection
                            .or(
                                // Directly accessed collection
                                users_organizations::access_all.eq(true).and(collections::default_user_uuid.is_null()), // access_all in Organization
                            )
                            .or(
                                groups::access_all.eq(true).and(collections::default_user_uuid.is_null()), // access_all in groups
                            )
                            .or(
                                // access via groups
                                groups_users::users_organizations_uuid
                                    .eq(users_organizations::uuid)
                                    .and(collections_groups::collections_uuid.is_not_null()),
                            ),
                    )
                    .select(collections::all_columns)
                    .distinct()
                    .load::<Self>(conn)
                    .expect("Error loading collections")
            })
            .await
        } else {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(users_collections::user_uuid.eq(user_uuid).or(
                        // Directly accessed collection
                        // access_all in Organization, which never reaches another member's My Items collection
                        users_organizations::access_all.eq(true).and(collections::default_user_uuid.is_null()),
                    ))
                    .select(collections::all_columns)
                    .distinct()
                    .load::<Self>(conn)
                    .expect("Error loading collections")
            })
            .await
        }
    }

    pub async fn find_by_organization_and_user_uuid(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Vec<Self> {
        Self::find_by_user_uuid(user_uuid.to_owned(), conn)
            .await
            .into_iter()
            .filter(|c| &c.org_uuid == org_uuid)
            .collect()
    }

    pub async fn find_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading collections")
        })
        .await
    }

    pub async fn count_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> i64 {
        conn.run(move |conn| {
            collections::table.filter(collections::org_uuid.eq(org_uuid)).count().first::<i64>(conn).ok().unwrap_or(0)
        })
        .await
    }

    pub async fn find_by_uuid_and_org(uuid: &CollectionId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            collections::table
                .filter(collections::uuid.eq(uuid))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(collections::all_columns)
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_default_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .filter(collections::default_user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Creates the member's My Items collection, with the name the client encrypted for it, when upstream does:
    /// the member is confirmed, not an Owner or Admin, and the organization data ownership policy is enabled.
    /// Without a name nothing is created, like upstream.
    pub async fn create_default_user_collection(member: &Membership, name: Option<&str>, conn: &DbConn) -> EmptyResult {
        if !OrgPolicy::is_personal_ownership_enforced_for(member, conn).await {
            return Ok(());
        }
        Self::create_default_user_collections(std::slice::from_ref(member), name, conn).await
    }

    /// Creates all missing My Items collections for an enabled organization data ownership policy in one
    /// transaction, and gives the members a missing access to their existing one back, which a member update racing
    /// the creation could remove in earlier versions. The caller is responsible for checking that the policy is
    /// enabled. Re-running this is safe and repairs incomplete provisioning from an earlier request. The unique index
    /// on `(org_uuid, default_user_uuid)` makes sure a member never gets a second one, also when requests race.
    pub async fn create_default_user_collections(
        members: &[Membership],
        name: Option<&str>,
        conn: &DbConn,
    ) -> EmptyResult {
        let Some(name) = name.filter(|n| !n.trim().is_empty()) else {
            return Ok(());
        };

        let eligible: Vec<(OrganizationId, UserId)> = members
            .iter()
            .filter(|member| member.has_status(MembershipStatus::Confirmed) && member.atype < MembershipType::Admin)
            .map(|member| (member.org_uuid.clone(), member.user_uuid.clone()))
            .collect();
        let Some((org_uuid, _)) = eligible.first() else {
            return Ok(());
        };
        if eligible.iter().any(|(member_org_uuid, _)| member_org_uuid != org_uuid) {
            err!("Cannot create My Items collections for members of different organizations")
        }
        let org_uuid = org_uuid.clone();
        let user_uuids: Vec<UserId> = eligible.into_iter().map(|(_, user_uuid)| user_uuid).collect();

        // The body of the transaction below, for the members it found still eligible: gives them back a missing
        // access to their existing My Items collection and creates the missing ones. Returns the members whose
        // access changed.
        macro_rules! provision {
            ($conn:ident, $org_uuid:ident, $members:ident, $name:ident) => {{
                let missing_access = collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.nullable().eq(collections::default_user_uuid))),
                    )
                    .filter(collections::org_uuid.eq(&$org_uuid))
                    .filter(collections::default_user_uuid.eq_any(&$members))
                    .filter(users_collections::user_uuid.is_null())
                    .select((
                        collections::default_user_uuid.assume_not_null(),
                        collections::uuid,
                        false.into_sql::<diesel::sql_types::Bool>(),
                        false.into_sql::<diesel::sql_types::Bool>(),
                        true.into_sql::<diesel::sql_types::Bool>(),
                    ));
                let restored = diesel::insert_into(users_collections::table)
                    .values(missing_access)
                    .into_columns((
                        users_collections::user_uuid,
                        users_collections::collection_uuid,
                        users_collections::read_only,
                        users_collections::hide_passwords,
                        users_collections::manage,
                    ))
                    .execute($conn)?;
                let existing: HashSet<UserId> = collections::table
                    .filter(collections::org_uuid.eq(&$org_uuid))
                    .filter(collections::default_user_uuid.eq_any(&$members))
                    .select(collections::default_user_uuid)
                    .load::<Option<UserId>>($conn)?
                    .into_iter()
                    .flatten()
                    .collect();

                let mut created = Vec::new();
                for user_uuid in $members.iter().filter(|user_uuid| !existing.contains(*user_uuid)) {
                    let mut collection = Self::new($org_uuid.clone(), $name.clone(), None);
                    collection.default_user_uuid = Some(user_uuid.clone());
                    let owner_access = CollectionUser {
                        user_uuid: user_uuid.clone(),
                        collection_uuid: collection.uuid.clone(),
                        read_only: false,
                        hide_passwords: false,
                        manage: true,
                    };
                    diesel::insert_into(collections::table).values(&collection).execute($conn)?;
                    diesel::insert_into(users_collections::table).values(&owner_access).execute($conn)?;
                    created.push(user_uuid.clone());
                }
                Ok::<_, DieselError>(if restored > 0 {
                    $members
                } else {
                    created
                })
            }};
        }

        // A concurrent request can create one of these between the read and insert. Retry when the unique index
        // rejects the insert, which MySQL and MariaDB often report as a deadlock instead of a unique violation; the
        // next read omits the collections created by the racer.
        for attempt in 0..3 {
            if attempt > 0 {
                // Give the concurrent request time to commit, so the next read sees what it created
                sleep(Duration::from_millis(100)).await;
            }
            let (org_uuid, name) = (org_uuid.clone(), name.to_owned());
            // Only the members that are still confirmed, and neither an Owner nor an Admin, when the transaction runs
            // get one. The members were loaded before, and a removal converting their My Items collection could have
            // run meanwhile or run concurrently: see `Membership::delete()`, which removes the membership first.
            let eligible = users_organizations::table
                .filter(users_organizations::org_uuid.eq(org_uuid.clone()))
                .filter(users_organizations::user_uuid.eq_any(user_uuids.clone()))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_organizations::atype.eq_any([MembershipType::User as i32, MembershipType::Manager as i32]),
                )
                .select(users_organizations::user_uuid);
            let result = db_run! { conn:
                mysql, postgresql {
                    // Locking the memberships makes a concurrent removal wait until the collections are created, so
                    // it converts them, or makes this wait until the removal is done, so it doesn't find the member.
                    conn.transaction(|conn| {
                        let members = eligible.for_update().load::<UserId>(conn)?;
                        provision!(conn, org_uuid, members, name)
                    })
                }
                sqlite {
                    // No row locks: taking the database write lock before reading serializes this with the removal.
                    conn.immediate_transaction(|conn| {
                        let members = eligible.load::<UserId>(conn)?;
                        provision!(conn, org_uuid, members, name)
                    })
                }
            };

            match result {
                Ok(changed) => {
                    User::update_uuid_revisions(changed, conn).await;
                    return Ok(());
                }
                Err(DieselError::DatabaseError(
                    DatabaseErrorKind::UniqueViolation | DatabaseErrorKind::SerializationFailure,
                    _,
                )) => {}
                Err(e) => return Err::<(), _>(e).map_res("Error creating My Items collections"),
            }
        }

        err!("A concurrent request kept changing the My Items collections; please retry")
    }

    /// Offboards what remains of a deleted account in the organizations, once its memberships are removed, like
    /// upstream's `User_DeleteById`: turns the My Items collections still attributed to the user into shared ones
    /// named by their email address, and removes their collection access, which would otherwise block the deletion.
    /// A member removal racing the creation of a My Items collection could leave both behind in earlier versions.
    pub async fn release_all_by_user(user_uuid: &UserId, email: &str, conn: &DbConn) -> EmptyResult {
        let email = email.to_owned();
        conn.run(move |conn| {
            conn.transaction::<_, DieselError, _>(|conn| {
                diesel::update(collections::table.filter(collections::default_user_uuid.eq(user_uuid)))
                    .set((
                        collections::default_user_uuid.eq(None::<UserId>),
                        collections::default_user_collection_email.eq(email),
                    ))
                    .execute(conn)?;
                diesel::delete(users_collections::table.filter(users_collections::user_uuid.eq(user_uuid)))
                    .execute(conn)?;
                Ok(())
            })
            .map_res("Error removing the user's collection access")
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &CollectionId, user_uuid: UserId, conn: &DbConn) -> Option<Self> {
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))),
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
                        collections_groups::table.on(collections_groups::groups_uuid
                            .eq(groups_users::groups_uuid)
                            .and(collections_groups::collections_uuid.eq(collections::uuid))),
                    )
                    .filter(collections::uuid.eq(uuid))
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(
                        users_collections::collection_uuid
                            .eq(uuid)
                            .or(
                                // Directly accessed collection
                                users_organizations::access_all.eq(true).or(
                                    // access_all in Organization
                                    users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                                ),
                            )
                            .or(
                                groups::access_all.eq(true), // access_all in groups
                            )
                            .or(
                                // access via groups
                                groups_users::users_organizations_uuid
                                    .eq(users_organizations::uuid)
                                    .and(collections_groups::collections_uuid.is_not_null()),
                            ),
                    )
                    .select(collections::all_columns)
                    .first::<Self>(conn)
                    .ok()
            })
            .await
        } else {
            conn.run(move |conn| {
                collections::table
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid))),
                    )
                    .filter(collections::uuid.eq(uuid))
                    .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                    .filter(users_collections::collection_uuid.eq(uuid).or(
                        // Directly accessed collection
                        users_organizations::access_all.eq(true).or(
                            // access_all in Organization
                            users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                        ),
                    ))
                    .select(collections::all_columns)
                    .first::<Self>(conn)
                    .ok()
            })
            .await
        }
    }

    pub async fn is_writable_by_user(&self, user_uuid: &UserId, conn: &DbConn) -> bool {
        // Only its owner can put items into a My Items collection, admin rights and access_all don't reach into it.
        // Like any collection access upstream, only while the owner is a confirmed member of the organization.
        if let Some(owner) = &self.default_user_uuid {
            return owner == user_uuid
                && Membership::find_confirmed_by_user_and_org(user_uuid, &self.org_uuid, conn).await.is_some();
        }
        let user_uuid = user_uuid.to_string();
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .filter(collections::uuid.eq(&self.uuid))
                    .inner_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))
                            .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid))),
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
                        collections_groups::table.on(collections_groups::groups_uuid
                            .eq(groups_users::groups_uuid)
                            .and(collections_groups::collections_uuid.eq(collections::uuid))),
                    )
                    .filter(
                        users_organizations::atype
                            .le(MembershipType::Admin as i32) // Org admin or owner
                            .or(users_organizations::access_all.eq(true)) // access_all via membership
                            .or(users_collections::collection_uuid
                                .eq(&self.uuid) // write access given to collection
                                .and(users_collections::read_only.eq(false)))
                            .or(groups::access_all.eq(true)) // access_all via group
                            .or(collections_groups::collections_uuid
                                .is_not_null() // write access given via group
                                .and(collections_groups::read_only.eq(false))),
                    )
                    .count()
                    .first::<i64>(conn)
                    .ok()
                    .unwrap_or(0)
                    != 0
            })
            .await
        } else {
            conn.run(move |conn| {
                collections::table
                    .filter(collections::uuid.eq(&self.uuid))
                    .inner_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))
                            .and(users_organizations::status.eq(MembershipStatus::Confirmed as i32))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid))),
                    )
                    .filter(
                        users_organizations::atype
                            .le(MembershipType::Admin as i32) // Org admin or owner
                            .or(users_organizations::access_all.eq(true)) // access_all via membership
                            .or(users_collections::collection_uuid
                                .eq(&self.uuid) // write access given to collection
                                .and(users_collections::read_only.eq(false))),
                    )
                    .count()
                    .first::<i64>(conn)
                    .ok()
                    .unwrap_or(0)
                    != 0
            })
            .await
        }
    }

    pub async fn hide_passwords_for_user(&self, user_uuid: &UserId, conn: &DbConn) -> bool {
        let user_uuid = user_uuid.to_string();
        conn.run(move |conn| {
            collections::table
                .left_join(
                    users_collections::table.on(users_collections::collection_uuid
                        .eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                )
                .left_join(
                    users_organizations::table.on(collections::org_uuid
                        .eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .left_join(groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)))
                .left_join(
                    groups::table.on(groups::uuid
                        .eq(groups_users::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .left_join(
                    collections_groups::table.on(collections_groups::groups_uuid
                        .eq(groups_users::groups_uuid)
                        .and(collections_groups::collections_uuid.eq(collections::uuid))),
                )
                .filter(collections::uuid.eq(&self.uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_collections::collection_uuid
                        .eq(&self.uuid)
                        .and(users_collections::hide_passwords.eq(true))
                        .or(
                            // Directly accessed collection
                            users_organizations::access_all.eq(true).or(
                                // access_all in Organization
                                users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                            ),
                        )
                        .or(
                            groups::access_all.eq(true), // access_all in groups
                        )
                        .or(
                            // access via groups
                            groups_users::users_organizations_uuid.eq(users_organizations::uuid).and(
                                collections_groups::collections_uuid
                                    .is_not_null()
                                    .and(collections_groups::hide_passwords.eq(true)),
                            ),
                        ),
                )
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    pub async fn is_coll_manageable_by_user(uuid: &CollectionId, user_uuid: &UserId, conn: &DbConn) -> bool {
        let uuid = uuid.to_string();
        let user_uuid = user_uuid.to_string();
        conn.run(move |conn| {
            collections::table
                .left_join(
                    users_collections::table.on(users_collections::collection_uuid
                        .eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                )
                .left_join(
                    users_organizations::table.on(collections::org_uuid
                        .eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .left_join(groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)))
                .left_join(
                    groups::table.on(groups::uuid
                        .eq(groups_users::groups_uuid)
                        .and(groups::organizations_uuid.eq(users_organizations::org_uuid))),
                )
                .left_join(
                    collections_groups::table.on(collections_groups::groups_uuid
                        .eq(groups_users::groups_uuid)
                        .and(collections_groups::collections_uuid.eq(collections::uuid))),
                )
                .filter(collections::uuid.eq(&uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    users_collections::collection_uuid
                        .eq(&uuid)
                        .and(users_collections::manage.eq(true))
                        .or(
                            // Directly accessed collection
                            users_organizations::access_all.eq(true).or(
                                // access_all in Organization
                                users_organizations::atype.le(MembershipType::Admin as i32), // Org admin or owner
                            ),
                        )
                        .or(
                            groups::access_all.eq(true), // access_all in groups
                        )
                        .or(
                            // access via groups
                            groups_users::users_organizations_uuid.eq(users_organizations::uuid).and(
                                collections_groups::collections_uuid
                                    .is_not_null()
                                    .and(collections_groups::manage.eq(true)),
                            ),
                        ),
                )
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    pub async fn is_manageable_by_user(&self, user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::is_coll_manageable_by_user(&self.uuid, user_uuid, conn).await
    }

    // Whether the user has manage access to at least one collection in the org, directly or via a
    // group. Org-scoped counterpart of is_coll_manageable_by_user.
    pub async fn has_manageable_collection_by_user(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> bool {
        let org_uuid = org_uuid.to_string();
        let user_uuid = user_uuid.to_string();
        conn.run(move |conn| {
            collections::table
                .left_join(
                    users_collections::table.on(users_collections::collection_uuid
                        .eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(user_uuid.clone()))),
                )
                .left_join(
                    users_organizations::table.on(collections::org_uuid
                        .eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid))),
                )
                .left_join(groups_users::table.on(groups_users::users_organizations_uuid.eq(users_organizations::uuid)))
                .left_join(
                    collections_groups::table.on(collections_groups::groups_uuid
                        .eq(groups_users::groups_uuid)
                        .and(collections_groups::collections_uuid.eq(collections::uuid))),
                )
                .filter(collections::org_uuid.eq(&org_uuid))
                // Like upstream, only shared collections count: every member manages their own My Items collection
                .filter(collections::default_user_uuid.is_null())
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(
                    // Manage permission on a collection assigned directly or via a group.
                    users_collections::manage.eq(true).or(collections_groups::manage.eq(true)),
                )
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }
}

/// Database methods
impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(
        org_uuid: &OrganizationId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::user_uuid.eq(user_uuid))
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn find_by_organization_swap_user_uuid_with_member_uuid(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<CollectionMembership> {
        let col_users = conn
            .run(move |conn| {
                users_collections::table
                    .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                    .filter(collections::org_uuid.eq(org_uuid))
                    .inner_join(
                        users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)),
                    )
                    .filter(users_organizations::org_uuid.eq(org_uuid))
                    .select((
                        users_organizations::uuid,
                        users_collections::collection_uuid,
                        users_collections::read_only,
                        users_collections::hide_passwords,
                        users_collections::manage,
                    ))
                    .load::<Self>(conn)
                    .expect("Error loading users_collections")
            })
            .await;
        col_users.into_iter().map(Into::into).collect()
    }

    pub async fn save(
        user_uuid: &UserId,
        collection_uuid: &CollectionId,
        read_only: bool,
        hide_passwords: bool,
        manage: bool,
        conn: &DbConn,
    ) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;

        let values = (
            users_collections::user_uuid.eq(user_uuid),
            users_collections::collection_uuid.eq(collection_uuid),
            users_collections::read_only.eq(read_only),
            users_collections::hide_passwords.eq(hide_passwords),
            users_collections::manage.eq(manage),
        );

        db_run! { conn:
            mysql {
                diesel::insert_into(users_collections::table)
                    .values(values)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(values)
                    .execute(conn)
                    .map_res("Error adding user to collection")
            }
            postgresql, sqlite {
                diesel::insert_into(users_collections::table)
                    .values(values)
                    .on_conflict((users_collections::user_uuid, users_collections::collection_uuid))
                    .do_update()
                    .set(values)
                    .execute(conn)
                    .map_res("Error adding user to collection")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(
                users_collections::table
                    .filter(users_collections::user_uuid.eq(&self.user_uuid))
                    .filter(users_collections::collection_uuid.eq(&self.collection_uuid)),
            )
            .execute(conn)
            .map_res("Error removing user from collection")
        })
        .await
    }

    pub async fn find_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn find_by_org_and_coll_swap_user_uuid_with_member_uuid(
        org_uuid: &OrganizationId,
        collection_uuid: &CollectionId,
        conn: &DbConn,
    ) -> Vec<CollectionMembership> {
        let col_users = conn
            .run(move |conn| {
                users_collections::table
                    .filter(users_collections::collection_uuid.eq(collection_uuid))
                    .filter(users_organizations::org_uuid.eq(org_uuid))
                    .inner_join(
                        users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)),
                    )
                    .select((
                        users_organizations::uuid,
                        users_collections::collection_uuid,
                        users_collections::read_only,
                        users_collections::hide_passwords,
                        users_collections::manage,
                    ))
                    .load::<Self>(conn)
                    .expect("Error loading users_collections")
            })
            .await;
        col_users.into_iter().map(Into::into).collect()
    }

    pub async fn find_by_collection_and_user(
        collection_uuid: &CollectionId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .filter(users_collections::user_uuid.eq(user_uuid))
                .select(users_collections::all_columns)
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    // Only returns the collections of organizations the user is a confirmed member of
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .inner_join(
                    users_organizations::table.on(users_organizations::org_uuid
                        .eq(collections::org_uuid)
                        .and(users_organizations::user_uuid.eq(users_collections::user_uuid))),
                )
                .filter(users_collections::user_uuid.eq(user_uuid))
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .select(users_collections::all_columns)
                .load::<Self>(conn)
                .expect("Error loading users_collections")
        })
        .await
    }

    pub async fn delete_all_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        for collection in &CollectionUser::find_by_collection(collection_uuid, conn).await {
            User::update_uuid_revision(&collection.user_uuid, conn).await;
        }

        conn.run(move |conn| {
            diesel::delete(users_collections::table.filter(users_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error deleting users from collection")
        })
        .await
    }

    pub async fn delete_all_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> EmptyResult {
        let collectionusers = Self::find_by_organization_and_user_uuid(org_uuid, user_uuid, conn).await;

        conn.run(move |conn| {
            for user in collectionusers {
                let _: () = diesel::delete(
                    users_collections::table.filter(
                        users_collections::user_uuid
                            .eq(user_uuid)
                            .and(users_collections::collection_uuid.eq(user.collection_uuid)),
                    ),
                )
                .execute(conn)
                .map_res("Error removing user from collections")?;
            }
            Ok(())
        })
        .await
    }

    /// Removes the user from all the organization's collections except their own My Items collection. In one
    /// statement, like upstream's `OrganizationUser_UpdateWithCollections`, so it also keeps a My Items
    /// collection another request creates meanwhile.
    pub async fn delete_all_but_my_items_by_user_and_org(
        user_uuid: &UserId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(
                users_collections::table.filter(users_collections::user_uuid.eq(user_uuid)).filter(
                    users_collections::collection_uuid.eq_any(
                        collections::table
                            .filter(collections::org_uuid.eq(org_uuid))
                            .filter(
                                collections::default_user_uuid
                                    .is_null()
                                    .or(collections::default_user_uuid.ne(user_uuid)),
                            )
                            .select(collections::uuid),
                    ),
                ),
            )
            .execute(conn)
            .map(|_| ())
            .map_res("Error removing user from collections")
        })
        .await
    }

    pub async fn has_access_to_collection_by_user(col_id: &CollectionId, user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::find_by_collection_and_user(col_id, user_uuid, conn).await.is_some()
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(cipher_uuid: &CipherId, collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        db_run! { conn:
            mysql {
                diesel::insert_into(ciphers_collections::table)
                    .values((
                        ciphers_collections::cipher_uuid.eq(cipher_uuid),
                        ciphers_collections::collection_uuid.eq(collection_uuid),
                    ))
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to collection")
            }
            postgresql, sqlite {
                diesel::insert_into(ciphers_collections::table)
                    .values((
                        ciphers_collections::cipher_uuid.eq(cipher_uuid),
                        ciphers_collections::collection_uuid.eq(collection_uuid),
                    ))
                    .on_conflict((ciphers_collections::cipher_uuid, ciphers_collections::collection_uuid))
                    .do_nothing()
                    .execute(conn)
                    .map_res("Error adding cipher to collection")
            }
        }
    }

    pub async fn delete(cipher_uuid: &CipherId, collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        conn.run(move |conn| {
            diesel::delete(
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                    .filter(ciphers_collections::collection_uuid.eq(collection_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting cipher from collection")
        })
        .await
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from collections")
        })
        .await
    }

    pub async fn delete_all_by_collection(collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from collection")
        })
        .await
    }

    pub async fn update_users_revision(collection_uuid: &CollectionId, conn: &DbConn) {
        if let Some(collection) = Collection::find_by_uuid(collection_uuid, conn).await {
            collection.update_users_revision(conn).await;
        }
    }

    /// Changes the cipher's collections in one transaction: adds it to `add` and removes it from `remove`.
    pub async fn update_for_cipher(
        cipher_uuid: &CipherId,
        add: Vec<CollectionId>,
        remove: Vec<CollectionId>,
        conn: &DbConn,
    ) -> EmptyResult {
        // Before the change, like `save()` and `delete()`, so the members that lose the cipher sync as well
        for collection_uuid in add.iter().chain(&remove) {
            Self::update_users_revision(collection_uuid, conn).await;
        }
        let rows: Vec<_> = add
            .iter()
            .map(|c| (ciphers_collections::cipher_uuid.eq(cipher_uuid), ciphers_collections::collection_uuid.eq(c)))
            .collect();
        let remove_rows = ciphers_collections::table
            .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
            .filter(ciphers_collections::collection_uuid.eq_any(&remove));
        db_run! { conn:
            mysql {
                conn.transaction::<_, DieselError, _>(|conn| {
                    if !rows.is_empty() {
                        diesel::insert_into(ciphers_collections::table)
                            .values(&rows)
                            .on_conflict(diesel::dsl::DuplicatedKeys)
                            .do_nothing()
                            .execute(conn)?;
                    }
                    diesel::delete(remove_rows).execute(conn)
                })
                .map(|_| ())
                .map_res("Error updating the cipher's collections")
            }
            postgresql, sqlite {
                conn.transaction::<_, DieselError, _>(|conn| {
                    if !rows.is_empty() {
                        diesel::insert_into(ciphers_collections::table)
                            .values(&rows)
                            .on_conflict((ciphers_collections::cipher_uuid, ciphers_collections::collection_uuid))
                            .do_nothing()
                            .execute(conn)?;
                    }
                    diesel::delete(remove_rows).execute(conn)
                })
                .map(|_| ())
                .map_res("Error updating the cipher's collections")
            }
        }
    }

    /// The organizations' ciphers that are in My Items collections only.
    pub async fn find_my_items_only_by_orgs(org_uuids: Vec<OrganizationId>, conn: &DbConn) -> HashSet<CipherId> {
        if org_uuids.is_empty() {
            return HashSet::new();
        }
        conn.run(move |conn| {
            ciphers_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                .filter(collections::org_uuid.eq_any(org_uuids))
                .group_by(ciphers_collections::cipher_uuid)
                .select((ciphers_collections::cipher_uuid, count(collections::default_user_uuid), count_star()))
                .load::<(CipherId, i64, i64)>(conn)
                .expect("Error loading My Items ciphers")
                .into_iter()
                .filter(|(_, in_my_items, in_total)| in_my_items == in_total)
                .map(|(cipher_uuid, _, _)| cipher_uuid)
                .collect()
        })
        .await
    }

    /// The organization's ciphers that are in a My Items collection, each with those My Items collections.
    pub async fn find_my_items_by_org(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> HashMap<CipherId, Vec<CollectionId>> {
        conn.run(move |conn| {
            ciphers_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .filter(collections::default_user_uuid.is_not_null())
                .select(ciphers_collections::all_columns)
                .load::<(CipherId, CollectionId)>(conn)
                .expect("Error loading My Items ciphers")
                .into_iter()
                .fold(HashMap::new(), |mut map: HashMap<CipherId, Vec<CollectionId>>, (cipher, collection)| {
                    map.entry(cipher).or_default().push(collection);
                    map
                })
        })
        .await
    }

    /// The My Items collections the cipher is in, whoever's they are.
    pub async fn find_my_items_of_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> HashSet<CollectionId> {
        conn.run(move |conn| {
            ciphers_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                .filter(collections::default_user_uuid.is_not_null())
                .select(ciphers_collections::collection_uuid)
                .load::<CollectionId>(conn)
                .expect("Error loading the cipher's My Items collections")
                .into_iter()
                .collect()
        })
        .await
    }

    /// Returns the owners when the cipher is assigned exclusively to My Items collections. `None` means that the
    /// cipher is unassigned or has at least one shared collection assignment.
    pub async fn find_my_items_owners_if_only(cipher_uuid: &CipherId, conn: &DbConn) -> Option<HashSet<UserId>> {
        let owners = conn
            .run(move |conn| {
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                    .inner_join(collections::table.on(collections::uuid.eq(ciphers_collections::collection_uuid)))
                    .select(collections::default_user_uuid)
                    .load::<Option<UserId>>(conn)
                    .expect("Error loading My Items owners")
            })
            .await;

        if owners.is_empty() || owners.iter().any(Option::is_none) {
            None
        } else {
            Some(owners.into_iter().flatten().collect())
        }
    }

    pub async fn delete_all_shared_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                ciphers_collections::table.filter(
                    ciphers_collections::collection_uuid.eq_any(
                        collections::table
                            .filter(collections::org_uuid.eq(org_uuid))
                            .filter(collections::default_user_uuid.is_null())
                            .select(collections::uuid),
                    ),
                ),
            )
            .execute(conn)
            .map_res("Error removing ciphers from the shared collections")
        })
        .await
    }
}

// Added in case we need the membership_uuid instead of the user_uuid
pub struct CollectionMembership {
    pub membership_uuid: MembershipId,
    pub collection_uuid: CollectionId,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl CollectionMembership {
    pub fn to_json_details_for_member(&self, membership_type: i32) -> Value {
        json!({
            "id": self.membership_uuid,
            "readOnly": self.read_only,
            "hidePasswords": self.hide_passwords,
            "manage": membership_type >= MembershipType::Admin
                || self.manage
                || (membership_type == MembershipType::Manager
                    && !self.read_only
                    && !self.hide_passwords),
        })
    }
}

impl From<CollectionUser> for CollectionMembership {
    fn from(c: CollectionUser) -> Self {
        Self {
            membership_uuid: c.user_uuid.to_string().into(),
            collection_uuid: c.collection_uuid,
            read_only: c.read_only,
            hide_passwords: c.hide_passwords,
            manage: c.manage,
        }
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
pub struct CollectionId(String);
