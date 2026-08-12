use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use num_traits::FromPrimitive;
use serde_json::Value;

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
    CipherId, CollectionGroup, GroupUser, Membership, MembershipId, MembershipStatus, MembershipType, OrganizationId,
    User, UserId,
    organization::{ORG_ADMIN_ATYPES, custom_membership_with_edit_any_collection},
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

/// Serialize the assignment-level `manage` capability using the same role boundary as the
/// collection mutation guards. Read/write access is deliberately not management authority.
///
/// This answers "may this member manage this collection?" and therefore belongs on the objects a
/// member receives about themselves. For the administrative lists that echo a *stored* grant back
/// to the client, use `stored_assignment_manage` instead.
pub(super) fn assignment_manage_for_member(membership_type: i32, stored_manage: bool) -> bool {
    match MembershipType::from_i32(membership_type) {
        Some(MembershipType::Owner | MembershipType::Admin) => true,
        Some(MembershipType::Custom) => stored_manage,
        Some(MembershipType::User) | None => false,
    }
}

/// Serialize a *stored* per-collection assignment row for the admin-console access lists.
///
/// These lists describe the grant an administrator configured, and the client writes the very same
/// value back when the dialog is saved. Reporting anything other than the persisted bit would make
/// an unrelated save silently strip it — for a plain User that would also revoke the cipher write
/// access `users_collections.manage` still grants (see `Cipher::get_access_restrictions`). Admins
/// and Owners manage implicitly, so they are reported as managing regardless of the stored row.
pub(super) fn stored_assignment_manage(membership_type: i32, stored_manage: bool) -> bool {
    matches!(MembershipType::from_i32(membership_type), Some(MembershipType::Owner | MembershipType::Admin))
        || stored_manage
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: OrganizationId, name: String, external_id: Option<String>) -> Self {
        let mut new_model = Self {
            uuid: CollectionId(crate::util::get_uuid()),
            org_uuid,
            name,
            external_id: None,
        };

        new_model.set_external_id(external_id);
        new_model
    }

    pub fn to_json(&self) -> Value {
        json!({
            "externalId": self.external_id,
            "id": self.uuid,
            "organizationId": self.org_uuid,
            "name": self.name,
            // Collection types are either 0: SharedCollection or 1: DefaultUserCollection, of which we do not yet support DefaultUserCollection.
            // See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/AdminConsole/Enums/CollectionType.cs
            "type": 0,
            // This is only used together with MyItems/DefaultUserCollection, which we do not yet support.
            "defaultUserCollectionEmail": null,
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
                Some(m) => {
                    // What the client is told here has to match what the collection guards actually
                    // allow, or it renders the wrong controls. A stored grant therefore counts even
                    // for a member who already reaches every collection: full visibility is not
                    // management authority, but it does not cancel out a real grant either.
                    //
                    // Reaching every collection through a group with `access_all` is deliberately not
                    // management authority: the guards accept an explicit
                    // `users_collections.manage` / `collections_groups.manage` row only.
                    let assignment = cipher_sync_data
                        .user_collections
                        .get(&self.uuid)
                        .map(|cu| (cu.read_only, cu.hide_passwords, cu.manage))
                        .or_else(|| {
                            cipher_sync_data
                                .user_collections_groups
                                .get(&self.uuid)
                                .map(|cg| (cg.read_only, cg.hide_passwords, cg.manage))
                        });
                    let stored_manage = assignment.is_some_and(|(_, _, manage)| manage);
                    let manage = assignment_manage_for_member(m.atype, stored_manage);
                    match assignment {
                        Some((read_only, hide_passwords, _)) if !m.has_full_access() => {
                            (read_only, hide_passwords, manage)
                        }
                        // Reaching every collection means nothing is read-only or hidden here.
                        _ => (false, false, manage),
                    }
                }
                _ => (true, true, false),
            }
        } else {
            match Membership::find_confirmed_by_user_and_org(user_uuid, &self.org_uuid, conn).await {
                // Same rule as the cached branch above: a member who reaches every collection still
                // reports a real stored grant, so the serialized value matches the guards.
                Some(m) if m.has_full_access() => (
                    false,
                    false,
                    assignment_manage_for_member(
                        m.atype,
                        m.has_explicit_collection_manage_access(&self.uuid, conn).await,
                    ),
                ),
                Some(m)
                    if m.atype >= MembershipType::Custom
                        && m.has_explicit_collection_manage_access(&self.uuid, conn).await =>
                {
                    (false, false, true)
                }
                Some(_) => {
                    let read_only = !self.is_writable_by_user(user_uuid, conn).await;
                    let hide_passwords = self.hide_passwords_for_user(user_uuid, conn).await;
                    (read_only, hide_passwords, false)
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

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(collections::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(collections::table)
                            .filter(collections::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving collection")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving collection")
            }
            postgresql {
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
                            .or(
                                // Full-access member: Custom "Edit any collection" or org admin/owner
                                // (successor of the removed membership access_all)
                                custom_membership_with_edit_any_collection()
                                    .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)),
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
                    .filter(
                        users_collections::user_uuid.eq(user_uuid).or(
                            // Full-access member: Custom "Edit any collection" or org admin/owner
                            // (successor of the removed membership access_all)
                            custom_membership_with_edit_any_collection()
                                .or(users_organizations::atype.eq_any(ORG_ADMIN_ATYPES)),
                        ),
                    )
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
                    .filter(
                        users_collections::collection_uuid
                            .eq(uuid)
                            .or(
                                // Directly accessed collection
                                custom_membership_with_edit_any_collection().or(
                                    // Custom "Edit any collection" or org admin/owner (successor of access_all)
                                    users_organizations::atype.eq_any(ORG_ADMIN_ATYPES), // Org admin or owner
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
                    .filter(users_collections::collection_uuid.eq(uuid).or(
                        // Directly accessed collection
                        custom_membership_with_edit_any_collection().or(
                            // Custom "Edit any collection" or org admin/owner (successor of access_all)
                            users_organizations::atype.eq_any(ORG_ADMIN_ATYPES), // Org admin or owner
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
        let user_uuid = user_uuid.to_string();
        if CONFIG.org_groups_enabled() {
            conn.run(move |conn| {
                collections::table
                    .filter(collections::uuid.eq(&self.uuid))
                    .inner_join(
                        users_organizations::table.on(collections::org_uuid
                            .eq(users_organizations::org_uuid)
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
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
                            .eq_any(ORG_ADMIN_ATYPES) // Org admin or owner
                            .or(custom_membership_with_edit_any_collection()) // Custom "Edit any collection" (successor of access_all)
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
                            .and(users_organizations::user_uuid.eq(user_uuid.clone()))),
                    )
                    .left_join(
                        users_collections::table.on(users_collections::collection_uuid
                            .eq(collections::uuid)
                            .and(users_collections::user_uuid.eq(user_uuid))),
                    )
                    .filter(
                        users_organizations::atype
                            .eq_any(ORG_ADMIN_ATYPES) // Org admin or owner
                            .or(custom_membership_with_edit_any_collection()) // Custom "Edit any collection" (successor of access_all)
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
                .filter(
                    users_collections::collection_uuid
                        .eq(&self.uuid)
                        .and(users_collections::hide_passwords.eq(true))
                        .or(
                            // Directly accessed collection
                            custom_membership_with_edit_any_collection().or(
                                // Custom "Edit any collection" or org admin/owner (successor of access_all)
                                users_organizations::atype.eq_any(ORG_ADMIN_ATYPES), // Org admin or owner
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

    // Whether the user has manage access to at least one collection in the org, directly or via a
    // group.
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
                .filter(users_organizations::status.eq(MembershipStatus::Confirmed as i32))
                .filter(users_organizations::atype.eq(MembershipType::Custom as i32))
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

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(users_collections::table)
                    .values((
                        users_collections::user_uuid.eq(user_uuid),
                        users_collections::collection_uuid.eq(collection_uuid),
                        users_collections::read_only.eq(read_only),
                        users_collections::hide_passwords.eq(hide_passwords),
                        users_collections::manage.eq(manage),
                    ))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(users_collections::table)
                            .filter(users_collections::user_uuid.eq(user_uuid))
                            .filter(users_collections::collection_uuid.eq(collection_uuid))
                            .set((
                                users_collections::user_uuid.eq(user_uuid),
                                users_collections::collection_uuid.eq(collection_uuid),
                                users_collections::read_only.eq(read_only),
                                users_collections::hide_passwords.eq(hide_passwords),
                                users_collections::manage.eq(manage),
                            ))
                            .execute(conn)
                            .map_res("Error adding user to collection")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding user to collection")
            }
            postgresql {
                diesel::insert_into(users_collections::table)
                    .values((
                        users_collections::user_uuid.eq(user_uuid),
                        users_collections::collection_uuid.eq(collection_uuid),
                        users_collections::read_only.eq(read_only),
                        users_collections::hide_passwords.eq(hide_passwords),
                        users_collections::manage.eq(manage),
                    ))
                    .on_conflict((users_collections::user_uuid, users_collections::collection_uuid))
                    .do_update()
                    .set((
                        users_collections::read_only.eq(read_only),
                        users_collections::hide_passwords.eq(hide_passwords),
                        users_collections::manage.eq(manage),
                    ))
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

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            users_collections::table
                .filter(users_collections::user_uuid.eq(user_uuid))
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

    pub async fn has_access_to_collection_by_user(col_id: &CollectionId, user_uuid: &UserId, conn: &DbConn) -> bool {
        Self::find_by_collection_and_user(col_id, user_uuid, conn).await.is_some()
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(cipher_uuid: &CipherId, collection_uuid: &CollectionId, conn: &DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        db_run! { conn:
            sqlite, mysql {
                // Not checking for ForeignKey Constraints here.
                // Table ciphers_collections does not have ForeignKey Constraints which would cause conflicts.
                // This table has no constraints pointing to itself, but only to others.
                diesel::replace_into(ciphers_collections::table)
                    .values((
                        ciphers_collections::cipher_uuid.eq(cipher_uuid),
                        ciphers_collections::collection_uuid.eq(collection_uuid),
                    ))
                    .execute(conn)
                    .map_res("Error adding cipher to collection")
            }
            postgresql {
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
            "manage": stored_assignment_manage(membership_type, self.manage),
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

#[cfg(test)]
mod tests {
    use super::{assignment_manage_for_member, stored_assignment_manage};
    use crate::db::models::MembershipType;

    // A stored `users_collections.manage` row must survive being listed in the admin console and
    // written back unchanged. Reporting `false` for a plain User made an unrelated save strip the
    // grant, which also revoked the cipher write access the row still confers.
    #[test]
    fn stored_assignment_manage_echoes_the_persisted_grant() {
        for role in [MembershipType::Owner, MembershipType::Admin] {
            assert!(stored_assignment_manage(role as i32, false));
        }

        for role in [MembershipType::Custom, MembershipType::User] {
            assert!(stored_assignment_manage(role as i32, true));
            assert!(!stored_assignment_manage(role as i32, false));
        }
    }

    #[test]
    fn assignment_manage_matches_collection_guard_role_boundaries() {
        for role in [MembershipType::Owner, MembershipType::Admin] {
            assert!(assignment_manage_for_member(role as i32, false));
        }

        assert!(assignment_manage_for_member(MembershipType::Custom as i32, true));
        assert!(!assignment_manage_for_member(MembershipType::Custom as i32, false));
        assert!(!assignment_manage_for_member(MembershipType::User as i32, true));
        assert!(!assignment_manage_for_member(i32::MAX, true));
    }
}
