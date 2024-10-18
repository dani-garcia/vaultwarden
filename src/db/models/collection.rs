use serde_json::Value;

use super::{CollectionGroup, GroupUser, User, UserOrgStatus, UserOrgType, UserOrganization};
use crate::CONFIG;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = collections)]
    #[diesel(primary_key(uuid))]
    pub struct Collection {
        pub uuid: String,
        pub org_uuid: String,
        pub name: String,
        pub external_id: Option<String>,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = users_collections)]
    #[diesel(primary_key(user_uuid, collection_uuid))]
    pub struct CollectionUser {
        pub user_uuid: String,
        pub collection_uuid: String,
        pub read_only: bool,
        pub hide_passwords: bool,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = ciphers_collections)]
    #[diesel(primary_key(cipher_uuid, collection_uuid))]
    pub struct CollectionCipher {
        pub cipher_uuid: String,
        pub collection_uuid: String,
    }
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: String, name: String, external_id: Option<String>) -> Self {
        let mut new_model = Self {
            uuid: crate::util::get_uuid(),
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
                    self.external_id = Some(external_id)
                }
            }
            None => self.external_id = None,
        }
    }

    pub async fn to_json_details(
        &self,
        user_uuid: &str,
        cipher_sync_data: Option<&crate::api::core::CipherSyncData>,
        conn: &mut DbConn,
    ) -> Value {
        let (read_only, hide_passwords, can_manage) = if let Some(cipher_sync_data) = cipher_sync_data {
            match cipher_sync_data.user_organizations.get(&self.org_uuid) {
                // Only for Manager types Bitwarden returns true for the can_manage option
                // Owners and Admins always have true
                Some(uo) if uo.has_full_access() => (false, false, uo.atype >= UserOrgType::Manager),
                Some(uo) => {
                    // Only let a manager manage collections when the have full read/write access
                    let is_manager = uo.atype == UserOrgType::Manager;
                    if let Some(uc) = cipher_sync_data.user_collections.get(&self.uuid) {
                        (uc.read_only, uc.hide_passwords, is_manager && !uc.read_only && !uc.hide_passwords)
                    } else if let Some(cg) = cipher_sync_data.user_collections_groups.get(&self.uuid) {
                        (cg.read_only, cg.hide_passwords, is_manager && !cg.read_only && !cg.hide_passwords)
                    } else {
                        (false, false, false)
                    }
                }
                _ => (true, true, false),
            }
        } else {
            match UserOrganization::find_confirmed_by_user_and_org(user_uuid, &self.org_uuid, conn).await {
                Some(ou) if ou.has_full_access() => (false, false, ou.atype >= UserOrgType::Manager),
                Some(ou) => {
                    let is_manager = ou.atype == UserOrgType::Manager;
                    let read_only = !self.is_writable_by_user(user_uuid, conn).await;
                    let hide_passwords = self.hide_passwords_for_user(user_uuid, conn).await;
                    (read_only, hide_passwords, is_manager && !read_only && !hide_passwords)
                }
                _ => (
                    !self.is_writable_by_user(user_uuid, conn).await,
                    self.hide_passwords_for_user(user_uuid, conn).await,
                    false,
                ),
            }
        };

        let mut json_object = self.to_json();
        json_object["object"] = json!("collectionDetails");
        json_object["readOnly"] = json!(read_only);
        json_object["hidePasswords"] = json!(hide_passwords);
        json_object["manage"] = json!(can_manage);
        json_object
    }

    pub async fn can_access_collection(org_user: &UserOrganization, col_id: &str, conn: &mut DbConn) -> bool {
        org_user.has_status(UserOrgStatus::Confirmed)
            && (org_user.has_full_access()
                || CollectionUser::has_access_to_collection_by_user(col_id, &org_user.user_uuid, conn).await
                || (CONFIG.org_groups_enabled()
                    && (GroupUser::has_full_access_by_member(&org_user.org_uuid, &org_user.uuid, conn).await
                        || GroupUser::has_access_to_collection_by_member(col_id, &org_user.uuid, conn).await)))
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Collection {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(collections::table)
                    .values(CollectionDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(collections::table)
                            .filter(collections::uuid.eq(&self.uuid))
                            .set(CollectionDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving collection")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving collection")
            }
            postgresql {
                let value = CollectionDb::to_db(self);
                diesel::insert_into(collections::table)
                    .values(&value)
                    .on_conflict(collections::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving collection")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        CollectionCipher::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionUser::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionGroup::delete_all_by_collection(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(collections::table.filter(collections::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting collection")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for collection in Self::find_by_organization(org_uuid, conn).await {
            collection.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn update_users_revision(&self, conn: &mut DbConn) {
        for user_org in UserOrganization::find_by_collection_and_org(&self.uuid, &self.org_uuid, conn).await.iter() {
            User::update_uuid_revision(&user_org.user_uuid, conn).await;
        }
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            collections::table
                .filter(collections::uuid.eq(uuid))
                .first::<CollectionDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_user_uuid(user_uuid: String, conn: &mut DbConn) -> Vec<Self> {
        if CONFIG.org_groups_enabled() {
            db_run! { conn: {
                collections::table
                .left_join(users_collections::table.on(
                    users_collections::collection_uuid.eq(collections::uuid).and(
                        users_collections::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .left_join(users_organizations::table.on(
                    collections::org_uuid.eq(users_organizations::org_uuid).and(
                        users_organizations::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .left_join(groups_users::table.on(
                    groups_users::users_organizations_uuid.eq(users_organizations::uuid)
                ))
                .left_join(groups::table.on(
                    groups::uuid.eq(groups_users::groups_uuid)
                ))
                .left_join(collections_groups::table.on(
                    collections_groups::groups_uuid.eq(groups_users::groups_uuid).and(
                        collections_groups::collections_uuid.eq(collections::uuid)
                    )
                ))
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .filter(
                    users_collections::user_uuid.eq(user_uuid).or( // Directly accessed collection
                        users_organizations::access_all.eq(true) // access_all in Organization
                    ).or(
                        groups::access_all.eq(true) // access_all in groups
                    ).or( // access via groups
                        groups_users::users_organizations_uuid.eq(users_organizations::uuid).and(
                            collections_groups::collections_uuid.is_not_null()
                        )
                    )
                )
                .select(collections::all_columns)
                .distinct()
                .load::<CollectionDb>(conn).expect("Error loading collections").from_db()
            }}
        } else {
            db_run! { conn: {
                collections::table
                .left_join(users_collections::table.on(
                    users_collections::collection_uuid.eq(collections::uuid).and(
                        users_collections::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .left_join(users_organizations::table.on(
                    collections::org_uuid.eq(users_organizations::org_uuid).and(
                        users_organizations::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .filter(
                    users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
                )
                .filter(
                    users_collections::user_uuid.eq(user_uuid).or( // Directly accessed collection
                        users_organizations::access_all.eq(true) // access_all in Organization
                    )
                )
                .select(collections::all_columns)
                .distinct()
                .load::<CollectionDb>(conn).expect("Error loading collections").from_db()
            }}
        }
    }

    pub async fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        Self::find_by_user_uuid(user_uuid.to_owned(), conn)
            .await
            .into_iter()
            .filter(|c| c.org_uuid == org_uuid)
            .collect()
    }

    pub async fn find_by_organization(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .load::<CollectionDb>(conn)
                .expect("Error loading collections")
                .from_db()
        }}
    }

    pub async fn count_by_org(org_uuid: &str, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            collections::table
                .filter(collections::uuid.eq(uuid))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(collections::all_columns)
                .first::<CollectionDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: String, conn: &mut DbConn) -> Option<Self> {
        if CONFIG.org_groups_enabled() {
            db_run! { conn: {
                collections::table
                .left_join(users_collections::table.on(
                    users_collections::collection_uuid.eq(collections::uuid).and(
                        users_collections::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .left_join(users_organizations::table.on(
                    collections::org_uuid.eq(users_organizations::org_uuid).and(
                        users_organizations::user_uuid.eq(user_uuid)
                    )
                ))
                .left_join(groups_users::table.on(
                    groups_users::users_organizations_uuid.eq(users_organizations::uuid)
                ))
                .left_join(groups::table.on(
                    groups::uuid.eq(groups_users::groups_uuid)
                ))
                .left_join(collections_groups::table.on(
                    collections_groups::groups_uuid.eq(groups_users::groups_uuid).and(
                        collections_groups::collections_uuid.eq(collections::uuid)
                    )
                ))
                .filter(collections::uuid.eq(uuid))
                .filter(
                    users_collections::collection_uuid.eq(uuid).or( // Directly accessed collection
                        users_organizations::access_all.eq(true).or( // access_all in Organization
                            users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin or owner
                    )).or(
                        groups::access_all.eq(true) // access_all in groups
                    ).or( // access via groups
                        groups_users::users_organizations_uuid.eq(users_organizations::uuid).and(
                            collections_groups::collections_uuid.is_not_null()
                        )
                    )
                ).select(collections::all_columns)
                .first::<CollectionDb>(conn).ok()
                .from_db()
            }}
        } else {
            db_run! { conn: {
                collections::table
                .left_join(users_collections::table.on(
                    users_collections::collection_uuid.eq(collections::uuid).and(
                        users_collections::user_uuid.eq(user_uuid.clone())
                    )
                ))
                .left_join(users_organizations::table.on(
                    collections::org_uuid.eq(users_organizations::org_uuid).and(
                        users_organizations::user_uuid.eq(user_uuid)
                    )
                ))
                .filter(collections::uuid.eq(uuid))
                .filter(
                    users_collections::collection_uuid.eq(uuid).or( // Directly accessed collection
                        users_organizations::access_all.eq(true).or( // access_all in Organization
                            users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin or owner
                    ))
                ).select(collections::all_columns)
                .first::<CollectionDb>(conn).ok()
                .from_db()
            }}
        }
    }

    pub async fn is_writable_by_user(&self, user_uuid: &str, conn: &mut DbConn) -> bool {
        let user_uuid = user_uuid.to_string();
        if CONFIG.org_groups_enabled() {
            db_run! { conn: {
                collections::table
                    .filter(collections::uuid.eq(&self.uuid))
                    .inner_join(users_organizations::table.on(
                        collections::org_uuid.eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid.clone()))
                    ))
                    .left_join(users_collections::table.on(
                        users_collections::collection_uuid.eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(user_uuid))
                    ))
                    .left_join(groups_users::table.on(
                        groups_users::users_organizations_uuid.eq(users_organizations::uuid)
                    ))
                    .left_join(groups::table.on(
                        groups::uuid.eq(groups_users::groups_uuid)
                    ))
                    .left_join(collections_groups::table.on(
                        collections_groups::groups_uuid.eq(groups_users::groups_uuid)
                        .and(collections_groups::collections_uuid.eq(collections::uuid))
                    ))
                    .filter(users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin or owner
                        .or(users_organizations::access_all.eq(true)) // access_all via membership
                        .or(users_collections::collection_uuid.eq(&self.uuid) // write access given to collection
                            .and(users_collections::read_only.eq(false)))
                        .or(groups::access_all.eq(true)) // access_all via group
                        .or(collections_groups::collections_uuid.is_not_null() // write access given via group
                            .and(collections_groups::read_only.eq(false)))
                    )
                    .count()
                    .first::<i64>(conn)
                    .ok()
                    .unwrap_or(0) != 0
            }}
        } else {
            db_run! { conn: {
                collections::table
                    .filter(collections::uuid.eq(&self.uuid))
                    .inner_join(users_organizations::table.on(
                        collections::org_uuid.eq(users_organizations::org_uuid)
                        .and(users_organizations::user_uuid.eq(user_uuid.clone()))
                    ))
                    .left_join(users_collections::table.on(
                        users_collections::collection_uuid.eq(collections::uuid)
                        .and(users_collections::user_uuid.eq(user_uuid))
                    ))
                    .filter(users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin or owner
                        .or(users_organizations::access_all.eq(true)) // access_all via membership
                        .or(users_collections::collection_uuid.eq(&self.uuid) // write access given to collection
                            .and(users_collections::read_only.eq(false)))
                    )
                    .count()
                    .first::<i64>(conn)
                    .ok()
                    .unwrap_or(0) != 0
            }}
        }
    }

    pub async fn hide_passwords_for_user(&self, user_uuid: &str, conn: &mut DbConn) -> bool {
        let user_uuid = user_uuid.to_string();
        db_run! { conn: {
            collections::table
            .left_join(users_collections::table.on(
                users_collections::collection_uuid.eq(collections::uuid).and(
                    users_collections::user_uuid.eq(user_uuid.clone())
                )
            ))
            .left_join(users_organizations::table.on(
                collections::org_uuid.eq(users_organizations::org_uuid).and(
                    users_organizations::user_uuid.eq(user_uuid)
                )
            ))
            .left_join(groups_users::table.on(
                groups_users::users_organizations_uuid.eq(users_organizations::uuid)
            ))
            .left_join(groups::table.on(
                groups::uuid.eq(groups_users::groups_uuid)
            ))
            .left_join(collections_groups::table.on(
                collections_groups::groups_uuid.eq(groups_users::groups_uuid).and(
                    collections_groups::collections_uuid.eq(collections::uuid)
                )
            ))
            .filter(collections::uuid.eq(&self.uuid))
            .filter(
                users_collections::collection_uuid.eq(&self.uuid).and(users_collections::hide_passwords.eq(true)).or(// Directly accessed collection
                    users_organizations::access_all.eq(true).or( // access_all in Organization
                        users_organizations::atype.le(UserOrgType::Admin as i32) // Org admin or owner
                )).or(
                    groups::access_all.eq(true) // access_all in groups
                ).or( // access via groups
                    groups_users::users_organizations_uuid.eq(users_organizations::uuid).and(
                        collections_groups::collections_uuid.is_not_null().and(
                            collections_groups::hide_passwords.eq(true))
                    )
                )
            )
            .count()
            .first::<i64>(conn)
            .ok()
            .unwrap_or(0) != 0
        }}
    }
}

/// Database methods
impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::user_uuid.eq(user_uuid))
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .select(users_collections::all_columns)
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn find_by_organization(org_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
                .filter(collections::org_uuid.eq(org_uuid))
                .inner_join(users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)))
                .select((users_organizations::uuid, users_collections::collection_uuid, users_collections::read_only, users_collections::hide_passwords))
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn save(
        user_uuid: &str,
        collection_uuid: &str,
        read_only: bool,
        hide_passwords: bool,
        conn: &mut DbConn,
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
                    ))
                    .on_conflict((users_collections::user_uuid, users_collections::collection_uuid))
                    .do_update()
                    .set((
                        users_collections::read_only.eq(read_only),
                        users_collections::hide_passwords.eq(hide_passwords),
                    ))
                    .execute(conn)
                    .map_res("Error adding user to collection")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn).await;

        db_run! { conn: {
            diesel::delete(
                users_collections::table
                    .filter(users_collections::user_uuid.eq(&self.user_uuid))
                    .filter(users_collections::collection_uuid.eq(&self.collection_uuid)),
            )
            .execute(conn)
            .map_res("Error removing user from collection")
        }}
    }

    pub async fn find_by_collection(collection_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .select(users_collections::all_columns)
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn find_by_collection_swap_user_uuid_with_org_user_uuid(
        collection_uuid: &str,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .inner_join(users_organizations::table.on(users_organizations::user_uuid.eq(users_collections::user_uuid)))
                .select((users_organizations::uuid, users_collections::collection_uuid, users_collections::read_only, users_collections::hide_passwords))
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn find_by_collection_and_user(
        collection_uuid: &str,
        user_uuid: &str,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .filter(users_collections::user_uuid.eq(user_uuid))
                .select(users_collections::all_columns)
                .first::<CollectionUserDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::user_uuid.eq(user_uuid))
                .select(users_collections::all_columns)
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn delete_all_by_collection(collection_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for collection in CollectionUser::find_by_collection(collection_uuid, conn).await.iter() {
            User::update_uuid_revision(&collection.user_uuid, conn).await;
        }

        db_run! { conn: {
            diesel::delete(users_collections::table.filter(users_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error deleting users from collection")
        }}
    }

    pub async fn delete_all_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        let collectionusers = Self::find_by_organization_and_user_uuid(org_uuid, user_uuid, conn).await;

        db_run! { conn: {
            for user in collectionusers {
                let _: () = diesel::delete(users_collections::table.filter(
                    users_collections::user_uuid.eq(user_uuid)
                    .and(users_collections::collection_uuid.eq(user.collection_uuid))
                ))
                    .execute(conn)
                    .map_res("Error removing user from collections")?;
            }
            Ok(())
        }}
    }

    pub async fn has_access_to_collection_by_user(col_id: &str, user_uuid: &str, conn: &mut DbConn) -> bool {
        Self::find_by_collection_and_user(col_id, user_uuid, conn).await.is_some()
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(cipher_uuid: &str, collection_uuid: &str, conn: &mut DbConn) -> EmptyResult {
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

    pub async fn delete(cipher_uuid: &str, collection_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        Self::update_users_revision(collection_uuid, conn).await;

        db_run! { conn: {
            diesel::delete(
                ciphers_collections::table
                    .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                    .filter(ciphers_collections::collection_uuid.eq(collection_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting cipher from collection")
        }}
    }

    pub async fn delete_all_by_cipher(cipher_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from collections")
        }}
    }

    pub async fn delete_all_by_collection(collection_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from collection")
        }}
    }

    pub async fn update_users_revision(collection_uuid: &str, conn: &mut DbConn) {
        if let Some(collection) = Collection::find_by_uuid(collection_uuid, conn).await {
            collection.update_users_revision(conn).await;
        }
    }
}
