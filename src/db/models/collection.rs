use serde_json::Value;

use super::{Cipher, Organization, User, UserOrgStatus, UserOrgType, UserOrganization};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "collections"]
    #[belongs_to(Organization, foreign_key = "org_uuid")]
    #[primary_key(uuid)]
    pub struct Collection {
        pub uuid: String,
        pub org_uuid: String,
        pub name: String,
    }

    #[derive(Identifiable, Queryable, Insertable, Associations)]
    #[table_name = "users_collections"]
    #[belongs_to(User, foreign_key = "user_uuid")]
    #[belongs_to(Collection, foreign_key = "collection_uuid")]
    #[primary_key(user_uuid, collection_uuid)]
    pub struct CollectionUser {
        pub user_uuid: String,
        pub collection_uuid: String,
        pub read_only: bool,
        pub hide_passwords: bool,
    }

    #[derive(Identifiable, Queryable, Insertable, Associations)]
    #[table_name = "ciphers_collections"]
    #[belongs_to(Cipher, foreign_key = "cipher_uuid")]
    #[belongs_to(Collection, foreign_key = "collection_uuid")]
    #[primary_key(cipher_uuid, collection_uuid)]
    pub struct CollectionCipher {
        pub cipher_uuid: String,
        pub collection_uuid: String,
    }
}

/// Local methods
impl Collection {
    pub fn new(org_uuid: String, name: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),

            org_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ExternalId": null, // Not support by us
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Name": self.name,
            "Object": "collection",
        })
    }

    pub async fn to_json_details(&self, user_uuid: &str, conn: &DbConn) -> Value {
        let mut json_object = self.to_json();
        json_object["Object"] = json!("collectionDetails");
        json_object["ReadOnly"] = json!(!self.is_writable_by_user(user_uuid, conn).await);
        json_object["HidePasswords"] = json!(self.hide_passwords_for_user(user_uuid, conn).await);
        json_object
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Collection {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
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

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        self.update_users_revision(conn).await;
        CollectionCipher::delete_all_by_collection(&self.uuid, conn).await?;
        CollectionUser::delete_all_by_collection(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(collections::table.filter(collections::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting collection")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for collection in Self::find_by_organization(org_uuid, conn).await {
            collection.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn update_users_revision(&self, conn: &DbConn) {
        for user_org in UserOrganization::find_by_collection_and_org(&self.uuid, &self.org_uuid, conn).await.iter() {
            User::update_uuid_revision(&user_org.user_uuid, conn).await;
        }
    }

    pub async fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            collections::table
                .filter(collections::uuid.eq(uuid))
                .first::<CollectionDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_user_uuid(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections::table
            .left_join(users_collections::table.on(
                users_collections::collection_uuid.eq(collections::uuid).and(
                    users_collections::user_uuid.eq(user_uuid)
                )
            ))
            .left_join(users_organizations::table.on(
                collections::org_uuid.eq(users_organizations::org_uuid).and(
                    users_organizations::user_uuid.eq(user_uuid)
                )
            ))
            .filter(
                users_organizations::status.eq(UserOrgStatus::Confirmed as i32)
            )
            .filter(
                users_collections::user_uuid.eq(user_uuid).or( // Directly accessed collection
                    users_organizations::access_all.eq(true) // access_all in Organization
                )
            ).select(collections::all_columns)
            .load::<CollectionDb>(conn).expect("Error loading collections").from_db()
        }}
    }

    pub async fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        Self::find_by_user_uuid(user_uuid, conn).await.into_iter().filter(|c| c.org_uuid == org_uuid).collect()
    }

    pub async fn find_by_organization(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections::table
                .filter(collections::org_uuid.eq(org_uuid))
                .load::<CollectionDb>(conn)
                .expect("Error loading collections")
                .from_db()
        }}
    }

    pub async fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
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

    pub async fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            collections::table
            .left_join(users_collections::table.on(
                users_collections::collection_uuid.eq(collections::uuid).and(
                    users_collections::user_uuid.eq(user_uuid)
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
                    )
                )
            ).select(collections::all_columns)
            .first::<CollectionDb>(conn).ok()
            .from_db()
        }}
    }

    pub async fn is_writable_by_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        match UserOrganization::find_by_user_and_org(user_uuid, &self.org_uuid, conn).await {
            None => false, // Not in Org
            Some(user_org) => {
                if user_org.has_full_access() {
                    return true;
                }

                db_run! { conn: {
                    users_collections::table
                        .filter(users_collections::collection_uuid.eq(&self.uuid))
                        .filter(users_collections::user_uuid.eq(user_uuid))
                        .filter(users_collections::read_only.eq(false))
                        .count()
                        .first::<i64>(conn)
                        .ok()
                        .unwrap_or(0) != 0
                }}
            }
        }
    }

    pub async fn hide_passwords_for_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        match UserOrganization::find_by_user_and_org(user_uuid, &self.org_uuid, conn).await {
            None => true, // Not in Org
            Some(user_org) => {
                if user_org.has_full_access() {
                    return false;
                }

                db_run! { conn: {
                    users_collections::table
                        .filter(users_collections::collection_uuid.eq(&self.uuid))
                        .filter(users_collections::user_uuid.eq(user_uuid))
                        .filter(users_collections::hide_passwords.eq(true))
                        .count()
                        .first::<i64>(conn)
                        .ok()
                        .unwrap_or(0) != 0
                }}
            }
        }
    }
}

/// Database methods
impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &DbConn) -> Vec<Self> {
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

    pub async fn save(
        user_uuid: &str,
        collection_uuid: &str,
        read_only: bool,
        hide_passwords: bool,
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

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
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

    pub async fn find_by_collection(collection_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            users_collections::table
                .filter(users_collections::collection_uuid.eq(collection_uuid))
                .select(users_collections::all_columns)
                .load::<CollectionUserDb>(conn)
                .expect("Error loading users_collections")
                .from_db()
        }}
    }

    pub async fn find_by_collection_and_user(collection_uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
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

    pub async fn delete_all_by_collection(collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        for collection in CollectionUser::find_by_collection(collection_uuid, conn).await.iter() {
            User::update_uuid_revision(&collection.user_uuid, conn).await;
        }

        db_run! { conn: {
            diesel::delete(users_collections::table.filter(users_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error deleting users from collection")
        }}
    }

    pub async fn delete_all_by_user_and_org(user_uuid: &str, org_uuid: &str, conn: &DbConn) -> EmptyResult {
        let collectionusers = Self::find_by_organization_and_user_uuid(org_uuid, user_uuid, conn).await;

        db_run! { conn: {
            for user in collectionusers {
                diesel::delete(users_collections::table.filter(
                    users_collections::user_uuid.eq(user_uuid)
                    .and(users_collections::collection_uuid.eq(user.collection_uuid))
                ))
                    .execute(conn)
                    .map_res("Error removing user from collections")?;
            }
            Ok(())
        }}
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(cipher_uuid: &str, collection_uuid: &str, conn: &DbConn) -> EmptyResult {
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

    pub async fn delete(cipher_uuid: &str, collection_uuid: &str, conn: &DbConn) -> EmptyResult {
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

    pub async fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing cipher from collections")
        }}
    }

    pub async fn delete_all_by_collection(collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(ciphers_collections::table.filter(ciphers_collections::collection_uuid.eq(collection_uuid)))
                .execute(conn)
                .map_res("Error removing ciphers from collection")
        }}
    }

    pub async fn update_users_revision(collection_uuid: &str, conn: &DbConn) {
        if let Some(collection) = Collection::find_by_uuid(collection_uuid, conn).await {
            collection.update_users_revision(conn).await;
        }
    }
}
