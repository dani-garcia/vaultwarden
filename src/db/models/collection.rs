use serde_json::Value;

use super::{Organization, UserOrgStatus, UserOrgType, UserOrganization};

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "collections"]
#[belongs_to(Organization, foreign_key = "org_uuid")]
#[primary_key(uuid)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
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
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Name": self.name,
            "Object": "collection",
        })
    }
}

use crate::db::schema::*;
use crate::db::DbConn;
use diesel;
use diesel::prelude::*;

use crate::api::EmptyResult;
use crate::error::MapResult;

/// Database methods
impl Collection {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        // Update affected users revision
        UserOrganization::find_by_collection_and_org(&self.uuid, &self.org_uuid, conn)
            .iter()
            .for_each(|user_org| {
                User::update_uuid_revision(&user_org.user_uuid, conn);
            });

        diesel::replace_into(collections::table)
            .values(&*self)
            .execute(&**conn)
            .map_res("Error saving collection")
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        CollectionCipher::delete_all_by_collection(&self.uuid, &conn)?;
        CollectionUser::delete_all_by_collection(&self.uuid, &conn)?;

        diesel::delete(collections::table.filter(collections::uuid.eq(self.uuid)))
            .execute(&**conn)
            .map_res("Error deleting collection")
    }

    pub fn delete_all_by_organization(org_uuid: &str, conn: &DbConn) -> EmptyResult {
        for collection in Self::find_by_organization(org_uuid, &conn) {
            collection.delete(&conn)?;
        }
        Ok(())
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        collections::table
            .filter(collections::uuid.eq(uuid))
            .first::<Self>(&**conn)
            .ok()
    }

    pub fn find_by_user_uuid(user_uuid: &str, conn: &DbConn) -> Vec<Self> {
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
        .load::<Self>(&**conn).expect("Error loading collections")
    }

    pub fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        Self::find_by_user_uuid(user_uuid, conn)
            .into_iter()
            .filter(|c| c.org_uuid == org_uuid)
            .collect()
    }

    pub fn find_by_organization(org_uuid: &str, conn: &DbConn) -> Vec<Self> {
        collections::table
            .filter(collections::org_uuid.eq(org_uuid))
            .load::<Self>(&**conn)
            .expect("Error loading collections")
    }

    pub fn find_by_uuid_and_org(uuid: &str, org_uuid: &str, conn: &DbConn) -> Option<Self> {
        collections::table
            .filter(collections::uuid.eq(uuid))
            .filter(collections::org_uuid.eq(org_uuid))
            .select(collections::all_columns)
            .first::<Self>(&**conn)
            .ok()
    }

    pub fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
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
                    users_organizations::type_.le(UserOrgType::Admin as i32) // Org admin or owner
                )
            )
        ).select(collections::all_columns)
        .first::<Self>(&**conn).ok()
    }

    pub fn is_writable_by_user(&self, user_uuid: &str, conn: &DbConn) -> bool {
        match UserOrganization::find_by_user_and_org(&user_uuid, &self.org_uuid, &conn) {
            None => false, // Not in Org
            Some(user_org) => {
                if user_org.access_all {
                    true
                } else {
                    users_collections::table
                        .inner_join(collections::table)
                        .filter(users_collections::collection_uuid.eq(&self.uuid))
                        .filter(users_collections::user_uuid.eq(&user_uuid))
                        .filter(users_collections::read_only.eq(false))
                        .select(collections::all_columns)
                        .first::<Self>(&**conn)
                        .ok()
                        .is_some() // Read only or no access to collection
                }
            }
        }
    }
}

use super::User;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "users_collections"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[belongs_to(Collection, foreign_key = "collection_uuid")]
#[primary_key(user_uuid, collection_uuid)]
pub struct CollectionUser {
    pub user_uuid: String,
    pub collection_uuid: String,
    pub read_only: bool,
}

/// Database methods
impl CollectionUser {
    pub fn find_by_organization_and_user_uuid(org_uuid: &str, user_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_collections::table
            .filter(users_collections::user_uuid.eq(user_uuid))
            .inner_join(collections::table.on(collections::uuid.eq(users_collections::collection_uuid)))
            .filter(collections::org_uuid.eq(org_uuid))
            .select(users_collections::all_columns)
            .load::<Self>(&**conn)
            .expect("Error loading users_collections")
    }

    pub fn save(user_uuid: &str, collection_uuid: &str, read_only: bool, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&user_uuid, conn);

        diesel::replace_into(users_collections::table)
            .values((
                users_collections::user_uuid.eq(user_uuid),
                users_collections::collection_uuid.eq(collection_uuid),
                users_collections::read_only.eq(read_only),
            ))
            .execute(&**conn)
            .map_res("Error adding user to collection")
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.user_uuid, conn);

        diesel::delete(
            users_collections::table
                .filter(users_collections::user_uuid.eq(&self.user_uuid))
                .filter(users_collections::collection_uuid.eq(&self.collection_uuid)),
        )
        .execute(&**conn)
        .map_res("Error removing user from collection")
    }

    pub fn find_by_collection(collection_uuid: &str, conn: &DbConn) -> Vec<Self> {
        users_collections::table
            .filter(users_collections::collection_uuid.eq(collection_uuid))
            .select(users_collections::all_columns)
            .load::<Self>(&**conn)
            .expect("Error loading users_collections")
    }

    pub fn find_by_collection_and_user(collection_uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
        users_collections::table
            .filter(users_collections::collection_uuid.eq(collection_uuid))
            .filter(users_collections::user_uuid.eq(user_uuid))
            .select(users_collections::all_columns)
            .first::<Self>(&**conn)
            .ok()
    }

    pub fn delete_all_by_collection(collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        CollectionUser::find_by_collection(&collection_uuid, conn)
            .iter()
            .for_each(|collection| User::update_uuid_revision(&collection.user_uuid, conn));

        diesel::delete(users_collections::table.filter(users_collections::collection_uuid.eq(collection_uuid)))
            .execute(&**conn)
            .map_res("Error deleting users from collection")
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&user_uuid, conn);

        diesel::delete(users_collections::table.filter(users_collections::user_uuid.eq(user_uuid)))
            .execute(&**conn)
            .map_res("Error removing user from collections")
    }
}

use super::Cipher;

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "ciphers_collections"]
#[belongs_to(Cipher, foreign_key = "cipher_uuid")]
#[belongs_to(Collection, foreign_key = "collection_uuid")]
#[primary_key(cipher_uuid, collection_uuid)]
pub struct CollectionCipher {
    pub cipher_uuid: String,
    pub collection_uuid: String,
}

/// Database methods
impl CollectionCipher {
    pub fn save(cipher_uuid: &str, collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        diesel::replace_into(ciphers_collections::table)
            .values((
                ciphers_collections::cipher_uuid.eq(cipher_uuid),
                ciphers_collections::collection_uuid.eq(collection_uuid),
            ))
            .execute(&**conn)
            .map_res("Error adding cipher to collection")
    }

    pub fn delete(cipher_uuid: &str, collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        diesel::delete(
            ciphers_collections::table
                .filter(ciphers_collections::cipher_uuid.eq(cipher_uuid))
                .filter(ciphers_collections::collection_uuid.eq(collection_uuid)),
        )
        .execute(&**conn)
        .map_res("Error deleting cipher from collection")
    }

    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        diesel::delete(ciphers_collections::table.filter(ciphers_collections::cipher_uuid.eq(cipher_uuid)))
            .execute(&**conn)
            .map_res("Error removing cipher from collections")
    }

    pub fn delete_all_by_collection(collection_uuid: &str, conn: &DbConn) -> EmptyResult {
        diesel::delete(ciphers_collections::table.filter(ciphers_collections::collection_uuid.eq(collection_uuid)))
            .execute(&**conn)
            .map_res("Error removing ciphers from collection")
    }
}
