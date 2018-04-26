use serde_json::Value as JsonValue;

use uuid::Uuid;

use super::Organization;

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
            uuid: Uuid::new_v4().to_string(),

            org_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> JsonValue {
        json!({
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Name": self.name,
            "Object": "collection",
        })
    }
}

use diesel;
use diesel::prelude::*;
use db::DbConn;
use db::schema::collections;

/// Database methods
impl Collection {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        match diesel::replace_into(collections::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }

    pub fn delete(self, conn: &DbConn) -> bool {
        match diesel::delete(collections::table.filter(
            collections::uuid.eq(self.uuid)))
            .execute(&**conn) {
            Ok(1) => true, // One row deleted
            _ => false,
        }
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        collections::table
            .filter(collections::uuid.eq(uuid))
            .first::<Self>(&**conn).ok()
    }

    pub fn find_by_user_uuid(uuid: &str, conn: &DbConn) -> Vec<Self> {
        match users_collections::table
            .filter(users_collections::user_uuid.eq(uuid))
            .select(users_collections::columns::collection_uuid)
            .load(&**conn) {
                Ok(uuids) => uuids.iter().map(|uuid: &String| {
                    Collection::find_by_uuid(uuid, &conn).unwrap()
                }).collect(),
                Err(list) => vec![]
        }
    }

    pub fn find_by_uuid_and_user(uuid: &str, user_uuid: &str, conn: &DbConn) -> Option<Self> {
        match users_collections::table
            .filter(users_collections::collection_uuid.eq(uuid))
            .filter(users_collections::user_uuid.eq(user_uuid))
            .first::<CollectionUsers>(&**conn).ok() {
                None => None,
                Some(collection_user) => Collection::find_by_uuid(&collection_user.collection_uuid, &conn)
        }
    }
}

use super::User; 

#[derive(Debug, Identifiable, Queryable, Insertable, Associations)]
#[table_name = "users_collections"]
#[belongs_to(User, foreign_key = "user_uuid")]
#[belongs_to(Collection, foreign_key = "collection_uuid")]
#[primary_key(user_uuid, collection_uuid)]
pub struct CollectionUsers {
    pub user_uuid: String,
    pub collection_uuid: String,
}

/// Local methods
impl CollectionUsers {
    pub fn new(
        user_uuid: String,
        collection_uuid: String,
    ) -> Self {
        Self {
            user_uuid,
            collection_uuid,
        }
    }
}

use db::schema::users_collections;

/// Database methods
impl CollectionUsers {
    pub fn save(&mut self, conn: &DbConn) -> bool {
        match diesel::replace_into(users_collections::table)
            .values(&*self)
            .execute(&**conn) {
            Ok(1) => true, // One row inserted
            _ => false,
        }
    }
}