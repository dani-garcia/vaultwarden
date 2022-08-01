use serde_json::Value;
use chrono::{NaiveDateTime, Utc};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[table_name = "groups"]
    #[primary_key(uuid)]
    pub struct Group {
        pub uuid: String,
        pub organizations_uuid: String,
        pub name: String,
        pub access_all: bool,
        pub external_id: String,
        pub creation_date: NaiveDateTime,
        pub revision_date: NaiveDateTime,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[table_name = "collection_groups"]
    #[primary_key(collections_uuid, groups_uuid)]
    pub struct CollectionGroup {
        pub collections_uuid: String,
        pub groups_uuid: String,
        pub read_only: bool,
        pub hide_passwords: bool,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[table_name = "groups_users"]
    #[primary_key(groups_uuid, users_organizations_uuid)]
    pub struct GroupUser {
        pub groups_uuid: String,
        pub users_organizations_uuid: String
    }
}

/// Local methods
impl Group {
    pub fn new(organizations_uuid: String, name: String, access_all: bool, external_id: String) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            organizations_uuid: organizations_uuid,
            name: name,
            access_all: access_all,
            external_id: external_id,
            creation_date: now,
            revision_date: now
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "Id": self.uuid,
            "OrganizationId": self.organizations_uuid,
            "Name": self.name,
            "AccessAll": self.access_all,
            "ExternalId": self.external_id,
            "CreationDate": format_date(&self.creation_date),
            "RevisionDate": format_date(&self.revision_date)
        })
    }
}

impl CollectionGroup {
    pub fn new(collections_uuid: String, groups_uuid: String, read_only: bool, hide_passwords: bool) -> Self {
        Self {
            collections_uuid,
            groups_uuid,
            read_only,
            hide_passwords
        }
    }
}

impl GroupUser {
    pub fn new (groups_uuid: String, users_organizations_uuid: String) -> Self {
        Self {
            groups_uuid: groups_uuid,
            users_organizations_uuid: users_organizations_uuid
        }
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

use super::{UserOrganization, User};

/// Database methods
impl Group {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        self.revision_date = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(groups::table)
                    .values(GroupDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(groups::table)
                            .filter(groups::uuid.eq(&self.uuid))
                            .set(GroupDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving group")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving group")
            }
            postgresql {
                let value = GroupDb::to_db(self);
                diesel::insert_into(groups::table)
                    .values(&value)
                    .on_conflict(groups::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving group")
            }
        }
    }

    pub async fn find_by_organization (organizations_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups::table
                .filter(groups::organizations_uuid.eq(organizations_uuid))
                .load::<GroupDb>(conn)
                .expect("Error loading groups")
                .from_db()
        }}
    }

    pub async fn find_by_uuid (uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            groups::table
                .filter(groups::uuid.eq(uuid))
                .first::<GroupDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        CollectionGroup::delete_all_by_group(&self.uuid, &conn).await?;
        GroupUser::delete_all_by_group(&self.uuid, &conn).await?;
        
        db_run! { conn: {
            diesel::delete(groups::table.filter(groups::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting group")
        }}
    }

    pub async fn update_revision(uuid: &str, conn: &DbConn) {
        if let Err(e) = Self::_update_revision(uuid, &Utc::now().naive_utc(), conn).await {
            warn!("Failed to update revision for {}: {:#?}", uuid, e);
        }
    }

    async fn _update_revision(uuid: &str, date: &NaiveDateTime, conn: &DbConn) -> EmptyResult {
        db_run! {conn: {
            crate::util::retry(|| {
                diesel::update(groups::table.filter(groups::uuid.eq(uuid)))
                    .set(groups::revision_date.eq(date))
                    .execute(conn)
            }, 10)
            .map_res("Error updating group revision")
        }}
    }
}

impl CollectionGroup {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(&self.groups_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }
        
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(collection_groups::table)
                    .values((
                        collection_groups::collections_uuid.eq(&self.collections_uuid),
                        collection_groups::groups_uuid.eq(&self.groups_uuid),
                        collection_groups::read_only.eq(&self.read_only),
                        collection_groups::hide_passwords.eq(&self.hide_passwords),
                    ))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(collection_groups::table)
                            .filter(collection_groups::collections_uuid.eq(&self.collections_uuid))
                            .filter(collection_groups::groups_uuid.eq(&self.groups_uuid))
                            .set((
                                collection_groups::collections_uuid.eq(&self.collections_uuid),
                                collection_groups::groups_uuid.eq(&self.groups_uuid),
                                collection_groups::read_only.eq(&self.read_only),
                                collection_groups::hide_passwords.eq(&self.hide_passwords),
                            ))
                            .execute(conn)
                            .map_res("Error adding group to collection")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding group to collection")
            }
            postgresql {
                diesel::insert_into(collection_groups::table)
                    .values((
                        collection_groups::collections_uuid.eq(&self.collections_uuid),
                        collection_groups::groups_uuid.eq(&self.groups_uuid),
                        collection_groups::read_only.eq(self.read_only),
                        collection_groups::hide_passwords.eq(self.hide_passwords),
                    ))
                    .on_conflict((collection_groups::collections_uuid, collection_groups::groups_uuid))
                    .do_update()
                    .set((
                        collection_groups::read_only.eq(self.read_only),
                        collection_groups::hide_passwords.eq(self.hide_passwords),
                    ))
                    .execute(conn)
                    .map_res("Error adding group to collection")
            }
        }
    }

    pub async fn find_by_group (group_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            collection_groups::table
                .filter(collection_groups::groups_uuid.eq(group_uuid))
                .load::<CollectionGroupDb>(conn)
                .expect("Error loading collection groups")
                .from_db()
        }}
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {        
        let group_users = GroupUser::find_by_group(&self.groups_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }
        
        db_run! { conn: {
            diesel::delete(collection_groups::table)
                .filter(collection_groups::collections_uuid.eq(&self.collections_uuid))
                .filter(collection_groups::groups_uuid.eq(&self.groups_uuid))
                .execute(conn)
                .map_res("Error deleting collection group")
        }}
    }

    pub async fn delete_all_by_group(group_uuid: &str, conn: &DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(group_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }
        
        db_run! { conn: {
            diesel::delete(collection_groups::table)
                .filter(collection_groups::groups_uuid.eq(group_uuid))
                .execute(conn)
                .map_res("Error deleting collection group")
        }}
    }
}

impl GroupUser {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {        
        self.update_user_revision(conn).await;
        
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(groups_users::table)
                    .values((
                        groups_users::users_organizations_uuid.eq(&self.users_organizations_uuid),
                        groups_users::groups_uuid.eq(&self.groups_uuid),
                    ))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(groups_users::table)
                            .filter(groups_users::users_organizations_uuid.eq(&self.users_organizations_uuid))
                            .filter(groups_users::groups_uuid.eq(&self.groups_uuid))
                            .set((
                                groups_users::users_organizations_uuid.eq(&self.users_organizations_uuid),
                                groups_users::groups_uuid.eq(&self.groups_uuid),
                            ))
                            .execute(conn)
                            .map_res("Error adding user to group")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding user to group")
            }
            postgresql {
                diesel::insert_into(groups_users::table)
                    .values((
                        groups_users::users_organizations_uuid.eq(&self.users_organizations_uuid),
                        groups_users::groups_uuid.eq(&self.groups_uuid),
                    ))
                    .on_conflict((groups_users::users_organizations_uuid, groups_users::groups_uuid))
                    .do_update()
                    .set((
                        groups_users::users_organizations_uuid.eq(&self.users_organizations_uuid),
                        groups_users::groups_uuid.eq(&self.groups_uuid),
                    ))
                    .execute(conn)
                    .map_res("Error adding user to group")
            }
        }
    }

    pub async fn find_by_group(group_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups_users::table
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .load::<GroupUserDb>(conn)
                .expect("Error loading group users")
                .from_db()
        }}
    }

    pub async fn find_by_user(users_organizations_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups_users::table
                .filter(groups_users::users_organizations_uuid.eq(users_organizations_uuid))
                .load::<GroupUserDb>(conn)
                .expect("Error loading groups for user")
                .from_db()
        }}
    }

    pub async fn update_user_revision(&self, conn: &DbConn) {
        match UserOrganization::find_by_uuid(&self.users_organizations_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!")
        }
    }

    pub async fn delete_by_group_id_and_user_id(group_uuid: &str, user_uuid: &str, conn: &DbConn) -> EmptyResult {        
        match UserOrganization::find_by_uuid(user_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!")
        };
        
        db_run! { conn: {
            diesel::delete(groups_users::table)
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .filter(groups_users::users_organizations_uuid.eq(user_uuid))
                .execute(conn)
                .map_res("Error deleting group users")
        }}
    }

    pub async fn delete_all_by_group(group_uuid: &str, conn: &DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(group_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }
        
        db_run! { conn: {
            diesel::delete(groups_users::table)
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .execute(conn)
                .map_res("Error deleting group users")
        }}
    }

    pub async fn delete_all_by_user(users_organizations_uuid: &str, conn: &DbConn) -> EmptyResult {
        match UserOrganization::find_by_uuid(users_organizations_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!")
        }
        
        db_run! { conn: {
            diesel::delete(groups_users::table)
                .filter(groups_users::users_organizations_uuid.eq(users_organizations_uuid))
                .execute(conn)
                .map_res("Error deleting user groups")
        }}
    }
}