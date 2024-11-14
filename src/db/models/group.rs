use super::{User, UserOrganization};
use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;
use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = groups)]
    #[diesel(primary_key(uuid))]
    pub struct Group {
        pub uuid: String,
        pub organizations_uuid: String,
        pub name: String,
        pub access_all: bool,
        pub external_id: Option<String>,
        pub creation_date: NaiveDateTime,
        pub revision_date: NaiveDateTime,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = collections_groups)]
    #[diesel(primary_key(collections_uuid, groups_uuid))]
    pub struct CollectionGroup {
        pub collections_uuid: String,
        pub groups_uuid: String,
        pub read_only: bool,
        pub hide_passwords: bool,
    }

    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = groups_users)]
    #[diesel(primary_key(groups_uuid, users_organizations_uuid))]
    pub struct GroupUser {
        pub groups_uuid: String,
        pub users_organizations_uuid: String
    }
}

/// Local methods
impl Group {
    pub fn new(organizations_uuid: String, name: String, access_all: bool, external_id: Option<String>) -> Self {
        let now = Utc::now().naive_utc();

        let mut new_model = Self {
            uuid: crate::util::get_uuid(),
            organizations_uuid,
            name,
            access_all,
            external_id: None,
            creation_date: now,
            revision_date: now,
        };

        new_model.set_external_id(external_id);

        new_model
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "id": self.uuid,
            "organizationId": self.organizations_uuid,
            "name": self.name,
            "accessAll": self.access_all,
            "externalId": self.external_id,
            "creationDate": format_date(&self.creation_date),
            "revisionDate": format_date(&self.revision_date),
            "object": "group"
        })
    }

    pub async fn to_json_details(&self, conn: &mut DbConn) -> Value {
        let collections_groups: Vec<Value> = CollectionGroup::find_by_group(&self.uuid, conn)
            .await
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.collections_uuid,
                    "readOnly": entry.read_only,
                    "hidePasswords": entry.hide_passwords,
                    "manage": false
                })
            })
            .collect();

        json!({
            "id": self.uuid,
            "organizationId": self.organizations_uuid,
            "name": self.name,
            "accessAll": self.access_all,
            "externalId": self.external_id,
            "collections": collections_groups,
            "object": "groupDetails"
        })
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) {
        // Check if external_id is empty. We do not want to have empty strings in the database
        self.external_id = match external_id {
            Some(external_id) if !external_id.trim().is_empty() => Some(external_id),
            _ => None,
        };
    }
}

impl CollectionGroup {
    pub fn new(collections_uuid: String, groups_uuid: String, read_only: bool, hide_passwords: bool) -> Self {
        Self {
            collections_uuid,
            groups_uuid,
            read_only,
            hide_passwords,
        }
    }
}

impl GroupUser {
    pub fn new(groups_uuid: String, users_organizations_uuid: String) -> Self {
        Self {
            groups_uuid,
            users_organizations_uuid,
        }
    }
}

/// Database methods
impl Group {
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
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

    pub async fn delete_all_by_organization(org_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for group in Self::find_by_organization(org_uuid, conn).await {
            group.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn find_by_organization(organizations_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups::table
                .filter(groups::organizations_uuid.eq(organizations_uuid))
                .load::<GroupDb>(conn)
                .expect("Error loading groups")
                .from_db()
        }}
    }

    pub async fn count_by_org(organizations_uuid: &str, conn: &mut DbConn) -> i64 {
        db_run! { conn: {
            groups::table
                .filter(groups::organizations_uuid.eq(organizations_uuid))
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            groups::table
                .filter(groups::uuid.eq(uuid))
                .first::<GroupDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn find_by_external_id_and_org(external_id: &str, org_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            groups::table
                .filter(groups::external_id.eq(external_id))
                .filter(groups::organizations_uuid.eq(org_uuid))
                .first::<GroupDb>(conn)
                .ok()
                .from_db()
        }}
    }
    //Returns all organizations the user has full access to
    pub async fn gather_user_organizations_full_access(user_uuid: &str, conn: &mut DbConn) -> Vec<String> {
        db_run! { conn: {
            groups_users::table
                .inner_join(users_organizations::table.on(
                    users_organizations::uuid.eq(groups_users::users_organizations_uuid)
                ))
                .inner_join(groups::table.on(
                    groups::uuid.eq(groups_users::groups_uuid)
                ))
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(groups::access_all.eq(true))
                .select(groups::organizations_uuid)
                .distinct()
                .load::<String>(conn)
                .expect("Error loading organization group full access information for user")
        }}
    }

    pub async fn is_in_full_access_group(user_uuid: &str, org_uuid: &str, conn: &mut DbConn) -> bool {
        db_run! { conn: {
            groups::table
                .inner_join(groups_users::table.on(
                    groups_users::groups_uuid.eq(groups::uuid)
                ))
                .inner_join(users_organizations::table.on(
                    users_organizations::uuid.eq(groups_users::users_organizations_uuid)
                ))
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .filter(groups::organizations_uuid.eq(org_uuid))
                .filter(groups::access_all.eq(true))
                .select(groups::access_all)
                .first::<bool>(conn)
                .unwrap_or_default()
        }}
    }

    pub async fn delete(&self, conn: &mut DbConn) -> EmptyResult {
        CollectionGroup::delete_all_by_group(&self.uuid, conn).await?;
        GroupUser::delete_all_by_group(&self.uuid, conn).await?;

        db_run! { conn: {
            diesel::delete(groups::table.filter(groups::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting group")
        }}
    }

    pub async fn update_revision(uuid: &str, conn: &mut DbConn) {
        if let Err(e) = Self::_update_revision(uuid, &Utc::now().naive_utc(), conn).await {
            warn!("Failed to update revision for {}: {:#?}", uuid, e);
        }
    }

    async fn _update_revision(uuid: &str, date: &NaiveDateTime, conn: &mut DbConn) -> EmptyResult {
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
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(&self.groups_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(collections_groups::table)
                    .values((
                        collections_groups::collections_uuid.eq(&self.collections_uuid),
                        collections_groups::groups_uuid.eq(&self.groups_uuid),
                        collections_groups::read_only.eq(&self.read_only),
                        collections_groups::hide_passwords.eq(&self.hide_passwords),
                    ))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(collections_groups::table)
                            .filter(collections_groups::collections_uuid.eq(&self.collections_uuid))
                            .filter(collections_groups::groups_uuid.eq(&self.groups_uuid))
                            .set((
                                collections_groups::collections_uuid.eq(&self.collections_uuid),
                                collections_groups::groups_uuid.eq(&self.groups_uuid),
                                collections_groups::read_only.eq(&self.read_only),
                                collections_groups::hide_passwords.eq(&self.hide_passwords),
                            ))
                            .execute(conn)
                            .map_res("Error adding group to collection")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding group to collection")
            }
            postgresql {
                diesel::insert_into(collections_groups::table)
                    .values((
                        collections_groups::collections_uuid.eq(&self.collections_uuid),
                        collections_groups::groups_uuid.eq(&self.groups_uuid),
                        collections_groups::read_only.eq(self.read_only),
                        collections_groups::hide_passwords.eq(self.hide_passwords),
                    ))
                    .on_conflict((collections_groups::collections_uuid, collections_groups::groups_uuid))
                    .do_update()
                    .set((
                        collections_groups::read_only.eq(self.read_only),
                        collections_groups::hide_passwords.eq(self.hide_passwords),
                    ))
                    .execute(conn)
                    .map_res("Error adding group to collection")
            }
        }
    }

    pub async fn find_by_group(group_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections_groups::table
                .filter(collections_groups::groups_uuid.eq(group_uuid))
                .load::<CollectionGroupDb>(conn)
                .expect("Error loading collection groups")
                .from_db()
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections_groups::table
                .inner_join(groups_users::table.on(
                    groups_users::groups_uuid.eq(collections_groups::groups_uuid)
                ))
                .inner_join(users_organizations::table.on(
                    users_organizations::uuid.eq(groups_users::users_organizations_uuid)
                ))
                .filter(users_organizations::user_uuid.eq(user_uuid))
                .select(collections_groups::all_columns)
                .load::<CollectionGroupDb>(conn)
                .expect("Error loading user collection groups")
                .from_db()
        }}
    }

    pub async fn find_by_collection(collection_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            collections_groups::table
                .filter(collections_groups::collections_uuid.eq(collection_uuid))
                .select(collections_groups::all_columns)
                .load::<CollectionGroupDb>(conn)
                .expect("Error loading collection groups")
                .from_db()
        }}
    }

    pub async fn delete(&self, conn: &mut DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(&self.groups_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }

        db_run! { conn: {
            diesel::delete(collections_groups::table)
                .filter(collections_groups::collections_uuid.eq(&self.collections_uuid))
                .filter(collections_groups::groups_uuid.eq(&self.groups_uuid))
                .execute(conn)
                .map_res("Error deleting collection group")
        }}
    }

    pub async fn delete_all_by_group(group_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        let group_users = GroupUser::find_by_group(group_uuid, conn).await;
        for group_user in group_users {
            group_user.update_user_revision(conn).await;
        }

        db_run! { conn: {
            diesel::delete(collections_groups::table)
                .filter(collections_groups::groups_uuid.eq(group_uuid))
                .execute(conn)
                .map_res("Error deleting collection group")
        }}
    }

    pub async fn delete_all_by_collection(collection_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        let collection_assigned_to_groups = CollectionGroup::find_by_collection(collection_uuid, conn).await;
        for collection_assigned_to_group in collection_assigned_to_groups {
            let group_users = GroupUser::find_by_group(&collection_assigned_to_group.groups_uuid, conn).await;
            for group_user in group_users {
                group_user.update_user_revision(conn).await;
            }
        }

        db_run! { conn: {
            diesel::delete(collections_groups::table)
                .filter(collections_groups::collections_uuid.eq(collection_uuid))
                .execute(conn)
                .map_res("Error deleting collection group")
        }}
    }
}

impl GroupUser {
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
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

    pub async fn find_by_group(group_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups_users::table
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .load::<GroupUserDb>(conn)
                .expect("Error loading group users")
                .from_db()
        }}
    }

    pub async fn find_by_user(users_organizations_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            groups_users::table
                .filter(groups_users::users_organizations_uuid.eq(users_organizations_uuid))
                .load::<GroupUserDb>(conn)
                .expect("Error loading groups for user")
                .from_db()
        }}
    }

    pub async fn has_access_to_collection_by_member(
        collection_uuid: &str,
        member_uuid: &str,
        conn: &mut DbConn,
    ) -> bool {
        db_run! { conn: {
            groups_users::table
                .inner_join(collections_groups::table.on(
                    collections_groups::groups_uuid.eq(groups_users::groups_uuid)
                ))
                .filter(collections_groups::collections_uuid.eq(collection_uuid))
                .filter(groups_users::users_organizations_uuid.eq(member_uuid))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0) != 0
        }}
    }

    pub async fn has_full_access_by_member(org_uuid: &str, member_uuid: &str, conn: &mut DbConn) -> bool {
        db_run! { conn: {
            groups_users::table
                .inner_join(groups::table.on(
                    groups::uuid.eq(groups_users::groups_uuid)
                ))
                .filter(groups::organizations_uuid.eq(org_uuid))
                .filter(groups::access_all.eq(true))
                .filter(groups_users::users_organizations_uuid.eq(member_uuid))
                .count()
                .first::<i64>(conn)
                .unwrap_or(0) != 0
        }}
    }

    pub async fn update_user_revision(&self, conn: &mut DbConn) {
        match UserOrganization::find_by_uuid(&self.users_organizations_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!"),
        }
    }

    pub async fn delete_by_group_id_and_user_id(
        group_uuid: &str,
        users_organizations_uuid: &str,
        conn: &mut DbConn,
    ) -> EmptyResult {
        match UserOrganization::find_by_uuid(users_organizations_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!"),
        };

        db_run! { conn: {
            diesel::delete(groups_users::table)
                .filter(groups_users::groups_uuid.eq(group_uuid))
                .filter(groups_users::users_organizations_uuid.eq(users_organizations_uuid))
                .execute(conn)
                .map_res("Error deleting group users")
        }}
    }

    pub async fn delete_all_by_group(group_uuid: &str, conn: &mut DbConn) -> EmptyResult {
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

    pub async fn delete_all_by_user(users_organizations_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        match UserOrganization::find_by_uuid(users_organizations_uuid, conn).await {
            Some(user) => User::update_uuid_revision(&user.user_uuid, conn).await,
            None => warn!("User could not be found!"),
        }

        db_run! { conn: {
            diesel::delete(groups_users::table)
                .filter(groups_users::users_organizations_uuid.eq(users_organizations_uuid))
                .execute(conn)
                .map_res("Error deleting user groups")
        }}
    }
}
