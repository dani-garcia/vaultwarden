use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use super::{CipherId, User, UserId};
use crate::api::EmptyResult;
use crate::db::schema::archives;
use crate::db::DbConn;
use crate::error::MapResult;

#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = archives)]
#[diesel(primary_key(user_uuid, cipher_uuid))]
pub struct Archive {
    pub user_uuid: UserId,
    pub cipher_uuid: CipherId,
    pub archived_at: NaiveDateTime,
}

impl Archive {
    // Returns the date the specified cipher was archived
    pub async fn get_archived_date(cipher_uuid: &CipherId, user_uuid: &UserId, conn: &DbConn) -> Option<NaiveDateTime> {
        db_run! { conn: {
            archives::table
                .filter(archives::cipher_uuid.eq(cipher_uuid))
                .filter(archives::user_uuid.eq(user_uuid))
                .select(archives::archived_at)
                .first::<NaiveDateTime>(conn).ok()
        }}
    }

    // Sets the specified cipher to be archived or unarchived
    pub async fn set_archived(
        archived: bool,
        cipher_uuid: &CipherId,
        user_uuid: &UserId,
        conn: &DbConn,
    ) -> EmptyResult {
        let (old, new) = (Self::get_archived_date(cipher_uuid, user_uuid, conn).await.is_some(), archived);
        match (old, new) {
            (false, true) => {
                User::update_uuid_revision(user_uuid, conn).await;
                db_run! { conn: {
                diesel::insert_into(archives::table)
                    .values((
                        archives::user_uuid.eq(user_uuid),
                        archives::cipher_uuid.eq(cipher_uuid),
                        archives::archived_at.eq(Utc::now().naive_utc()),
                    ))
                    .execute(conn)
                    .map_res("Error archiving")
                }}
            }
            (true, false) => {
                User::update_uuid_revision(user_uuid, conn).await;
                db_run! { conn: {
                    diesel::delete(
                        archives::table
                            .filter(archives::user_uuid.eq(user_uuid))
                            .filter(archives::cipher_uuid.eq(cipher_uuid))
                    )
                    .execute(conn)
                    .map_res("Error unarchiving")
                }}
            }
            // Otherwise, the archived status is already what it should be
            _ => Ok(()),
        }
    }

    /// Return a vec with (cipher_uuid, archived_at)
    /// This is used during a full sync so we only need one query for all archive matches
    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<(CipherId, NaiveDateTime)> {
        db_run! { conn: {
            archives::table
                .filter(archives::user_uuid.eq(user_uuid))
                .select((archives::cipher_uuid, archives::archived_at))
                .load::<(CipherId, NaiveDateTime)>(conn)
                .unwrap_or_default()
        }}
    }
}
