use chrono::NaiveDateTime;
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
    pub async fn get_archived_at(cipher_uuid: &CipherId, user_uuid: &UserId, conn: &DbConn) -> Option<NaiveDateTime> {
        db_run! { conn: {
            archives::table
                .filter(archives::cipher_uuid.eq(cipher_uuid))
                .filter(archives::user_uuid.eq(user_uuid))
                .select(archives::archived_at)
                .first::<NaiveDateTime>(conn).ok()
        }}
    }

    // Saves (inserts or updates) an archive record with the provided timestamp
    pub async fn save(
        user_uuid: &UserId,
        cipher_uuid: &CipherId,
        archived_at: NaiveDateTime,
        conn: &DbConn,
    ) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(archives::table)
                    .values((
                        archives::user_uuid.eq(user_uuid),
                        archives::cipher_uuid.eq(cipher_uuid),
                        archives::archived_at.eq(archived_at),
                    ))
                    .execute(conn)
                    .map_res("Error saving archive")
            }
            postgresql {
                diesel::insert_into(archives::table)
                    .values((
                        archives::user_uuid.eq(user_uuid),
                        archives::cipher_uuid.eq(cipher_uuid),
                        archives::archived_at.eq(archived_at),
                    ))
                    .on_conflict((archives::user_uuid, archives::cipher_uuid))
                    .do_update()
                    .set(archives::archived_at.eq(archived_at))
                    .execute(conn)
                    .map_res("Error saving archive")
            }
        }
    }

    // Deletes an archive record for a specific cipher
    pub async fn delete_by_cipher(user_uuid: &UserId, cipher_uuid: &CipherId, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(user_uuid, conn).await;
        db_run! { conn: {
            diesel::delete(
                archives::table
                    .filter(archives::user_uuid.eq(user_uuid))
                    .filter(archives::cipher_uuid.eq(cipher_uuid))
            )
            .execute(conn)
            .map_res("Error deleting archive")
        }}
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
