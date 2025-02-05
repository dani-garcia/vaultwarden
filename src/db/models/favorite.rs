use super::{CipherId, User, UserId};

db_object! {
    #[derive(Identifiable, Queryable, Insertable)]
    #[diesel(table_name = favorites)]
    #[diesel(primary_key(user_uuid, cipher_uuid))]
    pub struct Favorite {
        pub user_uuid: UserId,
        pub cipher_uuid: CipherId,
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

impl Favorite {
    // Returns whether the specified cipher is a favorite of the specified user.
    pub async fn is_favorite(cipher_uuid: &CipherId, user_uuid: &UserId, conn: &mut DbConn) -> bool {
        db_run! { conn: {
            let query = favorites::table
                .filter(favorites::cipher_uuid.eq(cipher_uuid))
                .filter(favorites::user_uuid.eq(user_uuid))
                .count();

            query.first::<i64>(conn).ok().unwrap_or(0) != 0
        }}
    }

    // Sets whether the specified cipher is a favorite of the specified user.
    pub async fn set_favorite(
        favorite: bool,
        cipher_uuid: &CipherId,
        user_uuid: &UserId,
        conn: &mut DbConn,
    ) -> EmptyResult {
        let (old, new) = (Self::is_favorite(cipher_uuid, user_uuid, conn).await, favorite);
        match (old, new) {
            (false, true) => {
                User::update_uuid_revision(user_uuid, conn).await;
                db_run! { conn: {
                diesel::insert_into(favorites::table)
                    .values((
                        favorites::user_uuid.eq(user_uuid),
                        favorites::cipher_uuid.eq(cipher_uuid),
                    ))
                    .execute(conn)
                    .map_res("Error adding favorite")
                }}
            }
            (true, false) => {
                User::update_uuid_revision(user_uuid, conn).await;
                db_run! { conn: {
                    diesel::delete(
                        favorites::table
                            .filter(favorites::user_uuid.eq(user_uuid))
                            .filter(favorites::cipher_uuid.eq(cipher_uuid))
                    )
                    .execute(conn)
                    .map_res("Error removing favorite")
                }}
            }
            // Otherwise, the favorite status is already what it should be.
            _ => Ok(()),
        }
    }

    // Delete all favorite entries associated with the specified cipher.
    pub async fn delete_all_by_cipher(cipher_uuid: &CipherId, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(favorites::table.filter(favorites::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing favorites by cipher")
        }}
    }

    // Delete all favorite entries associated with the specified user.
    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(favorites::table.filter(favorites::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing favorites by user")
        }}
    }

    /// Return a vec with (cipher_uuid) this will only contain favorite flagged ciphers
    /// This is used during a full sync so we only need one query for all favorite cipher matches.
    pub async fn get_all_cipher_uuid_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<CipherId> {
        db_run! { conn: {
            favorites::table
                .filter(favorites::user_uuid.eq(user_uuid))
                .select(favorites::cipher_uuid)
                .load::<CipherId>(conn)
                .unwrap_or_default()
        }}
    }
}
