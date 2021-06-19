use super::{Cipher, User};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations)]
    #[table_name = "favorites"]
    #[belongs_to(User, foreign_key = "user_uuid")]
    #[belongs_to(Cipher, foreign_key = "cipher_uuid")]
    #[primary_key(user_uuid, cipher_uuid)]
    pub struct Favorite {
        pub user_uuid: String,
        pub cipher_uuid: String,
    }
}

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

impl Favorite {
    // Returns whether the specified cipher is a favorite of the specified user.
    pub fn is_favorite(cipher_uuid: &str, user_uuid: &str, conn: &DbConn) -> bool {
        db_run! { conn: {
            let query = favorites::table
                .filter(favorites::cipher_uuid.eq(cipher_uuid))
                .filter(favorites::user_uuid.eq(user_uuid))
                .count();

            query.first::<i64>(conn).ok().unwrap_or(0) != 0
        }}
    }

    // Sets whether the specified cipher is a favorite of the specified user.
    pub fn set_favorite(favorite: bool, cipher_uuid: &str, user_uuid: &str, conn: &DbConn) -> EmptyResult {
        let (old, new) = (Self::is_favorite(cipher_uuid, user_uuid, conn), favorite);
        match (old, new) {
            (false, true) => {
                User::update_uuid_revision(user_uuid, conn);
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
                User::update_uuid_revision(user_uuid, conn);
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
    pub fn delete_all_by_cipher(cipher_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(favorites::table.filter(favorites::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error removing favorites by cipher")
        }}
    }

    // Delete all favorite entries associated with the specified user.
    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(favorites::table.filter(favorites::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing favorites by user")
        }}
    }
}
