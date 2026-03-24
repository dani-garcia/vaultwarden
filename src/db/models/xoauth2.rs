use crate::api::EmptyResult;
use crate::db::schema::xoauth2;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

#[derive(Debug, Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = xoauth2)]
#[diesel(primary_key(id))]
pub struct XOAuth2 {
    pub id: String,
    pub refresh_token: String,
}

impl XOAuth2 {
    pub fn new(id: String, refresh_token: String) -> Self {
        Self {
            id,
            refresh_token,
        }
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(xoauth2::table)
                    .values(self)
                    .execute(conn)
                    .map_res("Error saving xoauth2")
            }
            postgresql {
                diesel::insert_into(xoauth2::table)
                    .values(self)
                    .on_conflict(xoauth2::id)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving xoauth2")
            }
        }
    }

    pub async fn find_by_id(id: String, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            xoauth2::table
                .filter(xoauth2::id.eq(id))
                .first::<Self>(conn)
                .ok()
        }}
    }
}
