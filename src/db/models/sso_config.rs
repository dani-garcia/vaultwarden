use crate::api::EmptyResult;
use crate::db::DbConn;
use crate::error::MapResult;
use serde_json::Value;

use super::Organization;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "sso_config"]
    #[belongs_to(Organization, foreign_key = "org_uuid")]
    #[primary_key(uuid)]
    pub struct SsoConfig {
        pub uuid: String,
        pub org_uuid: String,
        pub use_sso: bool,
        pub callback_path: String,
        pub signed_out_callback_path: String,
        pub authority: Option<String>,
        pub client_id: Option<String>,
        pub client_secret: Option<String>,
    }
}

/// Local methods
impl SsoConfig {
    pub fn new(org_uuid: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            org_uuid,
            use_sso: false,
            callback_path: String::from("http://localhost/#/sso/"),
            signed_out_callback_path: String::from("http://localhost/#/sso/"),
            authority: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "UseSso": self.use_sso,
            "CallbackPath": self.callback_path,
            "SignedOutCallbackPath": self.signed_out_callback_path,
            "Authority": self.authority,
            "ClientId": self.client_id,
            "ClientSecret": self.client_secret,
        })
    }
}

/// Database methods
impl SsoConfig {
    pub fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(sso_config::table)
                    .values(SsoConfigDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(sso_config::table)
                            .filter(sso_config::uuid.eq(&self.uuid))
                            .set(SsoConfigDb::to_db(self))
                            .execute(conn)
                            .map_res("Error adding sso config to organization")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error adding sso config to organization")
            }
            postgresql {
                let value = SsoConfigDb::to_db(self);
                diesel::insert_into(sso_config::table)
                    .values(&value)
                    .on_conflict(sso_config::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error adding sso config to organization")
            }
        }
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(sso_config::table.filter(sso_config::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting SSO Config")
        }}
    }

    pub fn find_by_org(org_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            sso_config::table
                .filter(sso_config::org_uuid.eq(org_uuid))
                .first::<SsoConfigDb>(conn)
                .ok()
                .from_db()
        }}
    }
}
