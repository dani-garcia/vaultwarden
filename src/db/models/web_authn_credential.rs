use derive_more::{AsRef, Deref, Display, From};
use macros::UuidFromParam;
use crate::api::EmptyResult;
use crate::db::DbConn;
use super::UserId;

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, AsChangeset, Deserialize, Serialize)]
    #[diesel(table_name = web_authn_credentials)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
    pub struct WebAuthnCredential {
        pub uuid: WebAuthnCredentialId,
        pub user_uuid: UserId,
        pub name: String,
        pub credential: String,
        pub supports_prf: bool,
        pub encrypted_user_key: String,
        pub encrypted_public_key: String,
        pub encrypted_private_key: String,
    }
}

impl WebAuthnCredential {
    pub fn new(
        user_uuid: UserId,
        name: String,
        credential: String,
        supports_prf: bool,
        encrypted_user_key: String,
        encrypted_public_key: String,
        encrypted_private_key: String,
    ) -> Self {
        Self {
            uuid: WebAuthnCredentialId(crate::util::get_uuid()),
            user_uuid,
            name,
            credential,
            supports_prf,
            encrypted_user_key,
            encrypted_public_key,
            encrypted_private_key,
        }
    }

    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        // TODO add mysql and postgres
        db_run! { conn: 
            sqlite {
                match diesel::insert_into(web_authn_credentials::table)
                    .values(WebAuthnCredentialDb::to_db(self))
                    .execute(conn) 
                {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    pub async fn find_all_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            web_authn_credentials::table
                .filter(web_authn_credentials::user_uuid.eq(user_uuid))
                .load::<WebAuthnCredentialDb>(conn)
                .ok()
                .from_db()
        // TODO do not unwrap
        }}.unwrap()
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct WebAuthnCredentialId(String);
