use serde_json::Value;

use crate::{api::EmptyResult, db::DbConn, error::MapResult};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = twofactor)]
    #[diesel(primary_key(uuid))]
    pub struct TwoFactor {
        pub uuid: String,
        pub user_uuid: String,
        pub atype: i32,
        pub enabled: bool,
        pub data: String,
        pub last_used: i64,
    }
}

#[allow(dead_code)]
#[derive(num_derive::FromPrimitive)]
pub enum TwoFactorType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    Webauthn = 7,

    // These are implementation details
    U2fRegisterChallenge = 1000,
    U2fLoginChallenge = 1001,
    EmailVerificationChallenge = 1002,
    WebauthnRegisterChallenge = 1003,
    WebauthnLoginChallenge = 1004,

    // Special type for Protected Actions verification via email
    ProtectedActions = 2000,
}

/// Local methods
impl TwoFactor {
    pub fn new(user_uuid: String, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: crate::util::get_uuid(),
            user_uuid,
            atype: atype as i32,
            enabled: true,
            data,
            last_used: 0,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "key": "", // This key and value vary
            "Oobject": "twoFactorAuthenticator" // This value varies
        })
    }

    pub fn to_json_provider(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "type": self.atype,
            "object": "twoFactorProvider"
        })
    }
}

/// Database methods
impl TwoFactor {
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(twofactor::table)
                    .values(TwoFactorDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(twofactor::table)
                            .filter(twofactor::uuid.eq(&self.uuid))
                            .set(TwoFactorDb::to_db(self))
                            .execute(conn)
                            .map_res("Error saving twofactor")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving twofactor")
            }
            postgresql {
                let value = TwoFactorDb::to_db(self);
                // We need to make sure we're not going to violate the unique constraint on user_uuid and atype.
                // This happens automatically on other DBMS backends due to replace_into(). PostgreSQL does
                // not support multiple constraints on ON CONFLICT clauses.
                let _: () = diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq(&self.user_uuid)).filter(twofactor::atype.eq(&self.atype)))
                    .execute(conn)
                    .map_res("Error deleting twofactor for insert")?;

                diesel::insert_into(twofactor::table)
                    .values(&value)
                    .on_conflict(twofactor::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving twofactor")
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor::table.filter(twofactor::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting twofactor")
        }}
    }

    pub async fn find_by_user(user_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.lt(1000)) // Filter implementation types
                .load::<TwoFactorDb>(conn)
                .expect("Error loading twofactor")
                .from_db()
        }}
    }

    pub async fn find_by_user_and_type(user_uuid: &str, atype: i32, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.eq(atype))
                .first::<TwoFactorDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor::table.filter(twofactor::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting twofactors")
        }}
    }

    pub async fn migrate_u2f_to_webauthn(conn: &mut DbConn) -> EmptyResult {
        let u2f_factors = db_run! { conn: {
            twofactor::table
                .filter(twofactor::atype.eq(TwoFactorType::U2f as i32))
                .load::<TwoFactorDb>(conn)
                .expect("Error loading twofactor")
                .from_db()
        }};

        use crate::api::core::two_factor::webauthn::U2FRegistration;
        use crate::api::core::two_factor::webauthn::{get_webauthn_registrations, WebauthnRegistration};
        use webauthn_rs::proto::*;

        for mut u2f in u2f_factors {
            let mut regs: Vec<U2FRegistration> = serde_json::from_str(&u2f.data)?;
            // If there are no registrations or they are migrated (we do the migration in batch so we can consider them all migrated when the first one is)
            if regs.is_empty() || regs[0].migrated == Some(true) {
                continue;
            }

            let (_, mut webauthn_regs) = get_webauthn_registrations(&u2f.user_uuid, conn).await?;

            // If the user already has webauthn registrations saved, don't overwrite them
            if !webauthn_regs.is_empty() {
                continue;
            }

            for reg in &mut regs {
                let x: [u8; 32] = reg.reg.pub_key[1..33].try_into().unwrap();
                let y: [u8; 32] = reg.reg.pub_key[33..65].try_into().unwrap();

                let key = COSEKey {
                    type_: COSEAlgorithm::ES256,
                    key: COSEKeyType::EC_EC2(COSEEC2Key {
                        curve: ECDSACurve::SECP256R1,
                        x,
                        y,
                    }),
                };

                let new_reg = WebauthnRegistration {
                    id: reg.id,
                    migrated: true,
                    name: reg.name.clone(),
                    credential: Credential {
                        counter: reg.counter,
                        verified: false,
                        cred: key,
                        cred_id: reg.reg.key_handle.clone(),
                        registration_policy: UserVerificationPolicy::Discouraged,
                    },
                };

                webauthn_regs.push(new_reg);

                reg.migrated = Some(true);
            }

            u2f.data = serde_json::to_string(&regs)?;
            u2f.save(conn).await?;

            TwoFactor::new(u2f.user_uuid.clone(), TwoFactorType::Webauthn, serde_json::to_string(&webauthn_regs)?)
                .save(conn)
                .await?;
        }

        Ok(())
    }
}
