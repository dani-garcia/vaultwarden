use serde_json::Value;
use webauthn_rs::prelude::{Credential, ParsedAttestation};
use webauthn_rs_proto::{AttestationFormat, RegisteredExtensions};
use super::UserId;
use crate::{api::EmptyResult, db::DbConn, error::MapResult};

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = twofactor)]
    #[diesel(primary_key(uuid))]
    pub struct TwoFactor {
        pub uuid: TwoFactorId,
        pub user_uuid: UserId,
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

mod webauthn_0_3 {
    use webauthn_rs::prelude::ParsedAttestation;
    use webauthn_rs_proto::{AttestationFormat, RegisteredExtensions};

    // Copied from https://docs.rs/webauthn-rs/0.3.2/src/webauthn_rs/proto.rs.html#316-339
    pub struct Credential {
        pub cred_id: Vec<u8>,
        pub cred: COSEKey,
        pub counter: u32,
        pub verified: bool,
        pub registration_policy: webauthn_rs_proto::UserVerificationPolicy,
    }

    impl From<Credential> for webauthn_rs::prelude::Credential {
        fn from(value: Credential) -> Self {
            Self {
                cred_id: value.cred_id.into(),
                cred: value.cred.into(),
                counter: value.counter,
                transports: None,
                user_verified: value.verified,
                backup_eligible: false,
                backup_state: false,
                registration_policy: value.registration_policy,
                extensions: RegisteredExtensions::none(),
                attestation: ParsedAttestation::default(),
                attestation_format: AttestationFormat::None,
            }
        }
    }

    // Copied from https://docs.rs/webauthn-rs/0.3.2/src/webauthn_rs/proto.rs.html#300-305
    #[derive(Deserialize)]
    pub struct COSEKey {
        pub type_: webauthn_rs::prelude::COSEAlgorithm,
        pub key: COSEKeyType,
    }

    impl From<COSEKey> for webauthn_rs::prelude::COSEKey {
        fn from(value: COSEKey) -> Self {
            Self {
                type_: value.type_,
                key: value.key.into(),
            }
        }
    }

    // Copied from https://docs.rs/webauthn-rs/0.3.2/src/webauthn_rs/proto.rs.html#260-278
    #[allow(non_camel_case_types)]
    #[derive(Deserialize)]
    pub enum COSEKeyType {
        EC_OKP,
        EC_EC2(COSEEC2Key),
        RSA(COSERSAKey),
    }

    impl From<COSEKeyType> for webauthn_rs::prelude::COSEKeyType {
        fn from(value: COSEKeyType) -> Self {
            match value {
                COSEKeyType::EC_OKP => panic!(), // TODO what to do here
                COSEKeyType::EC_EC2(a) => Self::EC_EC2(a.into()),
                COSEKeyType::RSA(a) => Self::RSA(a.into()),
            }
        }
    }

    // Copied from https://docs.rs/webauthn-rs/0.3.2/src/webauthn_rs/proto.rs.html#249-254
    #[derive(Deserialize)]
    pub struct COSERSAKey {
        pub n: Vec<u8>,
        pub e: [u8; 3],
    }

    impl From<COSERSAKey> for webauthn_rs::prelude::COSERSAKey {
        fn from(value: COSERSAKey) -> Self {
            Self {
                n: value.n.into(),
                e: value.e,
            }
        }
    }

    // Copied from https://docs.rs/webauthn-rs/0.3.2/src/webauthn_rs/proto.rs.html#235-242
    #[derive(Deserialize)]
    pub struct COSEEC2Key {
        pub curve: webauthn_rs::prelude::ECDSACurve,
        pub x: [u8; 32],
        pub y: [u8; 32],
    }

    impl From<COSEEC2Key> for webauthn_rs::prelude::COSEEC2Key {
        fn from(value: COSEEC2Key) -> Self {
            Self {
                curve: value.curve,
                x: value.x.into(),
                y: value.y.into(),
            }
        }
    }
}

/// Local methods
impl TwoFactor {
    pub fn new(user_uuid: UserId, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: TwoFactorId(crate::util::get_uuid()),
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

    pub async fn find_by_user(user_uuid: &UserId, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.lt(1000)) // Filter implementation types
                .load::<TwoFactorDb>(conn)
                .expect("Error loading twofactor")
                .from_db()
        }}
    }

    pub async fn find_by_user_and_type(user_uuid: &UserId, atype: i32, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            twofactor::table
                .filter(twofactor::user_uuid.eq(user_uuid))
                .filter(twofactor::atype.eq(atype))
                .first::<TwoFactorDb>(conn)
                .ok()
                .from_db()
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &mut DbConn) -> EmptyResult {
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
        use webauthn_rs::prelude::{COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};
        use webauthn_rs_proto::{COSEAlgorithm, UserVerificationPolicy};

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
                        x: x.into(),
                        y: y.into(),
                    }),
                };

                let new_reg = WebauthnRegistration {
                    id: reg.id,
                    migrated: true,
                    name: reg.name.clone(),
                    credential: Credential {
                        counter: reg.counter,
                        user_verified: false,
                        cred: key,
                        cred_id: reg.reg.key_handle.clone().into(),
                        registration_policy: UserVerificationPolicy::Discouraged_DO_NOT_USE,

                        transports: None,
                        backup_eligible: false,
                        backup_state: false,
                        extensions: RegisteredExtensions::none(),
                        attestation: ParsedAttestation::default(),
                        attestation_format: AttestationFormat::None,
                    }.into(),
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

    pub async fn migrate_credential_to_passkey(conn: &mut DbConn) -> EmptyResult {
        todo!()
    }
}

#[derive(Clone, Debug, DieselNewType, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TwoFactorId(String);
