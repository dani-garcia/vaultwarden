use crate::db::DbConn;
use serde_json::Value;

use crate::{api::EmptyResult, error::MapResult, CONFIG};

use chrono::{Duration, NaiveDateTime, Utc};

// https://bitwarden.com/help/event-logs/

db_object! {
    // Upstream: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
    // Upstream: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Api/Models/Public/Response/EventResponseModel.cs
    // Upstream SQL: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Sql/dbo/Tables/Event.sql
    #[derive(Identifiable, Queryable, Insertable, AsChangeset)]
    #[diesel(table_name = event)]
    #[diesel(primary_key(uuid))]
    pub struct Event {
        pub uuid: String,
        pub event_type: i32, // EventType
        pub user_uuid: Option<String>,
        pub org_uuid: Option<String>,
        pub cipher_uuid: Option<String>,
        pub collection_uuid: Option<String>,
        pub group_uuid: Option<String>,
        pub org_user_uuid: Option<String>,
        pub act_user_uuid: Option<String>,
        // Upstream enum: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Enums/DeviceType.cs
        pub device_type: Option<i32>,
        pub ip_address: Option<String>,
        pub event_date: NaiveDateTime,
        pub policy_uuid: Option<String>,
        pub provider_uuid: Option<String>,
        pub provider_user_uuid: Option<String>,
        pub provider_org_uuid: Option<String>,
    }
}

// Upstream enum: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Enums/EventType.cs
#[derive(Debug, Copy, Clone)]
pub enum EventType {
    // User
    UserLoggedIn = 1000,
    UserChangedPassword = 1001,
    UserUpdated2fa = 1002,
    UserDisabled2fa = 1003,
    UserRecovered2fa = 1004,
    UserFailedLogIn = 1005,
    UserFailedLogIn2fa = 1006,
    UserClientExportedVault = 1007,
    // UserUpdatedTempPassword = 1008, // Not supported
    // UserMigratedKeyToKeyConnector = 1009, // Not supported

    // Cipher
    CipherCreated = 1100,
    CipherUpdated = 1101,
    CipherDeleted = 1102,
    CipherAttachmentCreated = 1103,
    CipherAttachmentDeleted = 1104,
    CipherShared = 1105,
    CipherUpdatedCollections = 1106,
    CipherClientViewed = 1107,
    CipherClientToggledPasswordVisible = 1108,
    CipherClientToggledHiddenFieldVisible = 1109,
    CipherClientToggledCardCodeVisible = 1110,
    CipherClientCopiedPassword = 1111,
    CipherClientCopiedHiddenField = 1112,
    CipherClientCopiedCardCode = 1113,
    CipherClientAutofilled = 1114,
    CipherSoftDeleted = 1115,
    CipherRestored = 1116,
    CipherClientToggledCardNumberVisible = 1117,

    // Collection
    CollectionCreated = 1300,
    CollectionUpdated = 1301,
    CollectionDeleted = 1302,

    // Group
    GroupCreated = 1400,
    GroupUpdated = 1401,
    GroupDeleted = 1402,

    // OrganizationUser
    OrganizationUserInvited = 1500,
    OrganizationUserConfirmed = 1501,
    OrganizationUserUpdated = 1502,
    OrganizationUserRemoved = 1503,
    OrganizationUserUpdatedGroups = 1504,
    // OrganizationUserUnlinkedSso = 1505, // Not supported
    OrganizationUserResetPasswordEnroll = 1506,
    OrganizationUserResetPasswordWithdraw = 1507,
    OrganizationUserAdminResetPassword = 1508,
    // OrganizationUserResetSsoLink = 1509, // Not supported
    // OrganizationUserFirstSsoLogin = 1510, // Not supported
    OrganizationUserRevoked = 1511,
    OrganizationUserRestored = 1512,

    // Organization
    OrganizationUpdated = 1600,
    OrganizationPurgedVault = 1601,
    OrganizationClientExportedVault = 1602,
    // OrganizationVaultAccessed = 1603,
    // OrganizationEnabledSso = 1604, // Not supported
    // OrganizationDisabledSso = 1605, // Not supported
    // OrganizationEnabledKeyConnector = 1606, // Not supported
    // OrganizationDisabledKeyConnector = 1607, // Not supported
    // OrganizationSponsorshipsSynced = 1608, // Not supported

    // Policy
    PolicyUpdated = 1700,
    // Provider (Not yet supported)
    // ProviderUserInvited = 1800, // Not supported
    // ProviderUserConfirmed = 1801, // Not supported
    // ProviderUserUpdated = 1802, // Not supported
    // ProviderUserRemoved = 1803, // Not supported
    // ProviderOrganizationCreated = 1900, // Not supported
    // ProviderOrganizationAdded = 1901, // Not supported
    // ProviderOrganizationRemoved = 1902, // Not supported
    // ProviderOrganizationVaultAccessed = 1903, // Not supported
}

/// Local methods
impl Event {
    pub fn new(event_type: i32, event_date: Option<NaiveDateTime>) -> Self {
        let event_date = match event_date {
            Some(d) => d,
            None => Utc::now().naive_utc(),
        };

        Self {
            uuid: crate::util::get_uuid(),
            event_type,
            user_uuid: None,
            org_uuid: None,
            cipher_uuid: None,
            collection_uuid: None,
            group_uuid: None,
            org_user_uuid: None,
            act_user_uuid: None,
            device_type: None,
            ip_address: None,
            event_date,
            policy_uuid: None,
            provider_uuid: None,
            provider_user_uuid: None,
            provider_org_uuid: None,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "type": self.event_type,
            "userId": self.user_uuid,
            "organizationId": self.org_uuid,
            "cipherId": self.cipher_uuid,
            "collectionId": self.collection_uuid,
            "groupId": self.group_uuid,
            "organizationUserId": self.org_user_uuid,
            "actingUserId": self.act_user_uuid,
            "date": format_date(&self.event_date),
            "deviceType": self.device_type,
            "ipAddress": self.ip_address,
            "policyId": self.policy_uuid,
            "providerId": self.provider_uuid,
            "providerUserId": self.provider_user_uuid,
            "providerOrganizationId": self.provider_org_uuid,
            // "installationId": null, // Not supported
        })
    }
}

/// Database methods
/// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
impl Event {
    pub const PAGE_SIZE: i64 = 30;

    /// #############
    /// Basic Queries
    pub async fn save(&self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(event::table)
                .values(EventDb::to_db(self))
                .execute(conn)
                .map_res("Error saving event")
            }
            postgresql {
                diesel::insert_into(event::table)
                .values(EventDb::to_db(self))
                .on_conflict(event::uuid)
                .do_update()
                .set(EventDb::to_db(self))
                .execute(conn)
                .map_res("Error saving event")
            }
        }
    }

    pub async fn save_user_event(events: Vec<Event>, conn: &mut DbConn) -> EmptyResult {
        // Special save function which is able to handle multiple events.
        // SQLite doesn't support the DEFAULT argument, and does not support inserting multiple values at the same time.
        // MySQL and PostgreSQL do.
        // We also ignore duplicate if they ever will exists, else it could break the whole flow.
        db_run! { conn:
            // Unfortunately SQLite does not support inserting multiple records at the same time
            // We loop through the events here and insert them one at a time.
            sqlite {
                for event in events {
                    diesel::insert_or_ignore_into(event::table)
                    .values(EventDb::to_db(&event))
                    .execute(conn)
                    .unwrap_or_default();
                }
                Ok(())
            }
            mysql {
                let events: Vec<EventDb> = events.iter().map(EventDb::to_db).collect();
                diesel::insert_or_ignore_into(event::table)
                .values(&events)
                .execute(conn)
                .unwrap_or_default();
                Ok(())
            }
            postgresql {
                let events: Vec<EventDb> = events.iter().map(EventDb::to_db).collect();
                diesel::insert_into(event::table)
                .values(&events)
                .on_conflict_do_nothing()
                .execute(conn)
                .unwrap_or_default();
                Ok(())
            }
        }
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(event::table.filter(event::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting event")
        }}
    }

    /// ##############
    /// Custom Queries
    pub async fn find_by_organization_uuid(
        org_uuid: &str,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            event::table
                .filter(event::org_uuid.eq(org_uuid))
                .filter(event::event_date.between(start, end))
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<EventDb>(conn)
                .expect("Error filtering events")
                .from_db()
        }}
    }

    pub async fn find_by_org_and_user_org(
        org_uuid: &str,
        user_org_uuid: &str,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            event::table
                .inner_join(users_organizations::table.on(users_organizations::uuid.eq(user_org_uuid)))
                .filter(event::org_uuid.eq(org_uuid))
                .filter(event::event_date.between(start, end))
                .filter(event::user_uuid.eq(users_organizations::user_uuid.nullable()).or(event::act_user_uuid.eq(users_organizations::user_uuid.nullable())))
                .select(event::all_columns)
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<EventDb>(conn)
                .expect("Error filtering events")
                .from_db()
        }}
    }

    pub async fn find_by_cipher_uuid(
        cipher_uuid: &str,
        start: &NaiveDateTime,
        end: &NaiveDateTime,
        conn: &mut DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            event::table
                .filter(event::cipher_uuid.eq(cipher_uuid))
                .filter(event::event_date.between(start, end))
                .order_by(event::event_date.desc())
                .limit(Self::PAGE_SIZE)
                .load::<EventDb>(conn)
                .expect("Error filtering events")
                .from_db()
        }}
    }

    pub async fn clean_events(conn: &mut DbConn) -> EmptyResult {
        if let Some(days_to_retain) = CONFIG.events_days_retain() {
            let dt = Utc::now().naive_utc() - Duration::days(days_to_retain);
            db_run! { conn: {
                diesel::delete(event::table.filter(event::event_date.lt(dt)))
                .execute(conn)
                .map_res("Error cleaning old events")
            }}
        } else {
            Ok(())
        }
    }
}
