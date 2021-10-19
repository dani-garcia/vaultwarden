use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use super::User;

db_object! {
    #[derive(Debug, Identifiable, Queryable, Insertable, Associations, AsChangeset)]
    #[table_name = "emergency_access"]
    #[changeset_options(treat_none_as_null="true")]
    #[belongs_to(User, foreign_key = "grantor_uuid")]
    #[primary_key(uuid)]
    pub struct EmergencyAccess {
        pub uuid: String,
        pub grantor_uuid: String,
        pub grantee_uuid: Option<String>,
        pub email: Option<String>,
        pub key_encrypted: Option<String>,
        pub atype: i32, //EmergencyAccessType
        pub status: i32, //EmergencyAccessStatus
        pub wait_time_days: i32,
        pub recovery_initiated_at: Option<NaiveDateTime>,
        pub last_notification_at: Option<NaiveDateTime>,
        pub updated_at: NaiveDateTime,
        pub created_at: NaiveDateTime,
    }
}

/// Local methods

impl EmergencyAccess {
    pub fn new(grantor_uuid: String, email: Option<String>, status: i32, atype: i32, wait_time_days: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            grantor_uuid,
            grantee_uuid: None,
            email,
            status,
            atype,
            wait_time_days,
            recovery_initiated_at: None,
            created_at: now,
            updated_at: now,
            key_encrypted: None,
            last_notification_at: None,
        }
    }

    pub fn get_type_as_str(&self) -> &'static str {
        if self.atype == EmergencyAccessType::View as i32 {
            "View"
        } else {
            "Takeover"
        }
    }

    pub fn has_type(&self, access_type: EmergencyAccessType) -> bool {
        self.atype == access_type as i32
    }

    pub fn has_status(&self, status: EmergencyAccessStatus) -> bool {
        self.status == status as i32
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "Status": self.status,
            "Type": self.atype,
            "WaitTimeDays": self.wait_time_days,
            "Object": "emergencyAccess",
        })
    }

    pub fn to_json_grantor_details(&self, conn: &DbConn) -> Value {
        let grantor_user = User::find_by_uuid(&self.grantor_uuid, conn).expect("Grantor user not found.");

        json!({
            "Id": self.uuid,
            "Status": self.status,
            "Type": self.atype,
            "WaitTimeDays": self.wait_time_days,
            "GrantorId": grantor_user.uuid,
            "Email": grantor_user.email,
            "Name": grantor_user.name,
            "Object": "emergencyAccessGrantorDetails",
        })
    }

    #[allow(clippy::manual_map)]
    pub fn to_json_grantee_details(&self, conn: &DbConn) -> Value {
        let grantee_user = if let Some(grantee_uuid) = self.grantee_uuid.as_deref() {
            Some(User::find_by_uuid(grantee_uuid, conn).expect("Grantee user not found."))
        } else if let Some(email) = self.email.as_deref() {
            Some(User::find_by_mail(email, conn).expect("Grantee user not found."))
        } else {
            None
        };

        json!({
            "Id": self.uuid,
            "Status": self.status,
            "Type": self.atype,
            "WaitTimeDays": self.wait_time_days,
            "GranteeId": grantee_user.as_ref().map_or("", |u| &u.uuid),
            "Email": grantee_user.as_ref().map_or("", |u| &u.email),
            "Name": grantee_user.as_ref().map_or("", |u| &u.name),
            "Object": "emergencyAccessGranteeDetails",
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum EmergencyAccessType {
    View = 0,
    Takeover = 1,
}

impl EmergencyAccessType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "View" => Some(EmergencyAccessType::View),
            "1" | "Takeover" => Some(EmergencyAccessType::Takeover),
            _ => None,
        }
    }
}

impl PartialEq<i32> for EmergencyAccessType {
    fn eq(&self, other: &i32) -> bool {
        *other == *self as i32
    }
}

impl PartialEq<EmergencyAccessType> for i32 {
    fn eq(&self, other: &EmergencyAccessType) -> bool {
        *self == *other as i32
    }
}

pub enum EmergencyAccessStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
    RecoveryInitiated = 3,
    RecoveryApproved = 4,
}

// region Database methods

use crate::db::DbConn;

use crate::api::EmptyResult;
use crate::error::MapResult;

impl EmergencyAccess {
    pub fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn);
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(emergency_access::table)
                    .values(EmergencyAccessDb::to_db(self))
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(emergency_access::table)
                            .filter(emergency_access::uuid.eq(&self.uuid))
                            .set(EmergencyAccessDb::to_db(self))
                            .execute(conn)
                            .map_res("Error updating emergency access")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving emergency access")
            }
            postgresql {
                let value = EmergencyAccessDb::to_db(self);
                diesel::insert_into(emergency_access::table)
                    .values(&value)
                    .on_conflict(emergency_access::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving emergency access")
            }
        }
    }

    pub fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for ea in Self::find_all_by_grantor_uuid(user_uuid, conn) {
            ea.delete(conn)?;
        }
        for ea in Self::find_all_by_grantee_uuid(user_uuid, conn) {
            ea.delete(conn)?;
        }
        Ok(())
    }

    pub fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn);

        db_run! { conn: {
            diesel::delete(emergency_access::table.filter(emergency_access::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from emergency access")
        }}
    }

    pub fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::uuid.eq(uuid))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_by_grantor_uuid_and_grantee_uuid_or_email(
        grantor_uuid: &str,
        grantee_uuid: &str,
        email: &str,
        conn: &DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .filter(emergency_access::grantee_uuid.eq(grantee_uuid).or(emergency_access::email.eq(email)))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_all_recoveries(conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::status.eq(EmergencyAccessStatus::RecoveryInitiated as i32))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub fn find_by_uuid_and_grantor_uuid(uuid: &str, grantor_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::uuid.eq(uuid))
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_all_by_grantee_uuid(grantee_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantee_uuid.eq(grantee_uuid))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub fn find_invited_by_grantee_email(grantee_email: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::email.eq(grantee_email))
                .filter(emergency_access::status.eq(EmergencyAccessStatus::Invited as i32))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub fn find_all_by_grantor_uuid(grantor_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }
}

// endregion
