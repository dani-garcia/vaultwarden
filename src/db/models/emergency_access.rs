use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use crate::{api::EmptyResult, db::DbConn, error::MapResult};

use super::User;
use crate::db::schema::emergency_access;

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = emergency_access)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct EmergencyAccess {
    pub uuid: String,
    pub grantor_uuid: String,
    pub grantee_uuid: Option<String>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,
    pub atype: i32,  //EmergencyAccessType
    pub status: i32, //EmergencyAccessStatus
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<NaiveDateTime>,
    pub last_notification_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

/// Local methods

impl EmergencyAccess {
    pub fn new(grantor_uuid: String, email: String, status: i32, atype: i32, wait_time_days: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: crate::util::get_uuid(),
            grantor_uuid,
            grantee_uuid: None,
            email: Some(email),
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

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "Status": self.status,
            "Type": self.atype,
            "WaitTimeDays": self.wait_time_days,
            "Object": "emergencyAccess",
        })
    }

    pub async fn to_json_grantor_details(&self, conn: &DbConn) -> Value {
        let grantor_user = User::find_by_uuid(&self.grantor_uuid, conn).await.expect("Grantor user not found.");

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

    pub async fn to_json_grantee_details(&self, conn: &DbConn) -> Value {
        let grantee_user = if let Some(grantee_uuid) = self.grantee_uuid.as_deref() {
            Some(User::find_by_uuid(grantee_uuid, conn).await.expect("Grantee user not found."))
        } else if let Some(email) = self.email.as_deref() {
            Some(User::find_by_mail(email, conn).await.expect("Grantee user not found."))
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

#[derive(Copy, Clone)]
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

pub enum EmergencyAccessStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
    RecoveryInitiated = 3,
    RecoveryApproved = 4,
}

// region Database methods

impl EmergencyAccess {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn).await;
        self.updated_at = Utc::now().naive_utc();

        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(schema::emergency_access::table)
                    .values(&*self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(schema::emergency_access::table)
                            .filter(schema::emergency_access::uuid.eq(&self.uuid))
                            .set(&*self)
                            .execute(conn)
                            .map_res("Error updating emergency access")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving emergency access")
            }
            postgresql {
                diesel::insert_into(schema::emergency_access::table)
                    .values(&*self)
                    .on_conflict(schema::emergency_access::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving emergency access")
            }
        }
    }

    pub async fn update_access_status_and_save(
        &mut self,
        status: i32,
        date: &NaiveDateTime,
        conn: &DbConn,
    ) -> EmptyResult {
        // Update the grantee so that it will refresh it's status.
        User::update_uuid_revision(self.grantee_uuid.as_ref().expect("Error getting grantee"), conn).await;
        self.status = status;
        self.updated_at = date.to_owned();

        db_run! {conn: {
            crate::util::retry(|| {
                diesel::update(schema::emergency_access::table.filter(schema::emergency_access::uuid.eq(&self.uuid)))
                    .set((schema::emergency_access::status.eq(status), schema::emergency_access::updated_at.eq(date)))
                    .execute(conn)
            }, 10)
            .map_res("Error updating emergency access status")
        }}
    }

    pub async fn update_last_notification_date_and_save(&mut self, date: &NaiveDateTime, conn: &DbConn) -> EmptyResult {
        self.last_notification_at = Some(date.to_owned());
        self.updated_at = date.to_owned();

        db_run! {conn: {
            crate::util::retry(|| {
                diesel::update(schema::emergency_access::table.filter(schema::emergency_access::uuid.eq(&self.uuid)))
                    .set((schema::emergency_access::last_notification_at.eq(date), schema::emergency_access::updated_at.eq(date)))
                    .execute(conn)
            }, 10)
            .map_res("Error updating emergency access status")
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        for ea in Self::find_all_by_grantor_uuid(user_uuid, conn).await {
            ea.delete(conn).await?;
        }
        for ea in Self::find_all_by_grantee_uuid(user_uuid, conn).await {
            ea.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn).await;

        db_run! { conn: {
            diesel::delete(schema::emergency_access::table.filter(schema::emergency_access::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from emergency access")
        }}
    }

    pub async fn find_by_uuid(uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_grantor_uuid_and_grantee_uuid_or_email(
        grantor_uuid: &str,
        grantee_uuid: &str,
        email: &str,
        conn: &DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::grantor_uuid.eq(grantor_uuid))
                .filter(schema::emergency_access::grantee_uuid.eq(grantee_uuid).or(schema::emergency_access::email.eq(email)))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_all_recoveries_initiated(conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::status.eq(EmergencyAccessStatus::RecoveryInitiated as i32))
                .filter(schema::emergency_access::recovery_initiated_at.is_not_null())
                .load::<Self>(conn).expect("Error loading emergency_access")
        }}
    }

    pub async fn find_by_uuid_and_grantor_uuid(uuid: &str, grantor_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::uuid.eq(uuid))
                .filter(schema::emergency_access::grantor_uuid.eq(grantor_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_all_by_grantee_uuid(grantee_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::grantee_uuid.eq(grantee_uuid))
                .load::<Self>(conn).expect("Error loading emergency_access")
        }}
    }

    pub async fn find_invited_by_grantee_email(grantee_email: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::email.eq(grantee_email))
                .filter(schema::emergency_access::status.eq(EmergencyAccessStatus::Invited as i32))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_all_by_grantor_uuid(grantor_uuid: &str, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            schema::emergency_access::table
                .filter(schema::emergency_access::grantor_uuid.eq(grantor_uuid))
                .load::<Self>(conn).expect("Error loading emergency_access")
        }}
    }
}

// endregion
