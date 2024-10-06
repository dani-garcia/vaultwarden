use chrono::{NaiveDateTime, Utc};
use serde_json::Value;

use crate::{api::EmptyResult, db::DbConn, error::MapResult};

use super::User;

db_object! {
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
        pub atype: i32, //EmergencyAccessType
        pub status: i32, //EmergencyAccessStatus
        pub wait_time_days: i32,
        pub recovery_initiated_at: Option<NaiveDateTime>,
        pub last_notification_at: Option<NaiveDateTime>,
        pub updated_at: NaiveDateTime,
        pub created_at: NaiveDateTime,
    }
}

// Local methods

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
            "id": self.uuid,
            "status": self.status,
            "type": self.atype,
            "waitTimeDays": self.wait_time_days,
            "object": "emergencyAccess",
        })
    }

    pub async fn to_json_grantor_details(&self, conn: &mut DbConn) -> Value {
        let grantor_user = User::find_by_uuid(&self.grantor_uuid, conn).await.expect("Grantor user not found.");

        json!({
            "id": self.uuid,
            "status": self.status,
            "type": self.atype,
            "waitTimeDays": self.wait_time_days,
            "grantorId": grantor_user.uuid,
            "email": grantor_user.email,
            "name": grantor_user.name,
            "object": "emergencyAccessGrantorDetails",
        })
    }

    pub async fn to_json_grantee_details(&self, conn: &mut DbConn) -> Option<Value> {
        let grantee_user = if let Some(grantee_uuid) = self.grantee_uuid.as_deref() {
            User::find_by_uuid(grantee_uuid, conn).await.expect("Grantee user not found.")
        } else if let Some(email) = self.email.as_deref() {
            match User::find_by_mail(email, conn).await {
                Some(user) => user,
                None => {
                    // remove outstanding invitations which should not exist
                    Self::delete_all_by_grantee_email(email, conn).await.ok();
                    return None;
                }
            }
        } else {
            return None;
        };

        Some(json!({
            "id": self.uuid,
            "status": self.status,
            "type": self.atype,
            "waitTimeDays": self.wait_time_days,
            "granteeId": grantee_user.uuid,
            "email": grantee_user.email,
            "name": grantee_user.name,
            "object": "emergencyAccessGranteeDetails",
        }))
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
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn).await;
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

    pub async fn update_access_status_and_save(
        &mut self,
        status: i32,
        date: &NaiveDateTime,
        conn: &mut DbConn,
    ) -> EmptyResult {
        // Update the grantee so that it will refresh it's status.
        User::update_uuid_revision(self.grantee_uuid.as_ref().expect("Error getting grantee"), conn).await;
        self.status = status;
        date.clone_into(&mut self.updated_at);

        db_run! {conn: {
            crate::util::retry(|| {
                diesel::update(emergency_access::table.filter(emergency_access::uuid.eq(&self.uuid)))
                    .set((emergency_access::status.eq(status), emergency_access::updated_at.eq(date)))
                    .execute(conn)
            }, 10)
            .map_res("Error updating emergency access status")
        }}
    }

    pub async fn update_last_notification_date_and_save(
        &mut self,
        date: &NaiveDateTime,
        conn: &mut DbConn,
    ) -> EmptyResult {
        self.last_notification_at = Some(date.to_owned());
        date.clone_into(&mut self.updated_at);

        db_run! {conn: {
            crate::util::retry(|| {
                diesel::update(emergency_access::table.filter(emergency_access::uuid.eq(&self.uuid)))
                    .set((emergency_access::last_notification_at.eq(date), emergency_access::updated_at.eq(date)))
                    .execute(conn)
            }, 10)
            .map_res("Error updating emergency access status")
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &mut DbConn) -> EmptyResult {
        for ea in Self::find_all_by_grantor_uuid(user_uuid, conn).await {
            ea.delete(conn).await?;
        }
        for ea in Self::find_all_by_grantee_uuid(user_uuid, conn).await {
            ea.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete_all_by_grantee_email(grantee_email: &str, conn: &mut DbConn) -> EmptyResult {
        for ea in Self::find_all_invited_by_grantee_email(grantee_email, conn).await {
            ea.delete(conn).await?;
        }
        Ok(())
    }

    pub async fn delete(self, conn: &mut DbConn) -> EmptyResult {
        User::update_uuid_revision(&self.grantor_uuid, conn).await;

        db_run! { conn: {
            diesel::delete(emergency_access::table.filter(emergency_access::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error removing user from emergency access")
        }}
    }

    pub async fn find_by_grantor_uuid_and_grantee_uuid_or_email(
        grantor_uuid: &str,
        grantee_uuid: &str,
        email: &str,
        conn: &mut DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .filter(emergency_access::grantee_uuid.eq(grantee_uuid).or(emergency_access::email.eq(email)))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_all_recoveries_initiated(conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::status.eq(EmergencyAccessStatus::RecoveryInitiated as i32))
                .filter(emergency_access::recovery_initiated_at.is_not_null())
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub async fn find_by_uuid_and_grantor_uuid(uuid: &str, grantor_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::uuid.eq(uuid))
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_uuid_and_grantee_uuid(uuid: &str, grantee_uuid: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::uuid.eq(uuid))
                .filter(emergency_access::grantee_uuid.eq(grantee_uuid))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_by_uuid_and_grantee_email(uuid: &str, grantee_email: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::uuid.eq(uuid))
                .filter(emergency_access::email.eq(grantee_email))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_all_by_grantee_uuid(grantee_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantee_uuid.eq(grantee_uuid))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub async fn find_invited_by_grantee_email(grantee_email: &str, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::email.eq(grantee_email))
                .filter(emergency_access::status.eq(EmergencyAccessStatus::Invited as i32))
                .first::<EmergencyAccessDb>(conn)
                .ok().from_db()
        }}
    }

    pub async fn find_all_invited_by_grantee_email(grantee_email: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::email.eq(grantee_email))
                .filter(emergency_access::status.eq(EmergencyAccessStatus::Invited as i32))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub async fn find_all_by_grantor_uuid(grantor_uuid: &str, conn: &mut DbConn) -> Vec<Self> {
        db_run! { conn: {
            emergency_access::table
                .filter(emergency_access::grantor_uuid.eq(grantor_uuid))
                .load::<EmergencyAccessDb>(conn).expect("Error loading emergency_access").from_db()
        }}
    }

    pub async fn accept_invite(&mut self, grantee_uuid: &str, grantee_email: &str, conn: &mut DbConn) -> EmptyResult {
        if self.email.is_none() || self.email.as_ref().unwrap() != grantee_email {
            err!("User email does not match invite.");
        }

        if self.status == EmergencyAccessStatus::Accepted as i32 {
            err!("Emergency contact already accepted.");
        }

        self.status = EmergencyAccessStatus::Accepted as i32;
        self.grantee_uuid = Some(String::from(grantee_uuid));
        self.email = None;
        self.save(conn).await
    }
}

// endregion
