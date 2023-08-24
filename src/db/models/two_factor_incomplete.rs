use chrono::{NaiveDateTime, Utc};

use crate::db::schema::twofactor_incomplete;
use crate::{api::EmptyResult, auth::ClientIp, db::DbConn, error::MapResult, CONFIG};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = twofactor_incomplete)]
#[diesel(primary_key(user_uuid, device_uuid))]
pub struct TwoFactorIncomplete {
    pub user_uuid: String,
    // This device UUID is simply what's claimed by the device. It doesn't
    // necessarily correspond to any UUID in the devices table, since a device
    // must complete 2FA login before being added into the devices table.
    pub device_uuid: String,
    pub device_name: String,
    pub login_time: NaiveDateTime,
    pub ip_address: String,
}

impl TwoFactorIncomplete {
    pub async fn mark_incomplete(
        user_uuid: &str,
        device_uuid: &str,
        device_name: &str,
        ip: &ClientIp,
        conn: &DbConn,
    ) -> EmptyResult {
        if CONFIG.incomplete_2fa_time_limit() <= 0 || !CONFIG.mail_enabled() {
            return Ok(());
        }

        // Don't update the data for an existing user/device pair, since that
        // would allow an attacker to arbitrarily delay notifications by
        // sending repeated 2FA attempts to reset the timer.
        let existing = Self::find_by_user_and_device(user_uuid, device_uuid, conn).await;
        if existing.is_some() {
            return Ok(());
        }

        db_run! { conn: {
            diesel::insert_into(twofactor_incomplete::table)
                .values((
                    twofactor_incomplete::user_uuid.eq(user_uuid),
                    twofactor_incomplete::device_uuid.eq(device_uuid),
                    twofactor_incomplete::device_name.eq(device_name),
                    twofactor_incomplete::login_time.eq(Utc::now().naive_utc()),
                    twofactor_incomplete::ip_address.eq(ip.ip.to_string()),
                ))
                .execute(conn)
                .map_res("Error adding twofactor_incomplete record")
        }}
    }

    pub async fn mark_complete(user_uuid: &str, device_uuid: &str, conn: &DbConn) -> EmptyResult {
        if CONFIG.incomplete_2fa_time_limit() <= 0 || !CONFIG.mail_enabled() {
            return Ok(());
        }

        Self::delete_by_user_and_device(user_uuid, device_uuid, conn).await
    }

    pub async fn find_by_user_and_device(user_uuid: &str, device_uuid: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            twofactor_incomplete::table
                .filter(twofactor_incomplete::user_uuid.eq(user_uuid))
                .filter(twofactor_incomplete::device_uuid.eq(device_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_logins_before(dt: &NaiveDateTime, conn: &DbConn) -> Vec<Self> {
        db_run! {conn: {
            twofactor_incomplete::table
                .filter(twofactor_incomplete::login_time.lt(dt))
                .load::<Self>(conn)
                .expect("Error loading twofactor_incomplete")
        }}
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        Self::delete_by_user_and_device(&self.user_uuid, &self.device_uuid, conn).await
    }

    pub async fn delete_by_user_and_device(user_uuid: &str, device_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor_incomplete::table
                           .filter(twofactor_incomplete::user_uuid.eq(user_uuid))
                           .filter(twofactor_incomplete::device_uuid.eq(device_uuid)))
                .execute(conn)
                .map_res("Error in twofactor_incomplete::delete_by_user_and_device()")
        }}
    }

    pub async fn delete_all_by_user(user_uuid: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(twofactor_incomplete::table.filter(twofactor_incomplete::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error in twofactor_incomplete::delete_all_by_user()")
        }}
    }
}
