use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    crypto::ct_eq,
    db::{DbConn, schema::auth_requests},
    error::MapResult,
    util::format_date,
};
use macros::UuidFromParam;

use super::{DeviceId, DeviceType, MembershipId, OrganizationId, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Deserialize, Serialize)]
#[diesel(table_name = auth_requests)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct AuthRequest {
    pub uuid: AuthRequestId,
    pub user_uuid: UserId,
    pub organization_uuid: Option<OrganizationId>,
    /// See `AuthRequestType`. Decides who may answer the request and how long it stays open.
    pub atype: i32,

    pub request_device_identifier: DeviceId,
    pub device_type: i32, // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Enums/DeviceType.cs

    pub request_ip: String,
    pub response_device_id: Option<DeviceId>,

    pub access_code: String,
    pub public_key: String,

    pub enc_key: Option<String>,

    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub creation_date: NaiveDateTime,
    pub response_date: Option<NaiveDateTime>,

    pub authentication_date: Option<NaiveDateTime>,
}

/// https://github.com/bitwarden/server/blob/main/src/Core/Auth/Enums/AuthRequestType.cs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRequestType {
    /// A new session asking one of the user's own devices to let it in.
    AuthenticateAndUnlock = 0,
    /// An existing session asking one of the user's own devices to unlock it.
    Unlock = 1,
    /// The user asking an administrator of their organization to let a device in, for when no
    /// device of their own is around to ask.
    AdminApproval = 2,
}

impl AuthRequestType {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(AuthRequestType::AuthenticateAndUnlock),
            1 => Some(AuthRequestType::Unlock),
            2 => Some(AuthRequestType::AdminApproval),
            _ => None,
        }
    }
}

impl AuthRequest {
    /// A request between the user's own devices is short lived, an administrator gets a week to
    /// answer, and their answer stays usable for half a day. Same windows as upstream.
    /// https://github.com/bitwarden/server/blob/main/src/Core/Settings/GlobalSettings.cs
    pub fn user_request_expiration() -> TimeDelta {
        TimeDelta::try_minutes(15).unwrap()
    }

    pub fn admin_request_expiration() -> TimeDelta {
        TimeDelta::try_days(7).unwrap()
    }

    pub fn after_admin_approval_expiration() -> TimeDelta {
        TimeDelta::try_hours(12).unwrap()
    }

    #[expect(clippy::too_many_arguments, reason = "Every field of the request is supplied by the caller")]
    pub fn new(
        user_uuid: UserId,
        organization_uuid: Option<OrganizationId>,
        atype: AuthRequestType,
        request_device_identifier: DeviceId,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
    ) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: AuthRequestId(crate::util::get_uuid()),
            user_uuid,
            organization_uuid,
            atype: atype as i32,

            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: now,
            response_date: None,
            authentication_date: None,
        }
    }

    pub fn is_admin_approval(&self) -> bool {
        self.atype == AuthRequestType::AdminApproval as i32
    }

    pub fn is_expired(&self) -> bool {
        let now = Utc::now().naive_utc();

        if self.is_admin_approval() {
            // Once approved the clock restarts, so the user has time to come back and use it.
            if let (Some(true), Some(response_date)) = (self.approved, self.response_date) {
                return now > response_date + Self::after_admin_approval_expiration();
            }
            return now > self.creation_date + Self::admin_request_expiration();
        }

        now > self.creation_date + Self::user_request_expiration()
    }

    pub fn to_json_for_pending_device(&self) -> Value {
        json!({
            "id": self.uuid,
            "creationDate": format_date(&self.creation_date),
        })
    }

    /// What an administrator gets to see about a request waiting for them: the public key of the asking
    /// device and enough about it to recognise it. Same shape as
    /// `PendingOrganizationAuthRequestResponseModel` upstream.
    ///
    /// Deliberately no access code, which is the asking device's own proof, and no wrapped key: a waiting
    /// request has none, and handing one out here would be crypto material the answering side cannot use.
    pub fn to_json_for_organization(&self, email: &str, member_id: &MembershipId) -> Value {
        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "organizationUserId": member_id,
            "email": email,
            "publicKey": self.public_key,
            "requestDeviceIdentifier": self.request_device_identifier,
            "requestDeviceType": DeviceType::from_i32(self.device_type).to_string(),
            "requestIpAddress": self.request_ip,
            // Not recorded here, but the clients read it, so it is answered rather than missing.
            "requestCountryName": null,
            "creationDate": format_date(&self.creation_date),
            "object": "pending-org-auth-request",
        })
    }
}

impl AuthRequest {
    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(auth_requests::table)
                    .values(&*self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(auth_requests::table)
                            .filter(auth_requests::uuid.eq(&self.uuid))
                            .set(&*self)
                            .execute(conn)
                            .map_res("Error auth_request")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error auth_request")
            }
            postgresql {
                diesel::insert_into(auth_requests::table)
                    .values(&*self)
                    .on_conflict(auth_requests::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving auth_request")
            }
        }
    }

    pub async fn find_by_uuid(uuid: &AuthRequestId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| auth_requests::table.filter(auth_requests::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_uuid_and_user(uuid: &AuthRequestId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    /// The request a device is currently waiting on, if it is still open and within its window.
    ///
    /// Only the types a device answers for itself. A request addressed to an administrator is answered
    /// through the organization and stays open for a week, so counting it here would let it shadow the
    /// short lived request the user is actually being shown.
    /// https://github.com/bitwarden/server/blob/main/src/Infrastructure.EntityFramework/Auth/Repositories/Queries/DeviceWithPendingAuthByUserIdQuery.cs
    pub async fn find_by_user_and_requested_device(
        user_uuid: &UserId,
        device_uuid: &DeviceId,
        conn: &DbConn,
    ) -> Option<Self> {
        let oldest = Utc::now().naive_utc() - Self::user_request_expiration();

        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .filter(auth_requests::request_device_identifier.eq(device_uuid))
                .filter(auth_requests::atype.ne(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::approved.is_null())
                .filter(auth_requests::creation_date.gt(oldest))
                .order_by(auth_requests::creation_date.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// The open request a device already has waiting at this organization, if any.
    ///
    /// Asking again from the same device updates that one instead of adding another, so a retrying client
    /// cannot fill the table or mail the administrators over and over. A request past its window does not
    /// count: nobody can answer it any more, and reviving it by moving its date forward would leave the
    /// user waiting on a request the administrators were never told about. Asking again is a new request.
    pub async fn find_pending_admin_approval(
        user_uuid: &UserId,
        device_uuid: &DeviceId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        let oldest = Utc::now().naive_utc() - Self::admin_request_expiration();

        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .filter(auth_requests::request_device_identifier.eq(device_uuid))
                .filter(auth_requests::organization_uuid.eq(org_uuid))
                .filter(auth_requests::atype.eq(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::approved.is_null())
                .filter(auth_requests::creation_date.gt(oldest))
                .order_by(auth_requests::creation_date.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    /// Everything an administrator of this organization still has to answer.
    pub async fn find_pending_admin_approval_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::organization_uuid.eq(org_uuid))
                .filter(auth_requests::atype.eq(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::approved.is_null())
                .order_by(auth_requests::creation_date.desc())
                .load::<Self>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    /// Bound to the organization on purpose: an administrator may only ever reach a request that
    /// was addressed to their own organization.
    pub async fn find_admin_approval_by_org_and_uuid(
        uuid: &AuthRequestId,
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Option<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::organization_uuid.eq(org_uuid))
                .filter(auth_requests::atype.eq(AuthRequestType::AdminApproval as i32))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(auth_requests::table.filter(auth_requests::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting auth request")
        })
        .await
    }

    pub fn check_access_code(&self, access_code: &str) -> bool {
        ct_eq(&self.access_code, access_code)
    }

    /// Drops everything past its window, which is a different one per type. One statement per case rather
    /// than reading the table and deleting row by row, so the work stays in the database.
    /// https://github.com/bitwarden/server/blob/f8ee2270409f7a13125cd414c450740af605a175/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_DeleteIfExpired.sql
    pub async fn purge_expired_auth_requests(conn: &DbConn) {
        let now = Utc::now().naive_utc();
        let admin = AuthRequestType::AdminApproval as i32;

        let between_devices = now - Self::user_request_expiration();
        let for_an_admin = now - Self::admin_request_expiration();
        let after_approval = now - Self::after_admin_approval_expiration();

        let result = conn
            .run(move |conn| -> EmptyResult {
                // Between the user's own devices: 15 minutes from the moment it was asked.
                let _: () = diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.ne(admin))
                        .filter(auth_requests::creation_date.lt(between_devices)),
                )
                .execute(conn)
                .map_res("Error purging the expired auth requests")?;

                // Approved by an administrator: half a day from the answer, so the user has time to
                // come back and use it.
                let _: () = diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.eq(admin))
                        .filter(auth_requests::approved.eq(true))
                        .filter(auth_requests::response_date.lt(after_approval)),
                )
                .execute(conn)
                .map_res("Error purging the approved auth requests")?;

                // Waiting for an administrator, or refused by one: a week from the moment it was
                // asked either way, a refusal does not extend anything.
                diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.eq(admin))
                        .filter(auth_requests::approved.is_null().or(auth_requests::approved.eq(false)))
                        .filter(auth_requests::creation_date.lt(for_an_admin)),
                )
                .execute(conn)
                .map_res("Error purging the unanswered auth requests")
            })
            .await;

        if let Err(e) = result {
            error!("Error purging the expired auth requests: {e:#?}");
        }
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
pub struct AuthRequestId(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(atype: AuthRequestType, age: TimeDelta) -> AuthRequest {
        let mut auth_request = AuthRequest::new(
            String::from("user").into(),
            None,
            atype,
            String::from("device").into(),
            9,
            String::from("127.0.0.1"),
            String::from("code"),
            String::from("2.public"),
        );
        auth_request.creation_date = Utc::now().naive_utc() - age;
        auth_request
    }

    #[test]
    fn each_request_type_expires_after_its_own_window() {
        assert!(!request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(14).unwrap()).is_expired());
        assert!(request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(16).unwrap()).is_expired());
        assert!(request(AuthRequestType::Unlock, TimeDelta::try_minutes(16).unwrap()).is_expired());

        assert!(!request(AuthRequestType::AdminApproval, TimeDelta::try_days(6).unwrap()).is_expired());
        assert!(request(AuthRequestType::AdminApproval, TimeDelta::try_days(8).unwrap()).is_expired());
    }

    #[test]
    fn a_request_nobody_answered_in_time_is_not_still_pending() {
        // See `find_pending_admin_approval`: a request past its window must not come back, reviving
        // it would leave the user waiting on something the administrators were never told about.
        let mut auth_request =
            request(AuthRequestType::AdminApproval, AuthRequest::admin_request_expiration() + TimeDelta::seconds(1));
        assert_eq!(auth_request.approved, None, "still unanswered");
        assert!(auth_request.is_expired());

        // One minute short of the window is still the same request, and asking again updates it
        // rather than mailing everyone a second time.
        auth_request.creation_date =
            Utc::now().naive_utc() - AuthRequest::admin_request_expiration() + TimeDelta::minutes(1);
        assert!(!auth_request.is_expired());
    }

    #[test]
    fn the_answer_of_an_administrator_starts_its_own_clock() {
        // Answered right at the end of the week, so the request itself is long past its window.
        let mut auth_request = request(AuthRequestType::AdminApproval, TimeDelta::try_days(7).unwrap());
        auth_request.approved = Some(true);

        auth_request.response_date = Some(Utc::now().naive_utc() - TimeDelta::try_hours(11).unwrap());
        assert!(!auth_request.is_expired(), "the user still has time to come back and use it");

        auth_request.response_date = Some(Utc::now().naive_utc() - TimeDelta::try_hours(13).unwrap());
        assert!(auth_request.is_expired());

        // A refusal does not extend anything, the request stays dead after its own window.
        auth_request.approved = Some(false);
        auth_request.response_date = Some(Utc::now().naive_utc());
        assert!(auth_request.is_expired());
    }

    #[test]
    fn only_the_admin_approval_type_is_answered_by_an_organization() {
        assert!(request(AuthRequestType::AdminApproval, TimeDelta::zero()).is_admin_approval());
        assert!(!request(AuthRequestType::Unlock, TimeDelta::zero()).is_admin_approval());
        assert!(!request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::zero()).is_admin_approval());

        assert_eq!(AuthRequestType::from_i32(0), Some(AuthRequestType::AuthenticateAndUnlock));
        assert_eq!(AuthRequestType::from_i32(1), Some(AuthRequestType::Unlock));
        assert_eq!(AuthRequestType::from_i32(2), Some(AuthRequestType::AdminApproval));
        assert_eq!(AuthRequestType::from_i32(3), None);
        assert_eq!(AuthRequestType::from_i32(-1), None);
    }
}
