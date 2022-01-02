use chrono::{Duration, Utc};
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value;
use std::borrow::Borrow;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcase, NumberOrString},
    auth::{decode_emergency_access_invite, Headers},
    db::{models::*, DbConn, DbPool},
    mail, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_contacts,
        get_grantees,
        get_emergency_access,
        put_emergency_access,
        delete_emergency_access,
        post_delete_emergency_access,
        send_invite,
        resend_invite,
        accept_invite,
        confirm_emergency_access,
        initiate_emergency_access,
        approve_emergency_access,
        reject_emergency_access,
        takeover_emergency_access,
        password_emergency_access,
        view_emergency_access,
        policies_emergency_access,
    ]
}

// region get

#[get("/emergency-access/trusted")]
fn get_contacts(headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantor_uuid(&headers.user.uuid, &conn);

    let emergency_access_list_json: Vec<Value> =
        emergency_access_list.iter().map(|e| e.to_json_grantee_details(&conn)).collect();

    Ok(Json(json!({
      "Data": emergency_access_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/granted")]
fn get_grantees(headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantee_uuid(&headers.user.uuid, &conn);

    let emergency_access_list_json: Vec<Value> =
        emergency_access_list.iter().map(|e| e.to_json_grantor_details(&conn)).collect();

    Ok(Json(json!({
      "Data": emergency_access_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/<emer_id>")]
fn get_emergency_access(emer_id: String, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emergency_access) => Ok(Json(emergency_access.to_json_grantee_details(&conn))),
        None => err!("Emergency access not valid."),
    }
}

// endregion

// region put/post

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessUpdateData {
    Type: NumberOrString,
    WaitTimeDays: i32,
    KeyEncrypted: Option<String>,
}

#[put("/emergency-access/<emer_id>", data = "<data>")]
fn put_emergency_access(emer_id: String, data: JsonUpcase<EmergencyAccessUpdateData>, conn: DbConn) -> JsonResult {
    post_emergency_access(emer_id, data, conn)
}

#[post("/emergency-access/<emer_id>", data = "<data>")]
fn post_emergency_access(emer_id: String, data: JsonUpcase<EmergencyAccessUpdateData>, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessUpdateData = data.into_inner().data;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emergency_access) => emergency_access,
        None => err!("Emergency access not valid."),
    };

    let new_type = match EmergencyAccessType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid emergency access type."),
    };

    emergency_access.atype = new_type;
    emergency_access.wait_time_days = data.WaitTimeDays;
    emergency_access.key_encrypted = data.KeyEncrypted;

    emergency_access.save(&conn)?;
    Ok(Json(emergency_access.to_json()))
}

// endregion

// region delete

#[delete("/emergency-access/<emer_id>")]
fn delete_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let grantor_user = headers.user;

    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => {
            if emer.grantor_uuid != grantor_user.uuid && emer.grantee_uuid != Some(grantor_user.uuid) {
                err!("Emergency access not valid.")
            }
            emer
        }
        None => err!("Emergency access not valid."),
    };
    emergency_access.delete(&conn)?;
    Ok(())
}

#[post("/emergency-access/<emer_id>/delete")]
fn post_delete_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_emergency_access(emer_id, headers, conn)
}

// endregion

// region invite

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessInviteData {
    Email: String,
    Type: NumberOrString,
    WaitTimeDays: i32,
}

#[post("/emergency-access/invite", data = "<data>")]
fn send_invite(data: JsonUpcase<EmergencyAccessInviteData>, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessInviteData = data.into_inner().data;
    let email = data.Email.to_lowercase();
    let wait_time_days = data.WaitTimeDays;

    let emergency_access_status = EmergencyAccessStatus::Invited as i32;

    let new_type = match EmergencyAccessType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid emergency access type."),
    };

    let grantor_user = headers.user;

    // avoid setting yourself as emergency contact
    if email == grantor_user.email {
        err!("You can not set yourself as an emergency contact.")
    }

    let grantee_user = match User::find_by_mail(&email, &conn) {
        None => {
            if !CONFIG.invitations_allowed() {
                err!(format!("Grantee user does not exist: {}", email))
            }

            if !CONFIG.is_email_domain_allowed(&email) {
                err!("Email domain not eligible for invitations")
            }

            if !CONFIG.mail_enabled() {
                let invitation = Invitation::new(email.clone());
                invitation.save(&conn)?;
            }

            let mut user = User::new(email.clone());
            user.save(&conn)?;
            user
        }
        Some(user) => user,
    };

    if EmergencyAccess::find_by_grantor_uuid_and_grantee_uuid_or_email(
        &grantor_user.uuid,
        &grantee_user.uuid,
        &grantee_user.email,
        &conn,
    )
    .is_some()
    {
        err!(format!("Grantee user already invited: {}", email))
    }

    let mut new_emergency_access = EmergencyAccess::new(
        grantor_user.uuid.clone(),
        Some(grantee_user.email.clone()),
        emergency_access_status,
        new_type,
        wait_time_days,
    );
    new_emergency_access.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &grantee_user.email,
            &grantee_user.uuid,
            Some(new_emergency_access.uuid),
            Some(grantor_user.name.clone()),
            Some(grantor_user.email),
        )?;
    } else {
        // Automatically mark user as accepted if no email invites
        match User::find_by_mail(&email, &conn) {
            Some(user) => {
                match accept_invite_process(user.uuid, new_emergency_access.uuid, Some(email), conn.borrow()) {
                    Ok(v) => (v),
                    Err(e) => err!(e.to_string()),
                }
            }
            None => err!("Grantee user not found."),
        }
    }

    Ok(())
}

#[post("/emergency-access/<emer_id>/reinvite")]
fn resend_invite(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.grantor_uuid != headers.user.uuid {
        err!("Emergency access not valid.");
    }

    if emergency_access.status != EmergencyAccessStatus::Invited as i32 {
        err!("The grantee user is already accepted or confirmed to the organization");
    }

    let email = match emergency_access.email.clone() {
        Some(email) => email,
        None => err!("Email not valid."),
    };

    let grantee_user = match User::find_by_mail(&email, &conn) {
        Some(user) => user,
        None => err!("Grantee user not found."),
    };

    let grantor_user = headers.user;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &email,
            &grantor_user.uuid,
            Some(emergency_access.uuid),
            Some(grantor_user.name.clone()),
            Some(grantor_user.email),
        )?;
    } else {
        if Invitation::find_by_mail(&email, &conn).is_none() {
            let invitation = Invitation::new(email);
            invitation.save(&conn)?;
        }

        // Automatically mark user as accepted if no email invites
        match accept_invite_process(grantee_user.uuid, emergency_access.uuid, emergency_access.email, conn.borrow()) {
            Ok(v) => (v),
            Err(e) => err!(e.to_string()),
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcceptData {
    Token: String,
}

#[post("/emergency-access/<emer_id>/accept", data = "<data>")]
fn accept_invite(emer_id: String, data: JsonUpcase<AcceptData>, conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: AcceptData = data.into_inner().data;
    let token = &data.Token;
    let claims = decode_emergency_access_invite(token)?;

    let grantee_user = match User::find_by_mail(&claims.email, &conn) {
        Some(user) => {
            Invitation::take(&claims.email, &conn);
            user
        }
        None => err!("Invited user not found"),
    };

    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    // get grantor user to send Accepted email
    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if (claims.emer_id.is_some() && emer_id == claims.emer_id.unwrap())
        && (claims.grantor_name.is_some() && grantor_user.name == claims.grantor_name.unwrap())
        && (claims.grantor_email.is_some() && grantor_user.email == claims.grantor_email.unwrap())
    {
        match accept_invite_process(grantee_user.uuid.clone(), emer_id, Some(grantee_user.email.clone()), &conn) {
            Ok(v) => (v),
            Err(e) => err!(e.to_string()),
        }

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_accepted(&grantor_user.email, &grantee_user.email)?;
        }

        Ok(())
    } else {
        err!("Emergency access invitation error.")
    }
}

fn accept_invite_process(grantee_uuid: String, emer_id: String, email: Option<String>, conn: &DbConn) -> EmptyResult {
    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    let emer_email = emergency_access.email;
    if emer_email.is_none() || emer_email != email {
        err!("User email does not match invite.");
    }

    if emergency_access.status == EmergencyAccessStatus::Accepted as i32 {
        err!("Emergency contact already accepted.");
    }

    emergency_access.status = EmergencyAccessStatus::Accepted as i32;
    emergency_access.grantee_uuid = Some(grantee_uuid);
    emergency_access.email = None;
    emergency_access.save(conn)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ConfirmData {
    Key: String,
}

#[post("/emergency-access/<emer_id>/confirm", data = "<data>")]
fn confirm_emergency_access(
    emer_id: String,
    data: JsonUpcase<ConfirmData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    check_emergency_access_allowed()?;

    let confirming_user = headers.user;
    let data: ConfirmData = data.into_inner().data;
    let key = data.Key;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Accepted as i32
        || emergency_access.grantor_uuid != confirming_user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&confirming_user.uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed as i32;
        emergency_access.key_encrypted = Some(key);
        emergency_access.email = None;

        emergency_access.save(&conn)?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_confirmed(&grantee_user.email, &grantor_user.name)?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

// endregion

// region access emergency access

#[post("/emergency-access/<emer_id>/initiate")]
fn initiate_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let initiating_user = headers.user;
    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Confirmed as i32
        || emergency_access.grantee_uuid != Some(initiating_user.uuid.clone())
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let now = Utc::now().naive_utc();
    emergency_access.status = EmergencyAccessStatus::RecoveryInitiated as i32;
    emergency_access.updated_at = now;
    emergency_access.recovery_initiated_at = Some(now);
    emergency_access.last_notification_at = Some(now);
    emergency_access.save(&conn)?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_recovery_initiated(
            &grantor_user.email,
            &initiating_user.name,
            emergency_access.get_type_as_str(),
            &emergency_access.wait_time_days.clone().to_string(),
        )?;
    }
    Ok(Json(emergency_access.to_json()))
}

#[post("/emergency-access/<emer_id>/approve")]
fn approve_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let approving_user = headers.user;
    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32
        || emergency_access.grantor_uuid != approving_user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&approving_user.uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::RecoveryApproved as i32;
        emergency_access.save(&conn)?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name)?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

#[post("/emergency-access/<emer_id>/reject")]
fn reject_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let rejecting_user = headers.user;
    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if (emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32
        && emergency_access.status != EmergencyAccessStatus::RecoveryApproved as i32)
        || emergency_access.grantor_uuid != rejecting_user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&rejecting_user.uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &conn) {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed as i32;
        emergency_access.save(&conn)?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_rejected(&grantee_user.email, &grantor_user.name)?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

// endregion

// region action

#[post("/emergency-access/<emer_id>/view")]
fn view_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let requesting_user = headers.user;
    let host = headers.host;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::View) {
        err!("Emergency access not valid.")
    }

    let ciphers = Cipher::find_owned_by_user(&emergency_access.grantor_uuid, &conn);

    let ciphers_json: Vec<Value> =
        ciphers.iter().map(|c| c.to_json(&host, &emergency_access.grantor_uuid, &conn)).collect();

    Ok(Json(json!({
      "Ciphers": ciphers_json,
      "KeyEncrypted": &emergency_access.key_encrypted,
      "Object": "emergencyAccessView",
    })))
}

#[post("/emergency-access/<emer_id>/takeover")]
fn takeover_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    Ok(Json(json!({
      "Kdf": grantor_user.client_kdf_type,
      "KdfIterations": grantor_user.client_kdf_iter,
      "KeyEncrypted": &emergency_access.key_encrypted,
      "Object": "emergencyAccessTakeover",
    })))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EmergencyAccessPasswordData {
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/emergency-access/<emer_id>/password", data = "<data>")]
fn password_emergency_access(
    emer_id: String,
    data: JsonUpcase<EmergencyAccessPasswordData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessPasswordData = data.into_inner().data;
    let new_master_password_hash = &data.NewMasterPasswordHash;
    let key = data.Key;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let mut grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    // change grantor_user password
    grantor_user.set_password(new_master_password_hash, None);
    grantor_user.akey = key;
    grantor_user.save(&conn)?;

    // Disable TwoFactor providers since they will otherwise block logins
    TwoFactor::delete_all_by_user(&grantor_user.uuid, &conn)?;

    // Removing owner, check that there are at least another owner
    let user_org_grantor = UserOrganization::find_any_state_by_user(&grantor_user.uuid, &conn);

    // Remove grantor from all organisations unless Owner
    for user_org in user_org_grantor {
        if user_org.atype != UserOrgType::Owner as i32 {
            user_org.delete(&conn)?;
        }
    }
    Ok(())
}

// endregion

#[get("/emergency-access/<emer_id>/policies")]
fn policies_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> JsonResult {
    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &conn) {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &conn) {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let policies = OrgPolicy::find_confirmed_by_user(&grantor_user.uuid, &conn);
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

fn is_valid_request(
    emergency_access: &EmergencyAccess,
    requesting_user_uuid: String,
    requested_access_type: EmergencyAccessType,
) -> bool {
    emergency_access.grantee_uuid == Some(requesting_user_uuid)
        && emergency_access.status == EmergencyAccessStatus::RecoveryApproved as i32
        && emergency_access.atype == requested_access_type as i32
}

fn check_emergency_access_allowed() -> EmptyResult {
    if !CONFIG.emergency_access_allowed() {
        err!("Emergency access is not allowed.")
    }
    Ok(())
}

pub fn emergency_request_timeout_job(pool: DbPool) {
    debug!("Start emergency_request_timeout_job");
    if !CONFIG.emergency_access_allowed() {
        return;
    }

    if let Ok(conn) = pool.get() {
        let emergency_access_list = EmergencyAccess::find_all_recoveries(&conn);

        if emergency_access_list.is_empty() {
            debug!("No emergency request timeout to approve");
        }

        for mut emer in emergency_access_list {
            if emer.recovery_initiated_at.is_some()
                && Utc::now().naive_utc()
                    >= emer.recovery_initiated_at.unwrap() + Duration::days(emer.wait_time_days as i64)
            {
                emer.status = EmergencyAccessStatus::RecoveryApproved as i32;
                emer.save(&conn).expect("Cannot save emergency access on job");

                if CONFIG.mail_enabled() {
                    // get grantor user to send Accepted email
                    let grantor_user = User::find_by_uuid(&emer.grantor_uuid, &conn).expect("Grantor user not found.");

                    // get grantee user to send Accepted email
                    let grantee_user =
                        User::find_by_uuid(&emer.grantee_uuid.clone().expect("Grantee user invalid."), &conn)
                            .expect("Grantee user not found.");

                    mail::send_emergency_access_recovery_timed_out(
                        &grantor_user.email,
                        &grantee_user.name.clone(),
                        emer.get_type_as_str(),
                    )
                    .expect("Error on sending email");

                    mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name.clone())
                        .expect("Error on sending email");
                }
            }
        }
    } else {
        error!("Failed to get DB connection while searching emergency request timed out")
    }
}

pub fn emergency_notification_reminder_job(pool: DbPool) {
    debug!("Start emergency_notification_reminder_job");
    if !CONFIG.emergency_access_allowed() {
        return;
    }

    if let Ok(conn) = pool.get() {
        let emergency_access_list = EmergencyAccess::find_all_recoveries(&conn);

        if emergency_access_list.is_empty() {
            debug!("No emergency request reminder notification to send");
        }

        for mut emer in emergency_access_list {
            if (emer.recovery_initiated_at.is_some()
                && Utc::now().naive_utc()
                    >= emer.recovery_initiated_at.unwrap() + Duration::days((emer.wait_time_days as i64) - 1))
                && (emer.last_notification_at.is_none()
                    || (emer.last_notification_at.is_some()
                        && Utc::now().naive_utc() >= emer.last_notification_at.unwrap() + Duration::days(1)))
            {
                emer.save(&conn).expect("Cannot save emergency access on job");

                if CONFIG.mail_enabled() {
                    // get grantor user to send Accepted email
                    let grantor_user = User::find_by_uuid(&emer.grantor_uuid, &conn).expect("Grantor user not found.");

                    // get grantee user to send Accepted email
                    let grantee_user =
                        User::find_by_uuid(&emer.grantee_uuid.clone().expect("Grantee user invalid."), &conn)
                            .expect("Grantee user not found.");

                    mail::send_emergency_access_recovery_reminder(
                        &grantor_user.email,
                        &grantee_user.name.clone(),
                        emer.get_type_as_str(),
                        &emer.wait_time_days.to_string(), // TODO(jjlin): This should be the number of days left.
                    )
                    .expect("Error on sending email");
                }
            }
        }
    } else {
        error!("Failed to get DB connection while searching emergency notification reminder")
    }
}
