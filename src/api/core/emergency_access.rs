use chrono::{Duration, Utc};
use rocket::{serde::json::Json, Route};
use serde_json::Value;

use crate::{
    api::{
        core::{CipherSyncData, CipherSyncType},
        EmptyResult, JsonResult, JsonUpcase, NumberOrString,
    },
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
async fn get_contacts(headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantor_uuid(&headers.user.uuid, &mut conn).await;
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        emergency_access_list_json.push(ea.to_json_grantee_details(&mut conn).await);
    }

    Ok(Json(json!({
      "Data": emergency_access_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/granted")]
async fn get_grantees(headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantee_uuid(&headers.user.uuid, &mut conn).await;
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        emergency_access_list_json.push(ea.to_json_grantor_details(&mut conn).await);
    }

    Ok(Json(json!({
      "Data": emergency_access_list_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

#[get("/emergency-access/<emer_id>")]
async fn get_emergency_access(emer_id: String, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emergency_access) => Ok(Json(emergency_access.to_json_grantee_details(&mut conn).await)),
        None => err!("Emergency access not valid."),
    }
}

// endregion

// region put/post

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EmergencyAccessUpdateData {
    Type: NumberOrString,
    WaitTimeDays: i32,
    KeyEncrypted: Option<String>,
}

#[put("/emergency-access/<emer_id>", data = "<data>")]
async fn put_emergency_access(
    emer_id: String,
    data: JsonUpcase<EmergencyAccessUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_emergency_access(emer_id, data, conn).await
}

#[post("/emergency-access/<emer_id>", data = "<data>")]
async fn post_emergency_access(
    emer_id: String,
    data: JsonUpcase<EmergencyAccessUpdateData>,
    mut conn: DbConn,
) -> JsonResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessUpdateData = data.into_inner().data;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
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

    emergency_access.save(&mut conn).await?;
    Ok(Json(emergency_access.to_json()))
}

// endregion

// region delete

#[delete("/emergency-access/<emer_id>")]
async fn delete_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let grantor_user = headers.user;

    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => {
            if emer.grantor_uuid != grantor_user.uuid && emer.grantee_uuid != Some(grantor_user.uuid) {
                err!("Emergency access not valid.")
            }
            emer
        }
        None => err!("Emergency access not valid."),
    };
    emergency_access.delete(&mut conn).await?;
    Ok(())
}

#[post("/emergency-access/<emer_id>/delete")]
async fn post_delete_emergency_access(emer_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_emergency_access(emer_id, headers, conn).await
}

// endregion

// region invite

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EmergencyAccessInviteData {
    Email: String,
    Type: NumberOrString,
    WaitTimeDays: i32,
}

#[post("/emergency-access/invite", data = "<data>")]
async fn send_invite(data: JsonUpcase<EmergencyAccessInviteData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
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

    let grantee_user = match User::find_by_mail(&email, &mut conn).await {
        None => {
            if !CONFIG.invitations_allowed() {
                err!(format!("Grantee user does not exist: {}", &email))
            }

            if !CONFIG.is_email_domain_allowed(&email) {
                err!("Email domain not eligible for invitations")
            }

            if !CONFIG.mail_enabled() {
                let invitation = Invitation::new(&email);
                invitation.save(&mut conn).await?;
            }

            let mut user = User::new(email.clone());
            user.save(&mut conn).await?;
            user
        }
        Some(user) => user,
    };

    if EmergencyAccess::find_by_grantor_uuid_and_grantee_uuid_or_email(
        &grantor_user.uuid,
        &grantee_user.uuid,
        &grantee_user.email,
        &mut conn,
    )
    .await
    .is_some()
    {
        err!(format!("Grantee user already invited: {}", &grantee_user.email))
    }

    let mut new_emergency_access =
        EmergencyAccess::new(grantor_user.uuid, grantee_user.email, emergency_access_status, new_type, wait_time_days);
    new_emergency_access.save(&mut conn).await?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &new_emergency_access.email.expect("Grantee email does not exists"),
            &grantee_user.uuid,
            &new_emergency_access.uuid,
            &grantor_user.name,
            &grantor_user.email,
        )
        .await?;
    } else {
        // Automatically mark user as accepted if no email invites
        match User::find_by_mail(&email, &mut conn).await {
            Some(user) => match accept_invite_process(user.uuid, &mut new_emergency_access, &email, &mut conn).await {
                Ok(v) => v,
                Err(e) => err!(e.to_string()),
            },
            None => err!("Grantee user not found."),
        }
    }

    Ok(())
}

#[post("/emergency-access/<emer_id>/reinvite")]
async fn resend_invite(emer_id: String, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_allowed()?;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
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

    let grantee_user = match User::find_by_mail(&email, &mut conn).await {
        Some(user) => user,
        None => err!("Grantee user not found."),
    };

    let grantor_user = headers.user;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &email,
            &grantor_user.uuid,
            &emergency_access.uuid,
            &grantor_user.name,
            &grantor_user.email,
        )
        .await?;
    } else {
        if Invitation::find_by_mail(&email, &mut conn).await.is_none() {
            let invitation = Invitation::new(&email);
            invitation.save(&mut conn).await?;
        }

        // Automatically mark user as accepted if no email invites
        match accept_invite_process(grantee_user.uuid, &mut emergency_access, &email, &mut conn).await {
            Ok(v) => v,
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
async fn accept_invite(
    emer_id: String,
    data: JsonUpcase<AcceptData>,
    headers: Headers,
    mut conn: DbConn,
) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: AcceptData = data.into_inner().data;
    let token = &data.Token;
    let claims = decode_emergency_access_invite(token)?;

    // This can happen if the user who received the invite used a different email to signup.
    // Since we do not know if this is intented, we error out here and do nothing with the invite.
    if claims.email != headers.user.email {
        err!("Claim email does not match current users email")
    }

    let grantee_user = match User::find_by_mail(&claims.email, &mut conn).await {
        Some(user) => {
            Invitation::take(&claims.email, &mut conn).await;
            user
        }
        None => err!("Invited user not found"),
    };

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    // get grantor user to send Accepted email
    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if emer_id == claims.emer_id
        && grantor_user.name == claims.grantor_name
        && grantor_user.email == claims.grantor_email
    {
        match accept_invite_process(grantee_user.uuid, &mut emergency_access, &grantee_user.email, &mut conn).await {
            Ok(v) => v,
            Err(e) => err!(e.to_string()),
        }

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_accepted(&grantor_user.email, &grantee_user.email).await?;
        }

        Ok(())
    } else {
        err!("Emergency access invitation error.")
    }
}

async fn accept_invite_process(
    grantee_uuid: String,
    emergency_access: &mut EmergencyAccess,
    grantee_email: &str,
    conn: &mut DbConn,
) -> EmptyResult {
    if emergency_access.email.is_none() || emergency_access.email.as_ref().unwrap() != grantee_email {
        err!("User email does not match invite.");
    }

    if emergency_access.status == EmergencyAccessStatus::Accepted as i32 {
        err!("Emergency contact already accepted.");
    }

    emergency_access.status = EmergencyAccessStatus::Accepted as i32;
    emergency_access.grantee_uuid = Some(grantee_uuid);
    emergency_access.email = None;
    emergency_access.save(conn).await
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ConfirmData {
    Key: String,
}

#[post("/emergency-access/<emer_id>/confirm", data = "<data>")]
async fn confirm_emergency_access(
    emer_id: String,
    data: JsonUpcase<ConfirmData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    check_emergency_access_allowed()?;

    let confirming_user = headers.user;
    let data: ConfirmData = data.into_inner().data;
    let key = data.Key;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Accepted as i32
        || emergency_access.grantor_uuid != confirming_user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&confirming_user.uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &mut conn).await {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed as i32;
        emergency_access.key_encrypted = Some(key);
        emergency_access.email = None;

        emergency_access.save(&mut conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_confirmed(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

// endregion

// region access emergency access

#[post("/emergency-access/<emer_id>/initiate")]
async fn initiate_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let initiating_user = headers.user;
    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Confirmed as i32
        || emergency_access.grantee_uuid != Some(initiating_user.uuid)
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let now = Utc::now().naive_utc();
    emergency_access.status = EmergencyAccessStatus::RecoveryInitiated as i32;
    emergency_access.updated_at = now;
    emergency_access.recovery_initiated_at = Some(now);
    emergency_access.last_notification_at = Some(now);
    emergency_access.save(&mut conn).await?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_recovery_initiated(
            &grantor_user.email,
            &initiating_user.name,
            emergency_access.get_type_as_str(),
            &emergency_access.wait_time_days,
        )
        .await?;
    }
    Ok(Json(emergency_access.to_json()))
}

#[post("/emergency-access/<emer_id>/approve")]
async fn approve_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32
        || emergency_access.grantor_uuid != headers.user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&headers.user.uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &mut conn).await {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::RecoveryApproved as i32;
        emergency_access.save(&mut conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

#[post("/emergency-access/<emer_id>/reject")]
async fn reject_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let mut emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if (emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32
        && emergency_access.status != EmergencyAccessStatus::RecoveryApproved as i32)
        || emergency_access.grantor_uuid != headers.user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&headers.user.uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let grantee_user = match User::find_by_uuid(grantee_uuid, &mut conn).await {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed as i32;
        emergency_access.save(&mut conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_rejected(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

// endregion

// region action

#[post("/emergency-access/<emer_id>/view")]
async fn view_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, headers.user.uuid, EmergencyAccessType::View) {
        err!("Emergency access not valid.")
    }

    let ciphers = Cipher::find_owned_by_user(&emergency_access.grantor_uuid, &mut conn).await;
    let cipher_sync_data = CipherSyncData::new(&emergency_access.grantor_uuid, CipherSyncType::User, &mut conn).await;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json
            .push(c.to_json(&headers.host, &emergency_access.grantor_uuid, Some(&cipher_sync_data), &mut conn).await);
    }

    Ok(Json(json!({
      "Ciphers": ciphers_json,
      "KeyEncrypted": &emergency_access.key_encrypted,
      "Object": "emergencyAccessView",
    })))
}

#[post("/emergency-access/<emer_id>/takeover")]
async fn takeover_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_allowed()?;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await {
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

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EmergencyAccessPasswordData {
    NewMasterPasswordHash: String,
    Key: String,
}

#[post("/emergency-access/<emer_id>/password", data = "<data>")]
async fn password_emergency_access(
    emer_id: String,
    data: JsonUpcase<EmergencyAccessPasswordData>,
    headers: Headers,
    mut conn: DbConn,
) -> EmptyResult {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessPasswordData = data.into_inner().data;
    let new_master_password_hash = &data.NewMasterPasswordHash;
    //let key = &data.Key;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let mut grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    // change grantor_user password
    grantor_user.set_password(new_master_password_hash, Some(data.Key), true, None);
    grantor_user.save(&mut conn).await?;

    // Disable TwoFactor providers since they will otherwise block logins
    TwoFactor::delete_all_by_user(&grantor_user.uuid, &mut conn).await?;

    // Remove grantor from all organisations unless Owner
    for user_org in UserOrganization::find_any_state_by_user(&grantor_user.uuid, &mut conn).await {
        if user_org.atype != UserOrgType::Owner as i32 {
            user_org.delete(&mut conn).await?;
        }
    }
    Ok(())
}

// endregion

#[get("/emergency-access/<emer_id>/policies")]
async fn policies_emergency_access(emer_id: String, headers: Headers, mut conn: DbConn) -> JsonResult {
    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::find_by_uuid(&emer_id, &mut conn).await {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let policies = OrgPolicy::find_confirmed_by_user(&grantor_user.uuid, &mut conn);
    let policies_json: Vec<Value> = policies.await.iter().map(OrgPolicy::to_json).collect();

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

pub async fn emergency_request_timeout_job(pool: DbPool) {
    debug!("Start emergency_request_timeout_job");
    if !CONFIG.emergency_access_allowed() {
        return;
    }

    if let Ok(mut conn) = pool.get().await {
        let emergency_access_list = EmergencyAccess::find_all_recoveries_initiated(&mut conn).await;

        if emergency_access_list.is_empty() {
            debug!("No emergency request timeout to approve");
        }

        let now = Utc::now().naive_utc();
        for mut emer in emergency_access_list {
            // The find_all_recoveries_initiated already checks if the recovery_initiated_at is not null (None)
            let recovery_allowed_at =
                emer.recovery_initiated_at.unwrap() + Duration::days(i64::from(emer.wait_time_days));
            if recovery_allowed_at.le(&now) {
                // Only update the access status
                // Updating the whole record could cause issues when the emergency_notification_reminder_job is also active
                emer.update_access_status_and_save(EmergencyAccessStatus::RecoveryApproved as i32, &now, &mut conn)
                    .await
                    .expect("Unable to update emergency access status");

                if CONFIG.mail_enabled() {
                    // get grantor user to send Accepted email
                    let grantor_user =
                        User::find_by_uuid(&emer.grantor_uuid, &mut conn).await.expect("Grantor user not found");

                    // get grantee user to send Accepted email
                    let grantee_user =
                        User::find_by_uuid(&emer.grantee_uuid.clone().expect("Grantee user invalid"), &mut conn)
                            .await
                            .expect("Grantee user not found");

                    mail::send_emergency_access_recovery_timed_out(
                        &grantor_user.email,
                        &grantee_user.name,
                        emer.get_type_as_str(),
                    )
                    .await
                    .expect("Error on sending email");

                    mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name)
                        .await
                        .expect("Error on sending email");
                }
            }
        }
    } else {
        error!("Failed to get DB connection while searching emergency request timed out")
    }
}

pub async fn emergency_notification_reminder_job(pool: DbPool) {
    debug!("Start emergency_notification_reminder_job");
    if !CONFIG.emergency_access_allowed() {
        return;
    }

    if let Ok(mut conn) = pool.get().await {
        let emergency_access_list = EmergencyAccess::find_all_recoveries_initiated(&mut conn).await;

        if emergency_access_list.is_empty() {
            debug!("No emergency request reminder notification to send");
        }

        let now = Utc::now().naive_utc();
        for mut emer in emergency_access_list {
            // The find_all_recoveries_initiated already checks if the recovery_initiated_at is not null (None)
            // Calculate the day before the recovery will become active
            let final_recovery_reminder_at =
                emer.recovery_initiated_at.unwrap() + Duration::days(i64::from(emer.wait_time_days - 1));
            // Calculate if a day has passed since the previous notification, else no notification has been sent before
            let next_recovery_reminder_at = if let Some(last_notification_at) = emer.last_notification_at {
                last_notification_at + Duration::days(1)
            } else {
                now
            };
            if final_recovery_reminder_at.le(&now) && next_recovery_reminder_at.le(&now) {
                // Only update the last notification date
                // Updating the whole record could cause issues when the emergency_request_timeout_job is also active
                emer.update_last_notification_date_and_save(&now, &mut conn)
                    .await
                    .expect("Unable to update emergency access notification date");

                if CONFIG.mail_enabled() {
                    // get grantor user to send Accepted email
                    let grantor_user =
                        User::find_by_uuid(&emer.grantor_uuid, &mut conn).await.expect("Grantor user not found");

                    // get grantee user to send Accepted email
                    let grantee_user =
                        User::find_by_uuid(&emer.grantee_uuid.clone().expect("Grantee user invalid"), &mut conn)
                            .await
                            .expect("Grantee user not found");

                    mail::send_emergency_access_recovery_reminder(
                        &grantor_user.email,
                        &grantee_user.name,
                        emer.get_type_as_str(),
                        "1", // This notification is only triggered one day before the activation
                    )
                    .await
                    .expect("Error on sending email");
                }
            }
        }
    } else {
        error!("Failed to get DB connection while searching emergency notification reminder")
    }
}
