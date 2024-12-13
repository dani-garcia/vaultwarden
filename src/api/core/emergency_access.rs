use chrono::{TimeDelta, Utc};
use rocket::{serde::json::Json, Route};
use serde_json::Value;

use crate::{
    api::{
        core::{CipherSyncData, CipherSyncType},
        EmptyResult, JsonResult,
    },
    auth::{decode_emergency_access_invite, Headers},
    db::{models::*, DbConn, DbPool},
    mail,
    util::NumberOrString,
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![
        get_contacts,
        get_grantees,
        get_emergency_access,
        put_emergency_access,
        post_emergency_access,
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
async fn get_contacts(headers: Headers, mut conn: DbConn) -> Json<Value> {
    if !CONFIG.emergency_access_allowed() {
        return Json(json!({
            "data": [{
                "id": "",
                "status": 2,
                "type": 0,
                "waitTimeDays": 0,
                "granteeId": "",
                "email": "",
                "name": "NOTE: Emergency Access is disabled!",
                "object": "emergencyAccessGranteeDetails",

            }],
            "object": "list",
            "continuationToken": null
        }));
    }
    let emergency_access_list = EmergencyAccess::find_all_by_grantor_uuid(&headers.user.uuid, &mut conn).await;
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        if let Some(grantee) = ea.to_json_grantee_details(&mut conn).await {
            emergency_access_list_json.push(grantee)
        }
    }

    Json(json!({
      "data": emergency_access_list_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/emergency-access/granted")]
async fn get_grantees(headers: Headers, mut conn: DbConn) -> Json<Value> {
    let emergency_access_list = if CONFIG.emergency_access_allowed() {
        EmergencyAccess::find_all_by_grantee_uuid(&headers.user.uuid, &mut conn).await
    } else {
        Vec::new()
    };
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        emergency_access_list_json.push(ea.to_json_grantor_details(&mut conn).await);
    }

    Json(json!({
      "data": emergency_access_list_json,
      "object": "list",
      "continuationToken": null
    }))
}

#[get("/emergency-access/<emer_id>")]
async fn get_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    match EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await {
        Some(emergency_access) => Ok(Json(
            emergency_access.to_json_grantee_details(&mut conn).await.expect("Grantee user should exist but does not!"),
        )),
        None => err!("Emergency access not valid."),
    }
}

// endregion

// region put/post

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessUpdateData {
    r#type: NumberOrString,
    wait_time_days: i32,
    key_encrypted: Option<String>,
}

#[put("/emergency-access/<emer_id>", data = "<data>")]
async fn put_emergency_access(
    emer_id: &str,
    data: Json<EmergencyAccessUpdateData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    post_emergency_access(emer_id, data, headers, conn).await
}

#[post("/emergency-access/<emer_id>", data = "<data>")]
async fn post_emergency_access(
    emer_id: &str,
    data: Json<EmergencyAccessUpdateData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    check_emergency_access_enabled()?;

    let data: EmergencyAccessUpdateData = data.into_inner();

    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    let new_type = match EmergencyAccessType::from_str(&data.r#type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid emergency access type."),
    };

    emergency_access.atype = new_type;
    emergency_access.wait_time_days = data.wait_time_days;
    if data.key_encrypted.is_some() {
        emergency_access.key_encrypted = data.key_encrypted;
    }

    emergency_access.save(&mut conn).await?;
    Ok(Json(emergency_access.to_json()))
}

// endregion

// region delete

#[delete("/emergency-access/<emer_id>")]
async fn delete_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_enabled()?;

    let emergency_access = match (
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await,
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &headers.user.uuid, &mut conn).await,
    ) {
        (Some(grantor_emer), None) => {
            info!("Grantor deleted emergency access {emer_id}");
            grantor_emer
        }
        (None, Some(grantee_emer)) => {
            info!("Grantee deleted emergency access {emer_id}");
            grantee_emer
        }
        _ => err!("Emergency access not valid."),
    };

    emergency_access.delete(&mut conn).await?;
    Ok(())
}

#[post("/emergency-access/<emer_id>/delete")]
async fn post_delete_emergency_access(emer_id: &str, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_emergency_access(emer_id, headers, conn).await
}

// endregion

// region invite

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessInviteData {
    email: String,
    r#type: NumberOrString,
    wait_time_days: i32,
}

#[post("/emergency-access/invite", data = "<data>")]
async fn send_invite(data: Json<EmergencyAccessInviteData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_enabled()?;

    let data: EmergencyAccessInviteData = data.into_inner();
    let email = data.email.to_lowercase();
    let wait_time_days = data.wait_time_days;

    let emergency_access_status = EmergencyAccessStatus::Invited as i32;

    let new_type = match EmergencyAccessType::from_str(&data.r#type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid emergency access type."),
    };

    let grantor_user = headers.user;

    // avoid setting yourself as emergency contact
    if email == grantor_user.email {
        err!("You can not set yourself as an emergency contact.")
    }

    let (grantee_user, new_user) = match User::find_by_mail(&email, &mut conn).await {
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
            (user, true)
        }
        Some(user) if user.password_hash.is_empty() => (user, true),
        Some(user) => (user, false),
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
    } else if !new_user {
        // if mail is not enabled immediately accept the invitation for existing users
        new_emergency_access.accept_invite(&grantee_user.uuid, &email, &mut conn).await?;
    }

    Ok(())
}

#[post("/emergency-access/<emer_id>/reinvite")]
async fn resend_invite(emer_id: &str, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_enabled()?;

    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if emergency_access.status != EmergencyAccessStatus::Invited as i32 {
        err!("The grantee user is already accepted or confirmed to the organization");
    }

    let Some(email) = emergency_access.email.clone() else {
        err!("Email not valid.")
    };

    let Some(grantee_user) = User::find_by_mail(&email, &mut conn).await else {
        err!("Grantee user not found.")
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
    } else if !grantee_user.password_hash.is_empty() {
        // accept the invitation for existing user
        emergency_access.accept_invite(&grantee_user.uuid, &email, &mut conn).await?;
    } else if CONFIG.invitations_allowed() && Invitation::find_by_mail(&email, &mut conn).await.is_none() {
        let invitation = Invitation::new(&email);
        invitation.save(&mut conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
}

#[post("/emergency-access/<emer_id>/accept", data = "<data>")]
async fn accept_invite(emer_id: &str, data: Json<AcceptData>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    check_emergency_access_enabled()?;

    let data: AcceptData = data.into_inner();
    let token = &data.token;
    let claims = decode_emergency_access_invite(token)?;

    // This can happen if the user who received the invite used a different email to signup.
    // Since we do not know if this is intended, we error out here and do nothing with the invite.
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

    // We need to search for the uuid in combination with the email, since we do not yet store the uuid of the grantee in the database.
    // The uuid of the grantee gets stored once accepted.
    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_email(emer_id, &headers.user.email, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    // get grantor user to send Accepted email
    let Some(grantor_user) = User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    if emer_id == claims.emer_id
        && grantor_user.name == claims.grantor_name
        && grantor_user.email == claims.grantor_email
    {
        emergency_access.accept_invite(&grantee_user.uuid, &grantee_user.email, &mut conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_accepted(&grantor_user.email, &grantee_user.email).await?;
        }

        Ok(())
    } else {
        err!("Emergency access invitation error.")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    key: String,
}

#[post("/emergency-access/<emer_id>/confirm", data = "<data>")]
async fn confirm_emergency_access(
    emer_id: &str,
    data: Json<ConfirmData>,
    headers: Headers,
    mut conn: DbConn,
) -> JsonResult {
    check_emergency_access_enabled()?;

    let confirming_user = headers.user;
    let data: ConfirmData = data.into_inner();
    let key = data.key;

    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &confirming_user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if emergency_access.status != EmergencyAccessStatus::Accepted as i32
        || emergency_access.grantor_uuid != confirming_user.uuid
    {
        err!("Emergency access not valid.")
    }

    let Some(grantor_user) = User::find_by_uuid(&confirming_user.uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let Some(grantee_user) = User::find_by_uuid(grantee_uuid, &mut conn).await else {
            err!("Grantee user not found.")
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
async fn initiate_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    let initiating_user = headers.user;
    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &initiating_user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if emergency_access.status != EmergencyAccessStatus::Confirmed as i32 {
        err!("Emergency access not valid.")
    }

    let Some(grantor_user) = User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await else {
        err!("Grantor user not found.")
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
async fn approve_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32 {
        err!("Emergency access not valid.")
    }

    let Some(grantor_user) = User::find_by_uuid(&headers.user.uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let Some(grantee_user) = User::find_by_uuid(grantee_uuid, &mut conn).await else {
            err!("Grantee user not found.")
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
async fn reject_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    let Some(mut emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantor_uuid(emer_id, &headers.user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if emergency_access.status != EmergencyAccessStatus::RecoveryInitiated as i32
        && emergency_access.status != EmergencyAccessStatus::RecoveryApproved as i32
    {
        err!("Emergency access not valid.")
    }

    if let Some(grantee_uuid) = emergency_access.grantee_uuid.as_ref() {
        let Some(grantee_user) = User::find_by_uuid(grantee_uuid, &mut conn).await else {
            err!("Grantee user not found.")
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed as i32;
        emergency_access.save(&mut conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_rejected(&grantee_user.email, &headers.user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

// endregion

// region action

#[post("/emergency-access/<emer_id>/view")]
async fn view_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    let Some(emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &headers.user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if !is_valid_request(&emergency_access, &headers.user.uuid, EmergencyAccessType::View) {
        err!("Emergency access not valid.")
    }

    let ciphers = Cipher::find_owned_by_user(&emergency_access.grantor_uuid, &mut conn).await;
    let cipher_sync_data = CipherSyncData::new(&emergency_access.grantor_uuid, CipherSyncType::User, &mut conn).await;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(
            c.to_json(
                &headers.host,
                &emergency_access.grantor_uuid,
                Some(&cipher_sync_data),
                CipherSyncType::User,
                &mut conn,
            )
            .await,
        );
    }

    Ok(Json(json!({
      "ciphers": ciphers_json,
      "keyEncrypted": &emergency_access.key_encrypted,
      "object": "emergencyAccessView",
    })))
}

#[post("/emergency-access/<emer_id>/takeover")]
async fn takeover_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    check_emergency_access_enabled()?;

    let requesting_user = headers.user;
    let Some(emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &requesting_user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if !is_valid_request(&emergency_access, &requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let Some(grantor_user) = User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    let result = json!({
        "kdf": grantor_user.client_kdf_type,
        "kdfIterations": grantor_user.client_kdf_iter,
        "kdfMemory": grantor_user.client_kdf_memory,
        "kdfParallelism": grantor_user.client_kdf_parallelism,
        "keyEncrypted": &emergency_access.key_encrypted,
        "object": "emergencyAccessTakeover",
    });

    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessPasswordData {
    new_master_password_hash: String,
    key: String,
}

#[post("/emergency-access/<emer_id>/password", data = "<data>")]
async fn password_emergency_access(
    emer_id: &str,
    data: Json<EmergencyAccessPasswordData>,
    headers: Headers,
    mut conn: DbConn,
) -> EmptyResult {
    check_emergency_access_enabled()?;

    let data: EmergencyAccessPasswordData = data.into_inner();
    let new_master_password_hash = &data.new_master_password_hash;
    //let key = &data.Key;

    let requesting_user = headers.user;
    let Some(emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &requesting_user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if !is_valid_request(&emergency_access, &requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let Some(mut grantor_user) = User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    // change grantor_user password
    grantor_user.set_password(new_master_password_hash, Some(data.key), true, None);
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
async fn policies_emergency_access(emer_id: &str, headers: Headers, mut conn: DbConn) -> JsonResult {
    let requesting_user = headers.user;
    let Some(emergency_access) =
        EmergencyAccess::find_by_uuid_and_grantee_uuid(emer_id, &requesting_user.uuid, &mut conn).await
    else {
        err!("Emergency access not valid.")
    };

    if !is_valid_request(&emergency_access, &requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let Some(grantor_user) = User::find_by_uuid(&emergency_access.grantor_uuid, &mut conn).await else {
        err!("Grantor user not found.")
    };

    let policies = OrgPolicy::find_confirmed_by_user(&grantor_user.uuid, &mut conn);
    let policies_json: Vec<Value> = policies.await.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

fn is_valid_request(
    emergency_access: &EmergencyAccess,
    requesting_user_uuid: &str,
    requested_access_type: EmergencyAccessType,
) -> bool {
    emergency_access.grantee_uuid.is_some()
        && emergency_access.grantee_uuid.as_ref().unwrap() == requesting_user_uuid
        && emergency_access.status == EmergencyAccessStatus::RecoveryApproved as i32
        && emergency_access.atype == requested_access_type as i32
}

fn check_emergency_access_enabled() -> EmptyResult {
    if !CONFIG.emergency_access_allowed() {
        err!("Emergency access is not enabled.")
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
                emer.recovery_initiated_at.unwrap() + TimeDelta::try_days(i64::from(emer.wait_time_days)).unwrap();
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
                emer.recovery_initiated_at.unwrap() + TimeDelta::try_days(i64::from(emer.wait_time_days - 1)).unwrap();
            // Calculate if a day has passed since the previous notification, else no notification has been sent before
            let next_recovery_reminder_at = if let Some(last_notification_at) = emer.last_notification_at {
                last_notification_at + TimeDelta::try_days(1).unwrap()
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
