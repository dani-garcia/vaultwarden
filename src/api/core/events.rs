use std::net::IpAddr;

use chrono::NaiveDateTime;
use rocket::{Route, form::FromForm, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::{AccessEventLogsHeaders, Headers, may_access_event_logs},
    db::{
        DbConn, DbPool,
        models::{
            Cipher, CipherAccessScope, CipherId, Event, EventType, Membership, MembershipId, OrganizationId, UserId,
        },
    },
    util::try_parse_date,
};

/// ###############################################################################################################
/// /api routes
pub fn routes() -> Vec<Route> {
    routes![get_org_events, get_cipher_events, get_user_events,]
}

#[derive(FromForm)]
struct EventRange {
    start: String,
    end: String,
    #[field(name = "continuationToken")]
    continuation_token: Option<String>,
}

fn parse_event_date(date: &str, field: &str) -> Result<NaiveDateTime, crate::Error> {
    try_parse_date(date)
        .map_err(|error| crate::Error::new("Invalid event date", format!("Invalid RFC 3339 {field}: {error}")))
}

fn parse_event_range(data: &EventRange) -> Result<(NaiveDateTime, NaiveDateTime), crate::Error> {
    let start_date = parse_event_date(&data.start, "start date")?;

    let end_date = if let Some(continuation_token) = &data.continuation_token {
        try_parse_date(continuation_token).map_err(|error| {
            crate::Error::new(
                "Invalid continuation token",
                format!("Continuation token is not a valid RFC 3339 date: {error}"),
            )
        })?
    } else {
        parse_event_date(&data.end, "end date")?
    };

    Ok((start_date, end_date))
}

// Upstream: https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Controllers/EventsController.cs#L87
#[get("/organizations/<org_id>/events?<data..>")]
async fn get_org_events(
    org_id: OrganizationId,
    data: EventRange,
    headers: AccessEventLogsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if CONFIG.org_events_enabled() {
        let (start_date, end_date) = parse_event_range(&data)?;

        Event::find_by_organization_uuid(&org_id, &start_date, &end_date, &conn)
            .await
            .iter()
            .map(Event::to_json)
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(json!({
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
    })))
}

#[derive(Debug, Eq, PartialEq)]
enum CipherEventScope {
    Organization(OrganizationId),
    Personal,
}

impl CipherEventScope {
    fn organization_id(&self) -> Option<&OrganizationId> {
        match self {
            Self::Organization(org_id) => Some(org_id),
            Self::Personal => None,
        }
    }
}

fn cipher_event_scope(cipher: &Cipher, user_id: &UserId, membership: Option<&Membership>) -> Option<CipherEventScope> {
    match &cipher.organization_uuid {
        Some(org_id)
            if membership.is_some_and(|membership| {
                membership.user_uuid == *user_id && membership.org_uuid == *org_id && may_access_event_logs(membership)
            }) =>
        {
            Some(CipherEventScope::Organization(org_id.clone()))
        }
        None if cipher.is_owned_by_user(user_id) => Some(CipherEventScope::Personal),
        _ => None,
    }
}

#[get("/ciphers/<cipher_id>/events?<data..>")]
async fn get_cipher_events(cipher_id: CipherId, data: EventRange, headers: Headers, conn: DbConn) -> JsonResult {
    // Return an empty vec when org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if CONFIG.org_events_enabled() {
        let (start_date, end_date) = parse_event_range(&data)?;

        let scope = if let Some(cipher) = Cipher::find_by_uuid(&cipher_id, &conn).await {
            let membership = if let Some(org_id) = &cipher.organization_uuid {
                Membership::find_by_user_and_org(&headers.user.uuid, org_id, &conn).await
            } else {
                None
            };
            cipher_event_scope(&cipher, &headers.user.uuid, membership.as_ref())
        } else {
            None
        };

        if let Some(scope) = scope {
            Event::find_by_cipher_uuid(&cipher_id, scope.organization_id(), &start_date, &end_date, &conn)
                .await
                .iter()
                .map(Event::to_json)
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(Json(json!({
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
    })))
}

#[get("/organizations/<org_id>/users/<member_id>/events?<data..>")]
async fn get_user_events(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: EventRange,
    headers: AccessEventLogsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if CONFIG.org_events_enabled() {
        let (start_date, end_date) = parse_event_range(&data)?;

        Event::find_by_org_and_member(&org_id, &member_id, &start_date, &end_date, &conn)
            .await
            .iter()
            .map(Event::to_json)
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(json!({
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
    })))
}

fn get_continuation_token(events_json: &[Value]) -> Option<&str> {
    // When the length of the vec equals the max page_size there probably is more data
    // When it is less, then all events are loaded.
    #[expect(clippy::cast_possible_truncation, reason = "PAGE_SIZE fits within usize")]
    if events_json.len() == Event::PAGE_SIZE as usize {
        if let Some(last_event) = events_json.last() {
            last_event["date"].as_str()
        } else {
            None
        }
    } else {
        None
    }
}

/// ###############################################################################################################
/// /events routes
pub fn main_routes() -> Vec<Route> {
    routes![post_events_collect,]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventCollection {
    // Mandatory
    r#type: i32,
    date: String,

    // Optional
    cipher_id: Option<CipherId>,
    organization_id: Option<OrganizationId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientEventKind {
    User,
    Cipher,
    Organization,
    OrganizationUser,
}

const MAX_CLIENT_EVENT_BATCH_SIZE: usize = 1_000;

fn validate_client_event_batch_size(event_count: usize) -> Result<(), crate::Error> {
    if event_count > MAX_CLIENT_EVENT_BATCH_SIZE {
        return Err(crate::Error::new(
            "Event batch is too large",
            format!("At most {MAX_CLIENT_EVENT_BATCH_SIZE} events are accepted per request"),
        ));
    }
    Ok(())
}

/// The client-generated event types upstream's `/events/collect` accepts. Anything else is ignored,
/// so that an authenticated client cannot write arbitrary event types into an organization's audit
/// log. Keep this in sync with upstream's `CollectController`: a type missing here is silently not
/// logged, which is why the newer item-type events below are listed explicitly rather than matched
/// by range.
fn client_event_kind(event_type: i32) -> Option<ClientEventKind> {
    match event_type {
        event_type if event_type == EventType::UserClientExportedVault as i32 => Some(ClientEventKind::User),
        event_type
            if event_type == EventType::CipherClientViewed as i32
                || event_type == EventType::CipherClientToggledPasswordVisible as i32
                || event_type == EventType::CipherClientToggledHiddenFieldVisible as i32
                || event_type == EventType::CipherClientToggledCardCodeVisible as i32
                || event_type == EventType::CipherClientCopiedPassword as i32
                || event_type == EventType::CipherClientCopiedHiddenField as i32
                || event_type == EventType::CipherClientCopiedCardCode as i32
                || event_type == EventType::CipherClientAutofilled as i32
                || event_type == EventType::CipherClientToggledCardNumberVisible as i32
                || event_type == EventType::CipherClientCopiedBankAccountNumber as i32
                || event_type == EventType::CipherClientCopiedBankAccountPin as i32
                || event_type == EventType::CipherClientToggledBankAccountNumberVisible as i32
                || event_type == EventType::CipherClientToggledBankAccountPinVisible as i32
                || event_type == EventType::CipherClientCopiedLicenseNumber as i32
                || event_type == EventType::CipherClientToggledLicenseNumberVisible as i32
                || event_type == EventType::CipherClientCopiedPassportNumber as i32
                || event_type == EventType::CipherClientToggledPassportNumberVisible as i32
                || event_type == EventType::CipherClientCopiedSwiftCode as i32
                || event_type == EventType::CipherClientToggledSwiftCodeVisible as i32
                || event_type == EventType::CipherClientCopiedIban as i32
                || event_type == EventType::CipherClientToggledIbanVisible as i32
                || event_type == EventType::CipherClientCopiedNationalIdentificationNumber as i32
                || event_type == EventType::CipherClientToggledNationalIdentificationNumberVisible as i32 =>
        {
            Some(ClientEventKind::Cipher)
        }
        event_type
            if event_type == EventType::OrganizationClientExportedVault as i32
                || event_type == EventType::OrganizationAutoConfirmEnabledAdmin as i32
                || event_type == EventType::OrganizationAutoConfirmDisabledAdmin as i32
                || event_type == EventType::OrganizationInviteLinkClientCopied as i32 =>
        {
            Some(ClientEventKind::Organization)
        }
        // Upstream logs these through `LogOrganizationUserEventAsync`: they describe the acting
        // user's own membership, not the organization as a whole.
        event_type
            if event_type == EventType::OrganizationUserNotificationBannerActionClicked as i32
                || event_type == EventType::OrganizationItemOrganizationAccepted as i32
                || event_type == EventType::OrganizationItemOrganizationDeclined as i32 =>
        {
            Some(ClientEventKind::OrganizationUser)
        }
        _ => None,
    }
}

// Upstream:
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Events/Controllers/CollectController.cs
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/EventService.cs
#[post("/collect", format = "application/json", data = "<data>")]
async fn post_events_collect(data: Json<Vec<EventCollection>>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.org_events_enabled() {
        return Ok(());
    }

    // Official clients normally submit small batches (upstream explicitly exercises batches of
    // 100). Keep ample headroom while preventing one authenticated request from causing an
    // effectively unbounded sequence of database reads and writes under the shared 20 MiB JSON
    // limit.
    validate_client_event_batch_size(data.len())?;

    // Validate all accepted client events before writing any of them. Unsupported event types are
    // ignored, matching upstream, while malformed dates on accepted events produce a controlled
    // 400 response instead of panicking after a partially processed batch.
    let mut accepted_events = Vec::new();
    for event in data.iter() {
        if let Some(kind) = client_event_kind(event.r#type) {
            accepted_events.push((event, kind, parse_event_date(&event.date, "event date")?));
        }
    }

    for (event, kind, event_date) in accepted_events {
        match kind {
            ClientEventKind::User => {
                log_user_event_impl(
                    event.r#type,
                    &headers.user.uuid,
                    headers.device.atype,
                    Some(event_date),
                    &headers.ip.ip,
                    &conn,
                )
                .await;
            }
            ClientEventKind::Organization => {
                // Only allow logging events for an organization the user is actually a member of.
                if let Some(org_id) = &event.organization_id
                    && Membership::find_confirmed_by_user_and_org(&headers.user.uuid, org_id, &conn).await.is_some()
                {
                    log_event_impl(
                        event.r#type,
                        org_id,
                        org_id,
                        &headers.user.uuid,
                        headers.device.atype,
                        Some(event_date),
                        &headers.ip.ip,
                        &conn,
                    )
                    .await;
                }
            }
            ClientEventKind::OrganizationUser => {
                if let Some(org_id) = &event.organization_id {
                    log_client_org_user_event(
                        event.r#type,
                        org_id,
                        &headers.user.uuid,
                        headers.device.atype,
                        event_date,
                        &headers.ip.ip,
                        &conn,
                    )
                    .await;
                }
            }
            ClientEventKind::Cipher => {
                // The cipher determines the organization the event is logged to, so make sure the
                // user can actually access it instead of trusting the provided cipher uuid.
                if let Some(cipher_uuid) = &event.cipher_id
                    && let Some(cipher) = Cipher::find_by_uuid(cipher_uuid, &conn).await
                    && cipher.is_accessible_to_user(&headers.user.uuid, CipherAccessScope::User, &conn).await
                    && let Some(org_id) = cipher.organization_uuid
                {
                    log_event_impl(
                        event.r#type,
                        cipher_uuid,
                        &org_id,
                        &headers.user.uuid,
                        headers.device.atype,
                        Some(event_date),
                        &headers.ip.ip,
                        &conn,
                    )
                    .await;
                }
            }
        }
    }
    Ok(())
}

/// Logs a client event against the membership the acting user holds in `org_id`. Without such a
/// membership there is nothing to log against, so a request naming another organization writes no
/// event at all instead of one pointing at a foreign or non-existent membership.
async fn log_client_org_user_event(
    event_type: i32,
    org_id: &OrganizationId,
    act_user_id: &UserId,
    device_type: i32,
    event_date: NaiveDateTime,
    ip: &IpAddr,
    conn: &DbConn,
) {
    if let Some(membership) = Membership::find_confirmed_by_user_and_org(act_user_id, org_id, conn).await {
        log_event_impl(event_type, &membership.uuid, org_id, act_user_id, device_type, Some(event_date), ip, conn)
            .await;
    }
}

pub async fn log_user_event(event_type: i32, user_id: &UserId, device_type: i32, ip: &IpAddr, conn: &DbConn) {
    if !CONFIG.org_events_enabled() {
        return;
    }
    log_user_event_impl(event_type, user_id, device_type, None, ip, conn).await;
}

async fn log_user_event_impl(
    event_type: i32,
    user_id: &UserId,
    device_type: i32,
    event_date: Option<NaiveDateTime>,
    ip: &IpAddr,
    conn: &DbConn,
) {
    let memberships = Membership::find_confirmed_by_user(user_id, conn).await;
    let mut events: Vec<Event> = Vec::with_capacity(memberships.len() + 1); // We need an event per org and one without an org

    // Upstream saves the event also without any org_id.
    let mut event = Event::new(event_type, event_date);
    event.user_uuid = Some(user_id.clone());
    event.act_user_uuid = Some(user_id.clone());
    event.device_type = Some(device_type);
    event.ip_address = Some(ip.to_string());
    events.push(event);

    // For each org a user is a member of store these events per org
    for membership in memberships {
        let mut event = Event::new(event_type, event_date);
        event.user_uuid = Some(user_id.clone());
        event.org_uuid = Some(membership.org_uuid);
        event.org_user_uuid = Some(membership.uuid);
        event.act_user_uuid = Some(user_id.clone());
        event.device_type = Some(device_type);
        event.ip_address = Some(ip.to_string());
        events.push(event);
    }

    Event::save_user_event(events, conn).await.unwrap_or(());
}

pub async fn log_event(
    event_type: EventType,
    source_uuid: &str,
    org_id: &OrganizationId,
    act_user_id: &UserId,
    device_type: i32,
    ip: &IpAddr,
    conn: &DbConn,
) {
    if !CONFIG.org_events_enabled() {
        return;
    }
    log_event_impl(event_type as i32, source_uuid, org_id, act_user_id, device_type, None, ip, conn).await;
}

#[expect(clippy::too_many_arguments)]
async fn log_event_impl(
    event_type: i32,
    source_uuid: &str,
    org_id: &OrganizationId,
    act_user_id: &UserId,
    device_type: i32,
    event_date: Option<NaiveDateTime>,
    ip: &IpAddr,
    conn: &DbConn,
) {
    // Create a new empty event
    let mut event = Event::new(event_type, event_date);
    match event_type {
        // 1000..=1099 Are user events, they need to be logged via log_user_event()
        // Cipher Events
        1100..=1199 => {
            event.cipher_uuid = Some(source_uuid.to_owned().into());
        }
        // Collection Events
        1300..=1399 => {
            event.collection_uuid = Some(source_uuid.to_owned().into());
        }
        // Group Events
        1400..=1499 => {
            event.group_uuid = Some(source_uuid.to_owned().into());
        }
        // Org User Events
        1500..=1599 => {
            event.org_user_uuid = Some(source_uuid.to_owned().into());
        }
        // 1600..=1699 Are organizational events, and they do not need the source_uuid, except for
        // the two item-organization events, which upstream logs against a membership.
        event_type
            if event_type == EventType::OrganizationItemOrganizationAccepted as i32
                || event_type == EventType::OrganizationItemOrganizationDeclined as i32 =>
        {
            event.org_user_uuid = Some(source_uuid.to_owned().into());
        }
        // Policy Events
        1700..=1799 => {
            event.policy_uuid = Some(source_uuid.to_owned().into());
        }
        // Ignore others
        _ => {}
    }

    event.org_uuid = Some(org_id.clone());
    event.act_user_uuid = Some(act_user_id.clone());
    event.device_type = Some(device_type);
    event.ip_address = Some(ip.to_string());
    event.save(conn).await.unwrap_or(());
}

pub async fn event_cleanup_job(pool: DbPool) {
    debug!("Start events cleanup job");
    if CONFIG.events_days_retain().is_none() {
        debug!("events_days_retain is not configured, abort");
        return;
    }

    if let Ok(conn) = pool.get().await {
        Event::clean_events(&conn).await.ok();
    } else {
        error!("Failed to get DB connection while trying to cleanup the events table");
    }
}
