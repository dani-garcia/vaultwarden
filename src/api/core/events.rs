use std::net::IpAddr;

use chrono::NaiveDateTime;
use rocket::{form::FromForm, serde::json::Json, Route};
use serde_json::Value;

use crate::{
    api::{EmptyResult, JsonResult, JsonUpcaseVec},
    auth::{AdminHeaders, Headers},
    db::{
        models::{Cipher, Event, UserOrganization},
        DbConn, DbPool,
    },
    util::parse_date,
    CONFIG,
};

/// ###############################################################################################################
/// /api routes
pub fn routes() -> Vec<Route> {
    routes![get_org_events, get_cipher_events, get_user_events,]
}

#[derive(FromForm)]
#[allow(non_snake_case)]
struct EventRange {
    start: String,
    end: String,
    #[field(name = "continuationToken")]
    continuation_token: Option<String>,
}

// Upstream: https://github.com/bitwarden/server/blob/9ecf69d9cabce732cf2c57976dd9afa5728578fb/src/Api/Controllers/EventsController.cs#LL84C35-L84C41
#[get("/organizations/<org_id>/events?<data..>")]
async fn get_org_events(org_id: String, data: EventRange, _headers: AdminHeaders, mut conn: DbConn) -> JsonResult {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.org_events_enabled() {
        Vec::with_capacity(0)
    } else {
        let start_date = parse_date(&data.start);
        let end_date = if let Some(before_date) = &data.continuation_token {
            parse_date(before_date)
        } else {
            parse_date(&data.end)
        };

        Event::find_by_organization_uuid(&org_id, &start_date, &end_date, &mut conn)
            .await
            .iter()
            .map(|e| e.to_json())
            .collect()
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

#[get("/ciphers/<cipher_id>/events?<data..>")]
async fn get_cipher_events(cipher_id: String, data: EventRange, headers: Headers, mut conn: DbConn) -> JsonResult {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.org_events_enabled() {
        Vec::with_capacity(0)
    } else {
        let mut events_json = Vec::with_capacity(0);
        if UserOrganization::user_has_ge_admin_access_to_cipher(&headers.user.uuid, &cipher_id, &mut conn).await {
            let start_date = parse_date(&data.start);
            let end_date = if let Some(before_date) = &data.continuation_token {
                parse_date(before_date)
            } else {
                parse_date(&data.end)
            };

            events_json = Event::find_by_cipher_uuid(&cipher_id, &start_date, &end_date, &mut conn)
                .await
                .iter()
                .map(|e| e.to_json())
                .collect()
        }
        events_json
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

#[get("/organizations/<org_id>/users/<user_org_id>/events?<data..>")]
async fn get_user_events(
    org_id: String,
    user_org_id: String,
    data: EventRange,
    _headers: AdminHeaders,
    mut conn: DbConn,
) -> JsonResult {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.org_events_enabled() {
        Vec::with_capacity(0)
    } else {
        let start_date = parse_date(&data.start);
        let end_date = if let Some(before_date) = &data.continuation_token {
            parse_date(before_date)
        } else {
            parse_date(&data.end)
        };

        Event::find_by_org_and_user_org(&org_id, &user_org_id, &start_date, &end_date, &mut conn)
            .await
            .iter()
            .map(|e| e.to_json())
            .collect()
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

fn get_continuation_token(events_json: &Vec<Value>) -> Option<&str> {
    // When the length of the vec equals the max page_size there probably is more data
    // When it is less, then all events are loaded.
    if events_json.len() as i64 == Event::PAGE_SIZE {
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

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct EventCollection {
    // Mandatory
    Type: i32,
    Date: String,

    // Optional
    CipherId: Option<String>,
    OrganizationId: Option<String>,
}

// Upstream:
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Events/Controllers/CollectController.cs
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
#[post("/collect", format = "application/json", data = "<data>")]
async fn post_events_collect(data: JsonUpcaseVec<EventCollection>, headers: Headers, mut conn: DbConn) -> EmptyResult {
    if !CONFIG.org_events_enabled() {
        return Ok(());
    }

    for event in data.iter().map(|d| &d.data) {
        let event_date = parse_date(&event.Date);
        match event.Type {
            1000..=1099 => {
                _log_user_event(
                    event.Type,
                    &headers.user.uuid,
                    headers.device.atype,
                    Some(event_date),
                    &headers.ip.ip,
                    &mut conn,
                )
                .await;
            }
            1600..=1699 => {
                if let Some(org_uuid) = &event.OrganizationId {
                    _log_event(
                        event.Type,
                        org_uuid,
                        String::from(org_uuid),
                        &headers.user.uuid,
                        headers.device.atype,
                        Some(event_date),
                        &headers.ip.ip,
                        &mut conn,
                    )
                    .await;
                }
            }
            _ => {
                if let Some(cipher_uuid) = &event.CipherId {
                    if let Some(cipher) = Cipher::find_by_uuid(cipher_uuid, &mut conn).await {
                        if let Some(org_uuid) = cipher.organization_uuid {
                            _log_event(
                                event.Type,
                                cipher_uuid,
                                org_uuid,
                                &headers.user.uuid,
                                headers.device.atype,
                                Some(event_date),
                                &headers.ip.ip,
                                &mut conn,
                            )
                            .await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn log_user_event(event_type: i32, user_uuid: &str, device_type: i32, ip: &IpAddr, conn: &mut DbConn) {
    if !CONFIG.org_events_enabled() {
        return;
    }
    _log_user_event(event_type, user_uuid, device_type, None, ip, conn).await;
}

async fn _log_user_event(
    event_type: i32,
    user_uuid: &str,
    device_type: i32,
    event_date: Option<NaiveDateTime>,
    ip: &IpAddr,
    conn: &mut DbConn,
) {
    let orgs = UserOrganization::get_org_uuid_by_user(user_uuid, conn).await;
    let mut events: Vec<Event> = Vec::with_capacity(orgs.len() + 1); // We need an event per org and one without an org

    // Upstream saves the event also without any org_uuid.
    let mut event = Event::new(event_type, event_date);
    event.user_uuid = Some(String::from(user_uuid));
    event.act_user_uuid = Some(String::from(user_uuid));
    event.device_type = Some(device_type);
    event.ip_address = Some(ip.to_string());
    events.push(event);

    // For each org a user is a member of store these events per org
    for org_uuid in orgs {
        let mut event = Event::new(event_type, event_date);
        event.user_uuid = Some(String::from(user_uuid));
        event.org_uuid = Some(org_uuid);
        event.act_user_uuid = Some(String::from(user_uuid));
        event.device_type = Some(device_type);
        event.ip_address = Some(ip.to_string());
        events.push(event);
    }

    Event::save_user_event(events, conn).await.unwrap_or(());
}

pub async fn log_event(
    event_type: i32,
    source_uuid: &str,
    org_uuid: String,
    act_user_uuid: String,
    device_type: i32,
    ip: &IpAddr,
    conn: &mut DbConn,
) {
    if !CONFIG.org_events_enabled() {
        return;
    }
    _log_event(event_type, source_uuid, org_uuid, &act_user_uuid, device_type, None, ip, conn).await;
}

#[allow(clippy::too_many_arguments)]
async fn _log_event(
    event_type: i32,
    source_uuid: &str,
    org_uuid: String,
    act_user_uuid: &str,
    device_type: i32,
    event_date: Option<NaiveDateTime>,
    ip: &IpAddr,
    conn: &mut DbConn,
) {
    // Create a new empty event
    let mut event = Event::new(event_type, event_date);
    match event_type {
        // 1000..=1099 Are user events, they need to be logged via log_user_event()
        // Collection Events
        1100..=1199 => {
            event.cipher_uuid = Some(String::from(source_uuid));
        }
        // Collection Events
        1300..=1399 => {
            event.collection_uuid = Some(String::from(source_uuid));
        }
        // Group Events
        1400..=1499 => {
            event.group_uuid = Some(String::from(source_uuid));
        }
        // Org User Events
        1500..=1599 => {
            event.org_user_uuid = Some(String::from(source_uuid));
        }
        // 1600..=1699 Are organizational events, and they do not need the source_uuid
        // Policy Events
        1700..=1799 => {
            event.policy_uuid = Some(String::from(source_uuid));
        }
        // Ignore others
        _ => {}
    }

    event.org_uuid = Some(org_uuid);
    event.act_user_uuid = Some(String::from(act_user_uuid));
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

    if let Ok(mut conn) = pool.get().await {
        Event::clean_events(&mut conn).await.ok();
    } else {
        error!("Failed to get DB connection while trying to cleanup the events table")
    }
}
