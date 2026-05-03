use crate::{
    api::{self, purge_auth_requests},
    db::{models::SsoAuth, DbPool},
    Error,
};

use crate::api::core::two_factor::duo_oidc::purge_duo_contexts;

#[derive(Clone, Copy, Debug)]
pub enum ScheduledJob {
    SendPurge,
    TrashPurge,
    Incomplete2faNotifications,
    EmergencyRequestTimeout,
    EmergencyNotificationReminder,
    AuthRequestPurge,
    DuoContextPurge,
    EventCleanup,
    PurgeIncompleteSsoAuth,
}

const ALL_JOBS: [ScheduledJob; 9] = [
    ScheduledJob::SendPurge,
    ScheduledJob::TrashPurge,
    ScheduledJob::Incomplete2faNotifications,
    ScheduledJob::EmergencyRequestTimeout,
    ScheduledJob::EmergencyNotificationReminder,
    ScheduledJob::AuthRequestPurge,
    ScheduledJob::DuoContextPurge,
    ScheduledJob::EventCleanup,
    ScheduledJob::PurgeIncompleteSsoAuth,
];

impl ScheduledJob {
    pub const fn as_str(self) -> &'static str {
        match self {
            ScheduledJob::SendPurge => "send_purge",
            ScheduledJob::TrashPurge => "trash_purge",
            ScheduledJob::Incomplete2faNotifications => "incomplete_2fa_notifications",
            ScheduledJob::EmergencyRequestTimeout => "emergency_request_timeout",
            ScheduledJob::EmergencyNotificationReminder => "emergency_notification_reminder",
            ScheduledJob::AuthRequestPurge => "auth_request_purge",
            ScheduledJob::DuoContextPurge => "duo_context_purge",
            ScheduledJob::EventCleanup => "event_cleanup",
            ScheduledJob::PurgeIncompleteSsoAuth => "purge_incomplete_sso_auth",
        }
    }

    pub fn from_str(name: &str) -> Option<Self> {
        match name {
            "send_purge" => Some(ScheduledJob::SendPurge),
            "trash_purge" => Some(ScheduledJob::TrashPurge),
            "incomplete_2fa_notifications" => Some(ScheduledJob::Incomplete2faNotifications),
            "emergency_request_timeout" => Some(ScheduledJob::EmergencyRequestTimeout),
            "emergency_notification_reminder" => Some(ScheduledJob::EmergencyNotificationReminder),
            "auth_request_purge" => Some(ScheduledJob::AuthRequestPurge),
            "duo_context_purge" => Some(ScheduledJob::DuoContextPurge),
            "event_cleanup" => Some(ScheduledJob::EventCleanup),
            "purge_incomplete_sso_auth" => Some(ScheduledJob::PurgeIncompleteSsoAuth),
            _ => None,
        }
    }

    pub fn names() -> Vec<&'static str> {
        ALL_JOBS.iter().map(|job| job.as_str()).collect()
    }
}

pub async fn run(pool: DbPool, job: ScheduledJob) -> Result<(), Error> {
    info!("Running job: {}", job.as_str());

    match job {
        ScheduledJob::SendPurge => api::purge_sends(pool).await,
        ScheduledJob::TrashPurge => api::purge_trashed_ciphers(pool).await,
        ScheduledJob::Incomplete2faNotifications => api::send_incomplete_2fa_notifications(pool).await,
        ScheduledJob::EmergencyRequestTimeout => api::emergency_request_timeout_job(pool).await,
        ScheduledJob::EmergencyNotificationReminder => api::emergency_notification_reminder_job(pool).await,
        ScheduledJob::AuthRequestPurge => purge_auth_requests(pool).await,
        ScheduledJob::DuoContextPurge => purge_duo_contexts(pool).await,
        ScheduledJob::EventCleanup => api::event_cleanup_job(pool).await,
        ScheduledJob::PurgeIncompleteSsoAuth => SsoAuth::delete_expired(pool).await?,
    }

    info!("Finished job: {}", job.as_str());
    Ok(())
}
