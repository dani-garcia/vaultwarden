use std::{env::consts::EXE_SUFFIX, str::FromStr};

use chrono::NaiveDateTime;
use lettre::{
    Address, AsyncSendmailTransport, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    message::{Attachment, Body, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::{Credentials, Mechanism as SmtpAuthMechanism},
    transport::smtp::client::{Tls, TlsParameters},
    transport::smtp::extension::ClientId,
};
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};

use crate::{
    CONFIG,
    api::EmptyResult,
    auth::{
        encode_jwt, generate_delete_claims, generate_emergency_access_invite_claims, generate_invite_claims,
        generate_verify_email_claims,
    },
    db::models::{Device, DeviceType, EmergencyAccessId, MembershipId, OrganizationId, User, UserId},
    error::Error,
    i18n,
    util::upcase_first,
};

fn sendmail_transport() -> AsyncSendmailTransport<Tokio1Executor> {
    if let Some(command) = CONFIG.sendmail_command() {
        AsyncSendmailTransport::new_with_command(command)
    } else {
        AsyncSendmailTransport::new_with_command(format!("sendmail{EXE_SUFFIX}"))
    }
}

fn smtp_transport() -> AsyncSmtpTransport<Tokio1Executor> {
    use std::time::Duration;
    let host = CONFIG.smtp_host().unwrap();

    let smtp_client = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.as_str())
        .port(CONFIG.smtp_port())
        .timeout(Some(Duration::from_secs(u64::from(CONFIG.smtp_timeout()))));

    // Determine security
    let smtp_client = if CONFIG.smtp_security() == *"off" {
        smtp_client
    } else {
        let mut tls_parameters = TlsParameters::builder(host);
        if CONFIG.smtp_accept_invalid_hostnames() {
            tls_parameters = tls_parameters.dangerous_accept_invalid_hostnames(true);
        }
        if CONFIG.smtp_accept_invalid_certs() {
            tls_parameters = tls_parameters.dangerous_accept_invalid_certs(true);
        }
        let tls_parameters = tls_parameters.build().unwrap();

        if CONFIG.smtp_security() == *"force_tls" {
            smtp_client.tls(Tls::Wrapper(tls_parameters))
        } else {
            smtp_client.tls(Tls::Required(tls_parameters))
        }
    };

    let smtp_client = match (CONFIG.smtp_username(), CONFIG.smtp_password()) {
        (Some(user), Some(pass)) => smtp_client.credentials(Credentials::new(user, pass)),
        _ => smtp_client,
    };

    let smtp_client = match CONFIG.helo_name() {
        Some(helo_name) => smtp_client.hello_name(ClientId::Domain(helo_name)),
        None => smtp_client,
    };

    let smtp_client = match CONFIG.smtp_auth_mechanism() {
        Some(mechanism) => {
            let allowed_mechanisms = [SmtpAuthMechanism::Plain, SmtpAuthMechanism::Login, SmtpAuthMechanism::Xoauth2];
            let mut selected_mechanisms = vec![];
            for wanted_mechanism in mechanism.split(',') {
                for m in &allowed_mechanisms {
                    if m.to_string().to_lowercase()
                        == wanted_mechanism.trim_matches(|c| c == '"' || c == '\'' || c == ' ').to_lowercase()
                    {
                        selected_mechanisms.push(*m);
                    }
                }
            }

            if selected_mechanisms.is_empty() {
                // Only show a warning, and return without setting an actual authentication mechanism
                warn!("No valid SMTP Auth mechanism found for '{mechanism}', using default values");
                smtp_client
            } else {
                smtp_client.authentication(selected_mechanisms)
            }
        }
        _ => smtp_client,
    };

    smtp_client.build()
}

// This will sanitize the string values by stripping all the html tags to prevent XSS and HTML Injections
fn sanitize_data(data: &mut serde_json::Value) {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

    match data {
        serde_json::Value::String(s) => *s = RE.replace_all(s, "").to_string(),
        serde_json::Value::Object(obj) => {
            for d in obj.values_mut() {
                sanitize_data(d);
            }
        }
        serde_json::Value::Array(arr) => {
            for d in arr.iter_mut() {
                sanitize_data(d);
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
fn get_text(template_name: &'static str, data: serde_json::Value) -> Result<(String, String, String), Error> {
    get_text_for_locale(template_name, data, None)
}

fn get_text_for_locale(
    template_name: &'static str,
    data: serde_json::Value,
    locale_override: Option<&str>,
) -> Result<(String, String, String), Error> {
    let mut data = data;
    sanitize_data(&mut data);

    let resolved_locale =
        locale_override.map_or_else(|| i18n::normalize_locale(&CONFIG.default_locale()), i18n::normalize_locale);

    if let serde_json::Value::Object(map) = &mut data {
        map.entry("lang".to_owned()).or_insert_with(|| serde_json::Value::String(resolved_locale));
    }

    let (subject_html, body_html) = get_template(&format!("{template_name}.html"), &data, locale_override)?;
    let (_subject_text, body_text) = get_template(template_name, &data, locale_override)?;
    Ok((subject_html, body_html, body_text))
}

fn get_template(
    template_name: &str,
    data: &serde_json::Value,
    locale_override: Option<&str>,
) -> Result<(String, String), Error> {
    let template_name = get_localized_email_template_name(template_name, locale_override);
    let text = CONFIG.render_template(&template_name, data)?;
    let mut text_split = text.split("<!---------------->");

    let subject = if let Some(s) = text_split.next() {
        s.trim().to_owned()
    } else {
        err!(i18n::api_template_missing_subject(&CONFIG.default_locale()))
    };

    let body = if let Some(s) = text_split.next() {
        s.trim().to_owned()
    } else {
        err!(i18n::api_template_missing_body(&CONFIG.default_locale()))
    };

    if text_split.next().is_some() {
        err!(i18n::api_template_more_than_one_body(&CONFIG.default_locale()));
    }

    Ok((subject, body))
}

fn get_localized_email_template_name(template_name: &str, locale_override: Option<&str>) -> String {
    let preferred_locale =
        locale_override.map_or_else(|| i18n::normalize_locale(&CONFIG.default_locale()), i18n::normalize_locale);

    for locale in i18n::locale_candidates(&preferred_locale) {
        let Some(rest) = template_name.strip_prefix("email/") else {
            return template_name.to_owned();
        };

        let localized = format!("email/{locale}/{rest}");
        if CONFIG.has_template(&localized) {
            return localized;
        }
    }

    template_name.to_owned()
}

#[allow(dead_code)]
pub async fn send_password_hint(address: &str, hint: Option<String>) -> EmptyResult {
    send_password_hint_for_locale(address, hint, None).await
}

pub async fn send_password_hint_for_locale(address: &str, hint: Option<String>, locale: Option<&str>) -> EmptyResult {
    let template_name = if hint.is_some() {
        "email/pw_hint_some"
    } else {
        "email/pw_hint_none"
    };

    let (subject, body_html, body_text) = get_text_for_locale(
        template_name,
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "hint": hint,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_delete_account(address: &str, user_id: &UserId) -> EmptyResult {
    send_delete_account_for_locale(address, user_id, None).await
}

pub async fn send_delete_account_for_locale(address: &str, user_id: &UserId, locale: Option<&str>) -> EmptyResult {
    let claims = generate_delete_claims(user_id.to_string())?;
    let delete_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/delete_account",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": delete_token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_verify_email(address: &str, user_id: &UserId) -> EmptyResult {
    send_verify_email_for_locale(address, user_id, None).await
}

pub async fn send_verify_email_for_locale(address: &str, user_id: &UserId, locale: Option<&str>) -> EmptyResult {
    let claims = generate_verify_email_claims(user_id)?;
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/verify_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": verify_email_token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_register_verify_email(email: &str, token: &str) -> EmptyResult {
    send_register_verify_email_for_locale(email, token, None).await
}

pub async fn send_register_verify_email_for_locale(email: &str, token: &str, locale: Option<&str>) -> EmptyResult {
    let mut query = url::Url::parse("https://query.builder").unwrap();
    query.query_pairs_mut().append_pair("email", email).append_pair("token", token).append_pair("fromEmail", "true");
    let Some(query_string) = query.query() else {
        err!(i18n::api_failed_build_verify_url_query_params(&CONFIG.default_locale()))
    };

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/register_verify_email",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/finish-signup/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "email": email,
        }),
        locale,
    )?;

    send_email(email, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_welcome(address: &str) -> EmptyResult {
    send_welcome_for_locale(address, None).await
}

pub async fn send_welcome_for_locale(address: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/welcome",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_welcome_must_verify(address: &str, user_id: &UserId) -> EmptyResult {
    send_welcome_must_verify_for_locale(address, user_id, None).await
}

pub async fn send_welcome_must_verify_for_locale(address: &str, user_id: &UserId, locale: Option<&str>) -> EmptyResult {
    let claims = generate_verify_email_claims(user_id)?;
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/welcome_must_verify",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "token": verify_email_token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_2fa_removed_from_org(address: &str, org_name: &str) -> EmptyResult {
    send_2fa_removed_from_org_for_locale(address, org_name, None).await
}

pub async fn send_2fa_removed_from_org_for_locale(address: &str, org_name: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/send_2fa_removed_from_org",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_single_org_removed_from_org(address: &str, org_name: &str) -> EmptyResult {
    send_single_org_removed_from_org_for_locale(address, org_name, None).await
}

pub async fn send_single_org_removed_from_org_for_locale(
    address: &str,
    org_name: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/send_single_org_removed_from_org",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite(
    user: &User,
    org_id: OrganizationId,
    member_id: MembershipId,
    org_name: &str,
    invited_by_email: Option<String>,
) -> EmptyResult {
    let claims = generate_invite_claims(
        user.uuid.clone(),
        user.email.clone(),
        org_id.clone(),
        member_id.clone(),
        invited_by_email,
    )?;
    let invite_token = encode_jwt(&claims);
    let mut query = url::Url::parse("https://query.builder").unwrap();
    {
        let mut query_params = query.query_pairs_mut();
        query_params
            .append_pair("email", &user.email)
            .append_pair("organizationName", org_name)
            .append_pair("organizationId", &org_id)
            .append_pair("organizationUserId", &member_id)
            .append_pair("token", &invite_token);

        if CONFIG.sso_enabled() && CONFIG.sso_only() {
            query_params.append_pair("orgSsoIdentifier", &org_id);
        }

        // The web vault requires both of these parameters to be present.
        // If either is missing it rejects the invite client-side, before any
        // request reaches the server, showing only "Unable to accept invitation".
        query_params.append_pair("initOrganization", "false");

        let org_user_has_existing_user = if user.private_key.is_some() {
            "true"
        } else {
            "false"
        };
        query_params.append_pair("orgUserHasExistingUser", org_user_has_existing_user);
    }

    let Some(query_string) = query.query() else {
        err!(i18n::api_failed_build_invite_url_query_params(&CONFIG.default_locale()))
    };

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/send_org_invite",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/accept-organization/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
        user.locale.as_deref(),
    )?;

    send_email(&user.email, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_invite(
    address: &str,
    user_id: UserId,
    emer_id: EmergencyAccessId,
    grantor_name: &str,
    grantor_email: &str,
) -> EmptyResult {
    send_emergency_access_invite_for_locale(address, user_id, emer_id, grantor_name, grantor_email, None).await
}

pub async fn send_emergency_access_invite_for_locale(
    address: &str,
    user_id: UserId,
    emer_id: EmergencyAccessId,
    grantor_name: &str,
    grantor_email: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let claims = generate_emergency_access_invite_claims(
        user_id,
        String::from(address),
        emer_id.clone(),
        String::from(grantor_name),
        String::from(grantor_email),
    )?;

    // Build the query here to ensure proper escaping
    let mut query = url::Url::parse("https://query.builder").unwrap();
    {
        let mut query_params = query.query_pairs_mut();
        query_params
            .append_pair("id", &emer_id.to_string())
            .append_pair("name", grantor_name)
            .append_pair("email", address)
            .append_pair("token", &encode_jwt(&claims));
    }

    let Some(query_string) = query.query() else {
        err!(i18n::api_failed_build_emergency_invite_url_query_params(&CONFIG.default_locale()))
    };

    let (subject, body_html, body_text) = get_text_for_locale(
        "email/send_emergency_access_invite",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/accept-emergency/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_invite_accepted(address: &str, grantee_email: &str) -> EmptyResult {
    send_emergency_access_invite_accepted_for_locale(address, grantee_email, None).await
}

pub async fn send_emergency_access_invite_accepted_for_locale(
    address: &str,
    grantee_email: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_invite_accepted",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_email": grantee_email,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_invite_confirmed(address: &str, grantor_name: &str) -> EmptyResult {
    send_emergency_access_invite_confirmed_for_locale(address, grantor_name, None).await
}

pub async fn send_emergency_access_invite_confirmed_for_locale(
    address: &str,
    grantor_name: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_recovery_approved(address: &str, grantor_name: &str) -> EmptyResult {
    send_emergency_access_recovery_approved_for_locale(address, grantor_name, None).await
}

pub async fn send_emergency_access_recovery_approved_for_locale(
    address: &str,
    grantor_name: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_recovery_approved",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_recovery_initiated(
    address: &str,
    grantee_name: &str,
    atype: &str,
    wait_time_days: &i32,
) -> EmptyResult {
    send_emergency_access_recovery_initiated_for_locale(address, grantee_name, atype, wait_time_days, None).await
}

pub async fn send_emergency_access_recovery_initiated_for_locale(
    address: &str,
    grantee_name: &str,
    atype: &str,
    wait_time_days: &i32,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_recovery_initiated",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
            "wait_time_days": wait_time_days,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_recovery_reminder(
    address: &str,
    grantee_name: &str,
    atype: &str,
    days_left: &str,
) -> EmptyResult {
    send_emergency_access_recovery_reminder_for_locale(address, grantee_name, atype, days_left, None).await
}

pub async fn send_emergency_access_recovery_reminder_for_locale(
    address: &str,
    grantee_name: &str,
    atype: &str,
    days_left: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_recovery_reminder",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
            "days_left": days_left,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_recovery_rejected(address: &str, grantor_name: &str) -> EmptyResult {
    send_emergency_access_recovery_rejected_for_locale(address, grantor_name, None).await
}

pub async fn send_emergency_access_recovery_rejected_for_locale(
    address: &str,
    grantor_name: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_recovery_rejected",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_emergency_access_recovery_timed_out(address: &str, grantee_name: &str, atype: &str) -> EmptyResult {
    send_emergency_access_recovery_timed_out_for_locale(address, grantee_name, atype, None).await
}

pub async fn send_emergency_access_recovery_timed_out_for_locale(
    address: &str,
    grantee_name: &str,
    atype: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/emergency_access_recovery_timed_out",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_invite_accepted(new_user_email: &str, address: &str, org_name: &str) -> EmptyResult {
    send_invite_accepted_for_locale(new_user_email, address, org_name, None).await
}

pub async fn send_invite_accepted_for_locale(
    new_user_email: &str,
    address: &str,
    org_name: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/invite_accepted",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "email": new_user_email,
            "org_name": org_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_invite_confirmed(address: &str, org_name: &str) -> EmptyResult {
    send_invite_confirmed_for_locale(address, org_name, None).await
}

pub async fn send_invite_confirmed_for_locale(address: &str, org_name: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_new_device_logged_in(address: &str, ip: &str, dt: &NaiveDateTime, device: &Device) -> EmptyResult {
    send_new_device_logged_in_for_locale(address, ip, dt, device, None).await
}

pub async fn send_new_device_logged_in_for_locale(
    address: &str,
    ip: &str,
    dt: &NaiveDateTime,
    device: &Device,
    locale: Option<&str>,
) -> EmptyResult {
    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "device_name": upcase_first(&device.name),
            "device_type": DeviceType::from_i32(device.atype).to_string(),
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_recover_twofactor(address: &str, ip: &str, dt: &NaiveDateTime) -> EmptyResult {
    send_recover_twofactor_for_locale(address, ip, dt, None).await
}

pub async fn send_recover_twofactor_for_locale(
    address: &str,
    ip: &str,
    dt: &NaiveDateTime,
    locale: Option<&str>,
) -> EmptyResult {
    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/recover_twofactor",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_incomplete_2fa_login(
    address: &str,
    ip: &str,
    dt: &NaiveDateTime,
    device_name: &str,
    device_type: &str,
) -> EmptyResult {
    send_incomplete_2fa_login_for_locale(address, ip, dt, device_name, device_type, None).await
}

pub async fn send_incomplete_2fa_login_for_locale(
    address: &str,
    ip: &str,
    dt: &NaiveDateTime,
    device_name: &str,
    device_type: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/incomplete_2fa_login",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "device_name": upcase_first(device_name),
            "device_type": device_type,
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
            "time_limit": CONFIG.incomplete_2fa_time_limit(),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_token(address: &str, token: &str) -> EmptyResult {
    send_token_for_locale(address, token, None).await
}

pub async fn send_token_for_locale(address: &str, token: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/twofactor_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_change_email(address: &str, token: &str) -> EmptyResult {
    send_change_email_for_locale(address, token, None).await
}

pub async fn send_change_email_for_locale(address: &str, token: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/change_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_change_email_existing(address: &str, acting_address: &str) -> EmptyResult {
    send_change_email_existing_for_locale(address, acting_address, None).await
}

pub async fn send_change_email_existing_for_locale(
    address: &str,
    acting_address: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/change_email_existing",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "existing_address": address,
            "acting_address": acting_address,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_change_email_invited(address: &str, acting_address: &str) -> EmptyResult {
    send_change_email_invited_for_locale(address, acting_address, None).await
}

pub async fn send_change_email_invited_for_locale(
    address: &str,
    acting_address: &str,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/change_email_invited",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "existing_address": address,
            "acting_address": acting_address,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_sso_change_email(address: &str) -> EmptyResult {
    send_sso_change_email_for_locale(address, None).await
}

pub async fn send_sso_change_email_for_locale(address: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/sso_change_email",
        json!({
            "url": format!("{}/#/settings/account", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_test(address: &str) -> EmptyResult {
    send_test_for_locale(address, None).await
}

pub async fn send_test_for_locale(address: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/smtp_test",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_admin_account_recovery(
    address: &str,
    user_name: &str,
    org_name: &str,
    reset_password: bool,
    reset_2fa: bool,
    fallback_2fa_email: bool,
) -> EmptyResult {
    send_admin_account_recovery_for_locale(
        address,
        user_name,
        org_name,
        reset_password,
        reset_2fa,
        fallback_2fa_email,
        None,
    )
    .await
}

pub async fn send_admin_account_recovery_for_locale(
    address: &str,
    user_name: &str,
    org_name: &str,
    reset_password: bool,
    reset_2fa: bool,
    fallback_2fa_email: bool,
    locale: Option<&str>,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/admin_account_recovery",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_name": user_name,
            "org_name": org_name,
            "reset_password": reset_password,
            "reset_2fa": reset_2fa,
            "fallback_2fa_email": fallback_2fa_email,
        }),
        locale,
    )?;
    send_email(address, &subject, body_html, body_text).await
}

#[allow(dead_code)]
pub async fn send_protected_action_token(address: &str, token: &str) -> EmptyResult {
    send_protected_action_token_for_locale(address, token, None).await
}

pub async fn send_protected_action_token_for_locale(address: &str, token: &str, locale: Option<&str>) -> EmptyResult {
    let (subject, body_html, body_text) = get_text_for_locale(
        "email/protected_action",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
        locale,
    )?;

    send_email(address, &subject, body_html, body_text).await
}

async fn send_with_selected_transport(email: Message) -> EmptyResult {
    if CONFIG.use_sendmail() {
        match sendmail_transport().send(email).await {
            Ok(()) => Ok(()),
            // Match some common errors and make them more user friendly
            Err(e) => {
                if e.is_client() {
                    debug!("Sendmail client error: {e:?}");
                    err!(i18n::mail_sendmail_client_error(&CONFIG.default_locale()), e.to_string());
                } else if e.is_response() {
                    debug!("Sendmail response error: {e:?}");
                    err!(i18n::mail_sendmail_response_error(&CONFIG.default_locale()), e.to_string());
                }
                debug!("Sendmail error: {e:?}");
                err!(i18n::mail_sendmail_error(&CONFIG.default_locale()), e.to_string());
            }
        }
    } else {
        match smtp_transport().send(email).await {
            Ok(_) => Ok(()),
            // Match some common errors and make them more user friendly
            Err(e) => {
                if e.is_client() {
                    debug!("SMTP client error: {e:#?}");
                    err!(i18n::mail_smtp_client_error(&CONFIG.default_locale()), e.to_string());
                } else if e.is_transient() {
                    debug!("SMTP 4xx error: {e:#?}");
                    err!(i18n::mail_smtp_4xx_error(&CONFIG.default_locale()), e.to_string());
                } else if e.is_permanent() {
                    debug!("SMTP 5xx error: {e:#?}");
                    let mut msg = e.to_string();
                    // Add a special check for 535 to add a more descriptive message
                    if msg.contains("(535)") {
                        msg = format!("{msg} - Authentication credentials invalid");
                    }
                    err!(i18n::mail_smtp_5xx_error(&CONFIG.default_locale()), msg);
                } else if e.is_timeout() {
                    debug!("SMTP timeout error: {e:#?}");
                    err!(i18n::mail_smtp_timeout_error(&CONFIG.default_locale()), e.to_string());
                } else if e.is_tls() {
                    debug!("SMTP encryption error: {e:#?}");
                    err!(i18n::mail_smtp_encryption_error(&CONFIG.default_locale()), e.to_string());
                }
                debug!("SMTP error: {e:#?}");
                err!(i18n::mail_smtp_error(&CONFIG.default_locale()), e.to_string());
            }
        }
    }
}

async fn send_email(address: &str, subject: &str, body_html: String, body_text: String) -> EmptyResult {
    let smtp_from = Address::from_str(&CONFIG.smtp_from())?;

    let body = if CONFIG.smtp_embed_images() {
        let logo_gray_body = Body::new(crate::api::STATIC_FILES["logo-gray.png"].bytes.to_vec());
        let mail_github_body = Body::new(crate::api::STATIC_FILES["mail-github.png"].bytes.to_vec());
        MultiPart::alternative().singlepart(SinglePart::plain(body_text)).multipart(
            MultiPart::related()
                .singlepart(SinglePart::html(body_html))
                .singlepart(
                    Attachment::new_inline(String::from("logo-gray.png"))
                        .body(logo_gray_body, "image/png".parse().unwrap()),
                )
                .singlepart(
                    Attachment::new_inline(String::from("mail-github.png"))
                        .body(mail_github_body, "image/png".parse().unwrap()),
                ),
        )
    } else {
        MultiPart::alternative_plain_html(body_text, body_html)
    };

    let email = Message::builder()
        .message_id(Some(format!("<{}@{}>", crate::util::get_uuid(), smtp_from.domain())))
        .to(Mailbox::new(None, Address::from_str(address)?))
        .from(Mailbox::new(Some(CONFIG.smtp_from_name()), smtp_from))
        .subject(subject)
        .multipart(body)?;

    send_with_selected_transport(email).await
}
