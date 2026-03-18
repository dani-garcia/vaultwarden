use chrono::{NaiveDateTime, Utc};
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::{env::consts::EXE_SUFFIX, str::FromStr};
use tokio::sync::RwLock;

use lettre::{
    message::{Attachment, Body, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::{Credentials, Mechanism as SmtpAuthMechanism},
    transport::smtp::client::{Tls, TlsParameters},
    transport::smtp::extension::ClientId,
    Address, AsyncSendmailTransport, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};

use crate::{
    api::EmptyResult,
    auth::{
        encode_jwt, generate_delete_claims, generate_emergency_access_invite_claims, generate_invite_claims,
        generate_verify_email_claims,
    },
    db::models::{Device, DeviceType, EmergencyAccessId, MembershipId, OrganizationId, User, UserId, XOAuth2},
    error::Error,
    CONFIG,
};

use crate::http_client::make_http_request;

// OAuth2 Token structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct TokenRefreshResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    token_type: String,
}

pub async fn refresh_oauth2_token() -> Result<OAuth2Token, Error> {
    let conn = crate::db::get_conn().await?;
    let refresh_token = if let Some(x) = XOAuth2::find_by_id("smtp".to_string(), &conn).await {
        x.refresh_token
    } else {
        CONFIG.smtp_oauth2_refresh_token().ok_or("OAuth2 Refresh Token not configured")?
    };

    let client_id = CONFIG.smtp_oauth2_client_id().ok_or("OAuth2 Client ID not configured")?;
    let client_secret = CONFIG.smtp_oauth2_client_secret().ok_or("OAuth2 Client Secret not configured")?;
    let token_url = CONFIG.smtp_oauth2_token_url().ok_or("OAuth2 Token URL not configured")?;

    let form_params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
    ];

    let response = match make_http_request(reqwest::Method::POST, &token_url)?.form(&form_params).send().await {
        Ok(res) => res,
        Err(e) => err!(format!("OAuth2 Token Refresh Error: {e}")),
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| String::from("Unable to read response body"));
        err!("OAuth2 Token Refresh Failed", format!("HTTP {status}: {body}"));
    }

    let token_response: TokenRefreshResponse = match response.json().await {
        Ok(res) => res,
        Err(e) => err!(format!("OAuth2 Token Parse Error: {e}")),
    };

    let expires_at = token_response.expires_in.map(|expires_in| Utc::now().timestamp() + expires_in);

    let new_token = OAuth2Token {
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token.or(Some(refresh_token)),
        expires_at,
        token_type: token_response.token_type,
    };

    if let Some(ref new_refresh) = new_token.refresh_token {
        XOAuth2::new("smtp".to_string(), new_refresh.clone()).save(&conn).await?;
    }

    Ok(new_token)
}

async fn get_valid_oauth2_token() -> Result<OAuth2Token, Error> {
    static TOKEN_CACHE: LazyLock<RwLock<Option<OAuth2Token>>> = LazyLock::new(|| RwLock::new(None));

    {
        let token_cache = TOKEN_CACHE.read().await;
        if let Some(token) = token_cache.as_ref() {
            // Check if token is still valid (with 5 min buffer)
            if let Some(expires_at) = token.expires_at {
                let now = Utc::now().timestamp();
                if now + 300 < expires_at {
                    return Ok(token.clone());
                }
            }
        }
    }

    // Refresh token
    let mut token_cache = TOKEN_CACHE.write().await;

    // Double check
    if let Some(token) = token_cache.as_ref() {
        if let Some(expires_at) = token.expires_at {
            let now = Utc::now().timestamp();
            if now + 300 < expires_at {
                return Ok(token.clone());
            }
        }
    }

    let new_token = refresh_oauth2_token().await?;
    *token_cache = Some(new_token.clone());

    Ok(new_token)
}

fn sendmail_transport() -> AsyncSendmailTransport<Tokio1Executor> {
    if let Some(command) = CONFIG.sendmail_command() {
        AsyncSendmailTransport::new_with_command(command)
    } else {
        AsyncSendmailTransport::new_with_command(format!("sendmail{EXE_SUFFIX}"))
    }
}

async fn smtp_transport() -> AsyncSmtpTransport<Tokio1Executor> {
    use std::time::Duration;
    let host = CONFIG.smtp_host().unwrap();

    let smtp_client = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.as_str())
        .port(CONFIG.smtp_port())
        .timeout(Some(Duration::from_secs(CONFIG.smtp_timeout())));

    // Determine security
    let smtp_client = if CONFIG.smtp_security() != *"off" {
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
    } else {
        smtp_client
    };

    // Handle authentication - OAuth2 or traditional
    let smtp_client = match (CONFIG.smtp_username(), CONFIG.smtp_password(), CONFIG.smtp_oauth2_client_id()) {
        (Some(user), Some(pass), None) => {
            // Traditional authentication with username and password
            smtp_client.credentials(Credentials::new(user, pass))
        }
        (Some(user), None, Some(_)) => {
            // OAuth2 authentication
            match get_valid_oauth2_token().await {
                Ok(token) => {
                    // Pass the access token directly as the password.
                    // Note: This requires the Xoauth2 mechanism to be enabled for lettre to format it correctly.
                    smtp_client.credentials(Credentials::new(user, token.access_token))
                }
                Err(e) => {
                    error!("Error fetching OAuth2 token: {}", e);
                    warn!("Failed to get OAuth2 token, SMTP transport may not work properly");
                    smtp_client
                }
            }
        }
        (Some(user), Some(pass), Some(_)) => {
            // Both password and OAuth2 configured - prefer OAuth2
            warn!("Both SMTP_PASSWORD and SMTP_OAUTH2_CLIENT_ID are set. Using OAuth2 authentication.");
            match get_valid_oauth2_token().await {
                Ok(token) => {
                    // Pass the access token directly as password - lettre's Xoauth2 mechanism
                    // will format it correctly as: user={user}\x01auth=Bearer {token}\x01\x01
                    smtp_client.credentials(Credentials::new(user, token.access_token))
                }
                Err(e) => {
                    error!("Error fetching OAuth2 token: {}", e);
                    warn!("Falling back to password authentication");
                    smtp_client.credentials(Credentials::new(user, pass))
                }
            }
        }
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

            if !selected_mechanisms.is_empty() {
                smtp_client.authentication(selected_mechanisms)
            } else {
                // Only show a warning, and return without setting an actual authentication mechanism
                warn!("No valid SMTP Auth mechanism found for '{mechanism}', using default values");
                smtp_client
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

fn get_text(template_name: &'static str, data: serde_json::Value) -> Result<(String, String, String), Error> {
    let mut data = data;
    sanitize_data(&mut data);
    let (subject_html, body_html) = get_template(&format!("{template_name}.html"), &data)?;
    let (_subject_text, body_text) = get_template(template_name, &data)?;
    Ok((subject_html, body_html, body_text))
}

fn get_template(template_name: &str, data: &serde_json::Value) -> Result<(String, String), Error> {
    let text = CONFIG.render_template(template_name, data)?;
    let mut text_split = text.split("<!---------------->");

    let subject = match text_split.next() {
        Some(s) => s.trim().to_string(),
        None => err!("Template doesn't contain subject"),
    };

    let body = match text_split.next() {
        Some(s) => s.trim().to_string(),
        None => err!("Template doesn't contain body"),
    };

    if text_split.next().is_some() {
        err!("Template contains more than one body");
    }

    Ok((subject, body))
}

pub async fn send_password_hint(address: &str, hint: Option<String>) -> EmptyResult {
    let template_name = if hint.is_some() {
        "email/pw_hint_some"
    } else {
        "email/pw_hint_none"
    };

    let (subject, body_html, body_text) = get_text(
        template_name,
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "hint": hint,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_delete_account(address: &str, user_id: &UserId) -> EmptyResult {
    let claims = generate_delete_claims(user_id.to_string());
    let delete_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/delete_account",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": delete_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_verify_email(address: &str, user_id: &UserId) -> EmptyResult {
    let claims = generate_verify_email_claims(user_id);
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/verify_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_register_verify_email(email: &str, token: &str) -> EmptyResult {
    let mut query = url::Url::parse("https://query.builder").unwrap();
    query.query_pairs_mut().append_pair("email", email).append_pair("token", token);
    let query_string = match query.query() {
        None => err!("Failed to build verify URL query parameters"),
        Some(query) => query,
    };

    let (subject, body_html, body_text) = get_text(
        "email/register_verify_email",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/finish-signup/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "email": email,
        }),
    )?;

    send_email(email, &subject, body_html, body_text).await
}

pub async fn send_welcome(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/welcome",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_welcome_must_verify(address: &str, user_id: &UserId) -> EmptyResult {
    let claims = generate_verify_email_claims(user_id);
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/welcome_must_verify",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": user_id,
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_2fa_removed_from_org(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/send_2fa_removed_from_org",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_single_org_removed_from_org(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/send_single_org_removed_from_org",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
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
    );
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
        if user.private_key.is_some() {
            query_params.append_pair("orgUserHasExistingUser", "true");
        }
    }

    let Some(query_string) = query.query() else {
        err!("Failed to build invite URL query parameters")
    };

    let (subject, body_html, body_text) = get_text(
        "email/send_org_invite",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/accept-organization/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
    )?;

    send_email(&user.email, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite(
    address: &str,
    user_id: UserId,
    emer_id: EmergencyAccessId,
    grantor_name: &str,
    grantor_email: &str,
) -> EmptyResult {
    let claims = generate_emergency_access_invite_claims(
        user_id,
        String::from(address),
        emer_id.clone(),
        String::from(grantor_name),
        String::from(grantor_email),
    );

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
        err!("Failed to build emergency invite URL query parameters")
    };

    let (subject, body_html, body_text) = get_text(
        "email/send_emergency_access_invite",
        json!({
            // `url.Url` would place the anchor `#` after the query parameters
            "url": format!("{}/#/accept-emergency/?{query_string}", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite_accepted(address: &str, grantee_email: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_invite_accepted",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_email": grantee_email,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite_confirmed(address: &str, grantor_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_approved(address: &str, grantor_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_approved",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_initiated(
    address: &str,
    grantee_name: &str,
    atype: &str,
    wait_time_days: &i32,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_initiated",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
            "wait_time_days": wait_time_days,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_reminder(
    address: &str,
    grantee_name: &str,
    atype: &str,
    days_left: &str,
) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_reminder",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
            "days_left": days_left,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_rejected(address: &str, grantor_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_rejected",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_timed_out(address: &str, grantee_name: &str, atype: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_timed_out",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "grantee_name": grantee_name,
            "atype": atype,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite_accepted(new_user_email: &str, address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_accepted",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "email": new_user_email,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite_confirmed(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_new_device_logged_in(address: &str, ip: &str, dt: &NaiveDateTime, device: &Device) -> EmptyResult {
    use crate::util::upcase_first;

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "device_name": upcase_first(&device.name),
            "device_type": DeviceType::from_i32(device.atype).to_string(),
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_incomplete_2fa_login(
    address: &str,
    ip: &str,
    dt: &NaiveDateTime,
    device_name: &str,
    device_type: &str,
) -> EmptyResult {
    use crate::util::upcase_first;

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
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
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_token(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/twofactor_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_change_email(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/change_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_change_email_existing(address: &str, acting_address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/change_email_existing",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "existing_address": address,
            "acting_address": acting_address,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_change_email_invited(address: &str, acting_address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/change_email_invited",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "existing_address": address,
            "acting_address": acting_address,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_sso_change_email(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/sso_change_email",
        json!({
            "url": format!("{}/#/settings/account", CONFIG.domain()),
            "img_src": CONFIG._smtp_img_src(),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_test(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/smtp_test",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_admin_reset_password(address: &str, user_name: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/admin_reset_password",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_name": user_name,
            "org_name": org_name,
        }),
    )?;
    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_protected_action_token(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/protected_action",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

async fn send_with_selected_transport(email: Message) -> EmptyResult {
    if CONFIG.use_sendmail() {
        match sendmail_transport().send(email).await {
            Ok(_) => Ok(()),
            // Match some common errors and make them more user friendly
            Err(e) => {
                if e.is_client() {
                    debug!("Sendmail client error: {e:?}");
                    err!(format!("Sendmail client error: {e}"));
                } else if e.is_response() {
                    debug!("Sendmail response error: {e:?}");
                    err!(format!("Sendmail response error: {e}"));
                } else {
                    debug!("Sendmail error: {e:?}");
                    err!(format!("Sendmail error: {e}"));
                }
            }
        }
    } else {
        match smtp_transport().await.send(email).await {
            Ok(_) => Ok(()),
            // Match some common errors and make them more user friendly
            Err(e) => {
                if e.is_client() {
                    debug!("SMTP client error: {e:#?}");
                    err!(format!("SMTP client error: {e}"));
                } else if e.is_transient() {
                    debug!("SMTP 4xx error: {e:#?}");
                    err!(format!("SMTP 4xx error: {e}"));
                } else if e.is_permanent() {
                    debug!("SMTP 5xx error: {e:#?}");
                    let mut msg = e.to_string();
                    // Add a special check for 535 to add a more descriptive message
                    if msg.contains("(535)") {
                        msg = format!("{msg} - Authentication credentials invalid");
                    }
                    err!(format!("SMTP 5xx error: {msg}"));
                } else if e.is_timeout() {
                    debug!("SMTP timeout error: {e:#?}");
                    err!(format!("SMTP timeout error: {e}"));
                } else if e.is_tls() {
                    debug!("SMTP encryption error: {e:#?}");
                    err!(format!("SMTP encryption error: {e}"));
                } else {
                    debug!("SMTP error: {e:#?}");
                    err!(format!("SMTP error: {e}"));
                }
            }
        }
    }
}

async fn send_email(address: &str, subject: &str, body_html: String, body_text: String) -> EmptyResult {
    let smtp_from = Address::from_str(&CONFIG.smtp_from())?;

    let body = if CONFIG.smtp_embed_images() {
        let logo_gray_body = Body::new(crate::api::static_files("logo-gray.png").unwrap().1.to_vec());
        let mail_github_body = Body::new(crate::api::static_files("mail-github.png").unwrap().1.to_vec());
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
