use std::str::FromStr;

use chrono::NaiveDateTime;
use once_cell::sync::Lazy;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use lettre::{
    message::{Attachment, Body, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::{Credentials, Mechanism as SmtpAuthMechanism},
    transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters},
    transport::smtp::extension::ClientId,
    Address, AsyncSendmailTransport, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};

use crate::{
    api::EmptyResult,
    auth::{
        encode_jwt, generate_delete_claims, generate_emergency_access_invite_claims, generate_invite_claims,
        generate_verify_email_claims,
    },
    error::Error,
    CONFIG,
};

fn sendmail_transport() -> AsyncSendmailTransport<Tokio1Executor> {
    if let Some(command) = CONFIG.sendmail_command() {
        AsyncSendmailTransport::new_with_command(command)
    } else {
        AsyncSendmailTransport::new()
    }
}

static SMTP_ADDITIONAL_ROOT_CERTS: Lazy<Option<Vec<Certificate>>> = Lazy::new(|| {
    Some(
        CONFIG
            .smtp_additional_root_certs()?
            .split(';')
            .filter(|path| !path.is_empty())
            .map(|path| {
                let cert = std::fs::read(path)
                    .unwrap_or_else(|e| panic!("Error loading additional SMTP root certificate file {path}.\n{e}"));
                Certificate::from_pem(&cert).unwrap_or_else(|e| panic!("Error decoding certificate file {path}.\n{e}"))
            })
            .collect(),
    )
});

fn smtp_transport() -> AsyncSmtpTransport<Tokio1Executor> {
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
        if let Some(ref certs) = *SMTP_ADDITIONAL_ROOT_CERTS {
            for cert in certs {
                tls_parameters = tls_parameters.add_root_certificate(cert.clone());
            }
        }
        if !CONFIG.smtp_use_system_root_certs() {
            tls_parameters = tls_parameters.certificate_store(CertificateStore::None);
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

            if !selected_mechanisms.is_empty() {
                smtp_client.authentication(selected_mechanisms)
            } else {
                // Only show a warning, and return without setting an actual authentication mechanism
                warn!("No valid SMTP Auth mechanism found for '{}', using default values", mechanism);
                smtp_client
            }
        }
        _ => smtp_client,
    };

    smtp_client.build()
}

fn get_text(template_name: &'static str, data: serde_json::Value) -> Result<(String, String, String), Error> {
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

pub async fn send_delete_account(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_delete_claims(uuid.to_string());
    let delete_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/delete_account",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": delete_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_verify_email(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/verify_email",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
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

pub async fn send_welcome_must_verify(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/welcome_must_verify",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "user_id": uuid,
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
    address: &str,
    uuid: &str,
    org_id: Option<String>,
    org_user_id: Option<String>,
    org_name: &str,
    invited_by_email: Option<String>,
) -> EmptyResult {
    let claims = generate_invite_claims(
        uuid.to_string(),
        String::from(address),
        org_id.clone(),
        org_user_id.clone(),
        invited_by_email,
    );
    let invite_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/send_org_invite",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "org_id": org_id.as_deref().unwrap_or("_"),
            "org_user_id": org_user_id.as_deref().unwrap_or("_"),
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name_encoded": percent_encode(org_name.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name": org_name,
            "token": invite_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite(
    address: &str,
    uuid: &str,
    emer_id: &str,
    grantor_name: &str,
    grantor_email: &str,
) -> EmptyResult {
    let claims = generate_emergency_access_invite_claims(
        String::from(uuid),
        String::from(address),
        String::from(emer_id),
        String::from(grantor_name),
        String::from(grantor_email),
    );

    let invite_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/send_emergency_access_invite",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "emer_id": emer_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "grantor_name": grantor_name,
            "token": invite_token,
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

pub async fn send_new_device_logged_in(address: &str, ip: &str, dt: &NaiveDateTime, device: &str) -> EmptyResult {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "device": device,
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_incomplete_2fa_login(address: &str, ip: &str, dt: &NaiveDateTime, device: &str) -> EmptyResult {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/incomplete_2fa_login",
        json!({
            "url": CONFIG.domain(),
            "img_src": CONFIG._smtp_img_src(),
            "ip": ip,
            "device": device,
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
                    debug!("Sendmail client error: {:#?}", e);
                    err!(format!("Sendmail client error: {e}"));
                } else if e.is_response() {
                    debug!("Sendmail response error: {:#?}", e);
                    err!(format!("Sendmail response error: {e}"));
                } else {
                    debug!("Sendmail error: {:#?}", e);
                    err!(format!("Sendmail error: {e}"));
                }
            }
        }
    } else {
        match smtp_transport().send(email).await {
            Ok(_) => Ok(()),
            // Match some common errors and make them more user friendly
            Err(e) => {
                if e.is_client() {
                    debug!("SMTP client error: {:#?}", e);
                    err!(format!("SMTP client error: {e}"));
                } else if e.is_transient() {
                    debug!("SMTP 4xx error: {:#?}", e);
                    err!(format!("SMTP 4xx error: {e}"));
                } else if e.is_permanent() {
                    debug!("SMTP 5xx error: {:#?}", e);
                    let mut msg = e.to_string();
                    // Add a special check for 535 to add a more descriptive message
                    if msg.contains("(535)") {
                        msg = format!("{msg} - Authentication credentials invalid");
                    }
                    err!(format!("SMTP 5xx error: {msg}"));
                } else if e.is_timeout() {
                    debug!("SMTP timeout error: {:#?}", e);
                    err!(format!("SMTP timeout error: {e}"));
                } else if e.is_tls() {
                    debug!("SMTP encryption error: {:#?}", e);
                    err!(format!("SMTP encryption error: {e}"));
                } else {
                    debug!("SMTP error: {:#?}", e);
                    err!(format!("SMTP error: {e}"));
                }
            }
        }
    }
}

async fn send_email(address: &str, subject: &str, body_html: String, body_text: String) -> EmptyResult {
    let smtp_from = &CONFIG.smtp_from();

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
        .message_id(Some(format!("<{}@{}>", crate::util::get_uuid(), smtp_from.split('@').collect::<Vec<&str>>()[1])))
        .to(Mailbox::new(None, Address::from_str(address)?))
        .from(Mailbox::new(Some(CONFIG.smtp_from_name()), Address::from_str(smtp_from)?))
        .subject(subject)
        .multipart(body)?;

    send_with_selected_transport(email).await
}
