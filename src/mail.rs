use std::{str::FromStr};

use chrono::{DateTime, Local};
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use lettre::{
    message::{header, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::{Credentials, Mechanism as SmtpAuthMechanism},
    transport::smtp::client::{Tls, TlsParameters},
    transport::smtp::extension::ClientId,
    Address, SmtpTransport, Transport,
};

use crate::{
    api::EmptyResult,
    auth::{encode_jwt, generate_delete_claims, generate_invite_claims, generate_verify_email_claims},
    error::Error,
    CONFIG,
};

fn mailer() -> SmtpTransport {
    use std::time::Duration;
    let host = CONFIG.smtp_host().unwrap();

    let smtp_client = SmtpTransport::builder_dangerous(host.as_str())
        .port(CONFIG.smtp_port())
        .timeout(Some(Duration::from_secs(CONFIG.smtp_timeout())));

    // Determine security
    let smtp_client = if CONFIG.smtp_ssl() {
        let mut tls_parameters = TlsParameters::builder(host);
        if CONFIG.smtp_accept_invalid_hostnames() {
            tls_parameters.dangerous_accept_invalid_hostnames(true);
        }
        if CONFIG.smtp_accept_invalid_certs() {
            tls_parameters.dangerous_accept_invalid_certs(true);
        }
        let tls_parameters = tls_parameters.build().unwrap();

        if CONFIG.smtp_explicit_tls() {
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
                    if m.to_string().to_lowercase() == wanted_mechanism.trim_matches(|c| c == '"' || c == '\'' || c == ' ').to_lowercase() {
                        selected_mechanisms.push(*m);
                    }
                }
            };

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
    let (subject_html, body_html) = get_template(&format!("{}.html", template_name), &data)?;
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

    use newline_converter::unix2dos;
    let body = match text_split.next() {
        Some(s) => unix2dos(s.trim()).to_string(),
        None => err!("Template doesn't contain body"),
    };

    Ok((subject, body))
}

pub fn send_password_hint(address: &str, hint: Option<String>) -> EmptyResult {
    let template_name = if hint.is_some() {
        "email/pw_hint_some"
    } else {
        "email/pw_hint_none"
    };

    let (subject, body_html, body_text) = get_text(template_name, json!({ "hint": hint, "url": CONFIG.domain() }))?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_delete_account(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_delete_claims(uuid.to_string());
    let delete_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/delete_account",
        json!({
            "url": CONFIG.domain(),
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": delete_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_verify_email(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/verify_email",
        json!({
            "url": CONFIG.domain(),
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_welcome(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/welcome",
        json!({
            "url": CONFIG.domain(),
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_welcome_must_verify(address: &str, uuid: &str) -> EmptyResult {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/welcome_must_verify",
        json!({
            "url": CONFIG.domain(),
            "user_id": uuid,
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_invite(
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
            "org_id": org_id.as_deref().unwrap_or("_"),
            "org_user_id": org_user_id.as_deref().unwrap_or("_"),
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name": org_name,
            "token": invite_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_invite_accepted(new_user_email: &str, address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_accepted",
        json!({
            "url": CONFIG.domain(),
            "email": new_user_email,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_invite_confirmed(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_new_device_logged_in(address: &str, ip: &str, dt: &DateTime<Local>, device: &str) -> EmptyResult {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.domain(),
            "ip": ip,
            "device": device,
            "datetime": crate::util::format_datetime_local(dt, fmt),
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_token(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/twofactor_email",
        json!({
            "url": CONFIG.domain(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_change_email(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/change_email",
        json!({
            "url": CONFIG.domain(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

pub fn send_test(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/smtp_test",
        json!({
            "url": CONFIG.domain(),
        }),
    )?;

    send_email(address, &subject, body_html, body_text)
}

fn send_email(address: &str, subject: &str, body_html: String, body_text: String) -> EmptyResult {
    let address_split: Vec<&str> = address.rsplitn(2, '@').collect();
    if address_split.len() != 2 {
        err!("Invalid email address (no @)");
    }

    let domain_puny = match idna::domain_to_ascii_strict(address_split[0]) {
        Ok(d) => d,
        Err(_) => err!("Can't convert email domain to ASCII representation"),
    };

    let address = format!("{}@{}", address_split[1], domain_puny);

    let html = SinglePart::builder()
        // We force Base64 encoding because in the past we had issues with different encodings.
        .header(header::ContentTransferEncoding::Base64)
        .header(header::ContentType("text/html; charset=utf-8".parse()?))
        .body(body_html);

    let text = SinglePart::builder()
        // We force Base64 encoding because in the past we had issues with different encodings.
        .header(header::ContentTransferEncoding::Base64)
        .header(header::ContentType("text/plain; charset=utf-8".parse()?))
        .body(body_text);

    let smtp_from = &CONFIG.smtp_from();
    let email = Message::builder()
        .message_id(Some(format!("<{}@{}>", crate::util::get_uuid(), smtp_from.split('@').collect::<Vec<&str>>()[1] )))
        .to(Mailbox::new(None, Address::from_str(&address)?))
        .from(Mailbox::new(
            Some(CONFIG.smtp_from_name()),
            Address::from_str(smtp_from)?,
        ))
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(text)
                .singlepart(html)
        )?;

    match mailer().send(&email) {
        Ok(_) => Ok(()),
        // Match some common errors and make them more user friendly
        Err(e) => match e {
            lettre::transport::smtp::Error::Client(x) => {
                err!(format!("SMTP Client error: {}", x));
            },
            lettre::transport::smtp::Error::Transient(x) => {
                err!(format!("SMTP 4xx error: {:?}", x.message));
            },
            lettre::transport::smtp::Error::Permanent(x) => {
                err!(format!("SMTP 5xx error: {:?}", x.message));
            },
            lettre::transport::smtp::Error::Io(x) => {
                err!(format!("SMTP IO error: {}", x));
            },
            // Fallback for all other errors
            _ => Err(e.into())
        }
    }
}
