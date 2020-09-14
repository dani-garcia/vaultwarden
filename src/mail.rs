use std::{env, str::FromStr};

use chrono::{DateTime, Local};
use chrono_tz::Tz;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use lettre::{
    message::{header, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::{Credentials, Mechanism as SmtpAuthMechanism},
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

    // Determine security
    let smtp_client = if CONFIG.smtp_ssl() {
        if CONFIG.smtp_explicit_tls() {
            SmtpTransport::relay(host.as_str())
        } else {
            SmtpTransport::starttls_relay(host.as_str())
        }
    } else {
        Ok(SmtpTransport::builder_dangerous(host.as_str()))
    };

    let smtp_client = smtp_client.unwrap()
        .port(CONFIG.smtp_port())
        .timeout(Some(Duration::from_secs(CONFIG.smtp_timeout())));

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
            let allowed_mechanisms = vec![SmtpAuthMechanism::Plain, SmtpAuthMechanism::Login, SmtpAuthMechanism::Xoauth2];
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

pub fn format_datetime(dt: &DateTime<Local>) -> String {
    let fmt = "%A, %B %_d, %Y at %r %Z";

    // With a DateTime<Local>, `%Z` formats as the time zone's UTC offset
    // (e.g., `+00:00`). If the `TZ` environment variable is set, try to
    // format as a time zone abbreviation instead (e.g., `UTC`).
    if let Ok(tz) = env::var("TZ") {
        if let Ok(tz) = tz.parse::<Tz>() {
            return dt.with_timezone(&tz).format(fmt).to_string();
        }
    }

    // Otherwise, fall back to just displaying the UTC offset.
    dt.format(fmt).to_string()
}

pub fn send_password_hint(address: &str, hint: Option<String>) -> EmptyResult {
    let template_name = if hint.is_some() {
        "email/pw_hint_some"
    } else {
        "email/pw_hint_none"
    };

    let (subject, body_html, body_text) = get_text(template_name, json!({ "hint": hint, "url": CONFIG.domain() }))?;

    send_email(address, &subject, &body_html, &body_text)
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

    send_email(address, &subject, &body_html, &body_text)
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

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_welcome(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/welcome",
        json!({
            "url": CONFIG.domain(),
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
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

    send_email(address, &subject, &body_html, &body_text)
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
            "org_id": org_id.unwrap_or_else(|| "_".to_string()),
            "org_user_id": org_user_id.unwrap_or_else(|| "_".to_string()),
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name": org_name,
            "token": invite_token,
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
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

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_invite_confirmed(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_new_device_logged_in(address: &str, ip: &str, dt: &DateTime<Local>, device: &str) -> EmptyResult {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let (subject, body_html, body_text) = get_text(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.domain(),
            "ip": ip,
            "device": device,
            "datetime": format_datetime(dt),
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_token(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/twofactor_email",
        json!({
            "url": CONFIG.domain(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_change_email(address: &str, token: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/change_email",
        json!({
            "url": CONFIG.domain(),
            "token": token,
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
}

pub fn send_test(address: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/smtp_test",
        json!({
            "url": CONFIG.domain(),
        }),
    )?;

    send_email(address, &subject, &body_html, &body_text)
}

fn send_email(address: &str, subject: &str, body_html: &str, body_text: &str) -> EmptyResult {
    let address_split: Vec<&str> = address.rsplitn(2, '@').collect();
    if address_split.len() != 2 {
        err!("Invalid email address (no @)");
    }

    let domain_puny = match idna::domain_to_ascii_strict(address_split[0]) {
        Ok(d) => d,
        Err(_) => err!("Can't convert email domain to ASCII representation"),
    };

    let address = format!("{}@{}", address_split[1], domain_puny);

    let html = SinglePart::base64()
        .header(header::ContentType("text/html; charset=utf-8".parse()?))
        .body(body_html);

    let text = SinglePart::base64()
        .header(header::ContentType("text/plain; charset=utf-8".parse()?))
        .body(body_text);

    // The boundary generated by Lettre it self is mostly too large based on the RFC822, so we generate one our selfs.
    use uuid::Uuid;
    let boundary = format!("_Part_{}_", Uuid::new_v4().to_simple());
    let alternative = MultiPart::alternative().boundary(boundary).singlepart(text).singlepart(html);

    let email = Message::builder()
        .to(Mailbox::new(None, Address::from_str(&address)?))
        .from(Mailbox::new(
            Some(CONFIG.smtp_from_name()),
            Address::from_str(&CONFIG.smtp_from())?,
        ))
        .subject(subject)
        .multipart(alternative)?;

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
