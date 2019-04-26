use lettre::smtp::authentication::Credentials;
use lettre::smtp::ConnectionReuseParameters;
use lettre::{ClientSecurity, ClientTlsParameters, SmtpClient, SmtpTransport, Transport};
use lettre_email::{EmailBuilder, MimeMultipartType, PartBuilder};
use native_tls::{Protocol, TlsConnector};
use quoted_printable::encode_to_str;

use crate::api::EmptyResult;
use crate::auth::{encode_jwt, generate_invite_claims};
use crate::error::Error;
use crate::CONFIG;

fn mailer() -> SmtpTransport {
    let host = CONFIG.smtp_host().unwrap();

    let client_security = if CONFIG.smtp_ssl() {
        let tls = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv11))
            .build()
            .unwrap();

        let params = ClientTlsParameters::new(host.clone(), tls);

        if CONFIG.smtp_explicit_tls() {
            ClientSecurity::Wrapper(params)
        } else {
            ClientSecurity::Required(params)
        }
    } else {
        ClientSecurity::None
    };

    let smtp_client = SmtpClient::new((host.as_str(), CONFIG.smtp_port()), client_security).unwrap();

    let smtp_client = match (&CONFIG.smtp_username(), &CONFIG.smtp_password()) {
        (Some(user), Some(pass)) => smtp_client.credentials(Credentials::new(user.clone(), pass.clone())),
        _ => smtp_client,
    };

    smtp_client
        .smtp_utf8(true)
        .connection_reuse(ConnectionReuseParameters::NoReuse)
        .transport()
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

    let body = match text_split.next() {
        Some(s) => s.trim().to_string(),
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

    send_email(&address, &subject, &body_html, &body_text)
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
        invited_by_email.clone(),
    );
    let invite_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/send_org_invite",
        json!({
            "url": CONFIG.domain(),
            "org_id": org_id.unwrap_or_else(|| "_".to_string()),
            "org_user_id": org_user_id.unwrap_or_else(|| "_".to_string()),
            "email": address,
            "org_name": org_name,
            "token": invite_token,
        }),
    )?;

    send_email(&address, &subject, &body_html, &body_text)
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

    send_email(&address, &subject, &body_html, &body_text)
}

pub fn send_invite_confirmed(address: &str, org_name: &str) -> EmptyResult {
    let (subject, body_html, body_text) = get_text(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.domain(),
            "org_name": org_name,
        }),
    )?;

    send_email(&address, &subject, &body_html, &body_text)
}

fn send_email(address: &str, subject: &str, body_html: &str, body_text: &str) -> EmptyResult {
    let html = PartBuilder::new()
        .body(encode_to_str(body_html))
        .header(("Content-Type", "text/html; charset=utf-8"))
        .header(("Content-Transfer-Encoding", "quoted-printable"))
        .build();

    let text = PartBuilder::new()
        .body(encode_to_str(body_text))
        .header(("Content-Type", "text/plain; charset=utf-8"))
        .header(("Content-Transfer-Encoding", "quoted-printable"))
        .build();

    let alternative = PartBuilder::new()
        .message_type(MimeMultipartType::Alternative)
        .child(text)
        .child(html);

    let email = EmailBuilder::new()
        .to(address)
        .from((CONFIG.smtp_from().as_str(), CONFIG.smtp_from_name().as_str()))
        .subject(subject)
        .child(alternative.build())
        .build()
        .map_err(|e| Error::new("Error building email", e.to_string()))?;

    let mut transport = mailer();

    let result = transport
        .send(email.into())
        .map_err(|e| Error::new("Error sending email", e.to_string()))
        .and(Ok(()));

    // Explicitly close the connection, in case of error
    transport.close();
    result
}
