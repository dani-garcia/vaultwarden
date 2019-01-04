use lettre::smtp::authentication::Credentials;
use lettre::smtp::ConnectionReuseParameters;
use lettre::{ClientSecurity, ClientTlsParameters, SmtpClient, SmtpTransport, Transport};
use lettre_email::EmailBuilder;
use native_tls::{Protocol, TlsConnector};

use crate::MailConfig;
use crate::CONFIG;

use crate::api::EmptyResult;
use crate::error::Error;

fn mailer(config: &MailConfig) -> SmtpTransport {
    let client_security = if config.smtp_ssl {
        let tls = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv11))
            .build()
            .unwrap();

        ClientSecurity::Required(ClientTlsParameters::new(config.smtp_host.clone(), tls))
    } else {
        ClientSecurity::None
    };

    let smtp_client = SmtpClient::new((config.smtp_host.as_str(), config.smtp_port), client_security).unwrap();

    let smtp_client = match (&config.smtp_username, &config.smtp_password) {
        (Some(user), Some(pass)) => smtp_client.credentials(Credentials::new(user.clone(), pass.clone())),
        _ => smtp_client,
    };

    smtp_client
        .smtp_utf8(true)
        .connection_reuse(ConnectionReuseParameters::NoReuse)
        .transport()
}

pub fn send_password_hint(address: &str, hint: Option<String>, config: &MailConfig) -> EmptyResult {
    let (subject, body) = if let Some(hint) = hint {
        (
            "Your master password hint",
            format!(
                "You (or someone) recently requested your master password hint.\n\n\
                 Your hint is:  \"{}\"\n\n\
                 If you did not request your master password hint you can safely ignore this email.\n",
                hint
            ),
        )
    } else {
        (
            "Sorry, you have no password hint...",
            "Sorry, you have not specified any password hint...\n".into(),
        )
    };

    send_email(&address, &subject, &body, &config)
}

pub fn send_invite(
    address: &str,
    org_id: &str,
    org_user_id: &str,
    token: &str,
    org_name: &str,
    config: &MailConfig,
) -> EmptyResult {
    let (subject, body) = {
        (format!("Join {}", &org_name),
        format!(
            "<html>
             <p>You have been invited to join the <b>{}</b> organization.<br><br>
             <a href=\"{}/#/accept-organization/?organizationId={}&organizationUserId={}&email={}&organizationName={}&token={}\">Click here to join</a></p>
             <p>If you do not wish to join this organization, you can safely ignore this email.</p>
             </html>",
            org_name, CONFIG.domain, org_id, org_user_id, address, org_name, token
        ))
    };

    send_email(&address, &subject, &body, &config)
}

pub fn send_invite_accepted(
    new_user_email: &str,
    address: &str,
    org_name: &str,
    config: &MailConfig,
) -> EmptyResult {
    let (subject, body) = {
        ("Invitation accepted",
        format!(
            "<html>
             <p>Your invitation to <b>{}</b> to join <b>{}</b> was accepted. Please log in to the bitwarden_rs server and confirm them from the organization management page.</p>
             </html>", new_user_email, org_name))
    };

    send_email(&address, &subject, &body, &config)
}

pub fn send_invite_confirmed(
    address: &str,
    org_name: &str,
    config: &MailConfig,
) -> EmptyResult {
    let (subject, body) = {
        (format!("Invitation to {} confirmed", org_name),
        format!(
            "<html>
             <p>Your invitation to join <b>{}</b> was accepted. It will now appear under the Organizations the next time you log into the web vault.</p>
             </html>", org_name))
    };

    send_email(&address, &subject, &body, &config)
}

fn send_email(address: &str, subject: &str, body: &str, config: &MailConfig) -> EmptyResult {
    let email = EmailBuilder::new()
    .to(address)
    .from((config.smtp_from.clone(), "Bitwarden-rs"))
    .subject(subject)
    .header(("Content-Type", "text/html"))
    .body(body)
    .build()
    .map_err(|e| Error::new("Error building email", e.to_string()))?;

mailer(config)
    .send(email.into())
    .map_err(|e| Error::new("Error sending email", e.to_string()))
    .and(Ok(()))
}