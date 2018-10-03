use native_tls::{Protocol, TlsConnector};
use lettre::{Transport, SmtpTransport, SmtpClient, ClientTlsParameters, ClientSecurity};
use lettre::smtp::ConnectionReuseParameters;
use lettre::smtp::authentication::Credentials;
use lettre_email::EmailBuilder;

use MailConfig;

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

    let smtp_client = SmtpClient::new(
        (config.smtp_host.as_str(), config.smtp_port),
        client_security,
    ).unwrap();

    let smtp_client = match (&config.smtp_username, &config.smtp_password) {
        (Some(user), Some(pass)) => smtp_client.credentials(Credentials::new(user.clone(), pass.clone())),
        _ => smtp_client,
    };

    smtp_client
        .smtp_utf8(true)
        .connection_reuse(ConnectionReuseParameters::NoReuse)
        .transport()
}

pub fn send_password_hint(address: &str, hint: Option<String>, config: &MailConfig) -> Result<(), String> {
    let (subject, body) = if let Some(hint) = hint {
        ("Your master password hint",
         format!(
            "You (or someone) recently requested your master password hint.\n\n\
             Your hint is:  \"{}\"\n\n\
             If you did not request your master password hint you can safely ignore this email.\n",
            hint))
    } else {
        ("Sorry, you have no password hint...",
         "Sorry, you have not specified any password hint...\n".into())
    };

    let email = EmailBuilder::new()
        .to(address)
        .from((config.smtp_from.clone(), "Bitwarden-rs"))
        .subject(subject)
        .body(body)
        .build()
        .map_err(|e| e.to_string())?;

    mailer(config)
        .send(email.into())
        .map_err(|e| e.to_string())
        .and(Ok(()))
}
