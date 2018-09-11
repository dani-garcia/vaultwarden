use std::error::Error;
use native_tls::{Protocol, TlsConnector};
use lettre::{EmailTransport, SmtpTransport, ClientTlsParameters, ClientSecurity};
use lettre::smtp::{ConnectionReuseParameters, SmtpTransportBuilder};
use lettre::smtp::authentication::Credentials;
use lettre_email::EmailBuilder;

use MailConfig;

fn mailer(config: &MailConfig) -> SmtpTransport {
    let client_security = if config.smtp_ssl {
        let mut tls_builder = TlsConnector::builder().unwrap();
        tls_builder.supported_protocols(&[Protocol::Tlsv11, Protocol::Tlsv12]).unwrap();
        ClientSecurity::Required(
            ClientTlsParameters::new(config.smtp_host.to_owned(), tls_builder.build().unwrap())
        )
    } else {
        ClientSecurity::None
    };

    let smtp_transport = SmtpTransportBuilder::new(
        (config.smtp_host.to_owned().as_str(), config.smtp_port),
        client_security
    ).unwrap();

    let smtp_transport = match (&config.smtp_username, &config.smtp_password) {
        (Some(username), Some(password)) => {
            smtp_transport.credentials(Credentials::new(username.to_owned(), password.to_owned()))
        },
        (_, _) => smtp_transport,
    };

    smtp_transport
        .smtp_utf8(true)
        .connection_reuse(ConnectionReuseParameters::NoReuse)
        .build()
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
         "Sorry, you have not specified any password hint...\n".to_string())
    };

    let email = EmailBuilder::new()
        .to(address)
        .from((config.smtp_from.to_owned(), "Bitwarden-rs"))
        .subject(subject)
        .body(body)
        .build().unwrap();

    match mailer(config).send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.description().to_string()),
    }
}
