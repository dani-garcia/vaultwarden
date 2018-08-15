use std::error::Error;
use native_tls::TlsConnector;
use native_tls::{Protocol};
use lettre::{EmailTransport, SmtpTransport, ClientTlsParameters, ClientSecurity};
use lettre::smtp::{ConnectionReuseParameters, SmtpTransportBuilder};
use lettre::smtp::authentication::{Credentials, Mechanism};
use lettre_email::EmailBuilder;

use MailConfig;

fn mailer(config: &MailConfig) -> SmtpTransport {
    let client_security = if config.smtp_ssl {
        let mut tls_builder = TlsConnector::builder().unwrap();
        tls_builder.supported_protocols(&[
            Protocol::Tlsv10, Protocol::Tlsv11, Protocol::Tlsv12
        ]).unwrap();

        ClientSecurity::Required(
            ClientTlsParameters::new(config.smtp_host.to_owned(), tls_builder.build().unwrap())
        )
    } else {
        ClientSecurity::None
    };

    SmtpTransportBuilder::new((config.smtp_host.to_owned().as_str(), config.smtp_port), client_security)
        .unwrap()
        .credentials(Credentials::new(config.smtp_username.to_owned(), config.smtp_password.to_owned()))
        .authentication_mechanism(Mechanism::Login)
        .smtp_utf8(true)
        .connection_reuse(ConnectionReuseParameters::ReuseUnlimited)
        .build()
}

pub fn send_password_hint(address: &str, hint: &str, config: &MailConfig) -> Result<(), String> {
    let email = EmailBuilder::new()
        .to(address)
        .from((config.smtp_from.to_owned(), "Bitwarden-rs"))
        .subject("Your Master Password Hint")
        .body(hint)
        .build().unwrap();

    match mailer(config).send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.description().to_string()),
    }
}
        
