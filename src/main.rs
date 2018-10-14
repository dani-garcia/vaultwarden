#![feature(plugin, custom_derive, vec_remove_item, try_trait)]
#![plugin(rocket_codegen)]
#![recursion_limit="128"]
#![allow(proc_macro_derive_resolution_fallback)] // TODO: Remove this when diesel update fixes warnings
extern crate rocket;
extern crate rocket_contrib;
extern crate reqwest;
extern crate multipart;
extern crate ws;
extern crate rmpv;
extern crate chashmap;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
extern crate ring;
extern crate uuid;
extern crate chrono;
extern crate oath;
extern crate data_encoding;
extern crate jsonwebtoken as jwt;
extern crate u2f;
extern crate dotenv;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;
extern crate num_traits;
extern crate lettre;
extern crate lettre_email;
extern crate native_tls;
extern crate byteorder;

use std::{path::Path, process::{exit, Command}};
use rocket::Rocket;

#[macro_use]
mod util;

mod api;
mod db;
mod crypto;
mod auth;
mod mail;

fn init_rocket() -> Rocket {
    rocket::ignite()
        .mount("/", api::web_routes())
        .mount("/api", api::core_routes())
        .mount("/identity", api::identity_routes())
        .mount("/icons", api::icons_routes())
        .mount("/notifications", api::notifications_routes())
        .manage(db::init_pool())
        .manage(api::start_notification_server())
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[allow(unused_imports)]
mod migrations {
    embed_migrations!();

    pub fn run_migrations() {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = ::db::get_connection().expect("Can't conect to DB");

        use std::io::stdout;
        embedded_migrations::run_with_output(&connection, &mut stdout()).expect("Can't run migrations");
    }
}

fn main() {
    check_db();
    check_rsa_keys();
    check_web_vault();
    migrations::run_migrations();

    init_rocket().launch();
}

fn check_db() {
    let path = Path::new(&CONFIG.database_url);

    if let Some(parent) = path.parent() {
        use std::fs;
        if fs::create_dir_all(parent).is_err() {
            println!("Error creating database directory");
            exit(1);
        }
    }

    // Turn on WAL in SQLite
    use diesel::RunQueryDsl;
    let connection = db::get_connection().expect("Can't conect to DB");
    diesel::sql_query("PRAGMA journal_mode=wal").execute(&connection).expect("Failed to turn on WAL");
}

fn check_rsa_keys() {
    // If the RSA keys don't exist, try to create them
    if !util::file_exists(&CONFIG.private_rsa_key)
        || !util::file_exists(&CONFIG.public_rsa_key) {
        println!("JWT keys don't exist, checking if OpenSSL is available...");

        Command::new("openssl")
            .arg("version")
            .output().unwrap_or_else(|_| {
            println!("Can't create keys because OpenSSL is not available, make sure it's installed and available on the PATH");
            exit(1);
        });

        println!("OpenSSL detected, creating keys...");

        let mut success = Command::new("openssl").arg("genrsa")
            .arg("-out").arg(&CONFIG.private_rsa_key_pem)
            .output().expect("Failed to create private pem file")
            .status.success();

        success &= Command::new("openssl").arg("rsa")
            .arg("-in").arg(&CONFIG.private_rsa_key_pem)
            .arg("-outform").arg("DER")
            .arg("-out").arg(&CONFIG.private_rsa_key)
            .output().expect("Failed to create private der file")
            .status.success();

        success &= Command::new("openssl").arg("rsa")
            .arg("-in").arg(&CONFIG.private_rsa_key)
            .arg("-inform").arg("DER")
            .arg("-RSAPublicKey_out")
            .arg("-outform").arg("DER")
            .arg("-out").arg(&CONFIG.public_rsa_key)
            .output().expect("Failed to create public der file")
            .status.success();

        if success {
            println!("Keys created correctly.");
        } else {
            println!("Error creating keys, exiting...");
            exit(1);
        }
    }
}

fn check_web_vault() {
    if !CONFIG.web_vault_enabled {
        return;
    }

    let index_path = Path::new(&CONFIG.web_vault_folder).join("index.html");

    if !index_path.exists() {
        println!("Web vault is not found. Please follow the steps in the README to install it");
        exit(1);
    }
}

lazy_static! {
    // Load the config from .env or from environment variables
    static ref CONFIG: Config = Config::load();
}

#[derive(Debug)]
pub struct MailConfig {
    smtp_host: String,
    smtp_port: u16,
    smtp_ssl: bool,
    smtp_from: String,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
}

impl MailConfig {
    fn load() -> Option<Self> {
        use util::{get_env, get_env_or};

        // When SMTP_HOST is absent, we assume the user does not want to enable it.
        let smtp_host = match get_env("SMTP_HOST") {
            Some(host) => host,
            None => return None,
        };

        let smtp_from = get_env("SMTP_FROM").unwrap_or_else(|| {
            println!("Please specify SMTP_FROM to enable SMTP support.");
            exit(1);
        });

        let smtp_ssl = get_env_or("SMTP_SSL", true);
        let smtp_port = get_env("SMTP_PORT").unwrap_or_else(|| 
            if smtp_ssl { 
                587u16 
            } else { 
                25u16 
            }
        );

        let smtp_username = get_env("SMTP_USERNAME");
        let smtp_password = get_env("SMTP_PASSWORD").or_else(|| {
            if smtp_username.as_ref().is_some() {
                println!("SMTP_PASSWORD is mandatory when specifying SMTP_USERNAME.");
                exit(1);
            } else {
                None
            }
        });

        Some(MailConfig {
            smtp_host,
            smtp_port,
            smtp_ssl,
            smtp_from,
            smtp_username,
            smtp_password,
        })
    }
}

#[derive(Debug)]
pub struct Config {
    database_url: String,
    icon_cache_folder: String,
    attachments_folder: String,

    private_rsa_key: String,
    private_rsa_key_pem: String,
    public_rsa_key: String,

    web_vault_folder: String,
    web_vault_enabled: bool,

    websocket_enabled: bool,
    websocket_url: String,

    local_icon_extractor: bool,
    signups_allowed: bool,
    invitations_allowed: bool,
    server_admin_email: Option<String>,
    password_iterations: i32,
    show_password_hint: bool,

    domain: String,
    domain_set: bool,

    mail: Option<MailConfig>,
}

impl Config {
    fn load() -> Self {
        use util::{get_env, get_env_or};
        dotenv::dotenv().ok();

        let df = get_env_or("DATA_FOLDER", "data".to_string());
        let key = get_env_or("RSA_KEY_FILENAME", format!("{}/{}", &df, "rsa_key"));

        let domain = get_env("DOMAIN");

        Config {
            database_url: get_env_or("DATABASE_URL", format!("{}/{}", &df, "db.sqlite3")),
            icon_cache_folder: get_env_or("ICON_CACHE_FOLDER", format!("{}/{}", &df, "icon_cache")),
            attachments_folder: get_env_or("ATTACHMENTS_FOLDER", format!("{}/{}", &df, "attachments")),

            private_rsa_key: format!("{}.der", &key),
            private_rsa_key_pem: format!("{}.pem", &key),
            public_rsa_key: format!("{}.pub.der", &key),

            web_vault_folder: get_env_or("WEB_VAULT_FOLDER", "web-vault/".into()),
            web_vault_enabled: get_env_or("WEB_VAULT_ENABLED", true),

            websocket_enabled: get_env_or("WEBSOCKET_ENABLED", false),
            websocket_url: format!("{}:{}", get_env_or("WEBSOCKET_ADDRESS", "0.0.0.0".to_string()), get_env_or("WEBSOCKET_PORT", 3012)),

            local_icon_extractor: get_env_or("LOCAL_ICON_EXTRACTOR", false),
            signups_allowed: get_env_or("SIGNUPS_ALLOWED", true),
            server_admin_email: get_env("SERVER_ADMIN_EMAIL"),
            invitations_allowed: get_env_or("INVITATIONS_ALLOWED", true),
            password_iterations: get_env_or("PASSWORD_ITERATIONS", 100_000),
            show_password_hint: get_env_or("SHOW_PASSWORD_HINT", true),

            domain_set: domain.is_some(),
            domain: domain.unwrap_or("http://localhost".into()),

            mail: MailConfig::load(),
        }
    }
}
