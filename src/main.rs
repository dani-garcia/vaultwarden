#![feature(proc_macro_hygiene, decl_macro, vec_remove_item, try_trait)]
#![recursion_limit = "128"]
#![allow(proc_macro_derive_resolution_fallback)] // TODO: Remove this when diesel update fixes warnings

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate derive_more;
#[macro_use]
extern crate num_derive;

use handlebars::Handlebars;
use rocket::{fairing::AdHoc, Rocket};

use std::{
    path::Path,
    process::{exit, Command},
};

#[macro_use]
mod error;
mod api;
mod auth;
mod crypto;
mod db;
mod mail;
mod util;

fn init_rocket() -> Rocket {
    rocket::ignite()
        .mount("/", api::web_routes())
        .mount("/api", api::core_routes())
        .mount("/admin", api::admin_routes())
        .mount("/identity", api::identity_routes())
        .mount("/icons", api::icons_routes())
        .mount("/notifications", api::notifications_routes())
        .manage(db::init_pool())
        .manage(api::start_notification_server())
        .attach(util::AppHeaders())
        .attach(unofficial_warning())
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[allow(unused_imports)]
mod migrations {
    embed_migrations!();

    pub fn run_migrations() {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = crate::db::get_connection().expect("Can't conect to DB");

        use std::io::stdout;
        embedded_migrations::run_with_output(&connection, &mut stdout()).expect("Can't run migrations");
    }
}

fn main() {
    if CONFIG.extended_logging {
        init_logging().ok();
    }

    check_db();
    check_rsa_keys();
    check_web_vault();
    migrations::run_migrations();

    init_rocket().launch();
}

fn init_logging() -> Result<(), fern::InitError> {
    let mut logger = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .level_for("hyper", log::LevelFilter::Warn)
        .level_for("rustls", log::LevelFilter::Warn)
        .level_for("ws", log::LevelFilter::Info)
        .level_for("multipart", log::LevelFilter::Info)
        .chain(std::io::stdout());

    if let Some(log_file) = CONFIG.log_file.as_ref() {
        logger = logger.chain(fern::log_file(log_file)?);
    }

    logger = chain_syslog(logger);
    logger.apply()?;

    Ok(())
}

#[cfg(not(feature = "enable_syslog"))]
fn chain_syslog(logger: fern::Dispatch) -> fern::Dispatch {
    logger
}

#[cfg(feature = "enable_syslog")]
fn chain_syslog(logger: fern::Dispatch) -> fern::Dispatch {
    let syslog_fmt = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_USER,
        hostname: None,
        process: "bitwarden_rs".into(),
        pid: 0,
    };

    match syslog::unix(syslog_fmt) {
        Ok(sl) => logger.chain(sl),
        Err(e) => {
            error!("Unable to connect to syslog: {:?}", e);
            logger
        }
    }
}

fn check_db() {
    let path = Path::new(&CONFIG.database_url);

    if let Some(parent) = path.parent() {
        use std::fs;
        if fs::create_dir_all(parent).is_err() {
            error!("Error creating database directory");
            exit(1);
        }
    }

    // Turn on WAL in SQLite
    use diesel::RunQueryDsl;
    let connection = db::get_connection().expect("Can't conect to DB");
    diesel::sql_query("PRAGMA journal_mode=wal")
        .execute(&connection)
        .expect("Failed to turn on WAL");
}

fn check_rsa_keys() {
    // If the RSA keys don't exist, try to create them
    if !util::file_exists(&CONFIG.private_rsa_key) || !util::file_exists(&CONFIG.public_rsa_key) {
        info!("JWT keys don't exist, checking if OpenSSL is available...");

        Command::new("openssl").arg("version").output().unwrap_or_else(|_| {
            info!("Can't create keys because OpenSSL is not available, make sure it's installed and available on the PATH");
            exit(1);
        });

        info!("OpenSSL detected, creating keys...");

        let mut success = Command::new("openssl")
            .arg("genrsa")
            .arg("-out")
            .arg(&CONFIG.private_rsa_key_pem)
            .output()
            .expect("Failed to create private pem file")
            .status
            .success();

        success &= Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&CONFIG.private_rsa_key_pem)
            .arg("-outform")
            .arg("DER")
            .arg("-out")
            .arg(&CONFIG.private_rsa_key)
            .output()
            .expect("Failed to create private der file")
            .status
            .success();

        success &= Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&CONFIG.private_rsa_key)
            .arg("-inform")
            .arg("DER")
            .arg("-RSAPublicKey_out")
            .arg("-outform")
            .arg("DER")
            .arg("-out")
            .arg(&CONFIG.public_rsa_key)
            .output()
            .expect("Failed to create public der file")
            .status
            .success();

        if success {
            info!("Keys created correctly.");
        } else {
            error!("Error creating keys, exiting...");
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
        error!("Web vault is not found. Please follow the steps in the README to install it");
        exit(1);
    }
}

fn unofficial_warning() -> AdHoc {
    AdHoc::on_launch("Unofficial Warning", |_| {
        warn!("/--------------------------------------------------------------------\\");
        warn!("| This is an *unofficial* Bitwarden implementation, DO NOT use the   |");
        warn!("| official channels to report bugs/features, regardless of client.   |");
        warn!("| Report URL: https://github.com/dani-garcia/bitwarden_rs/issues/new |");
        warn!("\\--------------------------------------------------------------------/");
    })
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
        use crate::util::{get_env, get_env_or};

        // When SMTP_HOST is absent, we assume the user does not want to enable it.
        let smtp_host = match get_env("SMTP_HOST") {
            Some(host) => host,
            None => return None,
        };

        let smtp_from = get_env("SMTP_FROM").unwrap_or_else(|| {
            error!("Please specify SMTP_FROM to enable SMTP support.");
            exit(1);
        });

        let smtp_ssl = get_env_or("SMTP_SSL", true);
        let smtp_port = get_env("SMTP_PORT").unwrap_or_else(|| if smtp_ssl { 587u16 } else { 25u16 });

        let smtp_username = get_env("SMTP_USERNAME");
        let smtp_password = get_env("SMTP_PASSWORD").or_else(|| {
            if smtp_username.as_ref().is_some() {
                error!("SMTP_PASSWORD is mandatory when specifying SMTP_USERNAME.");
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

    icon_cache_ttl: u64,
    icon_cache_negttl: u64,

    private_rsa_key: String,
    private_rsa_key_pem: String,
    public_rsa_key: String,

    web_vault_folder: String,
    web_vault_enabled: bool,

    websocket_enabled: bool,
    websocket_url: String,

    extended_logging: bool,
    log_file: Option<String>,

    local_icon_extractor: bool,
    signups_allowed: bool,
    invitations_allowed: bool,
    admin_token: Option<String>,
    password_iterations: i32,
    show_password_hint: bool,

    domain: String,
    domain_set: bool,

    yubico_cred_set: bool,
    yubico_client_id: String,
    yubico_secret_key: String,
    yubico_server: Option<String>,

    mail: Option<MailConfig>,
    templates: Handlebars,
}

fn load_templates(path: String) -> Handlebars {
    let mut hb = Handlebars::new();

    macro_rules! reg {
        ($name:expr) => {
            let template = include_str!(concat!("static/templates/", $name, ".hbs"));
            hb.register_template_string($name, template).unwrap();
        };
    }

    // First register default templates here (use include_str?)
    reg!("email_invite_accepted");
    reg!("email_invite_confirmed");
    reg!("email_pw_hint_none");
    reg!("email_pw_hint_some");
    reg!("email_send_org_invite");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(".hbs", path).unwrap();

    hb
}

impl Config {
    fn load() -> Self {
        use crate::util::{get_env, get_env_or};
        dotenv::dotenv().ok();

        let df = get_env_or("DATA_FOLDER", "data".to_string());
        let key = get_env_or("RSA_KEY_FILENAME", format!("{}/{}", &df, "rsa_key"));

        let domain = get_env("DOMAIN");

        let yubico_client_id = get_env("YUBICO_CLIENT_ID");
        let yubico_secret_key = get_env("YUBICO_SECRET_KEY");

        Config {
            database_url: get_env_or("DATABASE_URL", format!("{}/{}", &df, "db.sqlite3")),
            icon_cache_folder: get_env_or("ICON_CACHE_FOLDER", format!("{}/{}", &df, "icon_cache")),
            attachments_folder: get_env_or("ATTACHMENTS_FOLDER", format!("{}/{}", &df, "attachments")),
            templates: load_templates(get_env_or("TEMPLATES_FOLDER", format!("{}/{}", &df, "templates"))),

            // icon_cache_ttl defaults to 30 days (30 * 24 * 60 * 60 seconds)
            icon_cache_ttl: get_env_or("ICON_CACHE_TTL", 2_592_000),
            // icon_cache_negttl defaults to 3 days (3 * 24 * 60 * 60 seconds)
            icon_cache_negttl: get_env_or("ICON_CACHE_NEGTTL", 259_200),

            private_rsa_key: format!("{}.der", &key),
            private_rsa_key_pem: format!("{}.pem", &key),
            public_rsa_key: format!("{}.pub.der", &key),

            web_vault_folder: get_env_or("WEB_VAULT_FOLDER", "web-vault/".into()),
            web_vault_enabled: get_env_or("WEB_VAULT_ENABLED", true),

            websocket_enabled: get_env_or("WEBSOCKET_ENABLED", false),
            websocket_url: format!(
                "{}:{}",
                get_env_or("WEBSOCKET_ADDRESS", "0.0.0.0".to_string()),
                get_env_or("WEBSOCKET_PORT", 3012)
            ),

            extended_logging: get_env_or("EXTENDED_LOGGING", true),
            log_file: get_env("LOG_FILE"),

            local_icon_extractor: get_env_or("LOCAL_ICON_EXTRACTOR", false),
            signups_allowed: get_env_or("SIGNUPS_ALLOWED", true),
            admin_token: get_env("ADMIN_TOKEN"),
            invitations_allowed: get_env_or("INVITATIONS_ALLOWED", true),
            password_iterations: get_env_or("PASSWORD_ITERATIONS", 100_000),
            show_password_hint: get_env_or("SHOW_PASSWORD_HINT", true),

            domain_set: domain.is_some(),
            domain: domain.unwrap_or("http://localhost".into()),

            yubico_cred_set: yubico_client_id.is_some() && yubico_secret_key.is_some(),
            yubico_client_id: yubico_client_id.unwrap_or("00000".into()),
            yubico_secret_key: yubico_secret_key.unwrap_or("AAAAAAA".into()),
            yubico_server: get_env("YUBICO_SERVER"),

            mail: MailConfig::load(),
        }
    }
}
