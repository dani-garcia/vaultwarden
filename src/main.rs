#![feature(proc_macro_hygiene, decl_macro, vec_remove_item, try_trait)]
#![recursion_limit = "256"]

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

use rocket::{fairing::AdHoc, Rocket};

use std::{
    path::Path,
    process::{exit, Command},
};

#[macro_use]
mod error;
mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod mail;
mod util;

pub use config::CONFIG;

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
    if CONFIG.extended_logging() {
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
        .level_for("handlebars", log::LevelFilter::Warn)
        .level_for("ws", log::LevelFilter::Info)
        .level_for("multipart", log::LevelFilter::Info)
        .level_for("html5ever", log::LevelFilter::Info)
        .chain(std::io::stdout());

    if let Some(log_file) = CONFIG.log_file() {
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
    let url = CONFIG.database_url();
    let path = Path::new(&url);

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
    if !util::file_exists(&CONFIG.private_rsa_key()) || !util::file_exists(&CONFIG.public_rsa_key()) {
        info!("JWT keys don't exist, checking if OpenSSL is available...");

        Command::new("openssl").arg("version").output().unwrap_or_else(|_| {
            info!("Can't create keys because OpenSSL is not available, make sure it's installed and available on the PATH");
            exit(1);
        });

        info!("OpenSSL detected, creating keys...");

        let mut success = Command::new("openssl")
            .arg("genrsa")
            .arg("-out")
            .arg(&CONFIG.private_rsa_key_pem())
            .output()
            .expect("Failed to create private pem file")
            .status
            .success();

        success &= Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&CONFIG.private_rsa_key_pem())
            .arg("-outform")
            .arg("DER")
            .arg("-out")
            .arg(&CONFIG.private_rsa_key())
            .output()
            .expect("Failed to create private der file")
            .status
            .success();

        success &= Command::new("openssl")
            .arg("rsa")
            .arg("-in")
            .arg(&CONFIG.private_rsa_key())
            .arg("-inform")
            .arg("DER")
            .arg("-RSAPublicKey_out")
            .arg("-outform")
            .arg("DER")
            .arg("-out")
            .arg(&CONFIG.public_rsa_key())
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
    if !CONFIG.web_vault_enabled() {
        return;
    }

    let index_path = Path::new(&CONFIG.web_vault_folder()).join("index.html");

    if !index_path.exists() {
        error!("Web vault is not found. To install it, please follow the steps in https://github.com/dani-garcia/bitwarden_rs/wiki/Building-binary#install-the-web-vault");
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
