#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]
#![allow(proc_macro_derive_resolution_fallback)] // TODO: Remove this when diesel update fixes warnings
extern crate rocket;
extern crate rocket_contrib;
extern crate reqwest;
extern crate multipart;
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

use std::{env, path::Path, process::{exit, Command}};
use rocket::Rocket;

#[macro_use]
mod util;

mod api;
mod db;
mod crypto;
mod auth;

fn init_rocket() -> Rocket {
    rocket::ignite()
        .mount("/", api::web_routes())
        .mount("/api", api::core_routes())
        .mount("/identity", api::identity_routes())
        .mount("/icons", api::icons_routes())
        .mount("/notifications", api::notifications_routes())
        .manage(db::init_pool())
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
pub struct Config {
    database_url: String,
    icon_cache_folder: String,
    attachments_folder: String,

    private_rsa_key: String,
    private_rsa_key_pem: String,
    public_rsa_key: String,

    web_vault_folder: String,
    web_vault_enabled: bool,

    local_icon_extractor: bool,
    signups_allowed: bool,
    password_iterations: i32,
    show_password_hint: bool,
    domain: String,
    domain_set: bool,
}

impl Config {
    fn load() -> Self {
        dotenv::dotenv().ok();

        let df = env::var("DATA_FOLDER").unwrap_or("data".into());
        let key = env::var("RSA_KEY_FILENAME").unwrap_or(format!("{}/{}", &df, "rsa_key"));

        let domain = env::var("DOMAIN");

        Config {
            database_url: env::var("DATABASE_URL").unwrap_or(format!("{}/{}", &df, "db.sqlite3")),
            icon_cache_folder: env::var("ICON_CACHE_FOLDER").unwrap_or(format!("{}/{}", &df, "icon_cache")),
            attachments_folder: env::var("ATTACHMENTS_FOLDER").unwrap_or(format!("{}/{}", &df, "attachments")),

            private_rsa_key: format!("{}.der", &key),
            private_rsa_key_pem: format!("{}.pem", &key),
            public_rsa_key: format!("{}.pub.der", &key),

            web_vault_folder: env::var("WEB_VAULT_FOLDER").unwrap_or("web-vault/".into()),
            web_vault_enabled: util::parse_option_string(env::var("WEB_VAULT_ENABLED").ok()).unwrap_or(true),

            local_icon_extractor: util::parse_option_string(env::var("LOCAL_ICON_EXTRACTOR").ok()).unwrap_or(false),
            signups_allowed: util::parse_option_string(env::var("SIGNUPS_ALLOWED").ok()).unwrap_or(true),
            password_iterations: util::parse_option_string(env::var("PASSWORD_ITERATIONS").ok()).unwrap_or(100_000),
            show_password_hint: util::parse_option_string(env::var("SHOW_PASSWORD_HINT").ok()).unwrap_or(true),

            domain_set: domain.is_ok(),
            domain: domain.unwrap_or("http://localhost".into()),
        }
    }
}
