#![allow(unused_variables, dead_code)]

#![feature(plugin, custom_derive)]
#![cfg_attr(test, plugin(stainless))]
#![plugin(rocket_codegen)]
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
extern crate r2d2_diesel;
extern crate r2d2;
extern crate ring;
extern crate uuid;
extern crate chrono;
extern crate time;
extern crate oath;
extern crate data_encoding;
extern crate jsonwebtoken as jwt;
extern crate dotenv;
#[macro_use]
extern crate lazy_static;


use std::{io, env};
use rocket::Rocket;

#[macro_use]
mod util;

#[cfg(test)]
mod tests;

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
        .manage(db::init_pool())
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
embed_migrations!();

fn main() {
    println!("{:#?}", *CONFIG);

    // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
    let connection = db::get_connection().expect("Can't conect to DB");
    embedded_migrations::run_with_output(&connection, &mut io::stdout()).expect("Can't run migrations");

    check_rsa_keys();

    init_rocket().launch();
}

fn check_rsa_keys() {
    // If the RSA keys don't exist, try to create them
    if !util::file_exists(&CONFIG.private_rsa_key)
        || !util::file_exists(&CONFIG.public_rsa_key) {
        println!("JWT keys don't exist, checking if OpenSSL is available...");
        use std::process::{exit, Command};

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
            println!("Keys created correcty.");
        } else {
            println!("Error creating keys, exiting...");
            exit(1);
        }
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

    signups_allowed: bool,
    password_iterations: i32,
}

impl Config {
    fn load() -> Self {
        dotenv::dotenv().ok();

        let df = env::var("DATA_FOLDER").unwrap_or("data".into());
        let key = env::var("RSA_KEY_NAME").unwrap_or("rsa_key".into());

        Config {
            database_url: env::var("DATABASE_URL").unwrap_or(format!("{}/{}", &df, "db.sqlite3")),
            icon_cache_folder: env::var("ICON_CACHE_FOLDER").unwrap_or(format!("{}/{}", &df, "icon_cache")),
            attachments_folder: env::var("ATTACHMENTS_FOLDER").unwrap_or(format!("{}/{}", &df, "attachments")),

            private_rsa_key: format!("{}/{}.der", &df, &key),
            private_rsa_key_pem: format!("{}/{}.pem", &df, &key),
            public_rsa_key: format!("{}/{}.pub.der", &df, &key),

            web_vault_folder: env::var("WEB_VAULT_FOLDER").unwrap_or("web-vault/".into()),

            signups_allowed: util::parse_option_string(env::var("SIGNUPS_ALLOWED").ok()).unwrap_or(false),
            password_iterations: util::parse_option_string(env::var("PASSWORD_ITERATIONS").ok()).unwrap_or(100_000),
        }
    }
}
