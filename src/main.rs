#![allow(dead_code, unused_variables, unused, unused_mut)]

#![feature(plugin, custom_derive)]
#![cfg_attr(test, plugin(stainless))]
#![plugin(rocket_codegen)]
extern crate rocket;
#[macro_use]
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

use rocket::{Data, Request, Rocket};
use rocket::fairing::{Fairing, Info, Kind};

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
        .attach(DebugFairing)
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
embed_migrations!();

fn main() {
    println!("{:#?}", *CONFIG);

    // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
    let connection = db::get_connection().expect("Can't conect to DB");
    embedded_migrations::run_with_output(&connection, &mut io::stdout());

    // Validate location of rsa keys
    if !util::file_exists(&CONFIG.private_rsa_key) {
        panic!("private_rsa_key doesn't exist");
    }
    if !util::file_exists(&CONFIG.public_rsa_key) {
        panic!("public_rsa_key doesn't exist");
    }

    init_rocket().launch();
}

lazy_static! {
    // Load the config from .env or from environment variables
    static ref CONFIG: Config = Config::load();
}

#[derive(Debug)]
pub struct Config {
    database_url: String,
    private_rsa_key: String,
    public_rsa_key: String,
    icon_cache_folder: String,
    attachments_folder: String,
    web_vault_folder: String,

    signups_allowed: bool,
    password_iterations: i32,
}

impl Config {
    fn load() -> Self {
        dotenv::dotenv().ok();

        Config {
            database_url: env::var("DATABASE_URL").unwrap_or("data/db.sqlite3".into()),
            private_rsa_key: env::var("PRIVATE_RSA_KEY").unwrap_or("data/private_rsa_key.der".into()),
            public_rsa_key: env::var("PUBLIC_RSA_KEY").unwrap_or("data/public_rsa_key.der".into()),
            icon_cache_folder: env::var("ICON_CACHE_FOLDER").unwrap_or("data/icon_cache".into()),
            attachments_folder: env::var("ATTACHMENTS_FOLDER").unwrap_or("data/attachments".into()),
            web_vault_folder: env::var("WEB_VAULT_FOLDER").unwrap_or("web-vault/".into()),

            signups_allowed: util::parse_option_string(env::var("SIGNUPS_ALLOWED").ok()).unwrap_or(false),
            password_iterations: util::parse_option_string(env::var("PASSWORD_ITERATIONS").ok()).unwrap_or(100_000),
        }
    }
}

struct DebugFairing;

impl Fairing for DebugFairing {
    fn info(&self) -> Info {
        Info {
            name: "Request Debugger",
            kind: Kind::Request,
        }
    }

    fn on_request(&self, req: &mut Request, data: &Data) {
        let uri_string = req.uri().to_string();

        // Ignore web requests
        if !uri_string.starts_with("/api") &&
            !uri_string.starts_with("/identity") {
            return;
        }

        /*
        for header in req.headers().iter() {
            println!("DEBUG- {:#?} {:#?}", header.name(), header.value());
        }
        */

        /*let body_data = data.peek();

        if body_data.len() > 0 {
            println!("DEBUG- Body Complete: {}", data.peek_complete());
            println!("DEBUG- {}", String::from_utf8_lossy(body_data));
        }*/
    }
}
