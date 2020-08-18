#![forbid(unsafe_code)]
#![cfg_attr(feature = "unstable", feature(ip))]
#![recursion_limit = "256"]

extern crate openssl;
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

use std::{
    fs::create_dir_all,
    panic,
    path::Path,
    process::{exit, Command},
    str::FromStr,
    thread,
};

use structopt::StructOpt;

#[macro_use]
mod error;
mod api;
mod auth;
mod config;
mod crypto;
#[macro_use]
mod db;
mod mail;
mod util;

pub use config::CONFIG;
pub use error::{Error, MapResult};

#[derive(Debug, StructOpt)]
#[structopt(name = "bitwarden_rs", about = "A Bitwarden API server written in Rust")]
struct Opt {
    /// Prints the app version
    #[structopt(short, long)]
    version: bool,
}

fn main() {
    parse_args();
    launch_info();

    use log::LevelFilter as LF;
    let level = LF::from_str(&CONFIG.log_level()).expect("Valid log level");
    init_logging(level).ok();

    let extra_debug = match level {
        LF::Trace | LF::Debug => true,
        _ => false,
    };

    check_rsa_keys();
    check_web_vault();

    create_icon_cache_folder();

    launch_rocket(extra_debug);
}

fn parse_args() {
    let opt = Opt::from_args();
    if opt.version {
        if let Some(version) = option_env!("BWRS_VERSION") {
            println!("bitwarden_rs {}", version);
        } else {
            println!("bitwarden_rs (Version info from Git not present)");
        }
        exit(0);
    }
}

fn launch_info() {
    println!("/--------------------------------------------------------------------\\");
    println!("|                       Starting Bitwarden_RS                        |");

    if let Some(version) = option_env!("BWRS_VERSION") {
        println!("|{:^68}|", format!("Version {}", version));
    }

    println!("|--------------------------------------------------------------------|");
    println!("| This is an *unofficial* Bitwarden implementation, DO NOT use the   |");
    println!("| official channels to report bugs/features, regardless of client.   |");
    println!("| Send usage/configuration questions or feature requests to:         |");
    println!("|   https://bitwardenrs.discourse.group/                             |");
    println!("| Report suspected bugs/issues in the software itself at:            |");
    println!("|   https://github.com/dani-garcia/bitwarden_rs/issues/new           |");
    println!("\\--------------------------------------------------------------------/\n");
}

fn init_logging(level: log::LevelFilter) -> Result<(), fern::InitError> {
    let mut logger = fern::Dispatch::new()
        .level(level)
        // Hide unknown certificate errors if using self-signed
        .level_for("rustls::session", log::LevelFilter::Off)
        // Hide failed to close stream messages
        .level_for("hyper::server", log::LevelFilter::Warn)
        // Silence rocket logs
        .level_for("_", log::LevelFilter::Off)
        .level_for("launch", log::LevelFilter::Off)
        .level_for("launch_", log::LevelFilter::Off)
        .level_for("rocket::rocket", log::LevelFilter::Off)
        .level_for("rocket::fairing", log::LevelFilter::Off)
        .chain(std::io::stdout());

    if CONFIG.extended_logging() {
        logger = logger.format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format(&CONFIG.log_timestamp_format()),
                record.target(),
                record.level(),
                message
            ))
        });
    } else {
        logger = logger.format(|out, message, _| out.finish(format_args!("{}", message)));
    }

    if let Some(log_file) = CONFIG.log_file() {
        logger = logger.chain(fern::log_file(log_file)?);
    }

    #[cfg(not(windows))]
    {
        if cfg!(feature = "enable_syslog") || CONFIG.use_syslog() {
            logger = chain_syslog(logger);
        }
    }

    logger.apply()?;

    // Catch panics and log them instead of default output to StdErr
    panic::set_hook(Box::new(|info| {
        let thread = thread::current();
        let thread = thread.name().unwrap_or("unnamed");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &**s,
                None => "Box<Any>",
            },
        };

        let backtrace = backtrace::Backtrace::new();

        match info.location() {
            Some(location) => {
                error!(
                    target: "panic", "thread '{}' panicked at '{}': {}:{}\n{:?}",
                    thread,
                    msg,
                    location.file(),
                    location.line(),
                    backtrace
                );
            }
            None => error!(
                target: "panic",
                "thread '{}' panicked at '{}'\n{:?}",
                thread,
                msg,
                backtrace
            ),
        }
    }));

    Ok(())
}

#[cfg(not(windows))]
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

fn create_icon_cache_folder() {
    // Try to create the icon cache folder, and generate an error if it could not.
    create_dir_all(&CONFIG.icon_cache_folder()).expect("Error creating icon cache directory");
}

fn check_rsa_keys() {
    // If the RSA keys don't exist, try to create them
    if !util::file_exists(&CONFIG.private_rsa_key()) || !util::file_exists(&CONFIG.public_rsa_key()) {
        info!("JWT keys don't exist, checking if OpenSSL is available...");

        Command::new("openssl").arg("version").status().unwrap_or_else(|_| {
            info!(
                "Can't create keys because OpenSSL is not available, make sure it's installed and available on the PATH"
            );
            exit(1);
        });

        info!("OpenSSL detected, creating keys...");

        let key = CONFIG.rsa_key_filename();

        let pem = format!("{}.pem", key);
        let priv_der = format!("{}.der", key);
        let pub_der = format!("{}.pub.der", key);

        let mut success = Command::new("openssl")
            .args(&["genrsa", "-out", &pem])
            .status()
            .expect("Failed to create private pem file")
            .success();

        success &= Command::new("openssl")
            .args(&["rsa", "-in", &pem, "-outform", "DER", "-out", &priv_der])
            .status()
            .expect("Failed to create private der file")
            .success();

        success &= Command::new("openssl")
            .args(&["rsa", "-in", &priv_der, "-inform", "DER"])
            .args(&["-RSAPublicKey_out", "-outform", "DER", "-out", &pub_der])
            .status()
            .expect("Failed to create public der file")
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
        error!("Web vault is not found at '{}'. To install it, please follow the steps in: ", CONFIG.web_vault_folder());
        error!("https://github.com/dani-garcia/bitwarden_rs/wiki/Building-binary#install-the-web-vault");
        error!("You can also set the environment variable 'WEB_VAULT_ENABLED=false' to disable it");
        exit(1);
    }
}

fn launch_rocket(extra_debug: bool) {
    let pool = match db::DbPool::from_config() {
        Ok(p) => p,
        Err(e) => {
            error!("Error creating database pool: {:?}", e);
            exit(1);
        }
    };

    let basepath = &CONFIG.domain_path();

    // If adding more paths here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    let result = rocket::ignite()
        .mount(&[basepath, "/"].concat(), api::web_routes())
        .mount(&[basepath, "/api"].concat(), api::core_routes())
        .mount(&[basepath, "/admin"].concat(), api::admin_routes())
        .mount(&[basepath, "/identity"].concat(), api::identity_routes())
        .mount(&[basepath, "/icons"].concat(), api::icons_routes())
        .mount(&[basepath, "/notifications"].concat(), api::notifications_routes())
        .manage(pool)
        .manage(api::start_notification_server())
        .attach(util::AppHeaders())
        .attach(util::CORS())
        .attach(util::BetterLogging(extra_debug))
        .launch();

    // Launch and print error if there is one
    // The launch will restore the original logging level
    error!("Launch error {:#?}", result);
}
