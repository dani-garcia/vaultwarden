#![forbid(unsafe_code)]
#![feature(proc_macro_hygiene, try_trait, ip)]
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
    path::Path,
    process::{exit, Command},
    str::FromStr,
    panic, thread, fmt // For panic logging
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
pub use error::{Error, MapResult};

use structopt::StructOpt;

// Used for catching panics and log them to file instead of stderr
use backtrace::Backtrace;
struct Shim(Backtrace);

impl fmt::Debug for Shim {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "\n{:?}", self.0)
    }
}

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

    check_db();
    check_rsa_keys();
    check_web_vault();
    migrations::run_migrations();

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
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"),
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
        let backtrace = Backtrace::new();

        let thread = thread::current();
        let thread = thread.name().unwrap_or("unnamed");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &**s,
                None => "Box<Any>",
            },
        };

        match info.location() {
            Some(location) => {
                error!(
                    target: "panic", "thread '{}' panicked at '{}': {}:{}{:?}",
                    thread,
                    msg,
                    location.file(),
                    location.line(),
                    Shim(backtrace)
                );
            }
            None => {
                error!(
                    target: "panic",
                    "thread '{}' panicked at '{}'{:?}",
                    thread,
                    msg,
                    Shim(backtrace)
                )
            }
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

fn check_db() {
    if cfg!(feature = "sqlite") {
        let url = CONFIG.database_url();
        let path = Path::new(&url);

        if let Some(parent) = path.parent() {
            if create_dir_all(parent).is_err() {
                error!("Error creating database directory");
                exit(1);
            }
        }

        // Turn on WAL in SQLite
        if CONFIG.enable_db_wal() {
            use diesel::RunQueryDsl;
            let connection = db::get_connection().expect("Can't connect to DB");
            diesel::sql_query("PRAGMA journal_mode=wal")
                .execute(&connection)
                .expect("Failed to turn on WAL");
        }
    }
    db::get_connection().expect("Can't connect to DB");
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
        error!("Web vault is not found. To install it, please follow the steps in: ");
        error!("https://github.com/dani-garcia/bitwarden_rs/wiki/Building-binary#install-the-web-vault");
        error!("You can also set the environment variable 'WEB_VAULT_ENABLED=false' to disable it");
        exit(1);
    }
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[allow(unused_imports)]
mod migrations {

    #[cfg(feature = "sqlite")]
    embed_migrations!("migrations/sqlite");
    #[cfg(feature = "mysql")]
    embed_migrations!("migrations/mysql");
    #[cfg(feature = "postgresql")]
    embed_migrations!("migrations/postgresql");

    pub fn run_migrations() {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let connection = crate::db::get_connection().expect("Can't connect to DB");

        use std::io::stdout;

        // Disable Foreign Key Checks during migration
        use diesel::RunQueryDsl;
        #[cfg(feature = "postgres")]
        diesel::sql_query("SET CONSTRAINTS ALL DEFERRED").execute(&connection).expect("Failed to disable Foreign Key Checks during migrations");
        #[cfg(feature = "mysql")]
        diesel::sql_query("SET FOREIGN_KEY_CHECKS = 0").execute(&connection).expect("Failed to disable Foreign Key Checks during migrations");
        #[cfg(feature = "sqlite")]
        diesel::sql_query("PRAGMA defer_foreign_keys = ON").execute(&connection).expect("Failed to disable Foreign Key Checks during migrations");

        embedded_migrations::run_with_output(&connection, &mut stdout()).expect("Can't run migrations");
    }
}

fn launch_rocket(extra_debug: bool) {
    // Create Rocket object, this stores current log level and sets its own
    let rocket = rocket::ignite();

    let basepath = &CONFIG.domain_path();

    // If adding more paths here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    let rocket = rocket
        .mount(&[basepath, "/"].concat(), api::web_routes())
        .mount(&[basepath, "/api"].concat(), api::core_routes())
        .mount(&[basepath, "/admin"].concat(), api::admin_routes())
        .mount(&[basepath, "/identity"].concat(), api::identity_routes())
        .mount(&[basepath, "/icons"].concat(), api::icons_routes())
        .mount(&[basepath, "/notifications"].concat(), api::notifications_routes())
        .manage(db::init_pool())
        .manage(api::start_notification_server())
        .attach(util::AppHeaders())
        .attach(util::CORS())
        .attach(util::BetterLogging(extra_debug));

    // Launch and print error if there is one
    // The launch will restore the original logging level
    error!("Launch error {:#?}", rocket.launch());
}
