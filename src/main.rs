#![forbid(unsafe_code)]
#![cfg_attr(feature = "unstable", feature(ip))]
// The recursion_limit is mainly triggered by the json!() macro.
// The more key/value pairs there are the more recursion occurs.
// We want to keep this as low as possible, but not higher then 128.
// If you go above 128 it will cause rust-analyzer to fail,
#![recursion_limit = "87"]

extern crate openssl;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

use job_scheduler::{Job, JobScheduler};
use std::{fs::create_dir_all, panic, path::Path, process::exit, str::FromStr, thread, time::Duration};

#[macro_use]
mod error;
mod api;
mod auth;
mod config;
mod crypto;
#[macro_use]
mod db;
mod mail;
mod ratelimit;
mod util;

pub use config::CONFIG;
pub use error::{Error, MapResult};
pub use util::is_running_in_docker;

fn main() {
    parse_args();
    launch_info();

    use log::LevelFilter as LF;
    let level = LF::from_str(&CONFIG.log_level()).expect("Valid log level");
    init_logging(level).ok();

    let extra_debug = matches!(level, LF::Trace | LF::Debug);

    check_data_folder();
    check_rsa_keys().unwrap_or_else(|_| {
        error!("Error creating keys, exiting...");
        exit(1);
    });
    check_web_vault();

    create_icon_cache_folder();

    let pool = create_db_pool();
    schedule_jobs(pool.clone());
    crate::db::models::TwoFactor::migrate_u2f_to_webauthn(&pool.get().unwrap()).unwrap();

    launch_rocket(pool, extra_debug); // Blocks until program termination.
}

const HELP: &str = "\
        Alternative implementation of the Bitwarden server API written in Rust

        USAGE:
            vaultwarden

        FLAGS:
            -h, --help       Prints help information
            -v, --version    Prints the app version
";

pub const VERSION: Option<&str> = option_env!("VW_VERSION");

fn parse_args() {
    let mut pargs = pico_args::Arguments::from_env();
    let version = VERSION.unwrap_or("(Version info from Git not present)");

    if pargs.contains(["-h", "--help"]) {
        println!("vaultwarden {}", version);
        print!("{}", HELP);
        exit(0);
    } else if pargs.contains(["-v", "--version"]) {
        println!("vaultwarden {}", version);
        exit(0);
    }
}

fn launch_info() {
    println!("/--------------------------------------------------------------------\\");
    println!("|                        Starting Vaultwarden                        |");

    if let Some(version) = VERSION {
        println!("|{:^68}|", format!("Version {}", version));
    }

    println!("|--------------------------------------------------------------------|");
    println!("| This is an *unofficial* Bitwarden implementation, DO NOT use the   |");
    println!("| official channels to report bugs/features, regardless of client.   |");
    println!("| Send usage/configuration questions or feature requests to:         |");
    println!("|   https://vaultwarden.discourse.group/                             |");
    println!("| Report suspected bugs/issues in the software itself at:            |");
    println!("|   https://github.com/dani-garcia/vaultwarden/issues/new            |");
    println!("\\--------------------------------------------------------------------/\n");
}

fn init_logging(level: log::LevelFilter) -> Result<(), fern::InitError> {
    // Depending on the main log level we either want to disable or enable logging for trust-dns.
    // Else if there are timeouts it will clutter the logs since trust-dns uses warn for this.
    let trust_dns_level = if level >= log::LevelFilter::Debug {
        level
    } else {
        log::LevelFilter::Off
    };

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
        // Never show html5ever and hyper::proto logs, too noisy
        .level_for("html5ever", log::LevelFilter::Off)
        .level_for("hyper::proto", log::LevelFilter::Off)
        .level_for("hyper::client", log::LevelFilter::Off)
        // Prevent cookie_store logs
        .level_for("cookie_store", log::LevelFilter::Off)
        // Variable level for trust-dns used by reqwest
        .level_for("trust_dns_proto", trust_dns_level)
        .chain(std::io::stdout());

    // Enable smtp debug logging only specifically for smtp when need.
    // This can contain sensitive information we do not want in the default debug/trace logging.
    if CONFIG.smtp_debug() {
        println!(
            "[WARNING] SMTP Debugging is enabled (SMTP_DEBUG=true). Sensitive information could be disclosed via logs!"
        );
        println!("[WARNING] Only enable SMTP_DEBUG during troubleshooting!\n");
        logger = logger.level_for("lettre::transport::smtp", log::LevelFilter::Debug)
    } else {
        logger = logger.level_for("lettre::transport::smtp", log::LevelFilter::Off)
    }

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
        process: "vaultwarden".into(),
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

fn create_dir(path: &str, description: &str) {
    // Try to create the specified dir, if it doesn't already exist.
    let err_msg = format!("Error creating {} directory '{}'", description, path);
    create_dir_all(path).expect(&err_msg);
}

fn create_icon_cache_folder() {
    create_dir(&CONFIG.icon_cache_folder(), "icon cache");
}

fn check_data_folder() {
    let data_folder = &CONFIG.data_folder();
    let path = Path::new(data_folder);
    if !path.exists() {
        error!("Data folder '{}' doesn't exist.", data_folder);
        if is_running_in_docker() {
            error!("Verify that your data volume is mounted at the correct location.");
        } else {
            error!("Create the data folder and try again.");
        }
        exit(1);
    }
}

fn check_rsa_keys() -> Result<(), crate::error::Error> {
    // If the RSA keys don't exist, try to create them
    let priv_path = CONFIG.private_rsa_key();
    let pub_path = CONFIG.public_rsa_key();

    if !util::file_exists(&priv_path) {
        let rsa_key = openssl::rsa::Rsa::generate(2048)?;

        let priv_key = rsa_key.private_key_to_pem()?;
        crate::util::write_file(&priv_path, &priv_key)?;
        info!("Private key created correctly.");
    }

    if !util::file_exists(&pub_path) {
        let rsa_key = openssl::rsa::Rsa::private_key_from_pem(&util::read_file(&priv_path)?)?;

        let pub_key = rsa_key.public_key_to_pem()?;
        crate::util::write_file(&pub_path, &pub_key)?;
        info!("Public key created correctly.");
    }

    auth::load_keys();
    Ok(())
}

fn check_web_vault() {
    if !CONFIG.web_vault_enabled() {
        return;
    }

    let index_path = Path::new(&CONFIG.web_vault_folder()).join("index.html");

    if !index_path.exists() {
        error!(
            "Web vault is not found at '{}'. To install it, please follow the steps in: ",
            CONFIG.web_vault_folder()
        );
        error!("https://github.com/dani-garcia/vaultwarden/wiki/Building-binary#install-the-web-vault");
        error!("You can also set the environment variable 'WEB_VAULT_ENABLED=false' to disable it");
        exit(1);
    }
}

fn create_db_pool() -> db::DbPool {
    match util::retry_db(db::DbPool::from_config, CONFIG.db_connection_retries()) {
        Ok(p) => p,
        Err(e) => {
            error!("Error creating database pool: {:?}", e);
            exit(1);
        }
    }
}

fn launch_rocket(pool: db::DbPool, extra_debug: bool) {
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
        .attach(util::Cors())
        .attach(util::BetterLogging(extra_debug))
        .launch();

    // Launch and print error if there is one
    // The launch will restore the original logging level
    error!("Launch error {:#?}", result);
}

fn schedule_jobs(pool: db::DbPool) {
    if CONFIG.job_poll_interval_ms() == 0 {
        info!("Job scheduler disabled.");
        return;
    }
    thread::Builder::new()
        .name("job-scheduler".to_string())
        .spawn(move || {
            let mut sched = JobScheduler::new();

            // Purge sends that are past their deletion date.
            if !CONFIG.send_purge_schedule().is_empty() {
                sched.add(Job::new(CONFIG.send_purge_schedule().parse().unwrap(), || {
                    api::purge_sends(pool.clone());
                }));
            }

            // Purge trashed items that are old enough to be auto-deleted.
            if !CONFIG.trash_purge_schedule().is_empty() {
                sched.add(Job::new(CONFIG.trash_purge_schedule().parse().unwrap(), || {
                    api::purge_trashed_ciphers(pool.clone());
                }));
            }

            // Send email notifications about incomplete 2FA logins, which potentially
            // indicates that a user's master password has been compromised.
            if !CONFIG.incomplete_2fa_schedule().is_empty() {
                sched.add(Job::new(CONFIG.incomplete_2fa_schedule().parse().unwrap(), || {
                    api::send_incomplete_2fa_notifications(pool.clone());
                }));
            }

            // Grant emergency access requests that have met the required wait time.
            // This job should run before the emergency access reminders job to avoid
            // sending reminders for requests that are about to be granted anyway.
            if !CONFIG.emergency_request_timeout_schedule().is_empty() {
                sched.add(Job::new(CONFIG.emergency_request_timeout_schedule().parse().unwrap(), || {
                    api::emergency_request_timeout_job(pool.clone());
                }));
            }

            // Send reminders to emergency access grantors that there are pending
            // emergency access requests.
            if !CONFIG.emergency_notification_reminder_schedule().is_empty() {
                sched.add(Job::new(CONFIG.emergency_notification_reminder_schedule().parse().unwrap(), || {
                    api::emergency_notification_reminder_job(pool.clone());
                }));
            }

            // Periodically check for jobs to run. We probably won't need any
            // jobs that run more often than once a minute, so a default poll
            // interval of 30 seconds should be sufficient. Users who want to
            // schedule jobs to run more frequently for some reason can reduce
            // the poll interval accordingly.
            //
            // Note that the scheduler checks jobs in the order in which they
            // were added, so if two jobs are both eligible to run at a given
            // tick, the one that was added earlier will run first.
            loop {
                sched.tick();
                thread::sleep(Duration::from_millis(CONFIG.job_poll_interval_ms()));
            }
        })
        .expect("Error spawning job scheduler thread");
}
