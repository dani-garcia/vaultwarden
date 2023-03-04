#![forbid(unsafe_code, non_ascii_idents)]
#![deny(
    rust_2018_idioms,
    rust_2021_compatibility,
    noop_method_call,
    pointer_structural_match,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    clippy::cast_lossless,
    clippy::clone_on_ref_ptr,
    clippy::equatable_if_let,
    clippy::float_cmp_const,
    clippy::inefficient_to_string,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::manual_assert,
    clippy::manual_instant_elapsed,
    clippy::manual_string_new,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::string_add_assign,
    clippy::string_to_string,
    clippy::unnecessary_join,
    clippy::unnecessary_self_imports,
    clippy::unused_async,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values
)]
#![cfg_attr(feature = "unstable", feature(ip))]
// The recursion_limit is mainly triggered by the json!() macro.
// The more key/value pairs there are the more recursion occurs.
// We want to keep this as low as possible, but not higher then 128.
// If you go above 128 it will cause rust-analyzer to fail,
#![recursion_limit = "103"]

// When enabled use MiMalloc as malloc instead of the default malloc
#[cfg(feature = "enable_mimalloc")]
use mimalloc::MiMalloc;
#[cfg(feature = "enable_mimalloc")]
#[cfg_attr(feature = "enable_mimalloc", global_allocator)]
static GLOBAL: MiMalloc = MiMalloc;

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

use std::{
    fs::{canonicalize, create_dir_all},
    panic,
    path::Path,
    process::exit,
    str::FromStr,
    thread,
};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

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
use rocket::data::{Limits, ToByteUnit};
pub use util::is_running_in_docker;

#[rocket::main]
async fn main() -> Result<(), Error> {
    parse_args();
    launch_info();

    use log::LevelFilter as LF;
    let level = LF::from_str(&CONFIG.log_level()).expect("Valid log level");
    init_logging(level).ok();

    let extra_debug = matches!(level, LF::Trace | LF::Debug);

    check_data_folder().await;
    check_rsa_keys().unwrap_or_else(|_| {
        error!("Error creating keys, exiting...");
        exit(1);
    });
    check_web_vault();

    create_dir(&CONFIG.icon_cache_folder(), "icon cache");
    create_dir(&CONFIG.tmp_folder(), "tmp folder");
    create_dir(&CONFIG.sends_folder(), "sends folder");
    create_dir(&CONFIG.attachments_folder(), "attachments folder");

    let pool = create_db_pool().await;
    schedule_jobs(pool.clone()).await;
    crate::db::models::TwoFactor::migrate_u2f_to_webauthn(&mut pool.get().await.unwrap()).await.unwrap();

    launch_rocket(pool, extra_debug).await // Blocks until program termination.
}

const HELP: &str = "\
Alternative implementation of the Bitwarden server API written in Rust

USAGE:
    vaultwarden [FLAGS|COMMAND]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints the app version

COMMAND:
    hash [--preset {bitwarden|owasp}]  Generate an Argon2id PHC ADMIN_TOKEN

PRESETS:                  m=         t=          p=
    bitwarden (default) 64MiB, 3 Iterations, 4 Threads
    owasp               19MiB, 2 Iterations, 1 Thread

";

pub const VERSION: Option<&str> = option_env!("VW_VERSION");

fn parse_args() {
    let mut pargs = pico_args::Arguments::from_env();
    let version = VERSION.unwrap_or("(Version info from Git not present)");

    if pargs.contains(["-h", "--help"]) {
        println!("vaultwarden {version}");
        print!("{HELP}");
        exit(0);
    } else if pargs.contains(["-v", "--version"]) {
        println!("vaultwarden {version}");
        exit(0);
    }

    if let Some(command) = pargs.subcommand().unwrap_or_default() {
        if command == "hash" {
            use argon2::{
                password_hash::SaltString, Algorithm::Argon2id, Argon2, ParamsBuilder, PasswordHasher, Version::V0x13,
            };

            let mut argon2_params = ParamsBuilder::new();
            let preset: Option<String> = pargs.opt_value_from_str(["-p", "--preset"]).unwrap_or_default();
            let selected_preset;
            match preset.as_deref() {
                Some("owasp") => {
                    selected_preset = "owasp";
                    argon2_params.m_cost(19456);
                    argon2_params.t_cost(2);
                    argon2_params.p_cost(1);
                }
                _ => {
                    // Bitwarden preset is the default
                    selected_preset = "bitwarden";
                    argon2_params.m_cost(65540);
                    argon2_params.t_cost(3);
                    argon2_params.p_cost(4);
                }
            }

            println!("Generate an Argon2id PHC string using the '{selected_preset}' preset:\n");

            let password = rpassword::prompt_password("Password: ").unwrap();
            if password.len() < 8 {
                println!("\nPassword must contain at least 8 characters");
                exit(1);
            }

            let password_verify = rpassword::prompt_password("Confirm Password: ").unwrap();
            if password != password_verify {
                println!("\nPasswords do not match");
                exit(1);
            }

            let argon2 = Argon2::new(Argon2id, V0x13, argon2_params.build().unwrap());
            let salt = SaltString::encode_b64(&crate::crypto::get_random_bytes::<32>()).unwrap();

            let argon2_timer = tokio::time::Instant::now();
            if let Ok(password_hash) = argon2.hash_password(password.as_bytes(), &salt) {
                println!(
                    "\n\
                    ADMIN_TOKEN='{password_hash}'\n\n\
                    Generation of the Argon2id PHC string took: {:?}",
                    argon2_timer.elapsed()
                );
            } else {
                error!("Unable to generate Argon2id PHC hash.");
                exit(1);
            }
        }
        exit(0);
    }
}
fn launch_info() {
    println!(
        "\
        /--------------------------------------------------------------------\\\n\
        |                        Starting Vaultwarden                        |"
    );

    if let Some(version) = VERSION {
        println!("|{:^68}|", format!("Version {version}"));
    }

    println!(
        "\
        |--------------------------------------------------------------------|\n\
        | This is an *unofficial* Bitwarden implementation, DO NOT use the   |\n\
        | official channels to report bugs/features, regardless of client.   |\n\
        | Send usage/configuration questions or feature requests to:         |\n\
        |   https://github.com/dani-garcia/vaultwarden/discussions or        |\n\
        |   https://vaultwarden.discourse.group/                             |\n\
        | Report suspected bugs/issues in the software itself at:            |\n\
        |   https://github.com/dani-garcia/vaultwarden/issues/new            |\n\
        \\--------------------------------------------------------------------/\n"
    );
}

fn init_logging(level: log::LevelFilter) -> Result<(), fern::InitError> {
    // Depending on the main log level we either want to disable or enable logging for trust-dns.
    // Else if there are timeouts it will clutter the logs since trust-dns uses warn for this.
    let trust_dns_level = if level >= log::LevelFilter::Debug {
        level
    } else {
        log::LevelFilter::Off
    };

    let diesel_logger_level: log::LevelFilter =
        if cfg!(feature = "query_logger") && std::env::var("QUERY_LOGGER").is_ok() {
            log::LevelFilter::Debug
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
        .level_for("_", log::LevelFilter::Warn)
        .level_for("rocket::launch", log::LevelFilter::Error)
        .level_for("rocket::launch_", log::LevelFilter::Error)
        .level_for("rocket::rocket", log::LevelFilter::Warn)
        .level_for("rocket::server", log::LevelFilter::Warn)
        .level_for("rocket::fairing::fairings", log::LevelFilter::Warn)
        .level_for("rocket::shield::shield", log::LevelFilter::Warn)
        .level_for("hyper::proto", log::LevelFilter::Off)
        .level_for("hyper::client", log::LevelFilter::Off)
        // Prevent cookie_store logs
        .level_for("cookie_store", log::LevelFilter::Off)
        // Variable level for trust-dns used by reqwest
        .level_for("trust_dns_proto", trust_dns_level)
        .level_for("diesel_logger", diesel_logger_level)
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
        logger = logger.format(|out, message, _| out.finish(format_args!("{message}")));
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

        let backtrace = std::backtrace::Backtrace::force_capture();

        match info.location() {
            Some(location) => {
                error!(
                    target: "panic", "thread '{}' panicked at '{}': {}:{}\n{:}",
                    thread,
                    msg,
                    location.file(),
                    location.line(),
                    backtrace
                );
            }
            None => error!(
                target: "panic",
                "thread '{}' panicked at '{}'\n{:}",
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
    let err_msg = format!("Error creating {description} directory '{path}'");
    create_dir_all(path).expect(&err_msg);
}

async fn check_data_folder() {
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
    if !path.is_dir() {
        error!("Data folder '{}' is not a directory.", data_folder);
        exit(1);
    }

    if is_running_in_docker()
        && std::env::var("I_REALLY_WANT_VOLATILE_STORAGE").is_err()
        && !docker_data_folder_is_persistent(data_folder).await
    {
        error!(
            "No persistent volume!\n\
            ########################################################################################\n\
            # It looks like you did not configure a persistent volume!                             #\n\
            # This will result in permanent data loss when the container is removed or updated!    #\n\
            # If you really want to use volatile storage set `I_REALLY_WANT_VOLATILE_STORAGE=true` #\n\
            ########################################################################################\n"
        );
        exit(1);
    }
}

/// Detect when using Docker or Podman the DATA_FOLDER is either a bind-mount or a volume created manually.
/// If not created manually, then the data will not be persistent.
/// A none persistent volume in either Docker or Podman is represented by a 64 alphanumerical string.
/// If we detect this string, we will alert about not having a persistent self defined volume.
/// This probably means that someone forgot to add `-v /path/to/vaultwarden_data/:/data`
async fn docker_data_folder_is_persistent(data_folder: &str) -> bool {
    if let Ok(mountinfo) = File::open("/proc/self/mountinfo").await {
        // Since there can only be one mountpoint to the DATA_FOLDER
        // We do a basic check for this mountpoint surrounded by a space.
        let data_folder_match = if data_folder.starts_with('/') {
            format!(" {data_folder} ")
        } else {
            format!(" /{data_folder} ")
        };
        let mut lines = BufReader::new(mountinfo).lines();
        while let Some(line) = lines.next_line().await.unwrap_or_default() {
            // Only execute a regex check if we find the base match
            if line.contains(&data_folder_match) {
                let re = regex::Regex::new(r"/volumes/[a-z0-9]{64}/_data /").unwrap();
                if re.is_match(&line) {
                    return false;
                }
                // If we did found a match for the mountpoint, but not the regex, then still stop searching.
                break;
            }
        }
    }
    // In all other cases, just assume a true.
    // This is just an informative check to try and prevent data loss.
    true
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
        let rsa_key = openssl::rsa::Rsa::private_key_from_pem(&std::fs::read(&priv_path)?)?;

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

async fn create_db_pool() -> db::DbPool {
    match util::retry_db(db::DbPool::from_config, CONFIG.db_connection_retries()).await {
        Ok(p) => p,
        Err(e) => {
            error!("Error creating database pool: {:?}", e);
            exit(1);
        }
    }
}

async fn launch_rocket(pool: db::DbPool, extra_debug: bool) -> Result<(), Error> {
    let basepath = &CONFIG.domain_path();

    let mut config = rocket::Config::from(rocket::Config::figment());
    config.temp_dir = canonicalize(CONFIG.tmp_folder()).unwrap().into();
    config.cli_colors = false; // Make sure Rocket does not color any values for logging.
    config.limits = Limits::new()
        .limit("json", 20.megabytes()) // 20MB should be enough for very large imports, something like 5000+ vault entries
        .limit("data-form", 525.megabytes()) // This needs to match the maximum allowed file size for Send
        .limit("file", 525.megabytes()); // This needs to match the maximum allowed file size for attachments

    // If adding more paths here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    let instance = rocket::custom(config)
        .mount([basepath, "/"].concat(), api::web_routes())
        .mount([basepath, "/api"].concat(), api::core_routes())
        .mount([basepath, "/admin"].concat(), api::admin_routes())
        .mount([basepath, "/events"].concat(), api::core_events_routes())
        .mount([basepath, "/identity"].concat(), api::identity_routes())
        .mount([basepath, "/icons"].concat(), api::icons_routes())
        .mount([basepath, "/notifications"].concat(), api::notifications_routes())
        .register([basepath, "/"].concat(), api::web_catchers())
        .register([basepath, "/api"].concat(), api::core_catchers())
        .register([basepath, "/admin"].concat(), api::admin_catchers())
        .manage(pool)
        .manage(api::start_notification_server())
        .attach(util::AppHeaders())
        .attach(util::Cors())
        .attach(util::BetterLogging(extra_debug))
        .ignite()
        .await?;

    CONFIG.set_rocket_shutdown_handle(instance.shutdown());

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Error setting Ctrl-C handler");
        info!("Exiting vaultwarden!");
        CONFIG.shutdown();
    });

    let _ = instance.launch().await?;

    info!("Vaultwarden process exited!");
    Ok(())
}

async fn schedule_jobs(pool: db::DbPool) {
    if CONFIG.job_poll_interval_ms() == 0 {
        info!("Job scheduler disabled.");
        return;
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();

    thread::Builder::new()
        .name("job-scheduler".to_string())
        .spawn(move || {
            use job_scheduler_ng::{Job, JobScheduler};
            let _runtime_guard = runtime.enter();

            let mut sched = JobScheduler::new();

            // Purge sends that are past their deletion date.
            if !CONFIG.send_purge_schedule().is_empty() {
                sched.add(Job::new(CONFIG.send_purge_schedule().parse().unwrap(), || {
                    runtime.spawn(api::purge_sends(pool.clone()));
                }));
            }

            // Purge trashed items that are old enough to be auto-deleted.
            if !CONFIG.trash_purge_schedule().is_empty() {
                sched.add(Job::new(CONFIG.trash_purge_schedule().parse().unwrap(), || {
                    runtime.spawn(api::purge_trashed_ciphers(pool.clone()));
                }));
            }

            // Send email notifications about incomplete 2FA logins, which potentially
            // indicates that a user's master password has been compromised.
            if !CONFIG.incomplete_2fa_schedule().is_empty() {
                sched.add(Job::new(CONFIG.incomplete_2fa_schedule().parse().unwrap(), || {
                    runtime.spawn(api::send_incomplete_2fa_notifications(pool.clone()));
                }));
            }

            // Grant emergency access requests that have met the required wait time.
            // This job should run before the emergency access reminders job to avoid
            // sending reminders for requests that are about to be granted anyway.
            if !CONFIG.emergency_request_timeout_schedule().is_empty() {
                sched.add(Job::new(CONFIG.emergency_request_timeout_schedule().parse().unwrap(), || {
                    runtime.spawn(api::emergency_request_timeout_job(pool.clone()));
                }));
            }

            // Send reminders to emergency access grantors that there are pending
            // emergency access requests.
            if !CONFIG.emergency_notification_reminder_schedule().is_empty() {
                sched.add(Job::new(CONFIG.emergency_notification_reminder_schedule().parse().unwrap(), || {
                    runtime.spawn(api::emergency_notification_reminder_job(pool.clone()));
                }));
            }

            // Cleanup the event table of records x days old.
            if CONFIG.org_events_enabled()
                && !CONFIG.event_cleanup_schedule().is_empty()
                && CONFIG.events_days_retain().is_some()
            {
                sched.add(Job::new(CONFIG.event_cleanup_schedule().parse().unwrap(), || {
                    runtime.spawn(api::event_cleanup_job(pool.clone()));
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
                runtime.block_on(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(CONFIG.job_poll_interval_ms())).await
                });
            }
        })
        .expect("Error spawning job scheduler thread");
}
