#![cfg_attr(feature = "unstable", feature(ip))]
// The recursion_limit is mainly triggered by the json!() macro.
// The more key/value pairs there are the more recursion occurs.
// We want to keep this as low as possible, but not higher then 128.
// If you go above 128 it will cause rust-analyzer to fail,
#![recursion_limit = "200"]

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
    collections::HashMap,
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

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

#[macro_use]
mod error;
mod api;
mod auth;
mod config;
mod crypto;
#[macro_use]
mod db;
mod http_client;
mod mail;
mod ratelimit;
mod util;

use crate::api::core::two_factor::duo_oidc::purge_duo_contexts;
use crate::api::purge_auth_requests;
use crate::api::{WS_ANONYMOUS_SUBSCRIPTIONS, WS_USERS};
pub use config::CONFIG;
pub use error::{Error, MapResult};
use rocket::data::{Limits, ToByteUnit};
use std::sync::{atomic::Ordering, Arc};
pub use util::is_running_in_container;

#[rocket::main]
async fn main() -> Result<(), Error> {
    parse_args();
    launch_info();

    let level = init_logging()?;

    check_data_folder().await;
    auth::initialize_keys().unwrap_or_else(|e| {
        error!("Error creating private key '{}'\n{e:?}\nExiting Vaultwarden!", CONFIG.private_rsa_key());
        exit(1);
    });
    check_web_vault();

    create_dir(&CONFIG.icon_cache_folder(), "icon cache");
    create_dir(&CONFIG.tmp_folder(), "tmp folder");
    create_dir(&CONFIG.sends_folder(), "sends folder");
    create_dir(&CONFIG.attachments_folder(), "attachments folder");

    let pool = create_db_pool().await;
    schedule_jobs(pool.clone());
    db::models::TwoFactor::migrate_u2f_to_webauthn(&mut pool.get().await.unwrap()).await.unwrap();

    let extra_debug = matches!(level, log::LevelFilter::Trace | log::LevelFilter::Debug);
    launch_rocket(pool, extra_debug).await // Blocks until program termination.
}

const HELP: &str = "\
Alternative implementation of the Bitwarden server API written in Rust

USAGE:
    vaultwarden [FLAGS|COMMAND]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints the app and web-vault version

COMMAND:
    hash [--preset {bitwarden|owasp}]  Generate an Argon2id PHC ADMIN_TOKEN
    backup                             Create a backup of the SQLite database
                                       You can also send the USR1 signal to trigger a backup

PRESETS:                  m=         t=          p=
    bitwarden (default) 64MiB, 3 Iterations, 4 Threads
    owasp               19MiB, 2 Iterations, 1 Thread

";

pub const VERSION: Option<&str> = option_env!("VW_VERSION");

fn parse_args() {
    let mut pargs = pico_args::Arguments::from_env();
    let version = VERSION.unwrap_or("(Version info from Git not present)");

    if pargs.contains(["-h", "--help"]) {
        println!("Vaultwarden {version}");
        print!("{HELP}");
        exit(0);
    } else if pargs.contains(["-v", "--version"]) {
        config::SKIP_CONFIG_VALIDATION.store(true, Ordering::Relaxed);
        let web_vault_version = util::get_web_vault_version();
        println!("Vaultwarden {version}");
        println!("Web-Vault {web_vault_version}");
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
            let salt = SaltString::encode_b64(&crypto::get_random_bytes::<32>()).unwrap();

            let argon2_timer = tokio::time::Instant::now();
            if let Ok(password_hash) = argon2.hash_password(password.as_bytes(), &salt) {
                println!(
                    "\n\
                    ADMIN_TOKEN='{password_hash}'\n\n\
                    Generation of the Argon2id PHC string took: {:?}",
                    argon2_timer.elapsed()
                );
            } else {
                println!("Unable to generate Argon2id PHC hash.");
                exit(1);
            }
        } else if command == "backup" {
            match backup_sqlite() {
                Ok(f) => {
                    println!("Backup to '{f}' was successful");
                    exit(0);
                }
                Err(e) => {
                    println!("Backup failed. {e:?}");
                    exit(1);
                }
            }
        }
        exit(0);
    }
}

fn backup_sqlite() -> Result<String, Error> {
    #[cfg(sqlite)]
    {
        use crate::db::{backup_sqlite_database, DbConnType};
        if DbConnType::from_url(&CONFIG.database_url()).map(|t| t == DbConnType::sqlite).unwrap_or(false) {
            use diesel::Connection;
            let url = CONFIG.database_url();

            // Establish a connection to the sqlite database
            let mut conn = diesel::sqlite::SqliteConnection::establish(&url)?;
            let backup_file = backup_sqlite_database(&mut conn)?;
            Ok(backup_file)
        } else {
            err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
        }
    }
    #[cfg(not(sqlite))]
    {
        err_silent!("The 'sqlite' feature is not enabled. Backups only works for SQLite databases")
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

fn init_logging() -> Result<log::LevelFilter, Error> {
    let levels = log::LevelFilter::iter().map(|lvl| lvl.as_str().to_lowercase()).collect::<Vec<String>>().join("|");
    let log_level_rgx_str = format!("^({levels})((,[^,=]+=({levels}))*)$");
    let log_level_rgx = regex::Regex::new(&log_level_rgx_str)?;
    let config_str = CONFIG.log_level().to_lowercase();

    let (level, levels_override) = if let Some(caps) = log_level_rgx.captures(&config_str) {
        let level = caps
            .get(1)
            .and_then(|m| log::LevelFilter::from_str(m.as_str()).ok())
            .ok_or(Error::new("Failed to parse global log level".to_string(), ""))?;

        let levels_override: Vec<(&str, log::LevelFilter)> = caps
            .get(2)
            .map(|m| {
                m.as_str()
                    .split(',')
                    .collect::<Vec<&str>>()
                    .into_iter()
                    .flat_map(|s| match s.split('=').collect::<Vec<&str>>()[..] {
                        [log, lvl_str] => log::LevelFilter::from_str(lvl_str).ok().map(|lvl| (log, lvl)),
                        _ => None,
                    })
                    .collect()
            })
            .ok_or(Error::new("Failed to parse overrides".to_string(), ""))?;

        (level, levels_override)
    } else {
        err!(format!("LOG_LEVEL should follow the format info,vaultwarden::api::icons=debug, invalid: {config_str}"))
    };

    // Depending on the main log level we either want to disable or enable logging for hickory.
    // Else if there are timeouts it will clutter the logs since hickory uses warn for this.
    let hickory_level = if level >= log::LevelFilter::Debug {
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

    // Only show Rocket underscore `_` logs when the level is Debug or higher
    // Else this will bloat the log output with useless messages.
    let rocket_underscore_level = if level >= log::LevelFilter::Debug {
        log::LevelFilter::Warn
    } else {
        log::LevelFilter::Off
    };

    // Only show handlebar logs when the level is Trace
    let handlebars_level = if level >= log::LevelFilter::Trace {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Warn
    };

    // Enable smtp debug logging only specifically for smtp when need.
    // This can contain sensitive information we do not want in the default debug/trace logging.
    let smtp_log_level = if CONFIG.smtp_debug() {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Off
    };

    let mut default_levels = HashMap::from([
        // Hide unknown certificate errors if using self-signed
        ("rustls::session", log::LevelFilter::Off),
        // Hide failed to close stream messages
        ("hyper::server", log::LevelFilter::Warn),
        // Silence Rocket `_` logs
        ("_", rocket_underscore_level),
        ("rocket::response::responder::_", rocket_underscore_level),
        ("rocket::server::_", rocket_underscore_level),
        ("vaultwarden::api::admin::_", rocket_underscore_level),
        ("vaultwarden::api::notifications::_", rocket_underscore_level),
        // Silence Rocket logs
        ("rocket::launch", log::LevelFilter::Error),
        ("rocket::launch_", log::LevelFilter::Error),
        ("rocket::rocket", log::LevelFilter::Warn),
        ("rocket::server", log::LevelFilter::Warn),
        ("rocket::fairing::fairings", log::LevelFilter::Warn),
        ("rocket::shield::shield", log::LevelFilter::Warn),
        ("hyper::proto", log::LevelFilter::Off),
        ("hyper::client", log::LevelFilter::Off),
        // Filter handlebars logs
        ("handlebars::render", handlebars_level),
        // Prevent cookie_store logs
        ("cookie_store", log::LevelFilter::Off),
        // Variable level for hickory used by reqwest
        ("hickory_resolver::name_server::name_server", hickory_level),
        ("hickory_proto::xfer", hickory_level),
        ("diesel_logger", diesel_logger_level),
        // SMTP
        ("lettre::transport::smtp", smtp_log_level),
    ]);

    for (path, level) in levels_override.into_iter() {
        let _ = default_levels.insert(path, level);
    }

    if Some(&log::LevelFilter::Debug) == default_levels.get("lettre::transport::smtp") {
        println!(
            "[WARNING] SMTP Debugging is enabled (SMTP_DEBUG=true). Sensitive information could be disclosed via logs!\n\
             [WARNING] Only enable SMTP_DEBUG during troubleshooting!\n"
        );
    }

    let mut logger = fern::Dispatch::new().level(level).chain(std::io::stdout());

    for (path, level) in default_levels {
        logger = logger.level_for(path.to_string(), level);
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
        #[cfg(windows)]
        {
            logger = logger.chain(fern::log_file(log_file)?);
        }
        #[cfg(unix)]
        {
            const SIGHUP: i32 = SignalKind::hangup().as_raw_value();
            let path = Path::new(&log_file);
            logger = logger.chain(fern::log_reopen1(path, [SIGHUP])?);
        }
    }

    #[cfg(unix)]
    {
        if cfg!(feature = "enable_syslog") || CONFIG.use_syslog() {
            logger = chain_syslog(logger);
        }
    }

    if let Err(err) = logger.apply() {
        err!(format!("Failed to activate logger: {err}"))
    }

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

    Ok(level)
}

#[cfg(unix)]
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
        if is_running_in_container() {
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

    if is_running_in_container()
        && std::env::var("I_REALLY_WANT_VOLATILE_STORAGE").is_err()
        && !container_data_folder_is_persistent(data_folder).await
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
async fn container_data_folder_is_persistent(data_folder: &str) -> bool {
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
        .manage(Arc::clone(&WS_USERS))
        .manage(Arc::clone(&WS_ANONYMOUS_SUBSCRIPTIONS))
        .attach(util::AppHeaders())
        .attach(util::Cors())
        .attach(util::BetterLogging(extra_debug))
        .ignite()
        .await?;

    CONFIG.set_rocket_shutdown_handle(instance.shutdown());

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Error setting Ctrl-C handler");
        info!("Exiting Vaultwarden!");
        CONFIG.shutdown();
    });

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let mut signal_user1 = tokio::signal::unix::signal(SignalKind::user_defined1()).unwrap();
            loop {
                // If we need more signals to act upon, we might want to use select! here.
                // With only one item to listen for this is enough.
                let _ = signal_user1.recv().await;
                match backup_sqlite() {
                    Ok(f) => info!("Backup to '{f}' was successful"),
                    Err(e) => error!("Backup failed. {e:?}"),
                }
            }
        });
    }

    instance.launch().await?;

    info!("Vaultwarden process exited!");
    Ok(())
}

fn schedule_jobs(pool: db::DbPool) {
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

            if !CONFIG.auth_request_purge_schedule().is_empty() {
                sched.add(Job::new(CONFIG.auth_request_purge_schedule().parse().unwrap(), || {
                    runtime.spawn(purge_auth_requests(pool.clone()));
                }));
            }

            // Clean unused, expired Duo authentication contexts.
            if !CONFIG.duo_context_purge_schedule().is_empty() && CONFIG._enable_duo() && !CONFIG.duo_use_iframe() {
                sched.add(Job::new(CONFIG.duo_context_purge_schedule().parse().unwrap(), || {
                    runtime.spawn(purge_duo_contexts(pool.clone()));
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
                runtime.block_on(tokio::time::sleep(tokio::time::Duration::from_millis(CONFIG.job_poll_interval_ms())));
            }
        })
        .expect("Error spawning job scheduler thread");
}
