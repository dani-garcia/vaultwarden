//! Test-only environment bootstrap.
//!
//! The main crate forbids `unsafe`, and `std::env::set_var` is `unsafe` on
//! edition 2024, so the mutation lives here. The `#[ctor]` constructor runs
//! before `main` and before any test thread exists, which is the only point
//! where the process environment can be changed race-free and the only point
//! early enough to beat the first deref of Vaultwarden's process-global
//! `CONFIG` (a `LazyLock` that reads the environment).
//!
//! Linkage is intentional: this crate only takes effect in test binaries that
//! reference it (`use test_support as _;`). Feature combos that do not compile
//! those test modules never link it and keep upstream behaviour.

/// Points every config-relevant environment variable at a per-process
/// temporary directory and enables the flags the SCIM test suite needs.
///
/// `DATABASE_URL` is deliberately left unset: Vaultwarden derives it as
/// `sqlite://{DATA_FOLDER}/db.sqlite3`, which lands inside the hermetic
/// directory, and hardcoding a sqlite URL here would poison config validation
/// for mysql/postgresql-only feature combos.
pub fn init_hermetic_env() {
    let base = std::env::temp_dir().join(format!("vaultwarden-test-{}", std::process::id()));
    let data = base.join("data");
    std::fs::create_dir_all(&data).expect("creating hermetic test data dir");

    // An empty env file: a configured-but-missing ENV_FILE makes Vaultwarden
    // exit at config load, and an unset one falls back to the repo's dev .env.
    let env_file = base.join("test.env");
    std::fs::write(&env_file, "").expect("creating hermetic test env file");

    let vars: &[(&str, String)] = &[
        ("ENV_FILE", env_file.to_string_lossy().into_owned()),
        ("DATA_FOLDER", data.to_string_lossy().into_owned()),
        ("DOMAIN", String::from("http://localhost:8000")),
        ("WEB_VAULT_ENABLED", String::from("false")),
        ("SIGNUPS_ALLOWED", String::from("true")),
        ("INVITATIONS_ALLOWED", String::from("true")),
        ("ORG_GROUPS_ENABLED", String::from("true")),
        ("SCIM_ENABLED", String::from("true")),
        ("SCIM_RATELIMIT_SECONDS", String::from("1")),
        // High burst so the shared per-IP limiter never trips ordinary tests;
        // the 429 path is exercised against a distinct synthetic IP.
        ("SCIM_RATELIMIT_MAX_BURST", String::from("10000")),
    ];

    for (key, value) in vars {
        // SAFETY: runs pre-main via #[ctor]; the process is single-threaded,
        // so mutating the environment cannot race with any reader.
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // Make sure a developer shell exporting SMTP settings cannot leak mail
    // sending into tests.
    for key in ["SMTP_HOST", "SMTP_FROM", "USE_SENDMAIL"] {
        // SAFETY: as above.
        unsafe {
            std::env::remove_var(key);
        }
    }
}

#[ctor::ctor(unsafe)]
fn hermetic_env() {
    init_hermetic_env();
}
