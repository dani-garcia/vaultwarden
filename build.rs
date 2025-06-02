use std::env;
use std::process::Command;

fn main() {
    // This allow using #[cfg(sqlite)] instead of #[cfg(feature = "sqlite")], which helps when trying to add them through macros
    #[cfg(feature = "sqlite")]
    println!("cargo:rustc-cfg=sqlite");
    #[cfg(feature = "mysql")]
    println!("cargo:rustc-cfg=mysql");
    #[cfg(feature = "postgresql")]
    println!("cargo:rustc-cfg=postgresql");
    #[cfg(feature = "query_logger")]
    println!("cargo:rustc-cfg=query_logger");
    #[cfg(feature = "s3")]
    println!("cargo:rustc-cfg=s3");

    #[cfg(not(any(feature = "sqlite", feature = "mysql", feature = "postgresql")))]
    compile_error!(
        "You need to enable one DB backend. To build with previous defaults do: cargo build --features sqlite"
    );

    // Use check-cfg to let cargo know which cfg's we define,
    // and avoid warnings when they are used in the code.
    println!("cargo::rustc-check-cfg=cfg(sqlite)");
    println!("cargo::rustc-check-cfg=cfg(mysql)");
    println!("cargo::rustc-check-cfg=cfg(postgresql)");
    println!("cargo::rustc-check-cfg=cfg(query_logger)");
    println!("cargo::rustc-check-cfg=cfg(s3)");

    // Rerun when these paths are changed.
    // Someone could have checked-out a tag or specific commit, but no other files changed.
    println!("cargo:rerun-if-changed=.git");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    #[cfg(all(not(debug_assertions), feature = "query_logger"))]
    compile_error!("Query Logging is only allowed during development, it is not intended for production usage!");

    // Support $BWRS_VERSION for legacy compatibility, but default to $VW_VERSION.
    // If neither exist, read from git.
    let maybe_vaultwarden_version =
        env::var("VW_VERSION").or_else(|_| env::var("BWRS_VERSION")).or_else(|_| version_from_git_info());

    if let Ok(version) = maybe_vaultwarden_version {
        println!("cargo:rustc-env=VW_VERSION={version}");
        println!("cargo:rustc-env=CARGO_PKG_VERSION={version}");
    }
}

fn run(args: &[&str]) -> Result<String, std::io::Error> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        use std::io::Error;
        return Err(Error::other("Command not successful"));
    }
    Ok(String::from_utf8(out.stdout).unwrap().trim().to_string())
}

/// This method reads info from Git, namely tags, branch, and revision
/// To access these values, use:
///    - `env!("GIT_EXACT_TAG")`
///    - `env!("GIT_LAST_TAG")`
///    - `env!("GIT_BRANCH")`
///    - `env!("GIT_REV")`
///    - `env!("VW_VERSION")`
fn version_from_git_info() -> Result<String, std::io::Error> {
    // The exact tag for the current commit, can be empty when
    // the current commit doesn't have an associated tag
    let exact_tag = run(&["git", "describe", "--abbrev=0", "--tags", "--exact-match"]).ok();
    if let Some(ref exact) = exact_tag {
        println!("cargo:rustc-env=GIT_EXACT_TAG={exact}");
    }

    // The last available tag, equal to exact_tag when
    // the current commit is tagged
    let last_tag = run(&["git", "describe", "--abbrev=0", "--tags"])?;
    println!("cargo:rustc-env=GIT_LAST_TAG={last_tag}");

    // The current branch name
    let branch = run(&["git", "rev-parse", "--abbrev-ref", "HEAD"])?;
    println!("cargo:rustc-env=GIT_BRANCH={branch}");

    // The current git commit hash
    let rev = run(&["git", "rev-parse", "HEAD"])?;
    let rev_short = rev.get(..8).unwrap_or_default();
    println!("cargo:rustc-env=GIT_REV={rev_short}");

    // Combined version
    if let Some(exact) = exact_tag {
        Ok(exact)
    } else if &branch != "main" && &branch != "master" && &branch != "HEAD" {
        Ok(format!("{last_tag}-{rev_short} ({branch})"))
    } else {
        Ok(format!("{last_tag}-{rev_short}"))
    }
}
