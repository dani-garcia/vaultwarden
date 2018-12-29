use std::process::Command;

fn main() {
    read_git_info().expect("Unable to read Git info");
}

fn run(args: &[&str]) -> Result<String, std::io::Error> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    Ok(String::from_utf8(out.stdout).unwrap().trim().to_string())
}

/// This method reads info from Git, namely tags, branch, and revision
fn read_git_info() -> Result<(), std::io::Error> {
    // The exact tag for the current commit, can be empty when
    // the current commit doesn't have an associated tag
    let exact_tag = run(&["git", "describe", "--abbrev=0", "--tags", "--exact-match"])?;
    println!("cargo:rustc-env=GIT_EXACT_TAG={}", exact_tag);

    // The last available tag, equal to exact_tag when
    // the current commit is tagged
    let last_tag = run(&["git", "describe", "--abbrev=0", "--tags"])?;
    println!("cargo:rustc-env=GIT_LAST_TAG={}", last_tag);

    // The current branch name
    let branch = run(&["git", "rev-parse", "--abbrev-ref", "HEAD"])?;
    println!("cargo:rustc-env=GIT_BRANCH={}", branch);

    // The current git commit hash
    let rev = run(&["git", "rev-parse", "HEAD"])?;
    let rev_short = rev.get(..12).unwrap_or_default();
    println!("cargo:rustc-env=GIT_REV={}", rev_short);

    // To access these values, use:
    //    env!("GIT_EXACT_TAG")
    //    env!("GIT_LAST_TAG")
    //    env!("GIT_BRANCH")
    //    env!("GIT_REV")
    Ok(())
}
