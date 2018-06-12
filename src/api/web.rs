use std::io;
use std::path::{Path, PathBuf};

use rocket::Route;
use rocket::response::NamedFile;
use rocket_contrib::Json;

use CONFIG;

pub fn routes() -> Vec<Route> {
    if CONFIG.web_vault_enabled {
        routes![web_index, web_files, attachments, alive]
    } else {
        routes![attachments, alive]
    }
}

// TODO: Might want to use in memory cache: https://github.com/hgzimmerman/rocket-file-cache
#[get("/")]
fn web_index() -> io::Result<NamedFile> {
    NamedFile::open(
        Path::new(&CONFIG.web_vault_folder)
            .join("index.html"))
}

#[get("/<p..>", rank = 1)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(
        Path::new(&CONFIG.web_vault_folder)
            .join(p))
}


#[get("/attachments/<uuid>/<file..>")]
fn attachments(uuid: String, file: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(
        Path::new(&CONFIG.attachments_folder)
            .join(uuid)
            .join(file)
    )
}


#[get("/alive")]
fn alive() -> Json<String> {
    use util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}
