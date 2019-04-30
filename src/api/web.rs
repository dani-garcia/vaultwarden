use std::io;
use std::path::{Path, PathBuf};

use rocket::http::ContentType;
use rocket::response::content::Content;
use rocket::response::NamedFile;
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::util::Cached;
use crate::error::Error;
use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    if CONFIG.web_vault_enabled() {
        routes![web_index, app_id, web_files, attachments, alive, images]
    } else {
        routes![attachments, alive]
    }
}

#[get("/")]
fn web_index() -> Cached<io::Result<NamedFile>> {
    Cached::short(NamedFile::open(
        Path::new(&CONFIG.web_vault_folder()).join("index.html"),
    ))
}

#[get("/app-id.json")]
fn app_id() -> Cached<Content<Json<Value>>> {
    let content_type = ContentType::new("application", "fido.trusted-apps+json");

    Cached::long(Content(
        content_type,
        Json(json!({
        "trustedFacets": [
            {
            "version": { "major": 1, "minor": 0 },
            "ids": [
                &CONFIG.domain(),
                "ios:bundle-id:com.8bit.bitwarden",
                "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
            }]
        })),
    ))
}

#[get("/<p..>", rank = 10)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> Cached<io::Result<NamedFile>> {
    Cached::long(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join(p)))
}

#[get("/attachments/<uuid>/<file..>")]
fn attachments(uuid: String, file: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.attachments_folder()).join(uuid).join(file))
}

#[get("/alive")]
fn alive() -> Json<String> {
    use crate::util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}

#[get("/images/<filename>")]
fn images(filename: String) -> Result<Content<Vec<u8>>, Error> {
    let image_type = ContentType::new("image", "png");
    match filename.as_ref() {
        "mail-github.png" => Ok(Content(image_type , include_bytes!("../static/images/mail-github.png").to_vec())),
        "logo-gray.png" => Ok(Content(image_type, include_bytes!("../static/images/logo-gray.png").to_vec())),
        _ => err!("Image not found")
    }
}