use std::io;
use std::path::{Path, PathBuf};

use rocket::http::ContentType;
use rocket::request::Request;
use rocket::response::content::Content;
use rocket::response::{self, NamedFile, Responder};
use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    if CONFIG.web_vault_enabled {
        routes![web_index, app_id, web_files, admin_page, attachments, alive]
    } else {
        routes![attachments, alive]
    }
}

#[get("/")]
fn web_index() -> Cached<io::Result<NamedFile>> {
    Cached::short(NamedFile::open(Path::new(&CONFIG.web_vault_folder).join("index.html")))
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
                &CONFIG.domain,
                "ios:bundle-id:com.8bit.bitwarden",
                "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
            }]
        })),
    ))
}

const ADMIN_PAGE: &'static str = include_str!("../static/admin.html");
use rocket::response::content::Html;

#[get("/admin")]
fn admin_page() -> Cached<Html<&'static str>> {
    Cached::short(Html(ADMIN_PAGE))
}

/* // Use this during Admin page development
#[get("/admin")]
fn admin_page() -> Cached<io::Result<NamedFile>> {
    Cached::short(NamedFile::open("src/static/admin.html"))
}
*/

#[get("/<p..>", rank = 1)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> Cached<io::Result<NamedFile>> {
    Cached::long(NamedFile::open(Path::new(&CONFIG.web_vault_folder).join(p)))
}

struct Cached<R>(R, &'static str);

impl<R> Cached<R> {
    fn long(r: R) -> Cached<R> {
        // 7 days
        Cached(r, "public, max-age=604800".into())
    }

    fn short(r: R) -> Cached<R> {
        // 10 minutes
        Cached(r, "public, max-age=600".into())
    }
}

impl<'r, R: Responder<'r>> Responder<'r> for Cached<R> {
    fn respond_to(self, req: &Request) -> response::Result<'r> {
        match self.0.respond_to(req) {
            Ok(mut res) => {
                res.set_raw_header("Cache-Control", self.1);
                Ok(res)
            }
            e @ Err(_) => e,
        }
    }
}

#[get("/attachments/<uuid>/<file..>")]
fn attachments(uuid: String, file: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.attachments_folder).join(uuid).join(file))
}

#[get("/alive")]
fn alive() -> Json<String> {
    use crate::util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}
