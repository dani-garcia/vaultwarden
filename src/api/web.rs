use std::io;
use std::path::{Path, PathBuf};

use rocket::request::Request;
use rocket::response::{self, NamedFile, Responder};
use rocket::response::content::Content;
use rocket::http::{ContentType, Status};
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

// TODO: Might want to use in memory cache: https://github.com/hgzimmerman/rocket-file-cache
#[get("/")]
fn web_index() -> WebHeaders<io::Result<NamedFile>> {
    web_files("index.html".into())
}

#[get("/app-id.json")]
fn app_id() -> WebHeaders<Content<Json<Value>>> {
    let content_type = ContentType::new("application", "fido.trusted-apps+json");

    WebHeaders(Content(content_type, Json(json!({
    "trustedFacets": [
        {
        "version": { "major": 1, "minor": 0 },
        "ids": [
            &CONFIG.domain,
            "ios:bundle-id:com.8bit.bitwarden",
            "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
        }]
    }))))
}

#[get("/admin")]
fn admin_page() -> WebHeaders<io::Result<NamedFile>> {
    WebHeaders(NamedFile::open("src/static/admin.html")) // TODO: Change this to embed the page in the binary
}

#[get("/<p..>", rank = 1)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> WebHeaders<io::Result<NamedFile>> {
    WebHeaders(NamedFile::open(Path::new(&CONFIG.web_vault_folder).join(p)))
}

struct WebHeaders<R>(R);

impl<'r, R: Responder<'r>> Responder<'r> for WebHeaders<R> {
    fn respond_to(self, req: &Request) -> response::Result<'r> {
        match self.0.respond_to(req) {
            Ok(mut res) => {
                res.set_raw_header("Referrer-Policy", "same-origin");
                res.set_raw_header("X-Frame-Options", "SAMEORIGIN");
                res.set_raw_header("X-Content-Type-Options", "nosniff");
                res.set_raw_header("X-XSS-Protection", "1; mode=block");
                let csp = "frame-ancestors 'self' chrome-extension://nngceckbapebfimnlniiiahkandclblb moz-extension://*;";
                res.set_raw_header("Content-Security-Policy", csp);

                Ok(res)
            },
            Err(_) => {
                Err(Status::NotFound)
            }
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
