use std::io;
use std::path::{Path, PathBuf};

use rocket::request::Request;
use rocket::response::{self, NamedFile, Responder};
use rocket::Route;
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
fn web_index() -> WebHeaders<io::Result<NamedFile>> {
    web_files("index.html".into())
}

#[get("/<p..>", rank = 1)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> WebHeaders<io::Result<NamedFile>> {
    WebHeaders(NamedFile::open(Path::new(&CONFIG.web_vault_folder).join(p)))
}

struct WebHeaders<R>(R);

impl<'r, R: Responder<'r>> Responder<'r> for WebHeaders<R> {
    fn respond_to(self, req: &Request) -> response::Result<'r> {
        let mut res = self.0.respond_to(req)?;

        res.set_raw_header("Referrer-Policy", "same-origin");
        res.set_raw_header("X-Frame-Options", "SAMEORIGIN");
        res.set_raw_header("X-Content-Type-Options", "nosniff");
        res.set_raw_header("X-XSS-Protection", "1; mode=block");

        Ok(res)
    }
}

#[get("/attachments/<uuid>/<file..>")]
fn attachments(uuid: String, file: PathBuf) -> io::Result<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.attachments_folder).join(uuid).join(file))
}


#[get("/alive")]
fn alive() -> Json<String> {
    use util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}
