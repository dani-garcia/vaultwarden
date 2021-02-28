use std::path::{Path, PathBuf};

use rocket::{http::ContentType, response::content::Content, response::NamedFile, Route};
use rocket_contrib::json::Json;
use serde_json::Value;

use crate::{error::Error, util::Cached, CONFIG};

pub fn routes() -> Vec<Route> {
    // If addding more routes here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    if CONFIG.web_vault_enabled() {
        routes![web_index, app_id, web_files, attachments, alive, static_files]
    } else {
        routes![attachments, alive, static_files]
    }
}

#[get("/")]
fn web_index() -> Cached<Option<NamedFile>> {
    Cached::short(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join("index.html")).ok())
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
                // Per <https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html#determining-the-facetid-of-a-calling-application>:
                //
                // "In the Web case, the FacetID MUST be the Web Origin [RFC6454]
                // of the web page triggering the FIDO operation, written as
                // a URI with an empty path. Default ports are omitted and any
                // path component is ignored."
                //
                // This leaves it unclear as to whether the path must be empty,
                // or whether it can be non-empty and will be ignored. To be on
                // the safe side, use a proper web origin (with empty path).
                &CONFIG.domain_origin(),
                "ios:bundle-id:com.8bit.bitwarden",
                "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
            }]
        })),
    ))
}

#[get("/<p..>", rank = 10)] // Only match this if the other routes don't match
fn web_files(p: PathBuf) -> Cached<Option<NamedFile>> {
    Cached::long(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join(p)).ok())
}

#[get("/attachments/<uuid>/<file..>")]
fn attachments(uuid: String, file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.attachments_folder()).join(uuid).join(file)).ok()
}

#[get("/alive")]
fn alive() -> Json<String> {
    use crate::util::format_date;
    use chrono::Utc;

    Json(format_date(&Utc::now().naive_utc()))
}

#[get("/bwrs_static/<filename>")]
fn static_files(filename: String) -> Result<Content<&'static [u8]>, Error> {
    match filename.as_ref() {
        "mail-github.png" => Ok(Content(ContentType::PNG, include_bytes!("../static/images/mail-github.png"))),
        "logo-gray.png" => Ok(Content(ContentType::PNG, include_bytes!("../static/images/logo-gray.png"))),
        "shield-white.png" => Ok(Content(ContentType::PNG, include_bytes!("../static/images/shield-white.png"))),
        "error-x.svg" => Ok(Content(ContentType::SVG, include_bytes!("../static/images/error-x.svg"))),
        "hibp.png" => Ok(Content(ContentType::PNG, include_bytes!("../static/images/hibp.png"))),

        "bootstrap.css" => Ok(Content(ContentType::CSS, include_bytes!("../static/scripts/bootstrap.css"))),
        "bootstrap-native.js" => Ok(Content(ContentType::JavaScript, include_bytes!("../static/scripts/bootstrap-native.js"))),
        "identicon.js" => Ok(Content(ContentType::JavaScript, include_bytes!("../static/scripts/identicon.js"))),
        "datatables.js" => Ok(Content(ContentType::JavaScript, include_bytes!("../static/scripts/datatables.js"))),
        "datatables.css" => Ok(Content(ContentType::CSS, include_bytes!("../static/scripts/datatables.css"))),
        "jquery-3.5.1.slim.js" => Ok(Content(ContentType::JavaScript, include_bytes!("../static/scripts/jquery-3.5.1.slim.js"))),
        _ => err!(format!("Static file not found: {}", filename)),
    }
}
