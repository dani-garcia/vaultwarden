use std::path::{Path, PathBuf};

use rocket::{fs::NamedFile, http::ContentType, response::content::RawHtml as Html, serde::json::Json, Catcher, Route};
use serde_json::Value;

use crate::{
    api::{core::now, ApiResult, EmptyResult},
    error::Error,
    util::{Cached, SafeString},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    // If addding more routes here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    if CONFIG.web_vault_enabled() {
        routes![web_index, web_index_head, app_id, web_files, attachments, alive, alive_head, static_files]
    } else {
        routes![attachments, alive, alive_head, static_files]
    }
}

pub fn catchers() -> Vec<Catcher> {
    if CONFIG.web_vault_enabled() {
        catchers![not_found]
    } else {
        catchers![]
    }
}

#[catch(404)]
fn not_found() -> ApiResult<Html<String>> {
    // Return the page
    let json = json!({
        "urlpath": CONFIG.domain_path()
    });
    let text = CONFIG.render_template("404", &json)?;
    Ok(Html(text))
}

#[get("/")]
async fn web_index() -> Cached<Option<NamedFile>> {
    Cached::short(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join("index.html")).await.ok(), false)
}

#[head("/")]
fn web_index_head() -> EmptyResult {
    // Add an explicit HEAD route to prevent uptime monitoring services from
    // generating "No matching routes for HEAD /" error messages.
    //
    // Rocket automatically implements a HEAD route when there's a matching GET
    // route, but relying on this behavior also means a spurious error gets
    // logged due to <https://github.com/SergioBenitez/Rocket/issues/1098>.
    Ok(())
}

#[get("/app-id.json")]
fn app_id() -> Cached<(ContentType, Json<Value>)> {
    let content_type = ContentType::new("application", "fido.trusted-apps+json");

    Cached::long(
        (
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
        ),
        true,
    )
}

#[get("/<p..>", rank = 10)] // Only match this if the other routes don't match
async fn web_files(p: PathBuf) -> Cached<Option<NamedFile>> {
    Cached::long(NamedFile::open(Path::new(&CONFIG.web_vault_folder()).join(p)).await.ok(), true)
}

#[get("/attachments/<uuid>/<file_id>")]
async fn attachments(uuid: SafeString, file_id: SafeString) -> Option<NamedFile> {
    NamedFile::open(Path::new(&CONFIG.attachments_folder()).join(uuid).join(file_id)).await.ok()
}

// We use DbConn here to let the alive healthcheck also verify the database connection.
use crate::db::DbConn;
#[get("/alive")]
fn alive(_conn: DbConn) -> Json<String> {
    now()
}

#[head("/alive")]
fn alive_head(_conn: DbConn) -> EmptyResult {
    // Avoid logging spurious "No matching routes for HEAD /alive" errors
    // due to <https://github.com/SergioBenitez/Rocket/issues/1098>.
    Ok(())
}

#[get("/vw_static/<filename>")]
pub fn static_files(filename: String) -> Result<(ContentType, &'static [u8]), Error> {
    match filename.as_ref() {
        "404.png" => Ok((ContentType::PNG, include_bytes!("../static/images/404.png"))),
        "mail-github.png" => Ok((ContentType::PNG, include_bytes!("../static/images/mail-github.png"))),
        "logo-gray.png" => Ok((ContentType::PNG, include_bytes!("../static/images/logo-gray.png"))),
        "error-x.svg" => Ok((ContentType::SVG, include_bytes!("../static/images/error-x.svg"))),
        "hibp.png" => Ok((ContentType::PNG, include_bytes!("../static/images/hibp.png"))),
        "vaultwarden-icon.png" => Ok((ContentType::PNG, include_bytes!("../static/images/vaultwarden-icon.png"))),
        "vaultwarden-favicon.png" => Ok((ContentType::PNG, include_bytes!("../static/images/vaultwarden-favicon.png"))),
        "404.css" => Ok((ContentType::CSS, include_bytes!("../static/scripts/404.css"))),
        "admin.css" => Ok((ContentType::CSS, include_bytes!("../static/scripts/admin.css"))),
        "admin.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/admin.js"))),
        "admin_settings.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/admin_settings.js"))),
        "admin_users.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/admin_users.js"))),
        "admin_organizations.js" => {
            Ok((ContentType::JavaScript, include_bytes!("../static/scripts/admin_organizations.js")))
        }
        "admin_diagnostics.js" => {
            Ok((ContentType::JavaScript, include_bytes!("../static/scripts/admin_diagnostics.js")))
        }
        "bootstrap.css" => Ok((ContentType::CSS, include_bytes!("../static/scripts/bootstrap.css"))),
        "bootstrap-native.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/bootstrap-native.js"))),
        "jdenticon.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/jdenticon.js"))),
        "datatables.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/datatables.js"))),
        "datatables.css" => Ok((ContentType::CSS, include_bytes!("../static/scripts/datatables.css"))),
        "jquery-3.6.3.slim.js" => {
            Ok((ContentType::JavaScript, include_bytes!("../static/scripts/jquery-3.6.3.slim.js")))
        }
        _ => err!(format!("Static file not found: {filename}")),
    }
}
