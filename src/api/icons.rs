use std::error::Error;
use std::fs::{create_dir_all, remove_file, symlink_metadata, File};
use std::io::prelude::*;
use std::time::SystemTime;

use rocket::http::ContentType;
use rocket::response::Content;
use rocket::Route;

use reqwest;

use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![icon]
}

const FALLBACK_ICON: &[u8; 344] = include_bytes!("../static/fallback-icon.png");

#[get("/<domain>/icon.png")]
fn icon(domain: String) -> Content<Vec<u8>> {
    let icon_type = ContentType::new("image", "x-icon");

    // Validate the domain to avoid directory traversal attacks
    if domain.contains('/') || domain.contains("..") {
        return Content(icon_type, FALLBACK_ICON.to_vec());
    }

    let icon = get_icon(&domain);

    Content(icon_type, icon)
}

fn get_icon(domain: &str) -> Vec<u8> {
    let path = format!("{}/{}.png", CONFIG.icon_cache_folder, domain);

    if let Some(icon) = get_cached_icon(&path) {
        return icon;
    }

    let url = get_icon_url(&domain);

    // Get the icon, or fallback in case of error
    match download_icon(&url) {
        Ok(icon) => {
            save_icon(&path, &icon);
            icon
        }
        Err(e) => {
            error!("Error downloading icon: {:?}", e);
            mark_negcache(&path);
            FALLBACK_ICON.to_vec()
        }
    }
}

fn get_cached_icon(path: &str) -> Option<Vec<u8>> {
    // Check for expiration of negatively cached copy
    if icon_is_negcached(path) {
        return Some(FALLBACK_ICON.to_vec());
    }

    // Check for expiration of successfully cached copy
    if icon_is_expired(path) {
        return None;
    }

    // Try to read the cached icon, and return it if it exists
    if let Ok(mut f) = File::open(path) {
        let mut buffer = Vec::new();

        if f.read_to_end(&mut buffer).is_ok() {
            return Some(buffer);
        }
    }

    None
}

fn file_is_expired(path: &str, ttl: u64) -> Result<bool, Box<Error>> {
    let meta = symlink_metadata(path)?;
    let modified = meta.modified()?;
    let age = SystemTime::now().duration_since(modified)?;

    Ok(ttl > 0 && ttl <= age.as_secs())
}

fn icon_is_negcached(path: &str) -> bool {
    let miss_indicator = path.to_owned() + ".miss";
    let expired = file_is_expired(&miss_indicator, CONFIG.icon_cache_negttl);

    match expired {
        // No longer negatively cached, drop the marker
        Ok(true) => {
            if let Err(e) = remove_file(&miss_indicator) {
                error!("Could not remove negative cache indicator for icon {:?}: {:?}", path, e);
            }
            false
        }
        // The marker hasn't expired yet.
        Ok(false) => true,
        // The marker is missing or inaccessible in some way.
        Err(_) => false,
    }
}

fn mark_negcache(path: &str) {
    let miss_indicator = path.to_owned() + ".miss";
    File::create(&miss_indicator).expect("Error creating negative cache marker");
}

fn icon_is_expired(path: &str) -> bool {
    let expired = file_is_expired(path, CONFIG.icon_cache_ttl);
    expired.unwrap_or(true)
}

fn get_icon_url(domain: &str) -> String {
    if CONFIG.local_icon_extractor {
        format!("http://{}/favicon.ico", domain)
    } else {
        format!("https://icons.bitwarden.com/{}/icon.png", domain)
    }
}

fn download_icon(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    info!("Downloading icon for {}...", url);
    let mut res = reqwest::get(url)?;

    res = res.error_for_status()?;

    let mut buffer: Vec<u8> = vec![];
    res.copy_to(&mut buffer)?;

    Ok(buffer)
}

fn save_icon(path: &str, icon: &[u8]) {
    create_dir_all(&CONFIG.icon_cache_folder).expect("Error creating icon cache");

    if let Ok(mut f) = File::create(path) {
        f.write_all(icon).expect("Error writing icon file");
    };
}
