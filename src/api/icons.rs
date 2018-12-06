use std::io::prelude::*;
use std::fs::{create_dir_all, File};

use rocket::Route;
use rocket::response::Content;
use rocket::http::ContentType;

use reqwest;

use CONFIG;

pub fn routes() -> Vec<Route> {
    routes![icon]
}

#[get("/<domain>/icon.png")]
fn icon(domain: String) -> Content<Vec<u8>> {
    let icon_type = ContentType::new("image", "x-icon");

    // Validate the domain to avoid directory traversal attacks
    if domain.contains('/') || domain.contains("..") {
        return Content(icon_type, get_fallback_icon());
    }

    let icon = get_icon(&domain);

    Content(icon_type, icon)
}

fn get_icon (domain: &str) -> Vec<u8> {
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
        },
        Err(e) => {
            error!("Error downloading icon: {:?}", e);
            get_fallback_icon()
        }
    }
}

fn get_cached_icon(path: &str) -> Option<Vec<u8>> {
    // Try to read the cached icon, and return it if it exists
    if let Ok(mut f) = File::open(path) {
        let mut buffer = Vec::new();

        if f.read_to_end(&mut buffer).is_ok() {
            return Some(buffer);
        }
    }

    None
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

const FALLBACK_ICON_URL: &str = "https://raw.githubusercontent.com/bitwarden/web/master/src/images/fa-globe.png";

fn get_fallback_icon() -> Vec<u8> {
    let path = format!("{}/default.png", CONFIG.icon_cache_folder);
    
    if let Some(icon) = get_cached_icon(&path) {
        return icon;
    }

    match download_icon(FALLBACK_ICON_URL) {
        Ok(icon) => {
            save_icon(&path, &icon);
            icon
        },
        Err(e) => {
            error!("Error downloading fallback icon: {:?}", e);
            vec![]
        }
    }
}
