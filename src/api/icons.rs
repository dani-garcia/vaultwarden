use std::io;
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
    if domain.contains("/") || domain.contains("..") {
        return Content(icon_type, get_fallback_icon());
    }

    let url = format!("https://icons.bitwarden.com/{}/icon.png", domain);

    // Get the icon, or fallback in case of error
    let icon = match get_icon_cached(&domain, &url) {
        Ok(icon) => icon,
        Err(_) => return Content(icon_type, get_fallback_icon())
    };

    Content(icon_type, icon)
}

fn get_icon(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let mut res = reqwest::get(url)?;

    res = match res.error_for_status() {
        Err(e) => return Err(e),
        Ok(res) => res
    };

    let mut buffer: Vec<u8> = vec![];
    res.copy_to(&mut buffer)?;

    Ok(buffer)
}

fn get_icon_cached(key: &str, url: &str) -> io::Result<Vec<u8>> {
    create_dir_all(&CONFIG.icon_cache_folder)?;
    let path = &format!("{}/{}.png", CONFIG.icon_cache_folder, key);

    // Try to read the cached icon, and return it if it exists
    if let Ok(mut f) = File::open(path) {
        let mut buffer = Vec::new();

        if f.read_to_end(&mut buffer).is_ok() {
            return Ok(buffer);
        }
        /* If error reading file continue */
    }

    println!("Downloading icon for {}...", key);
    let icon = match get_icon(url) {
        Ok(icon) => icon,
        Err(_) => return Err(io::Error::new(io::ErrorKind::NotFound, ""))
    };

    // Save the currently downloaded icon
    if let Ok(mut f) = File::create(path) {
        f.write_all(&icon).expect("Error writing icon file");
    };

    Ok(icon)
}

fn get_fallback_icon() -> Vec<u8> {
    let fallback_icon = "https://raw.githubusercontent.com/bitwarden/web/master/src/images/fa-globe.png";
    get_icon_cached("default", fallback_icon).unwrap()
}
