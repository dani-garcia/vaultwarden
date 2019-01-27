use std::fs::{create_dir_all, remove_file, symlink_metadata, File};
use std::io::prelude::*;
use std::time::SystemTime;

use rocket::http::ContentType;
use rocket::response::Content;
use rocket::Route;

use reqwest;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT_LANGUAGE, CACHE_CONTROL, PRAGMA, ACCEPT};
use std::time::Duration;

use crate::error::Error;
//use std::error::Error as StdError;
use crate::CONFIG;

//extern crate regex;
use regex::Regex;

//extern crate soup;
use soup::prelude::*;

use std::vec::Vec;
#[derive(Debug)]
struct IconList {
    priority: u8,
    href: String,
}

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
    let path = format!("{}/{}.png", CONFIG.icon_cache_folder(), domain);

    if let Some(icon) = get_cached_icon(&path) {
        return icon;
    }

    // Get the icon, or fallback in case of error
    match download_icon(&domain) {
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

fn file_is_expired(path: &str, ttl: u64) -> Result<bool, Error> {
    let meta = symlink_metadata(path)?;
    let modified = meta.modified()?;
    let age = SystemTime::now().duration_since(modified)?;

    Ok(ttl > 0 && ttl <= age.as_secs())
}

fn icon_is_negcached(path: &str) -> bool {
    let miss_indicator = path.to_owned() + ".miss";
    let expired = file_is_expired(&miss_indicator, CONFIG.icon_cache_negttl());

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
    let expired = file_is_expired(path, CONFIG.icon_cache_ttl());
    expired.unwrap_or(true)
}

/// Returns a Result with a String which holds the preferend favicon location.
/// There will always be a result with a string which will contain https://example.com/favicon.ico
/// This does not mean that that location does exists, but it is the default location.
///
/// # Argument
/// * `domain` - A string which holds the domain with extension.
///
/// # Example
/// ```
/// favicon_location1 = get_icon_url("github.com");
/// favicon_location2 = get_icon_url("gitlab.com");
/// ```
fn get_icon_url(domain: &str) -> Result<String, Error> {
    // Set some default headers for the request.
    // Use a browser like user-agent to make sure most websites will return there correct website.
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8"));

    let client = Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(5))
        .default_headers(headers)
        .build()?;

    // Default URL with secure and insecure schemes
    let ssldomain = format!("https://{}", domain);
    let httpdomain = format!("http://{}", domain);

    // Create the iconlist
    let mut iconlist: Vec<IconList> = Vec::new();

    let resp = client.get(&ssldomain).send().or_else(|_| client.get(&httpdomain).send());
    if let Ok(mut content) = resp {
        let body = content.text().unwrap();
        // Extract the URL from te respose incase redirects occured (like @ gitlab.com)
        let url = format!("{}://{}", content.url().scheme(), content.url().host().unwrap());

        // Add the default favicon.ico to the list with the domain the content responded from.
        iconlist.push(IconList { priority: 35, href: format!("{}{}", url, "/favicon.ico") });

        let soup = Soup::new(&body);
        // Search for and filter
        let favicons = soup
            .tag("link")
            .attr("rel", Regex::new(r"icon$|apple.*icon")?) // Only use icon rels
            .attr("href", Regex::new(r"(?i)\w+(\.jp(e){0,1}g$|\.png$|\.ico$)")?) // Only allow specific extensions
            .find_all();

        // Loop through all the found icons and determine it's priority
        for favicon in favicons {
            let favicon_sizes = favicon.get("sizes").unwrap_or("".to_string()).to_string();
            let favicon_href = fix_href(&favicon.get("href").unwrap_or("".to_string()).to_string(), &url);
            let favicon_priority = get_icon_priority(&favicon_href, &favicon_sizes);

            iconlist.push(IconList { priority: favicon_priority, href: favicon_href})
        }
    } else {
        // Add the default favicon.ico to the list with just the given domain
        iconlist.push(IconList { priority: 35, href: format!("{}{}", ssldomain, "/favicon.ico") });
    }

    // Sort the iconlist by priority
    iconlist.sort_by_key(|x| x.priority);

    // There always is an icon in the list, so no need to check if it exists, and just return the first one
    Ok(format!("{}", &iconlist[0].href))
}

/// Returns a Integer with the priority of the type of the icon which to prefer.
/// The lower the number the better.
///
/// # Arguments
/// * `href`  - A string which holds the href value or relative path.
/// * `sizes` - The size of the icon if available as a <width>x<height> value like 32x32.
///
/// # Example
/// ```
/// priority1 = get_icon_priority("http://example.com/path/to/a/favicon.png", "32x32");
/// priority2 = get_icon_priority("https://example.com/path/to/a/favicon.ico", "");
/// ```
fn get_icon_priority(href: &str, sizes: &str) -> u8 {
    // Check if there is a dimension set
    if ! sizes.is_empty() {
        let dimensions : Vec<&str> = sizes.split("x").collect();
        let width = dimensions[0].parse::<u16>().unwrap();
        let height = dimensions[1].parse::<u16>().unwrap();

        // Only allow square dimensions
        if width == height {
            // Change priority by given size
            if width == 32 {
                1
            } else if width == 64 {
                2
            } else if width >= 24 && width <= 128 {
                3
            } else if width == 16 {
                4
            } else {
                100
            }
        } else {
            200
        }
    } else {
        // Change priority by file extension
        if href.ends_with(".png") {
            10
        } else if href.ends_with(".jpg") || href.ends_with(".jpeg") {
            20
        } else {
            30
        }
    }
}

/// Returns a String which will have the given href fixed by adding the correct URL if it does not have this already.
///
/// # Arguments
/// * `href` - A string which holds the href value or relative path.
/// * `url`  - A string which holds the URL including http(s) which will preseed the href when needed.
///
/// # Example
/// ```
/// fixed_href1 = fix_href("/path/to/a/favicon.png", "https://eample.com");
/// fixed_href2 = fix_href("//example.com/path/to/a/second/favicon.jpg", "https://eample.com");
/// ```
fn fix_href(href: &str, url: &str) -> String {
    // When the href is starting with //, so without a scheme is valid and would use the browsers scheme.
    // We need to detect this and add the scheme here.
    if href.starts_with("//") {
        if url.starts_with("https") {
            format!("https:{}", href)
        } else {
            format!("http:{}", href)
        }
    // If the href_output just starts with a single / it does not have the host here at all.
    } else if ! href.starts_with("http") {
        if href.starts_with("/") {
            format!("{}{}", url, href)
        } else {
            format!("{}/{}", url, href)
        }
    // All seems oke, just return the given href
    } else {
        format!("{}", href)
    }
}

fn download_icon(domain: &str) -> Result<Vec<u8>, Error> {
    let url = get_icon_url(&domain)?;

    info!("Downloading icon for {} via {}...",domain, url);
    let mut res = reqwest::get(&url)?;

    res = res.error_for_status()?;

    let mut buffer: Vec<u8> = vec![];
    res.copy_to(&mut buffer)?;

    Ok(buffer)
}

fn save_icon(path: &str, icon: &[u8]) {
    create_dir_all(&CONFIG.icon_cache_folder()).expect("Error creating icon cache");

    if let Ok(mut f) = File::create(path) {
        f.write_all(icon).expect("Error writing icon file");
    };
}
