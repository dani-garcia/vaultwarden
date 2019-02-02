use std::fs::{create_dir_all, remove_file, symlink_metadata, File};
use std::io::prelude::*;
use std::time::{Duration, SystemTime};

use rocket::http::ContentType;
use rocket::response::Content;
use rocket::Route;

use reqwest::{header::HeaderMap, Client, Response};

use rocket::http::{Cookie};

use regex::Regex;
use soup::prelude::*;

use crate::error::Error;
use crate::CONFIG;

pub fn routes() -> Vec<Route> {
    routes![icon]
}

const FALLBACK_ICON: &[u8; 344] = include_bytes!("../static/fallback-icon.png");

lazy_static! {
    // Reuse the client between requests
    static ref CLIENT: Client = Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(5))
        .default_headers(_header_map())
        .build()
        .unwrap();
}

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

    if CONFIG.disable_icon_download() {
        return FALLBACK_ICON.to_vec();
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

#[derive(Debug)]
struct IconList {
    priority: u8,
    href: String,
}

/// Returns a Result/Tuple which holds a Vector IconList and a string which holds the cookies from the last response.
/// There will always be a result with a string which will contain https://example.com/favicon.ico and an empty string for the cookies.
/// This does not mean that that location does exists, but it is the default location browser use.
///
/// # Argument
/// * `domain` - A string which holds the domain with extension.
///
/// # Example
/// ```
/// let (mut iconlist, cookie_str) = get_icon_url("github.com")?;
/// let (mut iconlist, cookie_str) = get_icon_url("gitlab.com")?;
/// ```
fn get_icon_url(domain: &str) -> Result<(Vec<IconList>, String), Error> {
    // Default URL with secure and insecure schemes
    let ssldomain = format!("https://{}", domain);
    let httpdomain = format!("http://{}", domain);

    // Create the iconlist
    let mut iconlist: Vec<IconList> = Vec::new();

    // Create the cookie_str to fill it all the cookies from the response
    // These cookies can be used to request/download the favicon image.
    // Some sites have extra security in place with for example XSRF Tokens.
    let mut cookie_str = String::new();

    let resp = get_page(&ssldomain).or_else(|_| get_page(&httpdomain));
    if let Ok(content) = resp {
        // Extract the URL from the respose in case redirects occured (like @ gitlab.com)
        let url = content.url().clone();
        let raw_cookies = content.headers().get_all("set-cookie");
        cookie_str = raw_cookies.iter().map(|raw_cookie| {
            let cookie = Cookie::parse(raw_cookie.to_str().unwrap_or_default()).unwrap();
            format!("{}={}; ", cookie.name(), cookie.value())
        }).collect::<String>();

        // Add the default favicon.ico to the list with the domain the content responded from.
        iconlist.push(IconList { priority: 35, href: url.join("/favicon.ico").unwrap().into_string() });

        let soup = Soup::from_reader(content)?;
        // Search for and filter
        let favicons = soup
            .tag("link")
            .attr("rel", Regex::new(r"icon$|apple.*icon")?) // Only use icon rels
            .attr("href", Regex::new(r"(?i)\w+\.(jpg|jpeg|png|ico)(\?.*)?$")?) // Only allow specific extensions
            .find_all();

        // Loop through all the found icons and determine it's priority
        for favicon in favicons {
            let sizes = favicon.get("sizes").unwrap_or_default();
            let href = url.join(&favicon.get("href").unwrap_or_default()).unwrap().into_string();
            let priority = get_icon_priority(&href, &sizes);

            iconlist.push(IconList { priority, href })
        }
    } else {
        // Add the default favicon.ico to the list with just the given domain
        iconlist.push(IconList { priority: 35, href: format!("{}/favicon.ico", ssldomain) });
    }

    // Sort the iconlist by priority
    iconlist.sort_by_key(|x| x.priority);

    // There always is an icon in the list, so no need to check if it exists, and just return the first one
    Ok((iconlist, cookie_str))
}

fn get_page(url: &str) -> Result<Response, Error> {
    //CLIENT.get(url).send()?.error_for_status().map_err(Into::into)
    get_page_with_cookies(url, "")
}

fn get_page_with_cookies(url: &str, cookie_str: &str) -> Result<Response, Error> {
    CLIENT.get(url).header("cookie", cookie_str).send()?.error_for_status().map_err(Into::into)
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
    let (width, height) = parse_sizes(sizes);

    // Check if there is a size given
    if width != 0 && height != 0 {
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
                5
            }
        // There are dimensions available, but the image is not a square
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

/// Returns a Tuple with the width and hight as a seperate value extracted from the sizes attribute
/// It will return 0 for both values if no match has been found.
///
/// # Arguments
/// * `sizes` - The size of the icon if available as a <width>x<height> value like 32x32.
///
/// # Example
/// ```
/// let (width, height) = parse_sizes("64x64"); // (64, 64)
/// let (width, height) = parse_sizes("x128x128"); // (128, 128)
/// let (width, height) = parse_sizes("32"); // (0, 0)
/// ```
fn parse_sizes(sizes: &str) -> (u16, u16) {
    let mut width: u16 = 0;
    let mut height: u16 = 0;

    if !sizes.is_empty() {
        match Regex::new(r"(?x)(\d+)\D*(\d+)").unwrap().captures(sizes.trim()) {
            None => {},
            Some(dimensions) => {
                if dimensions.len() >= 3 {
                    width = dimensions[1].parse::<u16>().unwrap_or_default();
                    height = dimensions[2].parse::<u16>().unwrap_or_default();
                }
            },
        }
    }

    (width, height)
}

fn download_icon(domain: &str) -> Result<Vec<u8>, Error> {
    let (mut iconlist, cookie_str) = get_icon_url(&domain)?;

    let mut buffer = Vec::new();

    iconlist.truncate(5);
    for icon in iconlist {
        let url = icon.href;
        info!("Downloading icon for {} via {}...", domain, url);
        match get_page_with_cookies(&url, &cookie_str) {
            Ok(mut res) => {
                info!("Download finished for {}", url);
                res.copy_to(&mut buffer)?;
                break;
            },
            Err(_) => info!("Download failed for {}", url),
        };
    }

    if buffer.is_empty() {
        err!("Empty response")
    }

    Ok(buffer)
}

fn save_icon(path: &str, icon: &[u8]) {
    create_dir_all(&CONFIG.icon_cache_folder()).expect("Error creating icon cache");

    if let Ok(mut f) = File::create(path) {
        f.write_all(icon).expect("Error writing icon file");
    };
}

fn _header_map() -> HeaderMap {
    // Set some default headers for the request.
    // Use a browser like user-agent to make sure most websites will return there correct website.
    use reqwest::header::*;

    macro_rules! headers {
        ($( $name:ident : $value:literal),+ $(,)? ) => {
            let mut headers = HeaderMap::new();
            $( headers.insert($name, HeaderValue::from_static($value)); )+
            headers
        };
    }

    headers! {
        USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
        ACCEPT_LANGUAGE: "en-US,en;q=0.8",
        CACHE_CONTROL: "no-cache",
        PRAGMA: "no-cache",
        ACCEPT: "text/html,application/xhtml+xml,application/xml; q=0.9,image/webp,image/apng,*/*;q=0.8",
    }
}
