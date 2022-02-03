use std::{
    collections::HashMap,
    fs::{create_dir_all, remove_file, symlink_metadata, File},
    io::prelude::*,
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{blocking::Client, blocking::Response, header};
use rocket::{
    http::ContentType,
    response::{Content, Redirect},
    Route,
};

use crate::{
    error::Error,
    util::{get_reqwest_client_builder, Cached},
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    match CONFIG.icon_service().as_str() {
        "internal" => routes![icon_internal],
        "bitwarden" => routes![icon_bitwarden],
        "duckduckgo" => routes![icon_duckduckgo],
        "google" => routes![icon_google],
        _ => routes![icon_custom],
    }
}

static CLIENT: Lazy<Client> = Lazy::new(|| {
    // Generate the default headers
    let mut default_headers = header::HeaderMap::new();
    default_headers
        .insert(header::USER_AGENT, header::HeaderValue::from_static("Links (2.22; Linux X86_64; GNU C; text)"));
    default_headers
        .insert(header::ACCEPT, header::HeaderValue::from_static("text/html, text/*;q=0.5, image/*, */*;q=0.1"));
    default_headers.insert(header::ACCEPT_LANGUAGE, header::HeaderValue::from_static("en,*;q=0.1"));
    default_headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-cache"));
    default_headers.insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));

    // Reuse the client between requests
    get_reqwest_client_builder()
        .cookie_provider(Arc::new(Jar::default()))
        .timeout(Duration::from_secs(CONFIG.icon_download_timeout()))
        .default_headers(default_headers)
        .build()
        .expect("Failed to build icon client")
});

// Build Regex only once since this takes a lot of time.
static ICON_REL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)icon$|apple.*icon").unwrap());
static ICON_REL_BLACKLIST: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)mask-icon").unwrap());
static ICON_SIZE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?x)(\d+)\D*(\d+)").unwrap());

// Special HashMap which holds the user defined Regex to speedup matching the regex.
static ICON_BLACKLIST_REGEX: Lazy<RwLock<HashMap<String, Regex>>> = Lazy::new(|| RwLock::new(HashMap::new()));

fn icon_redirect(domain: &str, template: &str) -> Option<Redirect> {
    if !is_valid_domain(domain) {
        warn!("Invalid domain: {}", domain);
        return None;
    }

    if is_domain_blacklisted(domain) {
        return None;
    }

    let url = template.replace("{}", domain);
    match CONFIG.icon_redirect_code() {
        301 => Some(Redirect::moved(url)), // legacy permanent redirect
        302 => Some(Redirect::found(url)), // legacy temporary redirect
        307 => Some(Redirect::temporary(url)),
        308 => Some(Redirect::permanent(url)),
        _ => {
            error!("Unexpected redirect code {}", CONFIG.icon_redirect_code());
            None
        }
    }
}

#[get("/<domain>/icon.png")]
fn icon_custom(domain: String) -> Option<Redirect> {
    icon_redirect(&domain, &CONFIG.icon_service())
}

#[get("/<domain>/icon.png")]
fn icon_bitwarden(domain: String) -> Option<Redirect> {
    icon_redirect(&domain, "https://icons.bitwarden.net/{}/icon.png")
}

#[get("/<domain>/icon.png")]
fn icon_duckduckgo(domain: String) -> Option<Redirect> {
    icon_redirect(&domain, "https://icons.duckduckgo.com/ip3/{}.ico")
}

#[get("/<domain>/icon.png")]
fn icon_google(domain: String) -> Option<Redirect> {
    icon_redirect(&domain, "https://www.google.com/s2/favicons?domain={}&sz=32")
}

#[get("/<domain>/icon.png")]
fn icon_internal(domain: String) -> Cached<Content<Vec<u8>>> {
    const FALLBACK_ICON: &[u8] = include_bytes!("../static/images/fallback-icon.png");

    if !is_valid_domain(&domain) {
        warn!("Invalid domain: {}", domain);
        return Cached::ttl(
            Content(ContentType::new("image", "png"), FALLBACK_ICON.to_vec()),
            CONFIG.icon_cache_negttl(),
            true,
        );
    }

    match get_icon(&domain) {
        Some((icon, icon_type)) => {
            Cached::ttl(Content(ContentType::new("image", icon_type), icon), CONFIG.icon_cache_ttl(), true)
        }
        _ => Cached::ttl(
            Content(ContentType::new("image", "png"), FALLBACK_ICON.to_vec()),
            CONFIG.icon_cache_negttl(),
            true,
        ),
    }
}

/// Returns if the domain provided is valid or not.
///
/// This does some manual checks and makes use of Url to do some basic checking.
/// domains can't be larger then 63 characters (not counting multiple subdomains) according to the RFC's, but we limit the total size to 255.
fn is_valid_domain(domain: &str) -> bool {
    const ALLOWED_CHARS: &str = "_-.";

    // If parsing the domain fails using Url, it will not work with reqwest.
    if let Err(parse_error) = url::Url::parse(format!("https://{}", domain).as_str()) {
        debug!("Domain parse error: '{}' - {:?}", domain, parse_error);
        return false;
    } else if domain.is_empty()
        || domain.contains("..")
        || domain.starts_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
    {
        debug!(
            "Domain validation error: '{}' is either empty, contains '..', starts with an '.', starts or ends with a '-'",
            domain
        );
        return false;
    } else if domain.len() > 255 {
        debug!("Domain validation error: '{}' exceeds 255 characters", domain);
        return false;
    }

    for c in domain.chars() {
        if !c.is_alphanumeric() && !ALLOWED_CHARS.contains(c) {
            debug!("Domain validation error: '{}' contains an invalid character '{}'", domain, c);
            return false;
        }
    }

    true
}

/// TODO: This is extracted from IpAddr::is_global, which is unstable:
/// https://doc.rust-lang.org/nightly/std/net/enum.IpAddr.html#method.is_global
/// Remove once https://github.com/rust-lang/rust/issues/27709 is merged
#[allow(clippy::nonminimal_bool)]
#[cfg(not(feature = "unstable"))]
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            // check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
            // globally routable addresses in the 192.0.0.0/24 range.
            if u32::from(ip) == 0xc0000009 || u32::from(ip) == 0xc000000a {
                return true;
            }
            !ip.is_private()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ip.is_broadcast()
            && !ip.is_documentation()
            && !(ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000))
            && !(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
            && !(ip.octets()[0] & 240 == 240 && !ip.is_broadcast())
            && !(ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18)
            // Make sure the address is not in 0.0.0.0/8
            && ip.octets()[0] != 0
        }
        IpAddr::V6(ip) => {
            if ip.is_multicast() && ip.segments()[0] & 0x000f == 14 {
                true
            } else {
                !ip.is_multicast()
                    && !ip.is_loopback()
                    && !((ip.segments()[0] & 0xffc0) == 0xfe80)
                    && !((ip.segments()[0] & 0xfe00) == 0xfc00)
                    && !ip.is_unspecified()
                    && !((ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8))
            }
        }
    }
}

#[cfg(feature = "unstable")]
fn is_global(ip: IpAddr) -> bool {
    ip.is_global()
}

/// These are some tests to check that the implementations match
/// The IPv4 can be all checked in 5 mins or so and they are correct as of nightly 2020-07-11
/// The IPV6 can't be checked in a reasonable time, so we check  about ten billion random ones, so far correct
/// Note that the is_global implementation is subject to change as new IP RFCs are created
///
/// To run while showing progress output:
/// cargo test --features sqlite,unstable -- --nocapture --ignored
#[cfg(test)]
#[cfg(feature = "unstable")]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_ipv4_global() {
        for a in 0..u8::MAX {
            println!("Iter: {}/255", a);
            for b in 0..u8::MAX {
                for c in 0..u8::MAX {
                    for d in 0..u8::MAX {
                        let ip = IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
                        assert_eq!(ip.is_global(), is_global(ip))
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_ipv6_global() {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut v = [0u8; 16];
        let rand = SystemRandom::new();
        for i in 0..1_000 {
            println!("Iter: {}/1_000", i);
            for _ in 0..10_000_000 {
                rand.fill(&mut v).expect("Error generating random values");
                let ip = IpAddr::V6(std::net::Ipv6Addr::new(
                    (v[14] as u16) << 8 | v[15] as u16,
                    (v[12] as u16) << 8 | v[13] as u16,
                    (v[10] as u16) << 8 | v[11] as u16,
                    (v[8] as u16) << 8 | v[9] as u16,
                    (v[6] as u16) << 8 | v[7] as u16,
                    (v[4] as u16) << 8 | v[5] as u16,
                    (v[2] as u16) << 8 | v[3] as u16,
                    (v[0] as u16) << 8 | v[1] as u16,
                ));
                assert_eq!(ip.is_global(), is_global(ip))
            }
        }
    }
}

fn is_domain_blacklisted(domain: &str) -> bool {
    let mut is_blacklisted = CONFIG.icon_blacklist_non_global_ips()
        && (domain, 0)
            .to_socket_addrs()
            .map(|x| {
                for ip_port in x {
                    if !is_global(ip_port.ip()) {
                        warn!("IP {} for domain '{}' is not a global IP!", ip_port.ip(), domain);
                        return true;
                    }
                }
                false
            })
            .unwrap_or(false);

    // Skip the regex check if the previous one is true already
    if !is_blacklisted {
        if let Some(blacklist) = CONFIG.icon_blacklist_regex() {
            let mut regex_hashmap = ICON_BLACKLIST_REGEX.read().unwrap();

            // Use the pre-generate Regex stored in a Lazy HashMap if there's one, else generate it.
            let regex = if let Some(regex) = regex_hashmap.get(&blacklist) {
                regex
            } else {
                drop(regex_hashmap);

                let mut regex_hashmap_write = ICON_BLACKLIST_REGEX.write().unwrap();
                // Clear the current list if the previous key doesn't exists.
                // To prevent growing of the HashMap after someone has changed it via the admin interface.
                if regex_hashmap_write.len() >= 1 {
                    regex_hashmap_write.clear();
                }

                // Generate the regex to store in too the Lazy Static HashMap.
                let blacklist_regex = Regex::new(&blacklist).unwrap();
                regex_hashmap_write.insert(blacklist.to_string(), blacklist_regex);
                drop(regex_hashmap_write);

                regex_hashmap = ICON_BLACKLIST_REGEX.read().unwrap();
                regex_hashmap.get(&blacklist).unwrap()
            };

            // Use the pre-generate Regex stored in a Lazy HashMap.
            if regex.is_match(domain) {
                debug!("Blacklisted domain: {} matched ICON_BLACKLIST_REGEX", domain);
                is_blacklisted = true;
            }
        }
    }

    is_blacklisted
}

fn get_icon(domain: &str) -> Option<(Vec<u8>, String)> {
    let path = format!("{}/{}.png", CONFIG.icon_cache_folder(), domain);

    // Check for expiration of negatively cached copy
    if icon_is_negcached(&path) {
        return None;
    }

    if let Some(icon) = get_cached_icon(&path) {
        let icon_type = match get_icon_type(&icon) {
            Some(x) => x,
            _ => "x-icon",
        };
        return Some((icon, icon_type.to_string()));
    }

    if CONFIG.disable_icon_download() {
        return None;
    }

    // Get the icon, or None in case of error
    match download_icon(domain) {
        Ok((icon, icon_type)) => {
            save_icon(&path, &icon);
            Some((icon, icon_type.unwrap_or("x-icon").to_string()))
        }
        Err(e) => {
            warn!("Unable to download icon: {:?}", e);
            let miss_indicator = path + ".miss";
            save_icon(&miss_indicator, &[]);
            None
        }
    }
}

fn get_cached_icon(path: &str) -> Option<Vec<u8>> {
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

fn icon_is_expired(path: &str) -> bool {
    let expired = file_is_expired(path, CONFIG.icon_cache_ttl());
    expired.unwrap_or(true)
}

struct Icon {
    priority: u8,
    href: String,
}

impl Icon {
    const fn new(priority: u8, href: String) -> Self {
        Self {
            priority,
            href,
        }
    }
}

/// Iterates over the HTML document to find <base href="http://domain.tld">
/// When found it will stop the iteration and the found base href will be shared deref via `base_href`.
///
/// # Arguments
/// * `node` - A Parsed HTML document via html5ever::parse_document()
/// * `base_href` - a mutable url::Url which will be overwritten when a base href tag has been found.
///
fn get_base_href(node: &std::rc::Rc<markup5ever_rcdom::Node>, base_href: &mut url::Url) -> bool {
    if let markup5ever_rcdom::NodeData::Element {
        name,
        attrs,
        ..
    } = &node.data
    {
        if name.local.as_ref() == "base" {
            let attrs = attrs.borrow();
            for attr in attrs.iter() {
                let attr_name = attr.name.local.as_ref();
                let attr_value = attr.value.as_ref();

                if attr_name == "href" {
                    debug!("Found base href: {}", attr_value);
                    *base_href = match base_href.join(attr_value) {
                        Ok(href) => href,
                        _ => base_href.clone(),
                    };
                    return true;
                }
            }
            return true;
        }
    }

    // TODO: Might want to limit the recursion depth?
    for child in node.children.borrow().iter() {
        // Check if we got a true back and stop the iter.
        // This means we found a <base> tag and can stop processing the html.
        if get_base_href(child, base_href) {
            return true;
        }
    }
    false
}

fn get_favicons_node(node: &std::rc::Rc<markup5ever_rcdom::Node>, icons: &mut Vec<Icon>, url: &url::Url) {
    if let markup5ever_rcdom::NodeData::Element {
        name,
        attrs,
        ..
    } = &node.data
    {
        if name.local.as_ref() == "link" {
            let mut has_rel = false;
            let mut href = None;
            let mut sizes = None;

            let attrs = attrs.borrow();
            for attr in attrs.iter() {
                let attr_name = attr.name.local.as_ref();
                let attr_value = attr.value.as_ref();

                if attr_name == "rel" && ICON_REL_REGEX.is_match(attr_value) && !ICON_REL_BLACKLIST.is_match(attr_value)
                {
                    has_rel = true;
                } else if attr_name == "href" {
                    href = Some(attr_value);
                } else if attr_name == "sizes" {
                    sizes = Some(attr_value);
                }
            }

            if has_rel {
                if let Some(inner_href) = href {
                    if let Ok(full_href) = url.join(inner_href).map(String::from) {
                        let priority = get_icon_priority(&full_href, sizes);
                        icons.push(Icon::new(priority, full_href));
                    }
                }
            }
        }
    }

    // TODO: Might want to limit the recursion depth?
    for child in node.children.borrow().iter() {
        get_favicons_node(child, icons, url);
    }
}

struct IconUrlResult {
    iconlist: Vec<Icon>,
    referer: String,
}

/// Returns a IconUrlResult which holds a Vector IconList and a string which holds the referer.
/// There will always two items within the iconlist which holds http(s)://domain.tld/favicon.ico.
/// This does not mean that that location does exists, but it is the default location browser use.
///
/// # Argument
/// * `domain` - A string which holds the domain with extension.
///
/// # Example
/// ```
/// let icon_result = get_icon_url("github.com")?;
/// let icon_result = get_icon_url("vaultwarden.discourse.group")?;
/// ```
fn get_icon_url(domain: &str) -> Result<IconUrlResult, Error> {
    // Default URL with secure and insecure schemes
    let ssldomain = format!("https://{}", domain);
    let httpdomain = format!("http://{}", domain);

    // First check the domain as given during the request for both HTTPS and HTTP.
    let resp = match get_page(&ssldomain).or_else(|_| get_page(&httpdomain)) {
        Ok(c) => Ok(c),
        Err(e) => {
            let mut sub_resp = Err(e);

            // When the domain is not an IP, and has more then one dot, remove all subdomains.
            let is_ip = domain.parse::<IpAddr>();
            if is_ip.is_err() && domain.matches('.').count() > 1 {
                let mut domain_parts = domain.split('.');
                let base_domain = format!(
                    "{base}.{tld}",
                    tld = domain_parts.next_back().unwrap(),
                    base = domain_parts.next_back().unwrap()
                );
                if is_valid_domain(&base_domain) {
                    let sslbase = format!("https://{}", base_domain);
                    let httpbase = format!("http://{}", base_domain);
                    debug!("[get_icon_url]: Trying without subdomains '{}'", base_domain);

                    sub_resp = get_page(&sslbase).or_else(|_| get_page(&httpbase));
                }

            // When the domain is not an IP, and has less then 2 dots, try to add www. infront of it.
            } else if is_ip.is_err() && domain.matches('.').count() < 2 {
                let www_domain = format!("www.{}", domain);
                if is_valid_domain(&www_domain) {
                    let sslwww = format!("https://{}", www_domain);
                    let httpwww = format!("http://{}", www_domain);
                    debug!("[get_icon_url]: Trying with www. prefix '{}'", www_domain);

                    sub_resp = get_page(&sslwww).or_else(|_| get_page(&httpwww));
                }
            }

            sub_resp
        }
    };

    // Create the iconlist
    let mut iconlist: Vec<Icon> = Vec::new();
    let mut referer = String::from("");

    if let Ok(content) = resp {
        // Extract the URL from the respose in case redirects occured (like @ gitlab.com)
        let url = content.url().clone();

        // Set the referer to be used on the final request, some sites check this.
        // Mostly used to prevent direct linking and other security resons.
        referer = url.as_str().to_string();

        // Add the default favicon.ico to the list with the domain the content responded from.
        iconlist.push(Icon::new(35, String::from(url.join("/favicon.ico").unwrap())));

        // 384KB should be more than enough for the HTML, though as we only really need the HTML header.
        let mut limited_reader = content.take(384 * 1024);

        use html5ever::tendril::TendrilSink;
        let dom = html5ever::parse_document(markup5ever_rcdom::RcDom::default(), Default::default())
            .from_utf8()
            .read_from(&mut limited_reader)?;

        let mut base_url: url::Url = url;
        get_base_href(&dom.document, &mut base_url);
        get_favicons_node(&dom.document, &mut iconlist, &base_url);
    } else {
        // Add the default favicon.ico to the list with just the given domain
        iconlist.push(Icon::new(35, format!("{}/favicon.ico", ssldomain)));
        iconlist.push(Icon::new(35, format!("{}/favicon.ico", httpdomain)));
    }

    // Sort the iconlist by priority
    iconlist.sort_by_key(|x| x.priority);

    // There always is an icon in the list, so no need to check if it exists, and just return the first one
    Ok(IconUrlResult {
        iconlist,
        referer,
    })
}

fn get_page(url: &str) -> Result<Response, Error> {
    get_page_with_referer(url, "")
}

fn get_page_with_referer(url: &str, referer: &str) -> Result<Response, Error> {
    if is_domain_blacklisted(url::Url::parse(url).unwrap().host_str().unwrap_or_default()) {
        warn!("Favicon '{}' resolves to a blacklisted domain or IP!", url);
    }

    let mut client = CLIENT.get(url);
    if !referer.is_empty() {
        client = client.header("Referer", referer)
    }

    match client.send() {
        Ok(c) => c.error_for_status().map_err(Into::into),
        Err(e) => err_silent!(format!("{}", e)),
    }
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
fn get_icon_priority(href: &str, sizes: Option<&str>) -> u8 {
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
            } else if (24..=192).contains(&width) {
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
fn parse_sizes(sizes: Option<&str>) -> (u16, u16) {
    let mut width: u16 = 0;
    let mut height: u16 = 0;

    if let Some(sizes) = sizes {
        match ICON_SIZE_REGEX.captures(sizes.trim()) {
            None => {}
            Some(dimensions) => {
                if dimensions.len() >= 3 {
                    width = dimensions[1].parse::<u16>().unwrap_or_default();
                    height = dimensions[2].parse::<u16>().unwrap_or_default();
                }
            }
        }
    }

    (width, height)
}

fn download_icon(domain: &str) -> Result<(Vec<u8>, Option<&str>), Error> {
    if is_domain_blacklisted(domain) {
        err_silent!("Domain is blacklisted", domain)
    }

    let icon_result = get_icon_url(domain)?;

    let mut buffer = Vec::new();
    let mut icon_type: Option<&str> = None;

    use data_url::DataUrl;

    for icon in icon_result.iconlist.iter().take(5) {
        if icon.href.starts_with("data:image") {
            let datauri = DataUrl::process(&icon.href).unwrap();
            // Check if we are able to decode the data uri
            match datauri.decode_to_vec() {
                Ok((body, _fragment)) => {
                    // Also check if the size is atleast 67 bytes, which seems to be the smallest png i could create
                    if body.len() >= 67 {
                        // Check if the icon type is allowed, else try an icon from the list.
                        icon_type = get_icon_type(&body);
                        if icon_type.is_none() {
                            debug!("Icon from {} data:image uri, is not a valid image type", domain);
                            continue;
                        }
                        info!("Extracted icon from data:image uri for {}", domain);
                        buffer = body;
                        break;
                    }
                }
                _ => debug!("Extracted icon from data:image uri is invalid"),
            };
        } else {
            match get_page_with_referer(&icon.href, &icon_result.referer) {
                Ok(mut res) => {
                    res.copy_to(&mut buffer)?;
                    // Check if the icon type is allowed, else try an icon from the list.
                    icon_type = get_icon_type(&buffer);
                    if icon_type.is_none() {
                        buffer.clear();
                        debug!("Icon from {}, is not a valid image type", icon.href);
                        continue;
                    }
                    info!("Downloaded icon from {}", icon.href);
                    break;
                }
                Err(e) => debug!("{:?}", e),
            };
        }
    }

    if buffer.is_empty() {
        err_silent!("Empty response or unable find a valid icon", domain);
    }

    Ok((buffer, icon_type))
}

fn save_icon(path: &str, icon: &[u8]) {
    match File::create(path) {
        Ok(mut f) => {
            f.write_all(icon).expect("Error writing icon file");
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_dir_all(&CONFIG.icon_cache_folder()).expect("Error creating icon cache folder");
        }
        Err(e) => {
            warn!("Unable to save icon: {:?}", e);
        }
    }
}

fn get_icon_type(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [137, 80, 78, 71, ..] => Some("png"),
        [0, 0, 1, 0, ..] => Some("x-icon"),
        [82, 73, 70, 70, ..] => Some("webp"),
        [255, 216, 255, ..] => Some("jpeg"),
        [71, 73, 70, 56, ..] => Some("gif"),
        [66, 77, ..] => Some("bmp"),
        _ => None,
    }
}

/// This is an implementation of the default Cookie Jar from Reqwest and reqwest_cookie_store build by pfernie.
/// The default cookie jar used by Reqwest keeps all the cookies based upon the Max-Age or Expires which could be a long time.
/// That could be used for tracking, to prevent this we force the lifespan of the cookies to always be max two minutes.
/// A Cookie Jar is needed because some sites force a redirect with cookies to verify if a request uses cookies or not.
use cookie_store::CookieStore;
#[derive(Default)]
pub struct Jar(RwLock<CookieStore>);

impl reqwest::cookie::CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &header::HeaderValue>, url: &url::Url) {
        use cookie::{Cookie as RawCookie, ParseError as RawCookieParseError};
        use time::Duration;

        let mut cookie_store = self.0.write().unwrap();
        let cookies = cookie_headers.filter_map(|val| {
            std::str::from_utf8(val.as_bytes())
                .map_err(RawCookieParseError::from)
                .and_then(RawCookie::parse)
                .map(|mut c| {
                    c.set_expires(None);
                    c.set_max_age(Some(Duration::minutes(2)));
                    c.into_owned()
                })
                .ok()
        });
        cookie_store.store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<header::HeaderValue> {
        use bytes::Bytes;

        let cookie_store = self.0.read().unwrap();
        let s = cookie_store
            .get_request_values(url)
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        header::HeaderValue::from_maybe_shared(Bytes::from(s)).ok()
    }
}
