use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::{Bytes, BytesMut};
use futures::{stream::StreamExt, TryFutureExt};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    Client, Response,
};
use rocket::{http::ContentType, response::Redirect, Route};
use tokio::{
    fs::{create_dir_all, remove_file, symlink_metadata, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

use html5gum::{Emitter, HtmlString, Readable, StringReader, Tokenizer};

use crate::{
    error::Error,
    http_client::{get_reqwest_client_builder, should_block_address, CustomHttpClientError},
    util::Cached,
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    match CONFIG.icon_service().as_str() {
        "internal" => routes![icon_internal],
        _ => routes![icon_external],
    }
}

static CLIENT: Lazy<Client> = Lazy::new(|| {
    // Generate the default headers
    let mut default_headers = HeaderMap::new();
    default_headers.insert(header::USER_AGENT, HeaderValue::from_static("Links (2.22; Linux X86_64; GNU C; text)"));
    default_headers.insert(header::ACCEPT, HeaderValue::from_static("text/html, text/*;q=0.5, image/*, */*;q=0.1"));
    default_headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en,*;q=0.1"));
    default_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    default_headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    // Generate the cookie store
    let cookie_store = Arc::new(Jar::default());

    let icon_download_timeout = Duration::from_secs(CONFIG.icon_download_timeout());
    let pool_idle_timeout = Duration::from_secs(10);
    // Reuse the client between requests
    get_reqwest_client_builder()
        .cookie_provider(Arc::clone(&cookie_store))
        .timeout(icon_download_timeout)
        .pool_max_idle_per_host(5) // Configure the Hyper Pool to only have max 5 idle connections
        .pool_idle_timeout(pool_idle_timeout) // Configure the Hyper Pool to timeout after 10 seconds
        .default_headers(default_headers.clone())
        .build()
        .expect("Failed to build client")
});

// Build Regex only once since this takes a lot of time.
static ICON_SIZE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?x)(\d+)\D*(\d+)").unwrap());

#[get("/<domain>/icon.png")]
fn icon_external(domain: &str) -> Option<Redirect> {
    if !is_valid_domain(domain) {
        warn!("Invalid domain: {}", domain);
        return None;
    }

    if should_block_address(domain) {
        warn!("Blocked address: {}", domain);
        return None;
    }

    let url = CONFIG._icon_service_url().replace("{}", domain);
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
async fn icon_internal(domain: &str) -> Cached<(ContentType, Vec<u8>)> {
    const FALLBACK_ICON: &[u8] = include_bytes!("../static/images/fallback-icon.png");

    if !is_valid_domain(domain) {
        warn!("Invalid domain: {}", domain);
        return Cached::ttl(
            (ContentType::new("image", "png"), FALLBACK_ICON.to_vec()),
            CONFIG.icon_cache_negttl(),
            true,
        );
    }

    if should_block_address(domain) {
        warn!("Blocked address: {}", domain);
        return Cached::ttl(
            (ContentType::new("image", "png"), FALLBACK_ICON.to_vec()),
            CONFIG.icon_cache_negttl(),
            true,
        );
    }

    match get_icon(domain).await {
        Some((icon, icon_type)) => {
            Cached::ttl((ContentType::new("image", icon_type), icon), CONFIG.icon_cache_ttl(), true)
        }
        _ => Cached::ttl((ContentType::new("image", "png"), FALLBACK_ICON.to_vec()), CONFIG.icon_cache_negttl(), true),
    }
}

/// Returns if the domain provided is valid or not.
///
/// This does some manual checks and makes use of Url to do some basic checking.
/// domains can't be larger then 63 characters (not counting multiple subdomains) according to the RFC's, but we limit the total size to 255.
fn is_valid_domain(domain: &str) -> bool {
    const ALLOWED_CHARS: &str = "_-.";

    // If parsing the domain fails using Url, it will not work with reqwest.
    if let Err(parse_error) = url::Url::parse(format!("https://{domain}").as_str()) {
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

async fn get_icon(domain: &str) -> Option<(Vec<u8>, String)> {
    let path = format!("{}/{}.png", CONFIG.icon_cache_folder(), domain);

    // Check for expiration of negatively cached copy
    if icon_is_negcached(&path).await {
        return None;
    }

    if let Some(icon) = get_cached_icon(&path).await {
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
    match download_icon(domain).await {
        Ok((icon, icon_type)) => {
            save_icon(&path, &icon).await;
            Some((icon.to_vec(), icon_type.unwrap_or("x-icon").to_string()))
        }
        Err(e) => {
            // If this error comes from the custom resolver, this means this is a blocked domain
            // or non global IP, don't save the miss file in this case to avoid leaking it
            if let Some(error) = CustomHttpClientError::downcast_ref(&e) {
                warn!("{error}");
                return None;
            }

            warn!("Unable to download icon: {:?}", e);
            let miss_indicator = path + ".miss";
            save_icon(&miss_indicator, &[]).await;
            None
        }
    }
}

async fn get_cached_icon(path: &str) -> Option<Vec<u8>> {
    // Check for expiration of successfully cached copy
    if icon_is_expired(path).await {
        return None;
    }

    // Try to read the cached icon, and return it if it exists
    if let Ok(mut f) = File::open(path).await {
        let mut buffer = Vec::new();

        if f.read_to_end(&mut buffer).await.is_ok() {
            return Some(buffer);
        }
    }

    None
}

async fn file_is_expired(path: &str, ttl: u64) -> Result<bool, Error> {
    let meta = symlink_metadata(path).await?;
    let modified = meta.modified()?;
    let age = SystemTime::now().duration_since(modified)?;

    Ok(ttl > 0 && ttl <= age.as_secs())
}

async fn icon_is_negcached(path: &str) -> bool {
    let miss_indicator = path.to_owned() + ".miss";
    let expired = file_is_expired(&miss_indicator, CONFIG.icon_cache_negttl()).await;

    match expired {
        // No longer negatively cached, drop the marker
        Ok(true) => {
            if let Err(e) = remove_file(&miss_indicator).await {
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

async fn icon_is_expired(path: &str) -> bool {
    let expired = file_is_expired(path, CONFIG.icon_cache_ttl()).await;
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

fn get_favicons_node(dom: Tokenizer<StringReader<'_>, FaviconEmitter>, icons: &mut Vec<Icon>, url: &url::Url) {
    const TAG_LINK: &[u8] = b"link";
    const TAG_BASE: &[u8] = b"base";
    const TAG_HEAD: &[u8] = b"head";
    const ATTR_HREF: &[u8] = b"href";
    const ATTR_SIZES: &[u8] = b"sizes";

    let mut base_url = url.clone();
    let mut icon_tags: Vec<Tag> = Vec::new();
    for Ok(token) in dom {
        let tag_name: &[u8] = &token.tag.name;
        match tag_name {
            TAG_LINK => {
                icon_tags.push(token.tag);
            }
            TAG_BASE => {
                base_url = if let Some(href) = token.tag.attributes.get(ATTR_HREF) {
                    let href = std::str::from_utf8(href).unwrap_or_default();
                    debug!("Found base href: {href}");
                    match base_url.join(href) {
                        Ok(inner_url) => inner_url,
                        _ => continue,
                    }
                } else {
                    continue;
                };
            }
            TAG_HEAD if token.closing => {
                break;
            }
            _ => {
                continue;
            }
        }
    }

    for icon_tag in icon_tags {
        if let Some(icon_href) = icon_tag.attributes.get(ATTR_HREF) {
            if let Ok(full_href) = base_url.join(std::str::from_utf8(icon_href).unwrap_or_default()) {
                let sizes = if let Some(v) = icon_tag.attributes.get(ATTR_SIZES) {
                    std::str::from_utf8(v).unwrap_or_default()
                } else {
                    ""
                };
                let priority = get_icon_priority(full_href.as_str(), sizes);
                icons.push(Icon::new(priority, full_href.to_string()));
            }
        };
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
/// let icon_result = get_icon_url("github.com").await?;
/// let icon_result = get_icon_url("vaultwarden.discourse.group").await?;
/// ```
async fn get_icon_url(domain: &str) -> Result<IconUrlResult, Error> {
    // Default URL with secure and insecure schemes
    let ssldomain = format!("https://{domain}");
    let httpdomain = format!("http://{domain}");

    // First check the domain as given during the request for HTTPS.
    let resp = match get_page(&ssldomain).await {
        Err(e) if CustomHttpClientError::downcast_ref(&e).is_none() => {
            // If we get an error that is not caused by the blacklist, we retry with HTTP
            match get_page(&httpdomain).await {
                mut sub_resp @ Err(_) => {
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
                            let sslbase = format!("https://{base_domain}");
                            let httpbase = format!("http://{base_domain}");
                            debug!("[get_icon_url]: Trying without subdomains '{base_domain}'");

                            sub_resp = get_page(&sslbase).or_else(|_| get_page(&httpbase)).await;
                        }

                    // When the domain is not an IP, and has less then 2 dots, try to add www. infront of it.
                    } else if is_ip.is_err() && domain.matches('.').count() < 2 {
                        let www_domain = format!("www.{domain}");
                        if is_valid_domain(&www_domain) {
                            let sslwww = format!("https://{www_domain}");
                            let httpwww = format!("http://{www_domain}");
                            debug!("[get_icon_url]: Trying with www. prefix '{www_domain}'");

                            sub_resp = get_page(&sslwww).or_else(|_| get_page(&httpwww)).await;
                        }
                    }
                    sub_resp
                }
                res => res,
            }
        }

        // If we get a result or a blacklist error, just continue
        res => res,
    };

    // Create the iconlist
    let mut iconlist: Vec<Icon> = Vec::new();
    let mut referer = String::new();

    if let Ok(content) = resp {
        // Extract the URL from the response in case redirects occurred (like @ gitlab.com)
        let url = content.url().clone();

        // Set the referer to be used on the final request, some sites check this.
        // Mostly used to prevent direct linking and other security reasons.
        referer = url.to_string();

        // Add the fallback favicon.ico and apple-touch-icon.png to the list with the domain the content responded from.
        iconlist.push(Icon::new(35, String::from(url.join("/favicon.ico").unwrap())));
        iconlist.push(Icon::new(40, String::from(url.join("/apple-touch-icon.png").unwrap())));

        // 384KB should be more than enough for the HTML, though as we only really need the HTML header.
        let limited_reader = stream_to_bytes_limit(content, 384 * 1024).await?.to_vec();

        let dom = Tokenizer::new_with_emitter(limited_reader.to_reader(), FaviconEmitter::default());
        get_favicons_node(dom, &mut iconlist, &url);
    } else {
        // Add the default favicon.ico to the list with just the given domain
        iconlist.push(Icon::new(35, format!("{ssldomain}/favicon.ico")));
        iconlist.push(Icon::new(40, format!("{ssldomain}/apple-touch-icon.png")));
        iconlist.push(Icon::new(35, format!("{httpdomain}/favicon.ico")));
        iconlist.push(Icon::new(40, format!("{httpdomain}/apple-touch-icon.png")));
    }

    // Sort the iconlist by priority
    iconlist.sort_by_key(|x| x.priority);

    // There always is an icon in the list, so no need to check if it exists, and just return the first one
    Ok(IconUrlResult {
        iconlist,
        referer,
    })
}

async fn get_page(url: &str) -> Result<Response, Error> {
    get_page_with_referer(url, "").await
}

async fn get_page_with_referer(url: &str, referer: &str) -> Result<Response, Error> {
    let mut client = CLIENT.get(url);
    if !referer.is_empty() {
        client = client.header("Referer", referer)
    }

    Ok(client.send().await?.error_for_status()?)
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
    static PRIORITY_MAP: Lazy<HashMap<&'static str, u8>> =
        Lazy::new(|| [(".png", 10), (".jpg", 20), (".jpeg", 20)].into_iter().collect());

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
        match href.rsplit_once('.') {
            Some((_, extension)) => PRIORITY_MAP.get(&*extension.to_ascii_lowercase()).copied().unwrap_or(30),
            None => 30,
        }
    }
}

/// Returns a Tuple with the width and height as a separate value extracted from the sizes attribute
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

async fn download_icon(domain: &str) -> Result<(Bytes, Option<&str>), Error> {
    let icon_result = get_icon_url(domain).await?;

    let mut buffer = Bytes::new();
    let mut icon_type: Option<&str> = None;

    use data_url::DataUrl;

    for icon in icon_result.iconlist.iter().take(5) {
        if icon.href.starts_with("data:image") {
            let Ok(datauri) = DataUrl::process(&icon.href) else {
                continue;
            };
            // Check if we are able to decode the data uri
            let mut body = BytesMut::new();
            match datauri.decode::<_, ()>(|bytes| {
                body.extend_from_slice(bytes);
                Ok(())
            }) {
                Ok(_) => {
                    // Also check if the size is atleast 67 bytes, which seems to be the smallest png i could create
                    if body.len() >= 67 {
                        // Check if the icon type is allowed, else try an icon from the list.
                        icon_type = get_icon_type(&body);
                        if icon_type.is_none() {
                            debug!("Icon from {} data:image uri, is not a valid image type", domain);
                            continue;
                        }
                        info!("Extracted icon from data:image uri for {}", domain);
                        buffer = body.freeze();
                        break;
                    }
                }
                _ => debug!("Extracted icon from data:image uri is invalid"),
            };
        } else {
            let res = get_page_with_referer(&icon.href, &icon_result.referer).await?;

            buffer = stream_to_bytes_limit(res, 5120 * 1024).await?; // 5120KB/5MB for each icon max (Same as icons.bitwarden.net)

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
    }

    if buffer.is_empty() {
        err_silent!("Empty response or unable find a valid icon", domain);
    }

    Ok((buffer, icon_type))
}

async fn save_icon(path: &str, icon: &[u8]) {
    match File::create(path).await {
        Ok(mut f) => {
            f.write_all(icon).await.expect("Error writing icon file");
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_dir_all(&CONFIG.icon_cache_folder()).await.expect("Error creating icon cache folder");
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

/// Minimize the amount of bytes to be parsed from a reqwest result.
/// This prevents very long parsing and memory usage.
async fn stream_to_bytes_limit(res: Response, max_size: usize) -> Result<Bytes, reqwest::Error> {
    let mut stream = res.bytes_stream().take(max_size);
    let mut buf = BytesMut::new();
    let mut size = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = &chunk?;
        size += chunk.len();
        buf.extend(chunk);
        if size >= max_size {
            break;
        }
    }
    Ok(buf.freeze())
}

/// This is an implementation of the default Cookie Jar from Reqwest and reqwest_cookie_store build by pfernie.
/// The default cookie jar used by Reqwest keeps all the cookies based upon the Max-Age or Expires which could be a long time.
/// That could be used for tracking, to prevent this we force the lifespan of the cookies to always be max two minutes.
/// A Cookie Jar is needed because some sites force a redirect with cookies to verify if a request uses cookies or not.
use cookie_store::CookieStore;
#[derive(Default)]
pub struct Jar(std::sync::RwLock<CookieStore>);

impl reqwest::cookie::CookieStore for Jar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
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

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let cookie_store = self.0.read().unwrap();
        let s = cookie_store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        HeaderValue::from_maybe_shared(Bytes::from(s)).ok()
    }
}

/// Custom FaviconEmitter for the html5gum parser.
/// The FaviconEmitter is using an optimized version of the DefaultEmitter.
/// This prevents emitting tags like comments, doctype and also strings between the tags.
/// But it will also only emit the tags we need and only if they have the correct attributes
/// Therefore parsing the HTML content is faster.
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Tag {
    /// The tag's name, such as `"link"` or `"base"`.
    pub name: HtmlString,

    /// A mapping for any HTML attributes this start tag may have.
    ///
    /// Duplicate attributes are ignored after the first one as per WHATWG spec.
    pub attributes: BTreeMap<HtmlString, HtmlString>,
}

struct FaviconToken {
    tag: Tag,
    closing: bool,
}

#[derive(Default)]
struct FaviconEmitter {
    current_token: Option<FaviconToken>,
    last_start_tag: HtmlString,
    current_attribute: Option<(HtmlString, HtmlString)>,
    emit_token: bool,
}

impl FaviconEmitter {
    fn flush_current_attribute(&mut self, emit_current_tag: bool) {
        const ATTR_HREF: &[u8] = b"href";
        const ATTR_REL: &[u8] = b"rel";
        const TAG_LINK: &[u8] = b"link";
        const TAG_BASE: &[u8] = b"base";
        const TAG_HEAD: &[u8] = b"head";

        if let Some(ref mut token) = self.current_token {
            let tag_name: &[u8] = &token.tag.name;

            if self.current_attribute.is_some() && (tag_name == TAG_BASE || tag_name == TAG_LINK) {
                let (k, v) = self.current_attribute.take().unwrap();
                token.tag.attributes.entry(k).and_modify(|_| {}).or_insert(v);
            }

            let tag_attr = &token.tag.attributes;
            match tag_name {
                TAG_HEAD if token.closing => self.emit_token = true,
                TAG_BASE if tag_attr.contains_key(ATTR_HREF) => self.emit_token = true,
                TAG_LINK if emit_current_tag && tag_attr.contains_key(ATTR_REL) && tag_attr.contains_key(ATTR_HREF) => {
                    let rel_value =
                        std::str::from_utf8(token.tag.attributes.get(ATTR_REL).unwrap()).unwrap_or_default();
                    if rel_value.contains("icon") && !rel_value.contains("mask-icon") {
                        self.emit_token = true
                    }
                }
                _ => (),
            }
        }
    }
}

impl Emitter for FaviconEmitter {
    type Token = FaviconToken;

    fn set_last_start_tag(&mut self, last_start_tag: Option<&[u8]>) {
        self.last_start_tag.clear();
        self.last_start_tag.extend(last_start_tag.unwrap_or_default());
    }

    fn pop_token(&mut self) -> Option<Self::Token> {
        if self.emit_token {
            self.emit_token = false;
            return self.current_token.take();
        }
        None
    }

    fn init_start_tag(&mut self) {
        self.current_token = Some(FaviconToken {
            tag: Tag::default(),
            closing: false,
        });
    }

    fn init_end_tag(&mut self) {
        self.current_token = Some(FaviconToken {
            tag: Tag::default(),
            closing: true,
        });
    }

    fn emit_current_tag(&mut self) -> Option<html5gum::State> {
        self.flush_current_attribute(true);
        self.last_start_tag.clear();
        if self.current_token.is_some() && !self.current_token.as_ref().unwrap().closing {
            self.last_start_tag.extend(&*self.current_token.as_ref().unwrap().tag.name);
        }
        html5gum::naive_next_state(&self.last_start_tag)
    }

    fn push_tag_name(&mut self, s: &[u8]) {
        if let Some(ref mut token) = self.current_token {
            token.tag.name.extend(s);
        }
    }

    fn init_attribute(&mut self) {
        self.flush_current_attribute(false);
        self.current_attribute = match &self.current_token {
            Some(token) => {
                let tag_name: &[u8] = &token.tag.name;
                match tag_name {
                    b"link" | b"head" | b"base" => Some(Default::default()),
                    _ => None,
                }
            }
            _ => None,
        };
    }

    fn push_attribute_name(&mut self, s: &[u8]) {
        if let Some(attr) = &mut self.current_attribute {
            attr.0.extend(s)
        }
    }

    fn push_attribute_value(&mut self, s: &[u8]) {
        if let Some(attr) = &mut self.current_attribute {
            attr.1.extend(s)
        }
    }

    fn current_is_appropriate_end_tag_token(&mut self) -> bool {
        match &self.current_token {
            Some(token) if token.closing => !self.last_start_tag.is_empty() && self.last_start_tag == token.tag.name,
            _ => false,
        }
    }

    // We do not want and need these parts of the HTML document
    // These will be skipped and ignored during the tokenization and iteration.
    fn emit_current_comment(&mut self) {}
    fn emit_current_doctype(&mut self) {}
    fn emit_eof(&mut self) {}
    fn emit_error(&mut self, _: html5gum::Error) {}
    fn emit_string(&mut self, _: &[u8]) {}
    fn init_comment(&mut self) {}
    fn init_doctype(&mut self) {}
    fn push_comment(&mut self, _: &[u8]) {}
    fn push_doctype_name(&mut self, _: &[u8]) {}
    fn push_doctype_public_identifier(&mut self, _: &[u8]) {}
    fn push_doctype_system_identifier(&mut self, _: &[u8]) {}
    fn set_doctype_public_identifier(&mut self, _: &[u8]) {}
    fn set_doctype_system_identifier(&mut self, _: &[u8]) {}
    fn set_force_quirks(&mut self) {}
    fn set_self_closing(&mut self) {}
}
