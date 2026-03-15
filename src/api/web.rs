use std::path::{Path, PathBuf};

use rocket::{
    fs::NamedFile,
    http::ContentType,
    response::{content::RawCss as Css, content::RawHtml as Html, Redirect},
    serde::json::Json,
    Catcher, Route,
};
use serde_json::Value;

use crate::{
    api::{core::now, ApiResult, EmptyResult},
    auth::decode_file_download,
    db::models::{AttachmentId, CipherId},
    error::Error,
    sso,
    util::Cached,
    CONFIG,
};

pub fn routes() -> Vec<Route> {
    // If adding more routes here, consider also adding them to
    // crate::utils::LOGGED_ROUTES to make sure they appear in the log
    let mut routes = routes![attachments, alive, alive_head, static_files];
    if CONFIG.web_vault_enabled() {
        routes.append(&mut routes![web_index, web_index_direct, web_index_head, app_id, web_files, vaultwarden_css]);
        if CONFIG.sso_enabled() && CONFIG.sso_only() && CONFIG.sso_auto_redirect() {
            routes.append(&mut routes![vaultwarden_sso_js, sso_auto_redirect, sso_auto_redirect_js]);
        }
    }

    #[cfg(debug_assertions)]
    if CONFIG.reload_templates() {
        routes.append(&mut routes![_static_files_dev]);
    }

    routes
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

#[get("/css/vaultwarden.css")]
fn vaultwarden_css() -> Cached<Css<String>> {
    let css_options = json!({
        "emergency_access_allowed": CONFIG.emergency_access_allowed(),
        "load_user_scss": true,
        "mail_2fa_enabled": CONFIG._enable_email_2fa(),
        "mail_enabled": CONFIG.mail_enabled(),
        "sends_allowed": CONFIG.sends_allowed(),
        "remember_2fa_disabled": CONFIG.disable_2fa_remember(),
        "password_hints_allowed": CONFIG.password_hints_allowed(),
        "signup_disabled": CONFIG.is_signup_disabled(),
        "sso_enabled": CONFIG.sso_enabled(),
        "sso_only": CONFIG.sso_enabled() && CONFIG.sso_only(),
        "webauthn_2fa_supported": CONFIG.is_webauthn_2fa_supported(),
        "yubico_enabled": CONFIG._enable_yubico() && CONFIG.yubico_client_id().is_some() && CONFIG.yubico_secret_key().is_some(),
    });

    let scss = match CONFIG.render_template("scss/vaultwarden.scss", &css_options) {
        Ok(t) => t,
        Err(e) => {
            // Something went wrong loading the template. Use the fallback
            warn!("Loading scss/vaultwarden.scss.hbs or scss/user.vaultwarden.scss.hbs failed. {e}");
            CONFIG
                .render_fallback_template("scss/vaultwarden.scss", &css_options)
                .expect("Fallback scss/vaultwarden.scss.hbs to render")
        }
    };

    let css = match grass_compiler::from_string(
        scss,
        &grass_compiler::Options::default().style(grass_compiler::OutputStyle::Compressed),
    ) {
        Ok(css) => css,
        Err(e) => {
            // Something went wrong compiling the scss. Use the fallback
            warn!("Compiling the Vaultwarden SCSS styles failed. {e}");
            let mut css_options = css_options;
            css_options["load_user_scss"] = json!(false);
            let scss = CONFIG
                .render_fallback_template("scss/vaultwarden.scss", &css_options)
                .expect("Fallback scss/vaultwarden.scss.hbs to render");
            grass_compiler::from_string(
                scss,
                &grass_compiler::Options::default().style(grass_compiler::OutputStyle::Compressed),
            )
            .expect("SCSS to compile")
        }
    };

    // Cache for one day should be enough and not too much
    Cached::ttl(Css(css), 86_400, false)
}

#[get("/")]
async fn web_index() -> Cached<Option<Html<String>>> {
    let path = Path::new(&CONFIG.web_vault_folder()).join("index.html");
    match tokio::fs::read_to_string(&path).await {
        Ok(mut html) => {
            // When SSO auto-redirect is enabled, inject a script that redirects the login page
            // to the SSO provider and hides the default login UI to prevent flash
            if CONFIG.sso_enabled() && CONFIG.sso_only() && CONFIG.sso_auto_redirect() {
                html = html.replace(
                    "</head>",
                    "<style>app-root{display:none!important}html,body{background:#0f1419!important}</style>\
                     <script src=\"vaultwarden-sso.js\"></script></head>",
                );
            }
            Cached::short(Some(Html(html)), false)
        }
        Err(_) => Cached::short(None, false),
    }
}

// Make sure that `/index.html` redirect to actual domain path.
// If not, this might cause issues with the web-vault
#[get("/index.html")]
fn web_index_direct() -> Redirect {
    Redirect::to(format!("{}/", CONFIG.domain_path()))
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

#[get("/attachments/<cipher_id>/<file_id>?<token>")]
async fn attachments(cipher_id: CipherId, file_id: AttachmentId, token: String) -> Option<NamedFile> {
    let Ok(claims) = decode_file_download(&token) else {
        return None;
    };
    if claims.sub != cipher_id || claims.file_id != file_id {
        return None;
    }

    NamedFile::open(Path::new(&CONFIG.attachments_folder()).join(cipher_id.as_ref()).join(file_id.as_ref())).await.ok()
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

// This endpoint/function is used during development and development only.
// It allows to easily develop the admin interface by always loading the files from disk instead from a slice of bytes
// This will only be active during a debug build and only when `RELOAD_TEMPLATES` is set to `true`
// NOTE: Do not forget to add any new files added to the `static_files` function below!
#[cfg(debug_assertions)]
#[get("/vw_static/<filename>", rank = 1)]
pub async fn _static_files_dev(filename: PathBuf) -> Option<NamedFile> {
    warn!("LOADING STATIC FILES FROM DISK");
    let file = filename.to_str().unwrap_or_default();
    let ext = filename.extension().unwrap_or_default();

    let path = if ext == "png" || ext == "svg" {
        tokio::fs::canonicalize(Path::new(file!()).parent().unwrap().join("../static/images/").join(file)).await
    } else {
        tokio::fs::canonicalize(Path::new(file!()).parent().unwrap().join("../static/scripts/").join(file)).await
    };

    if let Ok(path) = path {
        return NamedFile::open(path).await.ok();
    };
    None
}

#[get("/vw_static/<filename>", rank = 2)]
pub fn static_files(filename: &str) -> Result<(ContentType, &'static [u8]), Error> {
    match filename {
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
        "bootstrap.bundle.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/bootstrap.bundle.js"))),
        "jdenticon-3.3.0.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/jdenticon-3.3.0.js"))),
        "datatables.js" => Ok((ContentType::JavaScript, include_bytes!("../static/scripts/datatables.js"))),
        "datatables.css" => Ok((ContentType::CSS, include_bytes!("../static/scripts/datatables.css"))),
        "jquery-4.0.0.slim.js" => {
            Ok((ContentType::JavaScript, include_bytes!("../static/scripts/jquery-4.0.0.slim.js")))
        }
        _ => err!(format!("Static file not found: {filename}")),
    }
}

/// Inline JS injected into index.html that intercepts the login page and redirects to the
/// SSO auto-redirect page. Non-login pages (SSO callback, vault, etc.) show `app-root` normally.
///
/// When SSO_LOGOUT_REDIRECT is also enabled, tracks the active session in localStorage.
/// On logout (page reloads to login hash while flag exists), redirects to the SSO provider's
/// end_session endpoint to properly terminate the SSO session before the next auto-redirect.
#[get("/vaultwarden-sso.js")]
fn vaultwarden_sso_js() -> Cached<(ContentType, String)> {
    let js = if CONFIG.sso_enabled() && CONFIG.sso_only() && CONFIG.sso_auto_redirect() {
        let logout_redirect = CONFIG.sso_logout_redirect();

        if logout_redirect {
            let sso_authority = CONFIG.sso_authority();
            let sso_client_id = CONFIG.sso_client_id();
            let domain = CONFIG.domain();
            let safe_authority: String = sso_authority.chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_'))
                .collect();
            let safe_client_id: String = sso_client_id.chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
                .collect();
            let safe_domain: String = domain.chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_'))
                .collect();

            // With logout redirect: track active session via localStorage flag.
            // Login hash + flag present = logout → redirect to IdP end_session.
            // Login hash + no flag = fresh visit → auto-redirect to SSO.
            // Other hash = active session → set flag, show app.
            format!(
                "(function(){{\
                    var h=window.location.hash||'';\
                    if(!h||h==='#'||h==='#/'||h==='#/login'||h.indexOf('#/login?')===0){{\
                        if(localStorage.getItem('__vw_sso_active')){{\
                            localStorage.removeItem('__vw_sso_active');\
                            window.location.replace('{safe_authority}/protocol/openid-connect/logout\
?client_id={safe_client_id}&post_logout_redirect_uri='+encodeURIComponent('{safe_domain}/sso-auto-redirect'));\
                        }}else{{\
                            var p=window.location.pathname;\
                            if(p.charAt(p.length-1)!=='/') p+='/';\
                            window.location.replace(p+'sso-auto-redirect');\
                        }}\
                    }}else{{\
                        localStorage.setItem('__vw_sso_active','1');\
                        var s=document.createElement('style');\
                        s.textContent='app-root{{display:block!important}}';\
                        document.head.appendChild(s);\
                    }}\
                }})();",
                safe_authority = safe_authority,
                safe_client_id = safe_client_id,
                safe_domain = safe_domain,
            )
        } else {
            // Without logout redirect: simple auto-redirect, no session tracking.
            "(function(){\
                var h=window.location.hash||'';\
                if(!h||h==='#'||h==='#/'||h==='#/login'||h.indexOf('#/login?')===0){\
                    var p=window.location.pathname;\
                    if(p.charAt(p.length-1)!=='/') p+='/';\
                    window.location.replace(p+'sso-auto-redirect');\
                } else {\
                    var s=document.createElement('style');\
                    s.textContent='app-root{display:block!important}';\
                    document.head.appendChild(s);\
                }\
            })();".to_string()
        }
    } else {
        String::new()
    };
    Cached::ttl((ContentType::JavaScript, js), 86_400, false)
}

/// Minimal HTML page that loads the PKCE redirect script as an external resource.
#[get("/sso-auto-redirect")]
fn sso_auto_redirect() -> Cached<Html<&'static str>> {
    Cached::short(
        Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>html,body{margin:0;background:#0f1419}</style>
</head><body>
<script src="sso-auto-redirect.js"></script>
</body></html>"#),
        false,
    )
}

/// PKCE-based SSO auto-redirect script. Generates code verifier, challenge, and state,
/// stores them in sessionStorage (where the web vault expects them), then redirects to
/// Vaultwarden's /identity/connect/authorize endpoint which forwards to the SSO provider.
#[get("/sso-auto-redirect.js")]
fn sso_auto_redirect_js() -> Cached<(ContentType, String)> {
    let domain = CONFIG.domain();
    // Sanitize values for safe JS string embedding (prevent XSS via config injection)
    let safe_domain: String = domain
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_'))
        .collect();

    let sso_id_cfg = CONFIG.sso_identifier();
    let sso_id = if sso_id_cfg.is_empty() { sso::FAKE_IDENTIFIER.to_string() } else { sso_id_cfg };
    let safe_sso_id: String = sso_id
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_'))
        .collect();

    let js = format!(
        r#"(async function(){{
var cv='';var a=new Uint8Array(64);crypto.getRandomValues(a);
for(var i=0;i<a.length;i++)cv+=a[i].toString(16).padStart(2,'0');
var enc=new TextEncoder().encode(cv);
var hash=await crypto.subtle.digest('SHA-256',enc);
var u8=new Uint8Array(hash);var b='';
for(var i=0;i<u8.length;i++)b+=String.fromCharCode(u8[i]);
var cc=btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
var sa=new Uint8Array(32);crypto.getRandomValues(sa);
var state='';for(var i=0;i<sa.length;i++)state+=sa[i].toString(16).padStart(2,'0');
state+='_identifier={safe_sso_id}';
sessionStorage.setItem('global_ssoLogin_ssoCodeVerifier',JSON.stringify(cv));
sessionStorage.setItem('global_ssoLogin_ssoState',JSON.stringify(state));
sessionStorage.setItem('global_ssoLogin_organizationSsoIdentifier',JSON.stringify('{safe_sso_id}'));
sessionStorage.setItem('global_ssoLogin_ssoEmail',JSON.stringify(''));
localStorage.setItem('global_ssoLogin_organizationSsoIdentifier',JSON.stringify('{safe_sso_id}'));
var p=new URLSearchParams({{
client_id:'web',
redirect_uri:'{safe_domain}/sso-connector.html',
response_type:'code',
scope:'api offline_access',
state:state,
code_challenge:cc,
code_challenge_method:'S256'
}});
window.location.replace('{safe_domain}/identity/connect/authorize?'+p.toString());
}})();"#,
        safe_domain = safe_domain,
        safe_sso_id = safe_sso_id,
    );
    Cached::short((ContentType::JavaScript, js), false)
}
