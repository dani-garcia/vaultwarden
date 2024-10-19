use std::env::consts::EXE_SUFFIX;
use std::process::exit;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    RwLock,
};

use job_scheduler_ng::Schedule;
use once_cell::sync::Lazy;
use reqwest::Url;

use crate::{
    db::DbConnType,
    error::Error,
    util::{get_env, get_env_bool, parse_experimental_client_feature_flags},
};

static CONFIG_FILE: Lazy<String> = Lazy::new(|| {
    let data_folder = get_env("DATA_FOLDER").unwrap_or_else(|| String::from("data"));
    get_env("CONFIG_FILE").unwrap_or_else(|| format!("{data_folder}/config.json"))
});

pub static SKIP_CONFIG_VALIDATION: AtomicBool = AtomicBool::new(false);

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n  {e:?}\n");
        exit(12)
    })
});

pub type Pass = String;

macro_rules! make_config {
    ($(
        $(#[doc = $groupdoc:literal])?
        $group:ident $(: $group_enabled:ident)? {
        $(
            $(#[doc = $doc:literal])+
            $name:ident : $ty:ident, $editable:literal, $none_action:ident $(, $default:expr)?;
        )+},
    )+) => {
        pub struct Config { inner: RwLock<Inner> }

        struct Inner {
            rocket_shutdown_handle: Option<rocket::Shutdown>,

            templates: Handlebars<'static>,
            config: ConfigItems,

            _env: ConfigBuilder,
            _usr: ConfigBuilder,

            _overrides: Vec<String>,
        }

        #[derive(Clone, Default, Deserialize, Serialize)]
        pub struct ConfigBuilder {
            $($(
                #[serde(skip_serializing_if = "Option::is_none")]
                $name: Option<$ty>,
            )+)+
        }

        impl ConfigBuilder {
            #[allow(clippy::field_reassign_with_default)]
            fn from_env() -> Self {
                let env_file = get_env("ENV_FILE").unwrap_or_else(|| String::from(".env"));
                match dotenvy::from_path(&env_file) {
                    Ok(_) => {
                        println!("[INFO] Using environment file `{env_file}` for configuration.\n");
                    },
                    Err(e) => match e {
                        dotenvy::Error::LineParse(msg, pos) => {
                            println!("[ERROR] Failed parsing environment file: `{env_file}`\nNear {msg:?} on position {pos}\nPlease fix and restart!\n");
                            exit(255);
                        },
                        dotenvy::Error::Io(ioerr) => match ioerr.kind() {
                            std::io::ErrorKind::NotFound => {
                                // Only exit if this environment variable is set, but the file was not found.
                                // This prevents incorrectly configured environments.
                                if let Some(env_file) = get_env::<String>("ENV_FILE") {
                                    println!("[ERROR] The configured ENV_FILE `{env_file}` was not found!\n");
                                    exit(255);
                                }
                            },
                            std::io::ErrorKind::PermissionDenied => {
                                println!("[ERROR] Permission denied while trying to read environment file `{env_file}`!\n");
                                exit(255);
                            },
                            _ => {
                                println!("[ERROR] Reading environment file `{env_file}` failed:\n{ioerr:?}\n");
                                exit(255);
                            }
                        },
                        _ => {
                            println!("[ERROR] Reading environment file `{env_file}` failed:\n{e:?}\n");
                            exit(255);
                        }
                    }
                };

                let mut builder = ConfigBuilder::default();
                $($(
                    builder.$name = make_config! { @getenv paste::paste!(stringify!([<$name:upper>])), $ty };
                )+)+

                builder
            }

            fn from_file(path: &str) -> Result<Self, Error> {
                let config_str = std::fs::read_to_string(path)?;
                println!("[INFO] Using saved config from `{path}` for configuration.\n");
                serde_json::from_str(&config_str).map_err(Into::into)
            }

            /// Merges the values of both builders into a new builder.
            /// If both have the same element, `other` wins.
            fn merge(&self, other: &Self, show_overrides: bool, overrides: &mut Vec<String>) -> Self {
                let mut builder = self.clone();
                $($(
                    if let v @Some(_) = &other.$name {
                        builder.$name = v.clone();

                        if self.$name.is_some() {
                            overrides.push(paste::paste!(stringify!([<$name:upper>])).into());
                        }
                    }
                )+)+

                if show_overrides && !overrides.is_empty() {
                    // We can't use warn! here because logging isn't setup yet.
                    println!("[WARNING] The following environment variables are being overridden by the config.json file.");
                    println!("[WARNING] Please use the admin panel to make changes to them:");
                    println!("[WARNING] {}\n", overrides.join(", "));
                }

                builder
            }

            fn build(&self) -> ConfigItems {
                let mut config = ConfigItems::default();
                let _domain_set = self.domain.is_some();
                $($(
                    config.$name = make_config!{ @build self.$name.clone(), &config, $none_action, $($default)? };
                )+)+
                config.domain_set = _domain_set;

                config.domain = config.domain.trim_end_matches('/').to_string();

                config.signups_domains_whitelist = config.signups_domains_whitelist.trim().to_lowercase();
                config.org_creation_users = config.org_creation_users.trim().to_lowercase();


                // Copy the values from the deprecated flags to the new ones
                if config.http_request_block_regex.is_none() {
                    config.http_request_block_regex = config.icon_blacklist_regex.clone();
                }

                config
            }
        }

        #[derive(Clone, Default)]
        struct ConfigItems { $($( $name: make_config!{@type $ty, $none_action}, )+)+ }

        #[allow(unused)]
        impl Config {
            $($(
                $(#[doc = $doc])+
                pub fn $name(&self) -> make_config!{@type $ty, $none_action} {
                    self.inner.read().unwrap().config.$name.clone()
                }
            )+)+

            pub fn prepare_json(&self) -> serde_json::Value {
                let (def, cfg, overridden) = {
                    let inner = &self.inner.read().unwrap();
                    (inner._env.build(), inner.config.clone(), inner._overrides.clone())
                };

                fn _get_form_type(rust_type: &str) -> &'static str {
                    match rust_type {
                        "Pass" => "password",
                        "String" => "text",
                        "bool" => "checkbox",
                        _ => "number"
                    }
                }

                fn _get_doc(doc: &str) -> serde_json::Value {
                    let mut split = doc.split("|>").map(str::trim);

                    // We do not use the json!() macro here since that causes a lot of macro recursion.
                    // This slows down compile time and it also causes issues with rust-analyzer
                    serde_json::Value::Object({
                        let mut doc_json = serde_json::Map::new();
                        doc_json.insert("name".into(), serde_json::to_value(split.next()).unwrap());
                        doc_json.insert("description".into(), serde_json::to_value(split.next()).unwrap());
                        doc_json
                    })
                }

                // We do not use the json!() macro here since that causes a lot of macro recursion.
                // This slows down compile time and it also causes issues with rust-analyzer
                serde_json::Value::Array(<[_]>::into_vec(Box::new([
                $(
                    serde_json::Value::Object({
                        let mut group = serde_json::Map::new();
                        group.insert("group".into(), (stringify!($group)).into());
                        group.insert("grouptoggle".into(), (stringify!($($group_enabled)?)).into());
                        group.insert("groupdoc".into(), (make_config!{ @show $($groupdoc)? }).into());

                        group.insert("elements".into(), serde_json::Value::Array(<[_]>::into_vec(Box::new([
                        $(
                            serde_json::Value::Object({
                                let mut element = serde_json::Map::new();
                                element.insert("editable".into(), ($editable).into());
                                element.insert("name".into(), (stringify!($name)).into());
                                element.insert("value".into(), serde_json::to_value(cfg.$name).unwrap());
                                element.insert("default".into(), serde_json::to_value(def.$name).unwrap());
                                element.insert("type".into(), (_get_form_type(stringify!($ty))).into());
                                element.insert("doc".into(), (_get_doc(concat!($($doc),+))).into());
                                element.insert("overridden".into(), (overridden.contains(&paste::paste!(stringify!([<$name:upper>])).into())).into());
                                element
                            }),
                        )+
                        ]))));
                        group
                    }),
                )+
                ])))
            }

            pub fn get_support_json(&self) -> serde_json::Value {
                // Define which config keys need to be masked.
                // Pass types will always be masked and no need to put them in the list.
                // Besides Pass, only String types will be masked via _privacy_mask.
                const PRIVACY_CONFIG: &[&str] = &[
                    "allowed_iframe_ancestors",
                    "database_url",
                    "domain_origin",
                    "domain_path",
                    "domain",
                    "helo_name",
                    "org_creation_users",
                    "signups_domains_whitelist",
                    "smtp_from",
                    "smtp_host",
                    "smtp_username",
                ];

                let cfg = {
                    let inner = &self.inner.read().unwrap();
                    inner.config.clone()
                };

                /// We map over the string and remove all alphanumeric, _ and - characters.
                /// This is the fastest way (within micro-seconds) instead of using a regex (which takes mili-seconds)
                fn _privacy_mask(value: &str) -> String {
                    let mut n: u16 = 0;
                    let mut colon_match = false;
                    value
                        .chars()
                        .map(|c| {
                            n += 1;
                            match c {
                                ':' if n <= 11 => {
                                    colon_match = true;
                                    c
                                }
                                '/' if n <= 13 && colon_match => c,
                                ',' => c,
                                _ => '*',
                            }
                        })
                        .collect::<String>()
                }

                serde_json::Value::Object({
                    let mut json = serde_json::Map::new();
                    $($(
                        json.insert(stringify!($name).into(), make_config!{ @supportstr $name, cfg.$name, $ty, $none_action });
                    )+)+;
                    json
                })
            }

            pub fn get_overrides(&self) -> Vec<String> {
                let overrides = {
                    let inner = &self.inner.read().unwrap();
                    inner._overrides.clone()
                };
                overrides
            }
        }
    };

    // Support string print
    ( @supportstr $name:ident, $value:expr, Pass, option ) => { serde_json::to_value($value.as_ref().map(|_| String::from("***"))).unwrap() }; // Optional pass, we map to an Option<String> with "***"
    ( @supportstr $name:ident, $value:expr, Pass, $none_action:ident ) => { "***".into() }; // Required pass, we return "***"
    ( @supportstr $name:ident, $value:expr, String, option ) => { // Optional other value, we return as is or convert to string to apply the privacy config
        if PRIVACY_CONFIG.contains(&stringify!($name)) {
            serde_json::to_value($value.as_ref().map(|x| _privacy_mask(x) )).unwrap()
        } else {
            serde_json::to_value($value).unwrap()
        }
    };
    ( @supportstr $name:ident, $value:expr, String, $none_action:ident ) => { // Required other value, we return as is or convert to string to apply the privacy config
        if PRIVACY_CONFIG.contains(&stringify!($name)) {
            _privacy_mask(&$value).into()
        } else {
            ($value).into()
        }
    };
    ( @supportstr $name:ident, $value:expr, $ty:ty, option ) => { serde_json::to_value($value).unwrap() }; // Optional other value, we return as is or convert to string to apply the privacy config
    ( @supportstr $name:ident, $value:expr, $ty:ty, $none_action:ident ) => { ($value).into() }; // Required other value, we return as is or convert to string to apply the privacy config

    // Group or empty string
    ( @show ) => { "" };
    ( @show $lit:literal ) => { $lit };

    // Wrap the optionals in an Option type
    ( @type $ty:ty, option) => { Option<$ty> };
    ( @type $ty:ty, $id:ident) => { $ty };

    // Generate the values depending on none_action
    ( @build $value:expr, $config:expr, option, ) => { $value };
    ( @build $value:expr, $config:expr, def, $default:expr ) => { $value.unwrap_or($default) };
    ( @build $value:expr, $config:expr, auto, $default_fn:expr ) => {{
        match $value {
            Some(v) => v,
            None => {
                let f: &dyn Fn(&ConfigItems) -> _ = &$default_fn;
                f($config)
            }
        }
    }};
    ( @build $value:expr, $config:expr, generated, $default_fn:expr ) => {{
        let f: &dyn Fn(&ConfigItems) -> _ = &$default_fn;
        f($config)
    }};

    ( @getenv $name:expr, bool ) => { get_env_bool($name) };
    ( @getenv $name:expr, $ty:ident ) => { get_env($name) };

}

//STRUCTURE:
// /// Short description (without this they won't appear on the list)
// group {
//   /// Friendly Name |> Description (Optional)
//   name: type, is_editable, action, <default_value (Optional)>
// }
//
// Where action applied when the value wasn't provided and can be:
//  def:       Use a default value
//  auto:      Value is auto generated based on other values
//  option:    Value is optional
//  generated: Value is always autogenerated and it's original value ignored
make_config! {
    folders {
        ///  Data folder |> Main data folder
        data_folder:            String, false,  def,    "data".to_string();
        /// Database URL
        database_url:           String, false,  auto,   |c| format!("{}/{}", c.data_folder, "db.sqlite3");
        /// Icon cache folder
        icon_cache_folder:      String, false,  auto,   |c| format!("{}/{}", c.data_folder, "icon_cache");
        /// Attachments folder
        attachments_folder:     String, false,  auto,   |c| format!("{}/{}", c.data_folder, "attachments");
        /// Sends folder
        sends_folder:           String, false,  auto,   |c| format!("{}/{}", c.data_folder, "sends");
        /// Temp folder |> Used for storing temporary file uploads
        tmp_folder:             String, false,  auto,   |c| format!("{}/{}", c.data_folder, "tmp");
        /// Templates folder
        templates_folder:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "templates");
        /// Session JWT key
        rsa_key_filename:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "rsa_key");
        /// Web vault folder
        web_vault_folder:       String, false,  def,    "web-vault/".to_string();
    },
    ws {
        /// Enable websocket notifications
        enable_websocket:       bool,   false,  def,    true;
    },
    push {
        /// Enable push notifications
        push_enabled:           bool,   false,  def,    false;
        /// Push relay uri
        push_relay_uri:         String, false,  def,    "https://push.bitwarden.com".to_string();
        /// Push identity uri
        push_identity_uri:      String, false,  def,    "https://identity.bitwarden.com".to_string();
        /// Installation id |> The installation id from https://bitwarden.com/host
        push_installation_id:   Pass,   false,  def,    String::new();
        /// Installation key |> The installation key from https://bitwarden.com/host
        push_installation_key:  Pass,   false,  def,    String::new();
    },
    jobs {
        /// Job scheduler poll interval |> How often the job scheduler thread checks for jobs to run.
        /// Set to 0 to globally disable scheduled jobs.
        job_poll_interval_ms:   u64,    false,  def,    30_000;
        /// Send purge schedule |> Cron schedule of the job that checks for Sends past their deletion date.
        /// Defaults to hourly. Set blank to disable this job.
        send_purge_schedule:    String, false,  def,    "0 5 * * * *".to_string();
        /// Trash purge schedule |> Cron schedule of the job that checks for trashed items to delete permanently.
        /// Defaults to daily. Set blank to disable this job.
        trash_purge_schedule:   String, false,  def,    "0 5 0 * * *".to_string();
        /// Incomplete 2FA login schedule |> Cron schedule of the job that checks for incomplete 2FA logins.
        /// Defaults to once every minute. Set blank to disable this job.
        incomplete_2fa_schedule: String, false,  def,   "30 * * * * *".to_string();
        /// Emergency notification reminder schedule |> Cron schedule of the job that sends expiration reminders to emergency access grantors.
        /// Defaults to hourly. (3 minutes after the hour) Set blank to disable this job.
        emergency_notification_reminder_schedule:   String, false,  def,    "0 3 * * * *".to_string();
        /// Emergency request timeout schedule |> Cron schedule of the job that grants emergency access requests that have met the required wait time.
        /// Defaults to hourly. (7 minutes after the hour) Set blank to disable this job.
        emergency_request_timeout_schedule:   String, false,  def,    "0 7 * * * *".to_string();
        /// Event cleanup schedule |> Cron schedule of the job that cleans old events from the event table.
        /// Defaults to daily. Set blank to disable this job.
        event_cleanup_schedule:   String, false,  def,    "0 10 0 * * *".to_string();
        /// Auth Request cleanup schedule |> Cron schedule of the job that cleans old auth requests from the auth request.
        /// Defaults to every minute. Set blank to disable this job.
        auth_request_purge_schedule:   String, false,  def,    "30 * * * * *".to_string();
        /// Duo Auth context cleanup schedule |> Cron schedule of the job that cleans expired Duo contexts from the database. Does nothing if Duo MFA is disabled or set to use the legacy iframe prompt.
        /// Defaults to once every minute. Set blank to disable this job.
        duo_context_purge_schedule:   String, false,  def,    "30 * * * * *".to_string();
    },

    /// General settings
    settings {
        /// Domain URL |> This needs to be set to the URL used to access the server, including 'http[s]://'
        /// and port, if it's different than the default. Some server functions don't work correctly without this value
        domain:                 String, true,   def,    "http://localhost".to_string();
        /// Domain Set |> Indicates if the domain is set by the admin. Otherwise the default will be used.
        domain_set:             bool,   false,  def,    false;
        /// Domain origin |> Domain URL origin (in https://example.com:8443/path, https://example.com:8443 is the origin)
        domain_origin:          String, false,  auto,   |c| extract_url_origin(&c.domain);
        /// Domain path |> Domain URL path (in https://example.com:8443/path, /path is the path)
        domain_path:            String, false,  auto,   |c| extract_url_path(&c.domain);
        /// Enable web vault
        web_vault_enabled:      bool,   false,  def,    true;

        /// Allow Sends |> Controls whether users are allowed to create Bitwarden Sends.
        /// This setting applies globally to all users. To control this on a per-org basis instead, use the "Disable Send" org policy.
        sends_allowed:          bool,   true,   def,    true;

        /// HIBP Api Key |> HaveIBeenPwned API Key, request it here: https://haveibeenpwned.com/API/Key
        hibp_api_key:           Pass,   true,   option;

        /// Per-user attachment storage limit (KB) |> Max kilobytes of attachment storage allowed per user. When this limit is reached, the user will not be allowed to upload further attachments.
        user_attachment_limit:  i64,    true,   option;
        /// Per-organization attachment storage limit (KB) |> Max kilobytes of attachment storage allowed per org. When this limit is reached, org members will not be allowed to upload further attachments for ciphers owned by that org.
        org_attachment_limit:   i64,    true,   option;
        /// Per-user send storage limit (KB) |> Max kilobytes of sends storage allowed per user. When this limit is reached, the user will not be allowed to upload further sends.
        user_send_limit:   i64,    true,   option;

        /// Trash auto-delete days |> Number of days to wait before auto-deleting a trashed item.
        /// If unset, trashed items are not auto-deleted. This setting applies globally, so make
        /// sure to inform all users of any changes to this setting.
        trash_auto_delete_days: i64,    true,   option;

        /// Incomplete 2FA time limit |> Number of minutes to wait before a 2FA-enabled login is
        /// considered incomplete, resulting in an email notification. An incomplete 2FA login is one
        /// where the correct master password was provided but the required 2FA step was not completed,
        /// which potentially indicates a master password compromise. Set to 0 to disable this check.
        /// This setting applies globally to all users.
        incomplete_2fa_time_limit: i64, true,   def,    3;

        /// Disable icon downloads |> Set to true to disable icon downloading in the internal icon service.
        /// This still serves existing icons from $ICON_CACHE_FOLDER, without generating any external
        /// network requests. $ICON_CACHE_TTL must also be set to 0; otherwise, the existing icons
        /// will be deleted eventually, but won't be downloaded again.
        disable_icon_download:  bool,   true,   def,    false;
        /// Allow new signups |> Controls whether new users can register. Users can be invited by the vaultwarden admin even if this is disabled
        signups_allowed:        bool,   true,   def,    true;
        /// Require email verification on signups. This will prevent logins from succeeding until the address has been verified
        signups_verify:         bool,   true,   def,    false;
        /// If signups require email verification, automatically re-send verification email if it hasn't been sent for a while (in seconds)
        signups_verify_resend_time: u64, true,  def,    3_600;
        /// If signups require email verification, limit how many emails are automatically sent when login is attempted (0 means no limit)
        signups_verify_resend_limit: u32, true, def,    6;
        /// Email domain whitelist |> Allow signups only from this list of comma-separated domains, even when signups are otherwise disabled
        signups_domains_whitelist: String, true, def,   String::new();
        /// Enable event logging |> Enables event logging for organizations.
        org_events_enabled:     bool,   false,  def,    false;
        /// Org creation users |> Allow org creation only by this list of comma-separated user emails.
        /// Blank or 'all' means all users can create orgs; 'none' means no users can create orgs.
        org_creation_users:     String, true,   def,    String::new();
        /// Allow invitations |> Controls whether users can be invited by organization admins, even when signups are otherwise disabled
        invitations_allowed:    bool,   true,   def,    true;
        /// Invitation token expiration time (in hours) |> The number of hours after which an organization invite token, emergency access invite token,
        /// email verification token and deletion request token will expire (must be at least 1)
        invitation_expiration_hours: u32, false, def, 120;
        /// Enable emergency access |> Controls whether users can enable emergency access to their accounts. This setting applies globally to all users.
        emergency_access_allowed:    bool,   true,   def,    true;
        /// Allow email change |> Controls whether users can change their email. This setting applies globally to all users.
        email_change_allowed:    bool,   true,   def,    true;
        /// Password iterations |> Number of server-side passwords hashing iterations for the password hash.
        /// The default for new users. If changed, it will be updated during login for existing users.
        password_iterations:    i32,    true,   def,    600_000;
        /// Allow password hints |> Controls whether users can set password hints. This setting applies globally to all users.
        password_hints_allowed: bool,   true,   def,    true;
        /// Show password hint |> Controls whether a password hint should be shown directly in the web page
        /// if SMTP service is not configured. Not recommended for publicly-accessible instances as this
        /// provides unauthenticated access to potentially sensitive data.
        show_password_hint:     bool,   true,   def,    false;

        /// Admin token/Argon2 PHC |> The plain text token or Argon2 PHC string used to authenticate in this very same page. Changing it here will not deauthorize the current session!
        admin_token:            Pass,   true,   option;

        /// Invitation organization name |> Name shown in the invitation emails that don't come from a specific organization
        invitation_org_name:    String, true,   def,    "Vaultwarden".to_string();

        /// Events days retain |> Number of days to retain events stored in the database. If unset, events are kept indefinitely.
        events_days_retain:     i64,    false,   option;
    },

    /// Advanced settings
    advanced {
        /// Client IP header |> If not present, the remote IP is used.
        /// Set to the string "none" (without quotes), to disable any headers and just use the remote IP
        ip_header:              String, true,   def,    "X-Real-IP".to_string();
        /// Internal IP header property, used to avoid recomputing each time
        _ip_header_enabled:     bool,   false,  generated,    |c| &c.ip_header.trim().to_lowercase() != "none";
        /// Icon service |> The predefined icon services are: internal, bitwarden, duckduckgo, google.
        /// To specify a custom icon service, set a URL template with exactly one instance of `{}`,
        /// which is replaced with the domain. For example: `https://icon.example.com/domain/{}`.
        /// `internal` refers to Vaultwarden's built-in icon fetching implementation. If an external
        /// service is set, an icon request to Vaultwarden will return an HTTP redirect to the
        /// corresponding icon at the external service.
        icon_service:           String, false,  def,    "internal".to_string();
        /// _icon_service_url
        _icon_service_url:      String, false,  generated,    |c| generate_icon_service_url(&c.icon_service);
        /// _icon_service_csp
        _icon_service_csp:      String, false,  generated,    |c| generate_icon_service_csp(&c.icon_service, &c._icon_service_url);
        /// Icon redirect code |> The HTTP status code to use for redirects to an external icon service.
        /// The supported codes are 301 (legacy permanent), 302 (legacy temporary), 307 (temporary), and 308 (permanent).
        /// Temporary redirects are useful while testing different icon services, but once a service
        /// has been decided on, consider using permanent redirects for cacheability. The legacy codes
        /// are currently better supported by the Bitwarden clients.
        icon_redirect_code:     u32,    true,   def,    302;
        /// Positive icon cache expiry |> Number of seconds to consider that an already cached icon is fresh. After this period, the icon will be refreshed
        icon_cache_ttl:         u64,    true,   def,    2_592_000;
        /// Negative icon cache expiry |> Number of seconds before trying to download an icon that failed again.
        icon_cache_negttl:      u64,    true,   def,    259_200;
        /// Icon download timeout |> Number of seconds when to stop attempting to download an icon.
        icon_download_timeout:  u64,    true,   def,    10;

        /// [Deprecated] Icon blacklist Regex |> Use `http_request_block_regex` instead
        icon_blacklist_regex:   String, false,   option;
        /// [Deprecated] Icon blacklist non global IPs |> Use `http_request_block_non_global_ips` instead
        icon_blacklist_non_global_ips:  bool,   false,   def, true;

        /// Block HTTP domains/IPs by Regex |> Any domains or IPs that match this regex won't be fetched by the internal HTTP client.
        /// Useful to hide other servers in the local network. Check the WIKI for more details
        http_request_block_regex:   String, true,   option;
        /// Block non global IPs |> Enabling this will cause the internal HTTP client to refuse to connect to any non global IP address.
        /// Useful to secure your internal environment: See https://en.wikipedia.org/wiki/Reserved_IP_addresses for a list of IPs which it will block
        http_request_block_non_global_ips:  bool,   true,   auto, |c| c.icon_blacklist_non_global_ips;

        /// Disable Two-Factor remember |> Enabling this would force the users to use a second factor to login every time.
        /// Note that the checkbox would still be present, but ignored.
        disable_2fa_remember:   bool,   true,   def,    false;

        /// Disable authenticator time drifted codes to be valid |> Enabling this only allows the current TOTP code to be valid
        /// TOTP codes of the previous and next 30 seconds will be invalid.
        authenticator_disable_time_drift: bool, true, def, false;

        /// Customize the enabled feature flags on the clients |> This is a comma separated list of feature flags to enable.
        experimental_client_feature_flags: String, false, def, "fido2-vault-credentials".to_string();

        /// Require new device emails |> When a user logs in an email is required to be sent.
        /// If sending the email fails the login attempt will fail.
        require_device_email:   bool,   true,   def,     false;

        /// Reload templates (Dev) |> When this is set to true, the templates get reloaded with every request.
        /// ONLY use this during development, as it can slow down the server
        reload_templates:       bool,   true,   def,    false;
        /// Enable extended logging
        extended_logging:       bool,   false,  def,    true;
        /// Log timestamp format
        log_timestamp_format:   String, true,   def,    "%Y-%m-%d %H:%M:%S.%3f".to_string();
        /// Enable the log to output to Syslog
        use_syslog:             bool,   false,  def,    false;
        /// Log file path
        log_file:               String, false,  option;
        /// Log level |> Valid values are "trace", "debug", "info", "warn", "error" and "off"
        /// For a specific module append it as a comma separated value "info,path::to::module=debug"
        log_level:              String, false,  def,    "info".to_string();

        /// Enable DB WAL |> Turning this off might lead to worse performance, but might help if using vaultwarden on some exotic filesystems,
        /// that do not support WAL. Please make sure you read project wiki on the topic before changing this setting.
        enable_db_wal:          bool,   false,  def,    true;

        /// Max database connection retries |> Number of times to retry the database connection during startup, with 1 second between each retry, set to 0 to retry indefinitely
        db_connection_retries:  u32,    false,  def,    15;

        /// Timeout when acquiring database connection
        database_timeout:       u64,    false,  def,    30;

        /// Database connection pool size
        database_max_conns:     u32,    false,  def,    10;

        /// Database connection init |> SQL statements to run when creating a new database connection, mainly useful for connection-scoped pragmas. If empty, a database-specific default is used.
        database_conn_init:     String, false,  def,    String::new();

        /// Bypass admin page security (Know the risks!) |> Disables the Admin Token for the admin page so you may use your own auth in-front
        disable_admin_token:    bool,   false,  def,    false;

        /// Allowed iframe ancestors (Know the risks!) |> Allows other domains to embed the web vault into an iframe, useful for embedding into secure intranets
        allowed_iframe_ancestors: String, true, def,    String::new();

        /// Seconds between login requests |> Number of seconds, on average, between login and 2FA requests from the same IP address before rate limiting kicks in
        login_ratelimit_seconds:       u64, false, def, 60;
        /// Max burst size for login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `login_ratelimit_seconds`. Note that this applies to both the login and the 2FA, so it's recommended to allow a burst size of at least 2
        login_ratelimit_max_burst:     u32, false, def, 10;

        /// Seconds between admin login requests |> Number of seconds, on average, between admin requests from the same IP address before rate limiting kicks in
        admin_ratelimit_seconds:       u64, false, def, 300;
        /// Max burst size for admin login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `admin_ratelimit_seconds`
        admin_ratelimit_max_burst:     u32, false, def, 3;

        /// Admin session lifetime |> Set the lifetime of admin sessions to this value (in minutes).
        admin_session_lifetime:        i64, true,  def, 20;

        /// Enable groups (BETA!) (Know the risks!) |> Enables groups support for organizations (Currently contains known issues!).
        org_groups_enabled:            bool, false, def, false;

        /// Increase note size limit (Know the risks!) |> Sets the secure note size limit to 100_000 instead of the default 10_000.
        /// WARNING: This could cause issues with clients. Also exports will not work on Bitwarden servers!
        increase_note_size_limit:      bool,  true,  def, false;
        /// Generated max_note_size value to prevent if..else matching during every check
        _max_note_size:                usize, false, generated, |c| if c.increase_note_size_limit {100_000} else {10_000};

        /// Enforce Single Org with Reset Password Policy |> Enforce that the Single Org policy is enabled before setting the Reset Password policy
        /// Bitwarden enforces this by default. In Vaultwarden we encouraged to use multiple organizations because groups were not available.
        /// Setting this to true will enforce the Single Org Policy to be enabled before you can enable the Reset Password policy.
        enforce_single_org_with_reset_pw_policy: bool, false, def, false;
    },

    /// Yubikey settings
    yubico: _enable_yubico {
        /// Enabled
        _enable_yubico:         bool,   true,   def,     true;
        /// Client ID
        yubico_client_id:       String, true,   option;
        /// Secret Key
        yubico_secret_key:      Pass,   true,   option;
        /// Server
        yubico_server:          String, true,   option;
    },

    /// Global Duo settings (Note that users can override them)
    duo: _enable_duo {
        /// Enabled
        _enable_duo:            bool,   true,   def,     true;
        /// Attempt to use deprecated iframe-based Traditional Prompt (Duo WebSDK 2)
        duo_use_iframe:         bool,   false,  def,     false;
        /// Integration Key
        duo_ikey:               String, true,   option;
        /// Secret Key
        duo_skey:               Pass,   true,   option;
        /// Host
        duo_host:               String, true,   option;
        /// Application Key (generated automatically)
        _duo_akey:              Pass,   false,  option;
    },

    /// SMTP Email Settings
    smtp: _enable_smtp {
        /// Enabled
        _enable_smtp:                  bool,   true,   def,     true;
        /// Use Sendmail |> Whether to send mail via the `sendmail` command
        use_sendmail:                  bool,   true,   def,     false;
        /// Sendmail Command |> Which sendmail command to use. The one found in the $PATH is used if not specified.
        sendmail_command:              String, true,   option;
        /// Host
        smtp_host:                     String, true,   option;
        /// DEPRECATED smtp_ssl |> DEPRECATED - Please use SMTP_SECURITY
        smtp_ssl:                      bool,   false,  option;
        /// DEPRECATED smtp_explicit_tls |> DEPRECATED - Please use SMTP_SECURITY
        smtp_explicit_tls:             bool,   false,  option;
        /// Secure SMTP |> ("starttls", "force_tls", "off") Enable a secure connection. Default is "starttls" (Explicit - ports 587 or 25), "force_tls" (Implicit - port 465) or "off", no encryption
        smtp_security:                 String, true,   auto,    |c| smtp_convert_deprecated_ssl_options(c.smtp_ssl, c.smtp_explicit_tls); // TODO: After deprecation make it `def, "starttls".to_string()`
        /// Port
        smtp_port:                     u16,    true,   auto,    |c| if c.smtp_security == *"force_tls" {465} else if c.smtp_security == *"starttls" {587} else {25};
        /// From Address
        smtp_from:                     String, true,   def,     String::new();
        /// From Name
        smtp_from_name:                String, true,   def,     "Vaultwarden".to_string();
        /// Username
        smtp_username:                 String, true,   option;
        /// Password
        smtp_password:                 Pass,   true,   option;
        /// SMTP Auth mechanism |> Defaults for SSL is "Plain" and "Login" and nothing for Non-SSL connections. Possible values: ["Plain", "Login", "Xoauth2"]. Multiple options need to be separated by a comma ','.
        smtp_auth_mechanism:           String, true,   option;
        /// SMTP connection timeout |> Number of seconds when to stop trying to connect to the SMTP server
        smtp_timeout:                  u64,    true,   def,     15;
        /// Server name sent during HELO |> By default this value should be is on the machine's hostname, but might need to be changed in case it trips some anti-spam filters
        helo_name:                     String, true,   option;
        /// Embed images as email attachments.
        smtp_embed_images:             bool, true, def, true;
        /// _smtp_img_src
        _smtp_img_src:                 String, false, generated, |c| generate_smtp_img_src(c.smtp_embed_images, &c.domain);
        /// Enable SMTP debugging (Know the risks!) |> DANGEROUS: Enabling this will output very detailed SMTP messages. This could contain sensitive information like passwords and usernames! Only enable this during troubleshooting!
        smtp_debug:                    bool,   false,  def,     false;
        /// Accept Invalid Certs (Know the risks!) |> DANGEROUS: Allow invalid certificates. This option introduces significant vulnerabilities to man-in-the-middle attacks!
        smtp_accept_invalid_certs:     bool,   true,   def,     false;
        /// Accept Invalid Hostnames (Know the risks!) |> DANGEROUS: Allow invalid hostnames. This option introduces significant vulnerabilities to man-in-the-middle attacks!
        smtp_accept_invalid_hostnames: bool,   true,   def,     false;
    },

    /// Email 2FA Settings
    email_2fa: _enable_email_2fa {
        /// Enabled |> Disabling will prevent users from setting up new email 2FA and using existing email 2FA configured
        _enable_email_2fa:      bool,   true,   auto,    |c| c._enable_smtp && (c.smtp_host.is_some() || c.use_sendmail);
        /// Email token size |> Number of digits in an email 2FA token (min: 6, max: 255). Note that the Bitwarden clients are hardcoded to mention 6 digit codes regardless of this setting.
        email_token_size:       u8,     true,   def,      6;
        /// Token expiration time |> Maximum time in seconds a token is valid. The time the user has to open email client and copy token.
        email_expiration_time:  u64,    true,   def,      600;
        /// Maximum attempts |> Maximum attempts before an email token is reset and a new email will need to be sent
        email_attempts_limit:   u64,    true,   def,      3;
        /// Automatically enforce at login |> Setup email 2FA provider regardless of any organization policy
        email_2fa_enforce_on_verified_invite: bool,   true,   def,      false;
        /// Auto-enable 2FA (Know the risks!) |> Automatically setup email 2FA as fallback provider when needed
        email_2fa_auto_fallback: bool,  true,   def,      false;
    },
}

fn validate_config(cfg: &ConfigItems) -> Result<(), Error> {
    // Validate connection URL is valid and DB feature is enabled
    let url = &cfg.database_url;
    if DbConnType::from_url(url)? == DbConnType::sqlite && url.contains('/') {
        let path = std::path::Path::new(&url);
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                err!(format!("SQLite database directory `{}` does not exist or is not a directory", parent.display()));
            }
        }
    }

    if cfg.password_iterations < 100_000 {
        err!("PASSWORD_ITERATIONS should be at least 100000 or higher. The default is 600000!");
    }

    let limit = 256;
    if cfg.database_max_conns < 1 || cfg.database_max_conns > limit {
        err!(format!("`DATABASE_MAX_CONNS` contains an invalid value. Ensure it is between 1 and {limit}.",));
    }

    if let Some(log_file) = &cfg.log_file {
        if std::fs::OpenOptions::new().append(true).create(true).open(log_file).is_err() {
            err!("Unable to write to log file", log_file);
        }
    }

    let dom = cfg.domain.to_lowercase();
    if !dom.starts_with("http://") && !dom.starts_with("https://") {
        err!(
            "DOMAIN variable needs to contain the protocol (http, https). Use 'http[s]://bw.example.com' instead of 'bw.example.com'"
        );
    }

    let whitelist = &cfg.signups_domains_whitelist;
    if !whitelist.is_empty() && whitelist.split(',').any(|d| d.trim().is_empty()) {
        err!("`SIGNUPS_DOMAINS_WHITELIST` contains empty tokens");
    }

    let org_creation_users = cfg.org_creation_users.trim().to_lowercase();
    if !(org_creation_users.is_empty() || org_creation_users == "all" || org_creation_users == "none")
        && org_creation_users.split(',').any(|u| !u.contains('@'))
    {
        err!("`ORG_CREATION_USERS` contains invalid email addresses");
    }

    if let Some(ref token) = cfg.admin_token {
        if token.trim().is_empty() && !cfg.disable_admin_token {
            println!("[WARNING] `ADMIN_TOKEN` is enabled but has an empty value, so the admin page will be disabled.");
            println!("[WARNING] To enable the admin page without a token, use `DISABLE_ADMIN_TOKEN`.");
        }
    }

    if cfg.push_enabled && (cfg.push_installation_id == String::new() || cfg.push_installation_key == String::new()) {
        err!(
            "Misconfigured Push Notification service\n\
            ########################################################################################\n\
            # It looks like you enabled Push Notification feature, but didn't configure it         #\n\
            # properly. Make sure the installation id and key from https://bitwarden.com/host are  #\n\
            # added to your configuration.                                                         #\n\
            ########################################################################################\n"
        )
    }

    if cfg.push_enabled {
        let push_relay_uri = cfg.push_relay_uri.to_lowercase();
        if !push_relay_uri.starts_with("https://") {
            err!("`PUSH_RELAY_URI` must start with 'https://'.")
        }

        if Url::parse(&push_relay_uri).is_err() {
            err!("Invalid URL format for `PUSH_RELAY_URI`.");
        }

        let push_identity_uri = cfg.push_identity_uri.to_lowercase();
        if !push_identity_uri.starts_with("https://") {
            err!("`PUSH_IDENTITY_URI` must start with 'https://'.")
        }

        if Url::parse(&push_identity_uri).is_err() {
            err!("Invalid URL format for `PUSH_IDENTITY_URI`.");
        }
    }

    // TODO: deal with deprecated flags so they can be removed from this list, cf. #4263
    const KNOWN_FLAGS: &[&str] =
        &["autofill-overlay", "autofill-v2", "browser-fileless-import", "extension-refresh", "fido2-vault-credentials"];
    let configured_flags = parse_experimental_client_feature_flags(&cfg.experimental_client_feature_flags);
    let invalid_flags: Vec<_> = configured_flags.keys().filter(|flag| !KNOWN_FLAGS.contains(&flag.as_str())).collect();
    if !invalid_flags.is_empty() {
        err!(format!("Unrecognized experimental client feature flags: {invalid_flags:?}.\n\n\
                     Please ensure all feature flags are spelled correctly and that they are supported in this version.\n\
                     Supported flags: {KNOWN_FLAGS:?}"));
    }

    const MAX_FILESIZE_KB: i64 = i64::MAX >> 10;

    if let Some(limit) = cfg.user_attachment_limit {
        if !(0i64..=MAX_FILESIZE_KB).contains(&limit) {
            err!("`USER_ATTACHMENT_LIMIT` is out of bounds");
        }
    }

    if let Some(limit) = cfg.org_attachment_limit {
        if !(0i64..=MAX_FILESIZE_KB).contains(&limit) {
            err!("`ORG_ATTACHMENT_LIMIT` is out of bounds");
        }
    }

    if let Some(limit) = cfg.user_send_limit {
        if !(0i64..=MAX_FILESIZE_KB).contains(&limit) {
            err!("`USER_SEND_LIMIT` is out of bounds");
        }
    }

    if cfg._enable_duo
        && (cfg.duo_host.is_some() || cfg.duo_ikey.is_some() || cfg.duo_skey.is_some())
        && !(cfg.duo_host.is_some() && cfg.duo_ikey.is_some() && cfg.duo_skey.is_some())
    {
        err!("All Duo options need to be set for global Duo support")
    }

    if cfg._enable_yubico {
        if cfg.yubico_client_id.is_some() != cfg.yubico_secret_key.is_some() {
            err!("Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` must be set for Yubikey OTP support")
        }

        if let Some(yubico_server) = &cfg.yubico_server {
            let yubico_server = yubico_server.to_lowercase();
            if !yubico_server.starts_with("https://") {
                err!("`YUBICO_SERVER` must be a valid URL and start with 'https://'. Either unset this variable or provide a valid URL.")
            }
        }
    }

    if cfg._enable_smtp {
        match cfg.smtp_security.as_str() {
            "off" | "starttls" | "force_tls" => (),
            _ => err!(
                "`SMTP_SECURITY` is invalid. It needs to be one of the following options: starttls, force_tls or off"
            ),
        }

        if cfg.use_sendmail {
            let command = cfg.sendmail_command.clone().unwrap_or_else(|| format!("sendmail{EXE_SUFFIX}"));

            let mut path = std::path::PathBuf::from(&command);

            if !path.is_absolute() {
                match which::which(&command) {
                    Ok(result) => path = result,
                    Err(_) => err!(format!("sendmail command {command:?} not found in $PATH")),
                }
            }

            match path.metadata() {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    err!(format!("sendmail command not found at `{path:?}`"))
                }
                Err(err) => {
                    err!(format!("failed to access sendmail command at `{path:?}`: {err}"))
                }
                Ok(metadata) => {
                    if metadata.is_dir() {
                        err!(format!("sendmail command at `{path:?}` isn't a directory"));
                    }

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if !metadata.permissions().mode() & 0o111 != 0 {
                            err!(format!("sendmail command at `{path:?}` isn't executable"));
                        }
                    }
                }
            }
        } else {
            if cfg.smtp_host.is_some() == cfg.smtp_from.is_empty() {
                err!("Both `SMTP_HOST` and `SMTP_FROM` need to be set for email support without `USE_SENDMAIL`")
            }

            if cfg.smtp_username.is_some() != cfg.smtp_password.is_some() {
                err!("Both `SMTP_USERNAME` and `SMTP_PASSWORD` need to be set to enable email authentication without `USE_SENDMAIL`")
            }
        }

        if (cfg.smtp_host.is_some() || cfg.use_sendmail) && !cfg.smtp_from.contains('@') {
            err!("SMTP_FROM does not contain a mandatory @ sign")
        }

        if cfg._enable_email_2fa && cfg.email_token_size < 6 {
            err!("`EMAIL_TOKEN_SIZE` has a minimum size of 6")
        }
    }

    if cfg._enable_email_2fa && !(cfg.smtp_host.is_some() || cfg.use_sendmail) {
        err!("To enable email 2FA, a mail transport must be configured")
    }

    if !cfg._enable_email_2fa && cfg.email_2fa_enforce_on_verified_invite {
        err!("To enforce email 2FA on verified invitations, email 2fa has to be enabled!");
    }
    if !cfg._enable_email_2fa && cfg.email_2fa_auto_fallback {
        err!("To use email 2FA as automatic fallback, email 2fa has to be enabled!");
    }

    // Check if the HTTP request block regex is valid
    if let Some(ref r) = cfg.http_request_block_regex {
        let validate_regex = regex::Regex::new(r);
        match validate_regex {
            Ok(_) => (),
            Err(e) => err!(format!("`HTTP_REQUEST_BLOCK_REGEX` is invalid: {e:#?}")),
        }
    }

    // Check if the icon service is valid
    let icon_service = cfg.icon_service.as_str();
    match icon_service {
        "internal" | "bitwarden" | "duckduckgo" | "google" => (),
        _ => {
            if !icon_service.starts_with("http") {
                err!(format!("Icon service URL `{icon_service}` must start with \"http\""))
            }
            match icon_service.matches("{}").count() {
                1 => (), // nominal
                0 => err!(format!("Icon service URL `{icon_service}` has no placeholder \"{{}}\"")),
                _ => err!(format!("Icon service URL `{icon_service}` has more than one placeholder \"{{}}\"")),
            }
        }
    }

    // Check if the icon redirect code is valid
    match cfg.icon_redirect_code {
        301 | 302 | 307 | 308 => (),
        _ => err!("Only HTTP 301/302 and 307/308 redirects are supported"),
    }

    if cfg.invitation_expiration_hours < 1 {
        err!("`INVITATION_EXPIRATION_HOURS` has a minimum duration of 1 hour")
    }

    // Validate schedule crontab format
    if !cfg.send_purge_schedule.is_empty() && cfg.send_purge_schedule.parse::<Schedule>().is_err() {
        err!("`SEND_PURGE_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.trash_purge_schedule.is_empty() && cfg.trash_purge_schedule.parse::<Schedule>().is_err() {
        err!("`TRASH_PURGE_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.incomplete_2fa_schedule.is_empty() && cfg.incomplete_2fa_schedule.parse::<Schedule>().is_err() {
        err!("`INCOMPLETE_2FA_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.emergency_notification_reminder_schedule.is_empty()
        && cfg.emergency_notification_reminder_schedule.parse::<Schedule>().is_err()
    {
        err!("`EMERGENCY_NOTIFICATION_REMINDER_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.emergency_request_timeout_schedule.is_empty()
        && cfg.emergency_request_timeout_schedule.parse::<Schedule>().is_err()
    {
        err!("`EMERGENCY_REQUEST_TIMEOUT_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.event_cleanup_schedule.is_empty() && cfg.event_cleanup_schedule.parse::<Schedule>().is_err() {
        err!("`EVENT_CLEANUP_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.auth_request_purge_schedule.is_empty() && cfg.auth_request_purge_schedule.parse::<Schedule>().is_err() {
        err!("`AUTH_REQUEST_PURGE_SCHEDULE` is not a valid cron expression")
    }

    if !cfg.disable_admin_token {
        match cfg.admin_token.as_ref() {
            Some(t) if t.starts_with("$argon2") => {
                if let Err(e) = argon2::password_hash::PasswordHash::new(t) {
                    err!(format!("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: '{e}'"))
                }
            }
            Some(_) => {
                println!(
                    "[NOTICE] You are using a plain text `ADMIN_TOKEN` which is insecure.\n\
                Please generate a secure Argon2 PHC string by using `vaultwarden hash` or `argon2`.\n\
                See: https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page#secure-the-admin_token\n"
                );
            }
            _ => {}
        }
    }

    if cfg.increase_note_size_limit {
        println!("[WARNING] Secure Note size limit is increased to 100_000!");
        println!("[WARNING] This could cause issues with clients. Also exports will not work on Bitwarden servers!.");
    }
    Ok(())
}

/// Extracts an RFC 6454 web origin from a URL.
fn extract_url_origin(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(e) => {
            println!("Error validating domain: {e}");
            String::new()
        }
    }
}

/// Extracts the path from a URL.
/// All trailing '/' chars are trimmed, even if the path is a lone '/'.
fn extract_url_path(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => u.path().trim_end_matches('/').to_string(),
        Err(_) => {
            // We already print it in the method above, no need to do it again
            String::new()
        }
    }
}

fn generate_smtp_img_src(embed_images: bool, domain: &str) -> String {
    if embed_images {
        "cid:".to_string()
    } else {
        format!("{domain}/vw_static/")
    }
}

/// Generate the correct URL for the icon service.
/// This will be used within icons.rs to call the external icon service.
fn generate_icon_service_url(icon_service: &str) -> String {
    match icon_service {
        "internal" => String::new(),
        "bitwarden" => "https://icons.bitwarden.net/{}/icon.png".to_string(),
        "duckduckgo" => "https://icons.duckduckgo.com/ip3/{}.ico".to_string(),
        "google" => "https://www.google.com/s2/favicons?domain={}&sz=32".to_string(),
        _ => icon_service.to_string(),
    }
}

/// Generate the CSP string needed to allow redirected icon fetching
fn generate_icon_service_csp(icon_service: &str, icon_service_url: &str) -> String {
    // We split on the first '{', since that is the variable delimiter for an icon service URL.
    // Everything up until the first '{' should be fixed and can be used as an CSP string.
    let csp_string = match icon_service_url.split_once('{') {
        Some((c, _)) => c.to_string(),
        None => String::new(),
    };

    // Because Google does a second redirect to there gstatic.com domain, we need to add an extra csp string.
    match icon_service {
        "google" => csp_string + " https://*.gstatic.com/favicon",
        _ => csp_string,
    }
}

/// Convert the old SMTP_SSL and SMTP_EXPLICIT_TLS options
fn smtp_convert_deprecated_ssl_options(smtp_ssl: Option<bool>, smtp_explicit_tls: Option<bool>) -> String {
    if smtp_explicit_tls.is_some() || smtp_ssl.is_some() {
        println!("[DEPRECATED]: `SMTP_SSL` or `SMTP_EXPLICIT_TLS` is set. Please use `SMTP_SECURITY` instead.");
    }
    if smtp_explicit_tls.is_some() && smtp_explicit_tls.unwrap() {
        return "force_tls".to_string();
    } else if smtp_ssl.is_some() && !smtp_ssl.unwrap() {
        return "off".to_string();
    }
    // Return the default `starttls` in all other cases
    "starttls".to_string()
}

impl Config {
    pub fn load() -> Result<Self, Error> {
        // Loading from env and file
        let _env = ConfigBuilder::from_env();
        let _usr = ConfigBuilder::from_file(&CONFIG_FILE).unwrap_or_default();

        // Create merged config, config file overwrites env
        let mut _overrides = Vec::new();
        let builder = _env.merge(&_usr, true, &mut _overrides);

        // Fill any missing with defaults
        let config = builder.build();
        if !SKIP_CONFIG_VALIDATION.load(Ordering::Relaxed) {
            validate_config(&config)?;
        }

        Ok(Config {
            inner: RwLock::new(Inner {
                rocket_shutdown_handle: None,
                templates: load_templates(&config.templates_folder),
                config,
                _env,
                _usr,
                _overrides,
            }),
        })
    }

    pub fn update_config(&self, other: ConfigBuilder) -> Result<(), Error> {
        // Remove default values
        //let builder = other.remove(&self.inner.read().unwrap()._env);

        // TODO: Remove values that are defaults, above only checks those set by env and not the defaults
        let builder = other;

        // Serialize now before we consume the builder
        let config_str = serde_json::to_string_pretty(&builder)?;

        // Prepare the combined config
        let mut overrides = Vec::new();
        let config = {
            let env = &self.inner.read().unwrap()._env;
            env.merge(&builder, false, &mut overrides).build()
        };
        validate_config(&config)?;

        // Save both the user and the combined config
        {
            let mut writer = self.inner.write().unwrap();
            writer.config = config;
            writer._usr = builder;
            writer._overrides = overrides;
        }

        //Save to file
        use std::{fs::File, io::Write};
        let mut file = File::create(&*CONFIG_FILE)?;
        file.write_all(config_str.as_bytes())?;

        Ok(())
    }

    fn update_config_partial(&self, other: ConfigBuilder) -> Result<(), Error> {
        let builder = {
            let usr = &self.inner.read().unwrap()._usr;
            let mut _overrides = Vec::new();
            usr.merge(&other, false, &mut _overrides)
        };
        self.update_config(builder)
    }

    /// Tests whether an email's domain is allowed. A domain is allowed if it
    /// is in signups_domains_whitelist, or if no whitelist is set (so there
    /// are no domain restrictions in effect).
    pub fn is_email_domain_allowed(&self, email: &str) -> bool {
        let e: Vec<&str> = email.rsplitn(2, '@').collect();
        if e.len() != 2 || e[0].is_empty() || e[1].is_empty() {
            warn!("Failed to parse email address '{}'", email);
            return false;
        }
        let email_domain = e[0].to_lowercase();
        let whitelist = self.signups_domains_whitelist();

        whitelist.is_empty() || whitelist.split(',').any(|d| d.trim() == email_domain)
    }

    /// Tests whether signup is allowed for an email address, taking into
    /// account the signups_allowed and signups_domains_whitelist settings.
    pub fn is_signup_allowed(&self, email: &str) -> bool {
        if !self.signups_domains_whitelist().is_empty() {
            // The whitelist setting overrides the signups_allowed setting.
            self.is_email_domain_allowed(email)
        } else {
            self.signups_allowed()
        }
    }

    /// Tests whether the specified user is allowed to create an organization.
    pub fn is_org_creation_allowed(&self, email: &str) -> bool {
        let users = self.org_creation_users();
        if users.is_empty() || users == "all" {
            true
        } else if users == "none" {
            false
        } else {
            let email = email.to_lowercase();
            users.split(',').any(|u| u.trim() == email)
        }
    }

    pub fn delete_user_config(&self) -> Result<(), Error> {
        std::fs::remove_file(&*CONFIG_FILE)?;

        // Empty user config
        let usr = ConfigBuilder::default();

        // Config now is env + defaults
        let config = {
            let env = &self.inner.read().unwrap()._env;
            env.build()
        };

        // Save configs
        {
            let mut writer = self.inner.write().unwrap();
            writer.config = config;
            writer._usr = usr;
            writer._overrides = Vec::new();
        }

        Ok(())
    }

    pub fn private_rsa_key(&self) -> String {
        format!("{}.pem", self.rsa_key_filename())
    }
    pub fn mail_enabled(&self) -> bool {
        let inner = &self.inner.read().unwrap().config;
        inner._enable_smtp && (inner.smtp_host.is_some() || inner.use_sendmail)
    }

    pub fn get_duo_akey(&self) -> String {
        if let Some(akey) = self._duo_akey() {
            akey
        } else {
            let akey_s = crate::crypto::encode_random_bytes::<64>(data_encoding::BASE64);

            // Save the new value
            let builder = ConfigBuilder {
                _duo_akey: Some(akey_s.clone()),
                ..Default::default()
            };
            self.update_config_partial(builder).ok();

            akey_s
        }
    }

    /// Tests whether the admin token is set to a non-empty value.
    pub fn is_admin_token_set(&self) -> bool {
        let token = self.admin_token();

        token.is_some() && !token.unwrap().trim().is_empty()
    }

    pub fn render_template<T: serde::ser::Serialize>(&self, name: &str, data: &T) -> Result<String, Error> {
        if self.reload_templates() {
            warn!("RELOADING TEMPLATES");
            let hb = load_templates(CONFIG.templates_folder());
            hb.render(name, data).map_err(Into::into)
        } else {
            let hb = &CONFIG.inner.read().unwrap().templates;
            hb.render(name, data).map_err(Into::into)
        }
    }

    pub fn set_rocket_shutdown_handle(&self, handle: rocket::Shutdown) {
        self.inner.write().unwrap().rocket_shutdown_handle = Some(handle);
    }

    pub fn shutdown(&self) {
        if let Ok(mut c) = self.inner.write() {
            if let Some(handle) = c.rocket_shutdown_handle.take() {
                handle.notify();
            }
        }
    }
}

use handlebars::{
    Context, DirectorySourceOptions, Handlebars, Helper, HelperResult, Output, RenderContext, RenderErrorReason,
    Renderable,
};

fn load_templates<P>(path: P) -> Handlebars<'static>
where
    P: AsRef<std::path::Path>,
{
    let mut hb = Handlebars::new();
    // Error on missing params
    hb.set_strict_mode(true);
    // Register helpers
    hb.register_helper("case", Box::new(case_helper));
    hb.register_helper("to_json", Box::new(to_json));

    macro_rules! reg {
        ($name:expr) => {{
            let template = include_str!(concat!("static/templates/", $name, ".hbs"));
            hb.register_template_string($name, template).unwrap();
        }};
        ($name:expr, $ext:expr) => {{
            reg!($name);
            reg!(concat!($name, $ext));
        }};
    }

    // First register default templates here
    reg!("email/email_header");
    reg!("email/email_footer");
    reg!("email/email_footer_text");

    reg!("email/admin_reset_password", ".html");
    reg!("email/change_email", ".html");
    reg!("email/delete_account", ".html");
    reg!("email/emergency_access_invite_accepted", ".html");
    reg!("email/emergency_access_invite_confirmed", ".html");
    reg!("email/emergency_access_recovery_approved", ".html");
    reg!("email/emergency_access_recovery_initiated", ".html");
    reg!("email/emergency_access_recovery_rejected", ".html");
    reg!("email/emergency_access_recovery_reminder", ".html");
    reg!("email/emergency_access_recovery_timed_out", ".html");
    reg!("email/incomplete_2fa_login", ".html");
    reg!("email/invite_accepted", ".html");
    reg!("email/invite_confirmed", ".html");
    reg!("email/new_device_logged_in", ".html");
    reg!("email/protected_action", ".html");
    reg!("email/pw_hint_none", ".html");
    reg!("email/pw_hint_some", ".html");
    reg!("email/send_2fa_removed_from_org", ".html");
    reg!("email/send_emergency_access_invite", ".html");
    reg!("email/send_org_invite", ".html");
    reg!("email/send_single_org_removed_from_org", ".html");
    reg!("email/smtp_test", ".html");
    reg!("email/twofactor_email", ".html");
    reg!("email/verify_email", ".html");
    reg!("email/welcome_must_verify", ".html");
    reg!("email/welcome", ".html");

    reg!("admin/base");
    reg!("admin/login");
    reg!("admin/settings");
    reg!("admin/users");
    reg!("admin/organizations");
    reg!("admin/diagnostics");

    reg!("404");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(path, DirectorySourceOptions::default()).unwrap();

    hb
}

fn case_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    r: &'reg Handlebars<'_>,
    ctx: &'rc Context,
    rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param =
        h.param(0).ok_or_else(|| RenderErrorReason::Other(String::from("Param not found for helper \"case\"")))?;
    let value = param.value().clone();

    if h.params().iter().skip(1).any(|x| x.value() == &value) {
        h.template().map(|t| t.render(r, ctx, rc, out)).unwrap_or_else(|| Ok(()))
    } else {
        Ok(())
    }
}

fn to_json<'reg, 'rc>(
    h: &Helper<'rc>,
    _r: &'reg Handlebars<'_>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h
        .param(0)
        .ok_or_else(|| RenderErrorReason::Other(String::from("Expected 1 parameter for \"to_json\"")))?
        .value();
    let json = serde_json::to_string(param)
        .map_err(|e| RenderErrorReason::Other(format!("Can't serialize parameter to JSON: {e}")))?;
    out.write(&json)?;
    Ok(())
}
