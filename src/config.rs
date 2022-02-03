use std::process::exit;
use std::sync::RwLock;

use once_cell::sync::Lazy;
use reqwest::Url;

use crate::{
    db::DbConnType,
    error::Error,
    util::{get_env, get_env_bool},
};

static CONFIG_FILE: Lazy<String> = Lazy::new(|| {
    let data_folder = get_env("DATA_FOLDER").unwrap_or_else(|| String::from("data"));
    get_env("CONFIG_FILE").unwrap_or_else(|| format!("{}/config.json", data_folder))
});

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n\t{:?}\n", e);
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
                match dotenv::from_path(".env") {
                    Ok(_) => (),
                    Err(e) => match e {
                        dotenv::Error::LineParse(msg, pos) => {
                            panic!("Error loading the .env file:\nNear {:?} on position {}\nPlease fix and restart!\n", msg, pos);
                        },
                        dotenv::Error::Io(ioerr) => match ioerr.kind() {
                            std::io::ErrorKind::NotFound => {
                                println!("[INFO] No .env file found.\n");
                            },
                            std::io::ErrorKind::PermissionDenied => {
                                println!("[WARNING] Permission Denied while trying to read the .env file!\n");
                            },
                            _ => {
                                println!("[WARNING] Reading the .env file failed:\n{:?}\n", ioerr);
                            }
                        },
                        _ => {
                            println!("[WARNING] Reading the .env file failed:\n{:?}\n", e);
                        }
                    }
                };

                let mut builder = ConfigBuilder::default();
                $($(
                    builder.$name = make_config! { @getenv &stringify!($name).to_uppercase(), $ty };
                )+)+

                builder
            }

            fn from_file(path: &str) -> Result<Self, Error> {
                use crate::util::read_file_string;
                let config_str = read_file_string(path)?;
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
                            overrides.push(stringify!($name).to_uppercase());
                        }
                    }
                )+)+

                if show_overrides && !overrides.is_empty() {
                    // We can't use warn! here because logging isn't setup yet.
                    println!("[WARNING] The following environment variables are being overriden by the config file,");
                    println!("[WARNING] please use the admin panel to make changes to them:");
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

                config.signups_domains_whitelist = config.signups_domains_whitelist.trim().to_lowercase();
                config.org_creation_users = config.org_creation_users.trim().to_lowercase();

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
                let (def, cfg, overriden) = {
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
                                element.insert("overridden".into(), (overriden.contains(&stringify!($name).to_uppercase())).into());
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
                    value.chars().map(|c|
                        match c {
                            c if c.is_alphanumeric() => '*',
                            '_' => '*',
                            '-' => '*',
                            _ => c
                        }
                    ).collect::<String>()
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
    ( @build $value:expr, $config:expr, gen, $default_fn:expr ) => {{
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
//  def:    Use a default value
//  auto:   Value is auto generated based on other values
//  option: Value is optional
//  gen:    Value is always autogenerated and it's original value ignored
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
        /// Templates folder
        templates_folder:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "templates");
        /// Session JWT key
        rsa_key_filename:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "rsa_key");
        /// Web vault folder
        web_vault_folder:       String, false,  def,    "web-vault/".to_string();
    },
    ws {
        /// Enable websocket notifications
        websocket_enabled:      bool,   false,  def,    false;
        /// Websocket address
        websocket_address:      String, false,  def,    "0.0.0.0".to_string();
        /// Websocket port
        websocket_port:         u16,    false,  def,    3012;
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
        /// Defaults to hourly. Set blank to disable this job.
        emergency_notification_reminder_schedule:   String, false,  def,    "0 5 * * * *".to_string();
        /// Emergency request timeout schedule |> Cron schedule of the job that grants emergency access requests that have met the required wait time.
        /// Defaults to hourly. Set blank to disable this job.
        emergency_request_timeout_schedule:   String, false,  def,    "0 5 * * * *".to_string();
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
        signups_domains_whitelist: String, true, def,   "".to_string();
        /// Org creation users |> Allow org creation only by this list of comma-separated user emails.
        /// Blank or 'all' means all users can create orgs; 'none' means no users can create orgs.
        org_creation_users:     String, true,   def,    "".to_string();
        /// Allow invitations |> Controls whether users can be invited by organization admins, even when signups are otherwise disabled
        invitations_allowed:    bool,   true,   def,    true;
        /// Allow emergency access |> Controls whether users can enable emergency access to their accounts. This setting applies globally to all users.
        emergency_access_allowed:    bool,   true,   def,    true;
        /// Password iterations |> Number of server-side passwords hashing iterations.
        /// The changes only apply when a user changes their password. Not recommended to lower the value
        password_iterations:    i32,    true,   def,    100_000;
        /// Show password hint |> Controls whether a password hint should be shown directly in the web page
        /// if SMTP service is not configured. Not recommended for publicly-accessible instances as this
        /// provides unauthenticated access to potentially sensitive data.
        show_password_hint:     bool,   true,   def,    false;

        /// Admin page token |> The token used to authenticate in this very same page. Changing it here won't deauthorize the current session
        admin_token:            Pass,   true,   option;

        /// Invitation organization name |> Name shown in the invitation emails that don't come from a specific organization
        invitation_org_name:    String, true,   def,    "Vaultwarden".to_string();
    },

    /// Advanced settings
    advanced {
        /// Client IP header |> If not present, the remote IP is used.
        /// Set to the string "none" (without quotes), to disable any headers and just use the remote IP
        ip_header:              String, true,   def,    "X-Real-IP".to_string();
        /// Internal IP header property, used to avoid recomputing each time
        _ip_header_enabled:     bool,   false,  gen,    |c| &c.ip_header.trim().to_lowercase() != "none";
        /// Icon service |> The predefined icon services are: internal, bitwarden, duckduckgo, google.
        /// To specify a custom icon service, set a URL template with exactly one instance of `{}`,
        /// which is replaced with the domain. For example: `https://icon.example.com/domain/{}`.
        /// `internal` refers to Vaultwarden's built-in icon fetching implementation. If an external
        /// service is set, an icon request to Vaultwarden will return an HTTP redirect to the
        /// corresponding icon at the external service.
        icon_service:           String, false,  def,    "internal".to_string();
        /// Icon redirect code |> The HTTP status code to use for redirects to an external icon service.
        /// The supported codes are 301 (legacy permanent), 302 (legacy temporary), 307 (temporary), and 308 (permanent).
        /// Temporary redirects are useful while testing different icon services, but once a service
        /// has been decided on, consider using permanent redirects for cacheability. The legacy codes
        /// are currently better supported by the Bitwarden clients.
        icon_redirect_code:     u32,    true,   def,    302;
        /// Positive icon cache expiry |> Number of seconds to consider that an already cached icon is fresh. After this period, the icon will be redownloaded
        icon_cache_ttl:         u64,    true,   def,    2_592_000;
        /// Negative icon cache expiry |> Number of seconds before trying to download an icon that failed again.
        icon_cache_negttl:      u64,    true,   def,    259_200;
        /// Icon download timeout |> Number of seconds when to stop attempting to download an icon.
        icon_download_timeout:  u64,    true,   def,    10;
        /// Icon blacklist Regex |> Any domains or IPs that match this regex won't be fetched by the icon service.
        /// Useful to hide other servers in the local network. Check the WIKI for more details
        icon_blacklist_regex:   String, true,   option;
        /// Icon blacklist non global IPs |> Any IP which is not defined as a global IP will be blacklisted.
        /// Usefull to secure your internal environment: See https://en.wikipedia.org/wiki/Reserved_IP_addresses for a list of IPs which it will block
        icon_blacklist_non_global_ips:  bool,   true,   def,    true;

        /// Disable Two-Factor remember |> Enabling this would force the users to use a second factor to login every time.
        /// Note that the checkbox would still be present, but ignored.
        disable_2fa_remember:   bool,   true,   def,    false;

        /// Disable authenticator time drifted codes to be valid |> Enabling this only allows the current TOTP code to be valid
        /// TOTP codes of the previous and next 30 seconds will be invalid.
        authenticator_disable_time_drift: bool, true, def, false;

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
        /// Log level
        log_level:              String, false,  def,    "Info".to_string();

        /// Enable DB WAL |> Turning this off might lead to worse performance, but might help if using vaultwarden on some exotic filesystems,
        /// that do not support WAL. Please make sure you read project wiki on the topic before changing this setting.
        enable_db_wal:          bool,   false,  def,    true;

        /// Max database connection retries |> Number of times to retry the database connection during startup, with 1 second between each retry, set to 0 to retry indefinitely
        db_connection_retries:  u32,    false,  def,    15;

        /// Database connection pool size
        database_max_conns:     u32,    false,  def,    10;

        /// Bypass admin page security (Know the risks!) |> Disables the Admin Token for the admin page so you may use your own auth in-front
        disable_admin_token:    bool,   true,   def,    false;

        /// Allowed iframe ancestors (Know the risks!) |> Allows other domains to embed the web vault into an iframe, useful for embedding into secure intranets
        allowed_iframe_ancestors: String, true, def,    String::new();

        /// Seconds between login requests |> Number of seconds, on average, between login and 2FA requests from the same IP address before rate limiting kicks in
        login_ratelimit_seconds:       u64, false, def, 60;
        /// Max burst size for login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `login_ratelimit_seconds`. Note that this applies to both the login and the 2FA, so it's recommended to allow a burst size of at least 2
        login_ratelimit_max_burst:     u32, false, def, 10;

        /// Seconds between admin requests |> Number of seconds, on average, between admin requests from the same IP address before rate limiting kicks in
        admin_ratelimit_seconds:       u64, false, def, 300;
        /// Max burst size for login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `admin_ratelimit_seconds`
        admin_ratelimit_max_burst:     u32, false, def, 3;
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
        _enable_duo:            bool,   true,   def,     false;
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
        /// Host
        smtp_host:                     String, true,   option;
        /// Enable Secure SMTP |> (Explicit) - Enabling this by default would use STARTTLS (Standard ports 587 or 25)
        smtp_ssl:                      bool,   true,   def,     true;
        /// Force TLS |> (Implicit) - Enabling this would force the use of an SSL/TLS connection, instead of upgrading an insecure one with STARTTLS (Standard port 465)
        smtp_explicit_tls:             bool,   true,   def,     false;
        /// Port
        smtp_port:                     u16,    true,   auto,    |c| if c.smtp_explicit_tls {465} else if c.smtp_ssl {587} else {25};
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
        _enable_email_2fa:      bool,   true,   auto,    |c| c._enable_smtp && c.smtp_host.is_some();
        /// Email token size |> Number of digits in an email 2FA token (min: 6, max: 255). Note that the Bitwarden clients are hardcoded to mention 6 digit codes regardless of this setting.
        email_token_size:       u8,     true,   def,      6;
        /// Token expiration time |> Maximum time in seconds a token is valid. The time the user has to open email client and copy token.
        email_expiration_time:  u64,    true,   def,      600;
        /// Maximum attempts |> Maximum attempts before an email token is reset and a new email will need to be sent
        email_attempts_limit:   u64,    true,   def,      3;
    },
}

fn validate_config(cfg: &ConfigItems) -> Result<(), Error> {
    // Validate connection URL is valid and DB feature is enabled
    DbConnType::from_url(&cfg.database_url)?;

    let limit = 256;
    if cfg.database_max_conns < 1 || cfg.database_max_conns > limit {
        err!(format!("`DATABASE_MAX_CONNS` contains an invalid value. Ensure it is between 1 and {}.", limit,));
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

    if cfg._enable_duo
        && (cfg.duo_host.is_some() || cfg.duo_ikey.is_some() || cfg.duo_skey.is_some())
        && !(cfg.duo_host.is_some() && cfg.duo_ikey.is_some() && cfg.duo_skey.is_some())
    {
        err!("All Duo options need to be set for global Duo support")
    }

    if cfg._enable_yubico && cfg.yubico_client_id.is_some() != cfg.yubico_secret_key.is_some() {
        err!("Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` need to be set for Yubikey OTP support")
    }

    if cfg._enable_smtp {
        if cfg.smtp_host.is_some() == cfg.smtp_from.is_empty() {
            err!("Both `SMTP_HOST` and `SMTP_FROM` need to be set for email support")
        }

        if cfg.smtp_host.is_some() && !cfg.smtp_from.contains('@') {
            err!("SMTP_FROM does not contain a mandatory @ sign")
        }

        if cfg.smtp_username.is_some() != cfg.smtp_password.is_some() {
            err!("Both `SMTP_USERNAME` and `SMTP_PASSWORD` need to be set to enable email authentication")
        }

        if cfg._enable_email_2fa && (!cfg._enable_smtp || cfg.smtp_host.is_none()) {
            err!("To enable email 2FA, SMTP must be configured")
        }

        if cfg._enable_email_2fa && cfg.email_token_size < 6 {
            err!("`EMAIL_TOKEN_SIZE` has a minimum size of 6")
        }
    }

    // Check if the icon blacklist regex is valid
    if let Some(ref r) = cfg.icon_blacklist_regex {
        let validate_regex = regex::Regex::new(r);
        match validate_regex {
            Ok(_) => (),
            Err(e) => err!(format!("`ICON_BLACKLIST_REGEX` is invalid: {:#?}", e)),
        }
    }

    // Check if the icon service is valid
    let icon_service = cfg.icon_service.as_str();
    match icon_service {
        "internal" | "bitwarden" | "duckduckgo" | "google" => (),
        _ => {
            if !icon_service.starts_with("http") {
                err!(format!("Icon service URL `{}` must start with \"http\"", icon_service))
            }
            match icon_service.matches("{}").count() {
                1 => (), // nominal
                0 => err!(format!("Icon service URL `{}` has no placeholder \"{{}}\"", icon_service)),
                _ => err!(format!("Icon service URL `{}` has more than one placeholder \"{{}}\"", icon_service)),
            }
        }
    }

    // Check if the icon redirect code is valid
    match cfg.icon_redirect_code {
        301 | 302 | 307 | 308 => (),
        _ => err!("Only HTTP 301/302 and 307/308 redirects are supported"),
    }

    Ok(())
}

/// Extracts an RFC 6454 web origin from a URL.
fn extract_url_origin(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(e) => {
            println!("Error validating domain: {}", e);
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
        validate_config(&config)?;

        Ok(Config {
            inner: RwLock::new(Inner {
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
        crate::util::delete_file(&CONFIG_FILE)?;

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
        format!("{}.pem", CONFIG.rsa_key_filename())
    }
    pub fn public_rsa_key(&self) -> String {
        format!("{}.pub.pem", CONFIG.rsa_key_filename())
    }
    pub fn mail_enabled(&self) -> bool {
        let inner = &self.inner.read().unwrap().config;
        inner._enable_smtp && inner.smtp_host.is_some()
    }

    pub fn get_duo_akey(&self) -> String {
        if let Some(akey) = self._duo_akey() {
            akey
        } else {
            let akey = crate::crypto::get_random_64();
            let akey_s = data_encoding::BASE64.encode(&akey);

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

    pub fn render_template<T: serde::ser::Serialize>(
        &self,
        name: &str,
        data: &T,
    ) -> Result<String, crate::error::Error> {
        if CONFIG.reload_templates() {
            warn!("RELOADING TEMPLATES");
            let hb = load_templates(CONFIG.templates_folder());
            hb.render(name, data).map_err(Into::into)
        } else {
            let hb = &CONFIG.inner.read().unwrap().templates;
            hb.render(name, data).map_err(Into::into)
        }
    }
}

use handlebars::{Context, Handlebars, Helper, HelperResult, Output, RenderContext, RenderError, Renderable};

fn load_templates<P>(path: P) -> Handlebars<'static>
where
    P: AsRef<std::path::Path>,
{
    let mut hb = Handlebars::new();
    // Error on missing params
    hb.set_strict_mode(true);
    // Register helpers
    hb.register_helper("case", Box::new(case_helper));
    hb.register_helper("jsesc", Box::new(js_escape_helper));

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
    reg!("email/pw_hint_none", ".html");
    reg!("email/pw_hint_some", ".html");
    reg!("email/send_2fa_removed_from_org", ".html");
    reg!("email/send_single_org_removed_from_org", ".html");
    reg!("email/send_org_invite", ".html");
    reg!("email/send_emergency_access_invite", ".html");
    reg!("email/twofactor_email", ".html");
    reg!("email/verify_email", ".html");
    reg!("email/welcome", ".html");
    reg!("email/welcome_must_verify", ".html");
    reg!("email/smtp_test", ".html");

    reg!("admin/base");
    reg!("admin/login");
    reg!("admin/settings");
    reg!("admin/users");
    reg!("admin/organizations");
    reg!("admin/diagnostics");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(".hbs", path).unwrap();

    hb
}

fn case_helper<'reg, 'rc>(
    h: &Helper<'reg, 'rc>,
    r: &'reg Handlebars,
    ctx: &'rc Context,
    rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderError::new("Param not found for helper \"case\""))?;
    let value = param.value().clone();

    if h.params().iter().skip(1).any(|x| x.value() == &value) {
        h.template().map(|t| t.render(r, ctx, rc, out)).unwrap_or(Ok(()))
    } else {
        Ok(())
    }
}

fn js_escape_helper<'reg, 'rc>(
    h: &Helper<'reg, 'rc>,
    _r: &'reg Handlebars,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderError::new("Param not found for helper \"js_escape\""))?;

    let no_quote = h.param(1).is_some();

    let value =
        param.value().as_str().ok_or_else(|| RenderError::new("Param for helper \"js_escape\" is not a String"))?;

    let mut escaped_value = value.replace('\\', "").replace('\'', "\\x22").replace('\"', "\\x27");
    if !no_quote {
        escaped_value = format!("&quot;{}&quot;", escaped_value);
    }

    out.write(&escaped_value)?;
    Ok(())
}
