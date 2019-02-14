use std::process::exit;
use std::sync::RwLock;

use crate::error::Error;
use crate::util::get_env;

lazy_static! {
    pub static ref CONFIG: Config = Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n\t{:?}\n", e);
        exit(12)
    });
    pub static ref CONFIG_FILE: String = get_env("CONFIG_FILE").unwrap_or_else(|| "data/config.json".into());
}

pub type Pass = String;

macro_rules! make_config {
    ($(
        $(#[doc = $groupdoc:literal])?
        $group:ident $(: $group_enabled:ident)? {
        $(
            $(#[doc = $doc:literal])+
            $name:ident : $ty:ty, $editable:literal, $none_action:ident $(, $default:expr)?;
        )+},
    )+) => {
        pub struct Config { inner: RwLock<Inner> }

        struct Inner {
            templates: Handlebars,
            config: ConfigItems,

            _env: ConfigBuilder,
            _usr: ConfigBuilder,
        }

        #[derive(Debug, Clone, Default, Deserialize, Serialize)]
        pub struct ConfigBuilder {
            $($(
                #[serde(skip_serializing_if = "Option::is_none")]
                $name: Option<$ty>,
            )+)+
        }

        impl ConfigBuilder {
            fn from_env() -> Self {
                dotenv::from_path(".env").ok();

                let mut builder = ConfigBuilder::default();
                $($(
                    builder.$name = get_env(&stringify!($name).to_uppercase());
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
            fn merge(&self, other: &Self) -> Self {
                let mut builder = self.clone();
                $($(
                    if let v @Some(_) = &other.$name {
                        builder.$name = v.clone();
                    }
                )+)+
                builder
            }

            /// Returns a new builder with all the elements from self,
            /// except those that are equal in both sides
            fn _remove(&self, other: &Self) -> Self {
                let mut builder = ConfigBuilder::default();
                $($(
                    if &self.$name != &other.$name {
                        builder.$name = self.$name.clone();
                    }

                )+)+
                builder
            }

            fn build(&self) -> ConfigItems {
                let mut config = ConfigItems::default();
                let _domain_set = self.domain.is_some();
                $($(
                    config.$name = make_config!{ @build self.$name.clone(), &config, $none_action, $($default)? };
                )+)+
                config.domain_set = _domain_set;

                config
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct ConfigItems { $($(pub $name: make_config!{@type $ty, $none_action}, )+)+ }

        #[allow(unused)]
        impl Config {
            $($(
                pub fn $name(&self) -> make_config!{@type $ty, $none_action} {
                    self.inner.read().unwrap().config.$name.clone()
                }
            )+)+

            pub fn prepare_json(&self) -> serde_json::Value {
                let (def, cfg) = {
                    let inner = &self.inner.read().unwrap();
                    (inner._env.build(), inner.config.clone())
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
                    json!({
                        "name": split.next(),
                        "description": split.next()
                    })
                }

                json!([ $({
                    "group": stringify!($group),
                    "grouptoggle": stringify!($($group_enabled)?),
                    "groupdoc": make_config!{ @show $($groupdoc)? },
                    "elements": [
                    $( {
                        "editable": $editable,
                        "name": stringify!($name),
                        "value": cfg.$name,
                        "default": def.$name,
                        "type":  _get_form_type(stringify!($ty)),
                        "doc": _get_doc(concat!($($doc),+)),
                    }, )+
                    ]}, )+ ])
            }
        }
    };

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
                let f: &Fn(&ConfigItems) -> _ = &$default_fn;
                f($config)
            }
        }
    }};
}

//STRUCTURE:
// /// Short description (without this they won't appear on the list)
// group {
//   /// Friendly Name |> Description (Optional)
//   name: type, is_editable, none_action, <default_value (Optional)>
// }
//
// Where none_action applied when the value wasn't provided and can be:
//  def:    Use a default value
//  auto:   Value is auto generated based on other values
//  option: Value is optional
make_config! {
    folders {
        ///  Data folder |> Main data folder
        data_folder:            String, false,  def,    "data".to_string();

        /// Database URL
        database_url:           String, false,  auto,   |c| format!("{}/{}", c.data_folder, "db.sqlite3");
        /// Icon chache folder
        icon_cache_folder:      String, false,  auto,   |c| format!("{}/{}", c.data_folder, "icon_cache");
        /// Attachments folder
        attachments_folder:     String, false,  auto,   |c| format!("{}/{}", c.data_folder, "attachments");
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

    /// General settings
    settings {
        /// Domain URL |> This needs to be set to the URL used to access the server, including 'http[s]://' and port, if it's different than the default. Some server functions don't work correctly without this value
        domain:                 String, true,   def,    "http://localhost".to_string();
        /// PRIVATE |> Domain set
        domain_set:             bool,   false,  def,    false;
        /// Enable web vault
        web_vault_enabled:      bool,   false,  def,    true;

        /// Disable icon downloads |> Set to true to disable icon downloading, this would still serve icons from $ICON_CACHE_FOLDER,
        /// but it won't produce any external network request. Needs to set $ICON_CACHE_TTL to 0,
        /// otherwise it will delete them and they won't be downloaded again.
        disable_icon_download:  bool,   true,   def,    false;
        /// Allow new signups |> Controls if new users can register. Note that while this is disabled, users could still be invited
        signups_allowed:        bool,   true,   def,    true;
        /// Allow invitations |> Controls whether users can be invited by organization admins, even when signups are disabled
        invitations_allowed:    bool,   true,   def,    true;
        /// Password iterations |> Number of server-side passwords hashing iterations. The changes only apply when a user changes their password. Not recommended to lower the value
        password_iterations:    i32,    true,   def,    100_000;
        /// Show password hints |> Controls if the password hint should be shown directly in the web page. Otherwise, if email is disabled, there is no way to see the password hint
        show_password_hint:     bool,   true,   def,    true;

        /// Admin page token |> The token used to authenticate in this very same page. Changing it here won't deauthorize the current session
        admin_token:            Pass,   true,   option;
    },

    /// Advanced settings
    advanced {
        /// Positive icon cache expiry |> Number of seconds to consider that an already cached icon is fresh. After this period, the icon will be redownloaded
        icon_cache_ttl:         u64,    true,   def,    2_592_000;
        /// Negative icon cache expiry |> Number of seconds before trying to download an icon that failed again.
        icon_cache_negttl:      u64,    true,   def,    259_200;
        /// Icon download timeout |> Number of seconds when to stop attempting to download an icon.
        icon_download_timeout:  u64,   true,   def,    10;

        /// Reload templates (Dev) |> When this is set to true, the templates get reloaded with every request. ONLY use this during development, as it can slow down the server
        reload_templates:       bool,   true,   def,    false;

        /// Log routes at launch (Dev)
        log_mounts:             bool,   true,   def,    false;
        /// Enable extended logging
        extended_logging:       bool,   false,  def,    true;
        /// Log file path
        log_file:               String, false,  option;
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

    /// SMTP Email Settings
    smtp: _enable_smtp {
        /// Enabled
        _enable_smtp:           bool,   true,   def,     true;
        /// Host
        smtp_host:              String, true,   option;
        /// Enable SSL
        smtp_ssl:               bool,   true,   def,     true;
        /// Port
        smtp_port:              u16,    true,   auto,    |c| if c.smtp_ssl {587} else {25};
        /// From Address
        smtp_from:              String, true,   def,     String::new();
        /// From Name
        smtp_from_name:         String, true,   def,     "Bitwarden_RS".to_string();
        /// Username
        smtp_username:          String, true,   option;
        /// Password
        smtp_password:          Pass,   true,   option;
    },

    /// LDAP settings
    ldap: _enable_ldap {
        /// Enabled
        _enable_ldap:           bool,   true,   def,     true;
        /// Host
        ldap_host:              String, true,   option;
        /// Enable SSL
        ldap_ssl:               bool,   true,   def,     false;
        /// Port
        ldap_port:              u16,    true,   auto,    |c| if c.ldap_ssl {636} else {389};
        /// Bind dn
        ldap_bind_dn:           String, true,   option;
        /// Bind password
        ldap_bind_password:     Pass,   true,   option;
        /// Search base dn
        ldap_search_base_dn:    String, true,   option;
        /// Search filter
        ldap_search_filter:     String, true,   def,     "(&(objectClass=*)(uid=*))".to_string();
        /// Email field
        ldap_mail_field:        String, true,   def,     "mail".to_string();
    },
}

fn validate_config(cfg: &ConfigItems) -> Result<(), Error> {
    if cfg.yubico_client_id.is_some() != cfg.yubico_secret_key.is_some() {
        err!("Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` need to be set for Yubikey OTP support")
    }

    if cfg.smtp_host.is_some() == cfg.smtp_from.is_empty() {
        err!("Both `SMTP_HOST` and `SMTP_FROM` need to be set for email support")
    }

    if cfg.smtp_username.is_some() != cfg.smtp_password.is_some() {
        err!("Both `SMTP_USERNAME` and `SMTP_PASSWORD` need to be set to enable email authentication")
    }

    if cfg.ldap_bind_dn.is_some() != cfg.ldap_bind_password.is_some() {
        err!("Both `LDAP_BIND_DN` and `LDAP_BIND_PASSWORD` need to be set to enable ldap authentication")
    }

    Ok(())
}

impl Config {
    pub fn load() -> Result<Self, Error> {
        // Loading from env and file
        let _env = ConfigBuilder::from_env();
        let _usr = ConfigBuilder::from_file(&CONFIG_FILE).unwrap_or_default();

        // Create merged config, config file overwrites env
        let builder = _env.merge(&_usr);

        // Fill any missing with defaults
        let config = builder.build();
        validate_config(&config)?;

        Ok(Config {
            inner: RwLock::new(Inner {
                templates: load_templates(&config.templates_folder),
                config,
                _env,
                _usr,
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
        let config = {
            let env = &self.inner.read().unwrap()._env;
            env.merge(&builder).build()
        };
        validate_config(&config)?;

        // Save both the user and the combined config
        {
            let mut writer = self.inner.write().unwrap();
            writer.config = config;
            writer._usr = builder;
        }

        //Save to file
        use std::{fs::File, io::Write};
        let mut file = File::create(&*CONFIG_FILE)?;
        file.write_all(config_str.as_bytes())?;

        Ok(())
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
        }

        Ok(())
    }

    pub fn private_rsa_key(&self) -> String {
        format!("{}.der", CONFIG.rsa_key_filename())
    }
    pub fn private_rsa_key_pem(&self) -> String {
        format!("{}.pem", CONFIG.rsa_key_filename())
    }
    pub fn public_rsa_key(&self) -> String {
        format!("{}.pub.der", CONFIG.rsa_key_filename())
    }
    pub fn mail_enabled(&self) -> bool {
        let inner = &self.inner.read().unwrap().config;
        inner._enable_smtp && inner.smtp_host.is_some()
    }
    pub fn yubico_enabled(&self) -> bool {
        let inner = &self.inner.read().unwrap().config;
        inner._enable_yubico && inner.yubico_client_id.is_some() && inner.yubico_secret_key.is_some()
    }
    pub fn ldap_enabled(&self) -> bool {
        let inner = &self.inner.read().unwrap().config;
        inner._enable_ldap && inner.ldap_host.is_some() && inner.ldap_search_base_dn.is_some()
    }

    pub fn render_template<T: serde::ser::Serialize>(
        &self,
        name: &str,
        data: &T,
    ) -> Result<String, crate::error::Error> {
        if CONFIG.reload_templates() {
            warn!("RELOADING TEMPLATES");
            let hb = load_templates(CONFIG.templates_folder().as_ref());
            hb.render(name, data).map_err(Into::into)
        } else {
            let hb = &CONFIG.inner.read().unwrap().templates;
            hb.render(name, data).map_err(Into::into)
        }
    }
}

use handlebars::{
    Context, Handlebars, Helper, HelperDef, HelperResult, Output, RenderContext, RenderError, Renderable,
};

fn load_templates(path: &str) -> Handlebars {
    let mut hb = Handlebars::new();
    // Error on missing params
    hb.set_strict_mode(true);
    hb.register_helper("case", Box::new(CaseHelper));

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
    reg!("email/invite_accepted", ".html");
    reg!("email/invite_confirmed", ".html");
    reg!("email/pw_hint_none", ".html");
    reg!("email/pw_hint_some", ".html");
    reg!("email/send_org_invite", ".html");

    reg!("admin/base");
    reg!("admin/login");
    reg!("admin/page");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(".hbs", path).unwrap();

    hb
}

#[derive(Clone, Copy)]
pub struct CaseHelper;

impl HelperDef for CaseHelper {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'reg, 'rc>,
        r: &'reg Handlebars,
        ctx: &Context,
        rc: &mut RenderContext<'reg>,
        out: &mut Output,
    ) -> HelperResult {
        let param = h
            .param(0)
            .ok_or_else(|| RenderError::new("Param not found for helper \"case\""))?;
        let value = param.value().clone();

        if h.params().iter().skip(1).any(|x| x.value() == &value) {
            h.template().map(|t| t.render(r, ctx, rc, out)).unwrap_or(Ok(()))
        } else {
            Ok(())
        }
    }
}
