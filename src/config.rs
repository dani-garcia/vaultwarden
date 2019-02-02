use std::process::exit;
use std::sync::RwLock;

use handlebars::Handlebars;

use crate::error::Error;

lazy_static! {
    pub static ref CONFIG: Config = Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n\t{:?}\n", e);
        exit(12)
    });
    pub static ref CONFIG_PATH: String = "data/config.json".into();
}

macro_rules! make_config {
    ( $( $name:ident : $ty:ty $(, $default_fn:expr)? );+ $(;)? ) => {

        pub struct Config { inner: RwLock<Inner> }

        struct Inner {
            templates: Handlebars,
            config: ConfigItems,
        }

        #[derive(Debug, Default, Deserialize)]
        pub struct ConfigBuilder {
            $($name: Option<$ty>),+
        }

        impl ConfigBuilder {
            fn from_env() -> Self {
                dotenv::dotenv().ok();
                use crate::util::get_env;

                let mut builder = ConfigBuilder::default();
                $(
                    let $name = stringify!($name).to_uppercase();
                    builder.$name = make_config!{ @env &$name, $($default_fn)? };
                )+

                builder
            }

            fn from_file(path: &str) -> Result<Self, Error> {
                use crate::util::read_file_string;
                let config_str = read_file_string(path)?;
                serde_json::from_str(&config_str).map_err(Into::into)
            }

            fn merge(&mut self, other: Self) {
                $(
                    if let v @Some(_) = other.$name {
                        self.$name = v;
                    }
                )+
            }

            fn build(self) -> ConfigItems {
                let mut config = ConfigItems::default();
                let _domain_set = self.domain.is_some();
                $(
                    config.$name = make_config!{ @build self.$name, &config, $($default_fn)? };
                )+
                config.domain_set = _domain_set;

                config
            }
        }

        #[derive(Debug, Clone, Default, Serialize)]
        pub struct ConfigItems { $(pub $name: $ty),+ }

        paste::item! {
        #[allow(unused)]
        impl Config {
            $(
                pub fn $name(&self) -> $ty {
                    self.inner.read().unwrap().config.$name.clone()
                }
                pub fn [<set_ $name>](&self, value: $ty) {
                    self.inner.write().unwrap().config.$name = value;
                }
            )+

            pub fn load() -> Result<Self, Error> {
                // TODO: Get config.json from CONFIG_PATH env var or -c <CONFIG> console option

                // Loading from file
                let mut builder = match ConfigBuilder::from_file(&CONFIG_PATH) {
                    Ok(builder) => builder,
                    Err(_) => ConfigBuilder::default()
                };

                // Env variables overwrite config file
                builder.merge(ConfigBuilder::from_env());

                let config = builder.build();
                validate_config(&config)?;

                Ok(Config {
                    inner: RwLock::new(Inner {
                        templates: load_templates(&config.templates_folder),
                        config,
                    }),
                })
            }
        }
        }

    };

    ( @env $name:expr, $default_fn:expr ) => { get_env($name) };

    ( @env $name:expr, ) => {
        match get_env($name) {
            v @ Some(_) => Some(v),
            None => None
        }
    };

    ( @build $value:expr,$config:expr, $default_fn:expr ) => {
        match $value {
            Some(v) => v,
            None => {
                let f: &Fn(&ConfigItems) -> _ = &$default_fn;
                f($config)
            }
        }
    };

    ( @build $value:expr, $config:expr, ) => { $value.unwrap_or(None) };
}

make_config! {
    data_folder:            String, |_| "data".to_string();
    database_url:           String, |c| format!("{}/{}", c.data_folder, "db.sqlite3");
    icon_cache_folder:      String, |c| format!("{}/{}", c.data_folder, "icon_cache");
    attachments_folder:     String, |c| format!("{}/{}", c.data_folder, "attachments");
    templates_folder:       String, |c| format!("{}/{}", c.data_folder, "templates");

    rsa_key_filename:       String, |c| format!("{}/{}", c.data_folder, "rsa_key");
    private_rsa_key:        String, |c| format!("{}.der", c.rsa_key_filename);
    private_rsa_key_pem:    String, |c| format!("{}.pem", c.rsa_key_filename);
    public_rsa_key:         String, |c| format!("{}.pub.der", c.rsa_key_filename);

    websocket_enabled:      bool,   |_| false;
    websocket_address:      String, |_| "0.0.0.0".to_string();
    websocket_port:         u16,    |_| 3012;

    web_vault_folder:       String, |_| "web-vault/".to_string();
    web_vault_enabled:      bool,   |_| true;

    icon_cache_ttl:         u64,    |_| 2_592_000;
    icon_cache_negttl:      u64,    |_| 259_200;

    disable_icon_download:  bool,   |_| false;
    signups_allowed:        bool,   |_| true;
    invitations_allowed:    bool,   |_| true;
    password_iterations:    i32,    |_| 100_000;
    show_password_hint:     bool,   |_| true;

    domain:                 String, |_| "http://localhost".to_string();
    domain_set:             bool,   |_| false;

    reload_templates:       bool,   |_| false;

    extended_logging:       bool,   |_| true;
    log_file:               Option<String>;

    admin_token:            Option<String>;

    yubico_client_id:       Option<String>;
    yubico_secret_key:      Option<String>;
    yubico_server:          Option<String>;

    // Mail settings
    smtp_host:              Option<String>;
    smtp_ssl:               bool,   |_| true;
    smtp_port:              u16,    |c| if c.smtp_ssl {587} else {25};
    smtp_from:              String, |_| String::new();
    smtp_from_name:         String, |_| "Bitwarden_RS".to_string();
    smtp_username:          Option<String>;
    smtp_password:          Option<String>;
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

    Ok(())
}

impl Config {
    pub fn get_config(&self) -> String {
        let cfg = &self.inner.read().unwrap().config;
        serde_json::to_string_pretty(cfg).unwrap()
    }

    pub fn update_config(&self, other: ConfigBuilder) -> Result<(), Error> {
        let config = other.build();
        validate_config(&config)?;

        let config_str = serde_json::to_string_pretty(&config)?;

        self.inner.write().unwrap().config = config.clone();

        //Save to file
        use std::{fs::File, io::Write};
        let mut file = File::create(&*CONFIG_PATH)?;
        file.write_all(config_str.as_bytes())?;

        Ok(())
    }

    pub fn mail_enabled(&self) -> bool {
        self.inner.read().unwrap().config.smtp_host.is_some()
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

fn load_templates(path: &str) -> Handlebars {
    let mut hb = Handlebars::new();
    // Error on missing params
    hb.set_strict_mode(true);

    macro_rules! reg {
        ($name:expr) => {{
            let template = include_str!(concat!("static/templates/", $name, ".hbs"));
            hb.register_template_string($name, template).unwrap();
        }};
    }

    // First register default templates here
    reg!("email/invite_accepted");
    reg!("email/invite_confirmed");
    reg!("email/pw_hint_none");
    reg!("email/pw_hint_some");
    reg!("email/send_org_invite");

    reg!("admin/base");
    reg!("admin/login");
    reg!("admin/page");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(".hbs", path).unwrap();

    hb
}
