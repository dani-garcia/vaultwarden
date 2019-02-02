use std::process::exit;
use std::sync::RwLock;

use crate::error::Error;

lazy_static! {
    pub static ref CONFIG: Config = Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n\t{:?}\n", e);
        exit(12)
    });
    pub static ref CONFIG_PATH: String = "data/config.json".into();
}

macro_rules! make_config {
    ( $( $name:ident : $ty:ty, $editable:literal, $none_action:ident $(, $default:expr)? );+ $(;)? ) => {

        pub struct Config { inner: RwLock<Inner> }

        struct Inner {
            templates: Handlebars,
            config: ConfigItems,

            _env: ConfigBuilder,
            _usr: ConfigBuilder,
        }

        #[derive(Debug, Clone, Default, Deserialize, Serialize)]
        pub struct ConfigBuilder {
            $(
                #[serde(skip_serializing_if = "Option::is_none")]
                $name: Option<$ty>
            ),+
        }

        impl ConfigBuilder {
            fn from_env() -> Self {
                dotenv::dotenv().ok();
                use crate::util::get_env;

                let mut builder = ConfigBuilder::default();
                $(
                    builder.$name = get_env(&stringify!($name).to_uppercase());
                )+

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
                $(
                    if let v @Some(_) = &other.$name {
                        builder.$name = v.clone();
                    }
                )+
                builder
            }

            /// Returns a new builder with all the elements from self,
            /// except those that are equal in both sides
            fn remove(&self, other: &Self) -> Self {
                let mut builder = ConfigBuilder::default();
                $(
                    if &self.$name != &other.$name {
                        builder.$name = self.$name.clone();
                    }

                )+
                builder
            }

            fn build(&self) -> ConfigItems {
                let mut config = ConfigItems::default();
                let _domain_set = self.domain.is_some();
                $(
                    config.$name = make_config!{ @build self.$name.clone(), &config, $none_action, $($default)? };
                )+
                config.domain_set = _domain_set;

                config
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct ConfigItems { $(pub $name: make_config!{@type $ty, $none_action} ),+ }

        #[allow(unused)]
        impl Config {
            $(
                pub fn $name(&self) -> make_config!{@type $ty, $none_action} {
                    self.inner.read().unwrap().config.$name.clone()
                }
            )+

            pub fn load() -> Result<Self, Error> {
                // TODO: Get config.json from CONFIG_PATH env var or -c <CONFIG> console option

                // Loading from env and file
                let _env = ConfigBuilder::from_env();
                let _usr = ConfigBuilder::from_file(&CONFIG_PATH).unwrap_or_default();

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

            pub fn prepare_json(&self) -> serde_json::Value {
                let cfg = {
                    let inner = &self.inner.read().unwrap();
                    inner._env.merge(&inner._usr)
                };


                fn _get_form_type(rust_type: &str) -> &'static str {
                    match rust_type {
                        "String" => "text",
                        "bool" => "checkbox",
                        _ => "number"
                    }
                }

                json!([ $( {
                    "editable": $editable,
                    "name": stringify!($name),
                    "value": cfg.$name,
                    "default": make_config!{ @default &cfg, $none_action, $($default)? },
                    "type":  _get_form_type(stringify!($ty)),
                }, )+ ])
            }
        }
    };

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

    // Get a default value
    ( @default $config:expr, option, ) => { serde_json::Value::Null };
    ( @default $config:expr, def, $default:expr ) => { $default };
    ( @default $config:expr, auto, $default_fn:expr ) => {{
        let f: &Fn(ConfigItems) -> _ = &$default_fn;
        f($config.build())
    }};

}

//STRUCTURE: name: type, is_editable, none_action, <default_value (Optional)>
// Where none_action applied when the value wasn't provided and can be:
//  def:    Use a default value
//  auto:   Value is auto generated based on other values
//  option: Value is optional
make_config! {
    data_folder:            String, false,  def,    "data".to_string();

    database_url:           String, false,  auto,   |c| format!("{}/{}", c.data_folder, "db.sqlite3");
    icon_cache_folder:      String, false,  auto,   |c| format!("{}/{}", c.data_folder, "icon_cache");
    attachments_folder:     String, false,  auto,   |c| format!("{}/{}", c.data_folder, "attachments");
    templates_folder:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "templates");
    rsa_key_filename:       String, false,  auto,   |c| format!("{}/{}", c.data_folder, "rsa_key");

    websocket_enabled:      bool,   false,  def,    false;
    websocket_address:      String, false,  def,    "0.0.0.0".to_string();
    websocket_port:         u16,    false,  def,    3012;

    web_vault_folder:       String, false,  def,    "web-vault/".to_string();
    web_vault_enabled:      bool,   true,   def,    true;

    icon_cache_ttl:         u64,    true,   def,    2_592_000;
    icon_cache_negttl:      u64,    true,   def,    259_200;

    disable_icon_download:  bool,   true,   def,    false;
    signups_allowed:        bool,   true,   def,    true;
    invitations_allowed:    bool,   true,   def,    true;
    password_iterations:    i32,    true,   def,    100_000;
    show_password_hint:     bool,   true,   def,    true;

    domain:                 String, true,   def,    "http://localhost".to_string();
    domain_set:             bool,   false,  def,    false;

    reload_templates:       bool,   true,   def,    false;

    extended_logging:       bool,   false,  def,    true;
    log_file:               String, false,  option;

    admin_token:            String, true,   option;

    yubico_client_id:       String, true,   option;
    yubico_secret_key:      String, true,   option;
    yubico_server:          String, true,   option;

    // Mail settings
    smtp_host:              String, true,   option;
    smtp_ssl:               bool,   true,   def,     true;
    smtp_port:              u16,    true,   auto,    |c| if c.smtp_ssl {587} else {25};
    smtp_from:              String, true,   def,     String::new();
    smtp_from_name:         String, true,   def,     "Bitwarden_RS".to_string();
    smtp_username:          String, true,   option;
    smtp_password:          String, true,   option;
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
    pub fn update_config(&self, other: ConfigBuilder) -> Result<(), Error> {
        // Remove default values
        let builder = other.remove(&self.inner.read().unwrap()._env);

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
        let mut file = File::create(&*CONFIG_PATH)?;
        file.write_all(config_str.as_bytes())?;

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
