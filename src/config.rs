use std::process::exit;
use std::sync::RwLock;

use handlebars::Handlebars;

use crate::error::Error;
use crate::util::IntoResult;

lazy_static! {
    pub static ref CONFIG: Config = Config::load().unwrap_or_else(|e| {
        println!("Error loading config:\n\t{:?}\n", e);
        exit(12)
    });
}

macro_rules! make_config {
    ( $( $name:ident : $ty:ty $(, $default_fn:expr)? );+ $(;)* ) => {

        pub struct Config { inner: RwLock<Inner> }

        struct Inner {
            templates: Handlebars,
            config: _Config,
        }

        #[derive(Debug, Default, Serialize, Deserialize)]
        struct _Config { $(pub $name: $ty),+ }

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
                use crate::util::get_env;
                dotenv::dotenv().ok();

                let mut config = _Config::default();

                $(
                    config.$name = make_config!{ @expr &stringify!($name).to_uppercase(), $ty, &config, $($default_fn)? };
                )+

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

    ( @expr $name:expr, $ty:ty, $config:expr, $default_fn:expr ) => {{
        match get_env($name) {
            Some(v) => v,
            None => {
                let f: &Fn(&_Config) -> _ = &$default_fn;
                f($config).into_result()?
            }
        }
    }};

    ( @expr $name:expr, $ty:ty, $config:expr, ) => {
        get_env($name)
    };
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
    smtp_from:              String, |c| if c.smtp_host.is_some() { err!("Please specify SMTP_FROM to enable SMTP support") } else { Ok(String::new() )};
    smtp_from_name:         String, |_| "Bitwarden_RS".to_string();
    smtp_username:          Option<String>;
    smtp_password:          Option<String>;
}

impl Config {
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
