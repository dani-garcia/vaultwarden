use std::process::exit;
use std::sync::RwLock;

use handlebars::Handlebars;

lazy_static! {
    pub static ref CONFIG: Config = Config::load();
}

macro_rules! make_config {
    ( $( $name:ident: $ty:ty ),+ $(,)* ) => {

        pub struct Config { inner: RwLock<_Config> }

        #[derive(Default)]
        struct _Config {
            _templates: Handlebars,
           $(pub $name: $ty),+
        }

        paste::item! {
            #[allow(unused)]
            impl Config {
                $(
                    pub fn $name(&self) -> $ty {
                        self.inner.read().unwrap().$name.clone()
                    }
                    pub fn [<set_ $name>](&self, value: $ty) {
                        self.inner.write().unwrap().$name = value;
                    }
                )+
            }
        }

    };
}

make_config! {
    database_url: String,
    icon_cache_folder: String,
    attachments_folder: String,

    icon_cache_ttl: u64,
    icon_cache_negttl: u64,

    private_rsa_key: String,
    private_rsa_key_pem: String,
    public_rsa_key: String,

    web_vault_folder: String,
    web_vault_enabled: bool,

    websocket_enabled: bool,
    websocket_url: String,

    extended_logging: bool,
    log_file: Option<String>,

    disable_icon_download: bool,
    signups_allowed: bool,
    invitations_allowed: bool,
    admin_token: Option<String>,
    password_iterations: i32,
    show_password_hint: bool,

    domain: String,
    domain_set: bool,

    yubico_cred_set: bool,
    yubico_client_id: String,
    yubico_secret_key: String,
    yubico_server: Option<String>,

    mail: Option<MailConfig>,
    templates_folder: String,
    reload_templates: bool,
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

impl Config {
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
            let hb = &CONFIG.inner.read().unwrap()._templates;
            hb.render(name, data).map_err(Into::into)
        }
    }

    fn load() -> Self {
        use crate::util::{get_env, get_env_or};
        #[cfg(debug_assertions)] {
            dotenv::dotenv().ok();
        }

        let df = get_env_or("DATA_FOLDER", "data".to_string());
        let key = get_env_or("RSA_KEY_FILENAME", format!("{}/{}", &df, "rsa_key"));

        let domain = get_env("DOMAIN");

        let yubico_client_id = get_env("YUBICO_CLIENT_ID");
        let yubico_secret_key = get_env("YUBICO_SECRET_KEY");

        let templates_folder = get_env_or("TEMPLATES_FOLDER", format!("{}/{}", &df, "templates"));

        let cfg = _Config {
            database_url: get_env_or("DATABASE_URL", format!("{}/{}", &df, "db.sqlite3")),
            icon_cache_folder: get_env_or("ICON_CACHE_FOLDER", format!("{}/{}", &df, "icon_cache")),
            attachments_folder: get_env_or("ATTACHMENTS_FOLDER", format!("{}/{}", &df, "attachments")),
            _templates: load_templates(&templates_folder),
            templates_folder,
            reload_templates: get_env_or("RELOAD_TEMPLATES", false),

            // icon_cache_ttl defaults to 30 days (30 * 24 * 60 * 60 seconds)
            icon_cache_ttl: get_env_or("ICON_CACHE_TTL", 2_592_000),
            // icon_cache_negttl defaults to 3 days (3 * 24 * 60 * 60 seconds)
            icon_cache_negttl: get_env_or("ICON_CACHE_NEGTTL", 259_200),

            private_rsa_key: format!("{}.der", &key),
            private_rsa_key_pem: format!("{}.pem", &key),
            public_rsa_key: format!("{}.pub.der", &key),

            web_vault_folder: get_env_or("WEB_VAULT_FOLDER", "web-vault/".into()),
            web_vault_enabled: get_env_or("WEB_VAULT_ENABLED", true),

            websocket_enabled: get_env_or("WEBSOCKET_ENABLED", false),
            websocket_url: format!(
                "{}:{}",
                get_env_or("WEBSOCKET_ADDRESS", "0.0.0.0".to_string()),
                get_env_or("WEBSOCKET_PORT", 3012)
            ),

            extended_logging: get_env_or("EXTENDED_LOGGING", true),
            log_file: get_env("LOG_FILE"),

            disable_icon_download: get_env_or("DISABLE_ICON_DOWNLOAD", false),
            signups_allowed: get_env_or("SIGNUPS_ALLOWED", true),
            admin_token: get_env("ADMIN_TOKEN"),
            invitations_allowed: get_env_or("INVITATIONS_ALLOWED", true),
            password_iterations: get_env_or("PASSWORD_ITERATIONS", 100_000),
            show_password_hint: get_env_or("SHOW_PASSWORD_HINT", true),

            domain_set: domain.is_some(),
            domain: domain.unwrap_or("http://localhost".into()),

            yubico_cred_set: yubico_client_id.is_some() && yubico_secret_key.is_some(),
            yubico_client_id: yubico_client_id.unwrap_or("00000".into()),
            yubico_secret_key: yubico_secret_key.unwrap_or("AAAAAAA".into()),
            yubico_server: get_env("YUBICO_SERVER"),

            mail: MailConfig::load(),
        };

        Config {
            inner: RwLock::new(cfg),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_ssl: bool,
    pub smtp_from: String,
    pub smtp_from_name: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
}

impl MailConfig {
    fn load() -> Option<Self> {
        use crate::util::{get_env, get_env_or};

        // When SMTP_HOST is absent, we assume the user does not want to enable it.
        let smtp_host = match get_env("SMTP_HOST") {
            Some(host) => host,
            None => return None,
        };

        let smtp_from = get_env("SMTP_FROM").unwrap_or_else(|| {
            error!("Please specify SMTP_FROM to enable SMTP support.");
            exit(1);
        });

        let smtp_from_name = get_env_or("SMTP_FROM_NAME", "Bitwarden_RS".into());

        let smtp_ssl = get_env_or("SMTP_SSL", true);
        let smtp_port = get_env("SMTP_PORT").unwrap_or_else(|| if smtp_ssl { 587u16 } else { 25u16 });

        let smtp_username = get_env("SMTP_USERNAME");
        let smtp_password = get_env("SMTP_PASSWORD").or_else(|| {
            if smtp_username.as_ref().is_some() {
                error!("SMTP_PASSWORD is mandatory when specifying SMTP_USERNAME.");
                exit(1);
            } else {
                None
            }
        });

        Some(MailConfig {
            smtp_host,
            smtp_port,
            smtp_ssl,
            smtp_from,
            smtp_from_name,
            smtp_username,
            smtp_password,
        })
    }
}
