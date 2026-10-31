use std::{collections::HashMap, fs, path::Path, sync::LazyLock};

use include_dir::{Dir, include_dir};

use crate::{CONFIG, storage};

type LocaleMap = HashMap<String, String>;
type LocaleCatalog = HashMap<String, LocaleMap>;

static LOCALE_CATALOG: LazyLock<LocaleCatalog> = LazyLock::new(load_locale_catalog);
static BUILTIN_LOCALE_CATALOG: LazyLock<LocaleCatalog> = LazyLock::new(load_builtin_catalog);
static BUILTIN_LOCALES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/static/locales");

fn key_is_locale_scoped(key: &str) -> bool {
    key.starts_with("admin.") || key.starts_with("tpl.")
}

fn lookup_en<'a>(catalog: &'a LocaleCatalog, key: &str) -> Option<&'a str> {
    catalog.get("en").and_then(|m| m.get(key)).map(String::as_str)
}

pub fn normalize_locale(raw: &str) -> String {
    let normalized = raw.trim().replace('_', "-").to_ascii_lowercase();
    if normalized.is_empty() {
        "en".to_owned()
    } else {
        normalized
    }
}

pub fn locale_candidates(default_locale: &str) -> Vec<String> {
    let locale = normalize_locale(default_locale);

    let mut candidates = vec![locale.clone()];
    if let Some((lang, _)) = locale.split_once('-')
        && !lang.is_empty()
        && !candidates.iter().any(|x| x == lang)
    {
        candidates.push(lang.to_owned());
    }

    if !candidates.iter().any(|x| x == "en") {
        candidates.push("en".to_owned());
    }

    candidates
}

pub fn preferred_from_accept_language(raw: &str) -> Option<String> {
    let first = raw.split(',').next()?.trim();
    let locale = first.split(';').next()?.trim();
    if locale.is_empty() || locale == "*" {
        None
    } else {
        Some(normalize_locale(locale))
    }
}

pub fn resolve_locale(user_locale: Option<&str>, accept_language: Option<&str>, default_locale: &str) -> String {
    if let Some(locale) = user_locale.map(normalize_locale).filter(|l| !l.is_empty()) {
        return locale;
    }

    if let Some(raw_accept) = accept_language
        && let Some(locale) = preferred_from_accept_language(raw_accept)
    {
        return locale;
    }

    normalize_locale(default_locale)
}

pub fn to_client_culture(locale: &str) -> String {
    let normalized = normalize_locale(locale);
    if let Some((lang, region)) = normalized.split_once('-') {
        format!("{}-{}", lang, region.to_ascii_uppercase())
    } else {
        normalized
    }
}

pub fn is_russian(locale: &str) -> bool {
    locale_candidates(locale).iter().any(|c| c == "ru")
}

fn parse_locale_map(raw: &str) -> LocaleMap {
    serde_json::from_str(raw).unwrap_or_default()
}

fn merge_locale_map(target: &mut LocaleMap, raw: &str) {
    target.extend(parse_locale_map(raw));
}

fn load_locale_file(path: &Path) -> Option<LocaleMap> {
    let content = fs::read_to_string(path).ok()?;
    Some(parse_locale_map(&content))
}

fn load_locale_dir(path: &Path) -> Option<LocaleMap> {
    let mut files = fs::read_dir(path).ok()?.flatten().map(|e| e.path()).collect::<Vec<_>>();
    files.sort();

    let mut merged = LocaleMap::new();
    let mut found_json = false;

    for file in files {
        if file.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        if let Some(loaded) = load_locale_file(&file) {
            found_json = true;
            merged.extend(loaded);
        }
    }

    found_json.then_some(merged)
}

fn load_builtin_catalog() -> LocaleCatalog {
    let mut catalog = LocaleCatalog::new();

    let mut locale_dirs = BUILTIN_LOCALES_DIR.dirs().collect::<Vec<_>>();
    locale_dirs.sort_by_key(|dir| dir.path().to_string_lossy().to_string());

    for locale_dir in locale_dirs {
        let Some(locale_name) = locale_dir.path().file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let mut files = locale_dir.files().collect::<Vec<_>>();
        files.sort_by_key(|file| file.path().to_string_lossy().to_string());

        let mut merged = LocaleMap::new();
        let mut found_json = false;

        for file in files {
            if file.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            if let Some(raw) = file.contents_utf8() {
                found_json = true;
                merge_locale_map(&mut merged, raw);
            }
        }

        if found_json {
            catalog.insert(normalize_locale(locale_name), merged);
        }
    }

    catalog
}

fn load_runtime_catalog_extensions(catalog: &mut LocaleCatalog) {
    let locales_dir = storage::join_path(&CONFIG.data_folder(), "locales");
    let Ok(entries) = fs::read_dir(&locales_dir) else {
        return;
    };

    let mut paths = entries.flatten().map(|e| e.path()).collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        if path.is_dir() {
            let Some(locale_name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };

            let locale = normalize_locale(locale_name);
            if let Some(loaded) = load_locale_dir(&path) {
                catalog.entry(locale).or_default().extend(loaded);
            }
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };

        let locale = normalize_locale(stem);
        if let Some(loaded) = load_locale_file(&path) {
            catalog.entry(locale).or_default().extend(loaded);
        }
    }
}

fn load_locale_catalog() -> LocaleCatalog {
    // Built-ins define the baseline fallback catalogs bundled with the binary.
    let mut catalog = load_builtin_catalog();

    // Runtime catalogs can be provided either as DATA_FOLDER/locales/<locale>.json
    // or as modular files under DATA_FOLDER/locales/<locale>/*.json.
    // Runtime values extend or override built-ins and allow adding new languages.
    load_runtime_catalog_extensions(&mut catalog);

    catalog
}

fn tr(locale: &str, key: &str, en_fallback: &'static str, ru_fallback: &'static str) -> &'static str {
    if !key_is_locale_scoped(key) {
        return lookup_en(&LOCALE_CATALOG, key).unwrap_or(en_fallback);
    }

    for candidate in locale_candidates(locale) {
        if let Some(value) = LOCALE_CATALOG.get(&candidate).and_then(|m| m.get(key)) {
            return value.as_str();
        }
    }

    if is_russian(locale) {
        ru_fallback
    } else {
        en_fallback
    }
}

pub fn tr_lookup(locale: &str, key: &str) -> Option<&'static str> {
    for candidate in locale_candidates(locale) {
        if let Some(value) = LOCALE_CATALOG.get(&candidate).and_then(|m| m.get(key)) {
            return Some(value.as_str());
        }
    }

    None
}

fn tr_builtin(locale: &str, key: &str, en_fallback: &'static str, ru_fallback: &'static str) -> &'static str {
    if !key_is_locale_scoped(key) {
        return lookup_en(&BUILTIN_LOCALE_CATALOG, key).unwrap_or(en_fallback);
    }

    for candidate in locale_candidates(locale) {
        if let Some(value) = BUILTIN_LOCALE_CATALOG.get(&candidate).and_then(|m| m.get(key)) {
            return value.as_str();
        }
    }

    if is_russian(locale) {
        ru_fallback
    } else {
        en_fallback
    }
}

macro_rules! localized_msg {
    ($fn_name:ident, $key:literal, $en:literal, $ru:literal) => {
        pub fn $fn_name(locale: &str) -> &'static str {
            tr(locale, $key, $en, $ru)
        }
    };
}

macro_rules! localized_msg_bootstrap {
    ($fn_name:ident, $key:literal, $en:literal, $ru:literal) => {
        pub fn $fn_name(locale: &str) -> &'static str {
            tr_builtin(locale, $key, $en, $ru)
        }
    };
}

localized_msg!(
    api_not_found_description,
    "api.not_found_description",
    "The requested resource could not be found.",
    "Запрошенный ресурс не найден."
);
localized_msg!(
    admin_login_too_many_requests,
    "admin.login_too_many_requests",
    "Too many requests, try again later.",
    "Слишком много запросов, повторите позже."
);
localized_msg!(
    admin_login_invalid_token,
    "admin.login_invalid_token",
    "Invalid admin token, please try again.",
    "Неверный токен администратора, попробуйте снова."
);
localized_msg!(admin_mail_not_enabled, "admin.mail_not_enabled", "Mail is not enabled", "Почта не включена");
localized_msg!(
    admin_cannot_change_last_owner_type,
    "admin.cannot_change_last_owner_type",
    "Can't change the type of the last owner",
    "Нельзя изменить тип последнего владельца"
);
localized_msg!(
    admin_backup_only_sqlite,
    "admin.backup_only_sqlite",
    "Can't back up current DB (Only SQLite supports this feature)",
    "Нельзя сделать резервную копию текущей БД (только SQLite поддерживает эту функцию)"
);
localized_msg!(
    admin_unable_save_config,
    "admin.unable_save_config",
    "Unable to save config",
    "Не удалось сохранить конфигурацию"
);
localized_msg!(
    admin_unable_delete_config,
    "admin.unable_delete_config",
    "Unable to delete config",
    "Не удалось удалить конфигурацию"
);
localized_msg!(
    admin_backup_unsuccessful,
    "admin.backup_unsuccessful",
    "Backup was unsuccessful",
    "Резервное копирование завершилось неудачей"
);
localized_msg!(authorization_failed, "auth.authorization_failed", "Authorization failed.", "Ошибка авторизации.");
localized_msg!(identity_sso_required, "identity.sso_required", "SSO sign-in is required", "Требуется вход через SSO.");
localized_msg!(
    identity_sso_unavailable,
    "identity.sso_unavailable",
    "SSO sign-in is not available",
    "Вход через SSO недоступен."
);
localized_msg!(identity_invalid_type, "identity.invalid_type", "Invalid type", "Некорректный тип.");
localized_msg!(
    identity_unsupported_code_challenge_method,
    "identity.unsupported_code_challenge_method",
    "Unsupported code challenge method",
    "Неподдерживаемый метод code challenge"
);
localized_msg!(
    identity_cannot_retrieve_sso_auth,
    "identity.cannot_retrieve_sso_auth",
    "Cannot retrieve sso_auth",
    "Не удалось получить sso_auth"
);
localized_msg!(
    identity_sso_session_binding_mismatch,
    "identity.sso_session_binding_mismatch",
    "SSO session binding mismatch",
    "Несоответствие привязки SSO-сессии"
);
localized_msg!(
    identity_failed_parse_redirect_uri,
    "identity.failed_parse_redirect_uri",
    "Failed to parse redirect uri",
    "Не удалось разобрать redirect uri"
);
localized_msg!(
    auth_invalid_username_or_password,
    "auth.invalid_username_or_password",
    "Username or password is incorrect. Try again",
    "Неверные имя пользователя или пароль. Попробуйте еще раз."
);
localized_msg!(
    auth_invalid_username_or_access_code,
    "auth.invalid_username_or_access_code",
    "Username or access code is incorrect. Try again",
    "Неверные имя пользователя или код доступа. Попробуйте еще раз."
);
localized_msg!(auth_user_disabled, "auth.user_disabled", "This user has been disabled", "Пользователь отключен");
localized_msg!(
    auth_verify_email_before_login,
    "auth.verify_email_before_login",
    "Please verify your email before trying again.",
    "Подтвердите email, прежде чем пытаться снова."
);
localized_msg!(
    auth_scope_not_supported,
    "auth.scope_not_supported",
    "Scope not supported",
    "Область действия не поддерживается"
);
localized_msg!(auth_malformed_client_id, "auth.malformed_client_id", "Malformed client_id", "Некорректный client_id");
localized_msg!(auth_invalid_client_id, "auth.invalid_client_id", "Invalid client_id", "Некорректный client_id");
localized_msg!(
    auth_incorrect_client_secret,
    "auth.incorrect_client_secret",
    "Incorrect client_secret",
    "Некорректный client_secret"
);
localized_msg!(
    auth_no_2fa_providers,
    "auth.no_2fa_providers",
    "No enabled and usable two factor providers are available for this account",
    "Для этой учетной записи нет включенных и доступных провайдеров двухфакторной аутентификации"
);
localized_msg!(
    auth_invalid_twofactor_provider,
    "auth.invalid_twofactor_provider",
    "Invalid two factor provider",
    "Некорректный провайдер двухфакторной аутентификации"
);
localized_msg!(
    auth_two_step_token_invalid,
    "auth.two_step_token_invalid",
    "Two-step token is invalid. Try again.",
    "Некорректный токен двухфакторной аутентификации. Попробуйте еще раз."
);
localized_msg!(
    auth_no_yubikey_devices,
    "auth.no_yubikey_devices",
    "No YubiKey devices registered",
    "Устройства YubiKey не зарегистрированы"
);
localized_msg!(
    auth_no_twofactor_email,
    "auth.no_twofactor_email",
    "No twofactor email registered",
    "Двухфакторная аутентификация по email не настроена"
);
localized_msg!(auth_invalid_password, "auth.invalid_password", "Invalid password", "Неверный пароль");
localized_msg!(
    auth_private_rsa_key_init_once,
    "auth.private_rsa_key_init_once",
    "PRIVATE_RSA_KEY must only be initialized once",
    "PRIVATE_RSA_KEY должен инициализироваться только один раз"
);
localized_msg!(
    auth_public_rsa_key_init_once,
    "auth.public_rsa_key_init_once",
    "PUBLIC_RSA_KEY must only be initialized once",
    "PUBLIC_RSA_KEY должен инициализироваться только один раз"
);
localized_msg!(
    auth_prelogin_kdf_key_init_once,
    "auth.prelogin_kdf_key_init_once",
    "PRELOGIN_KDF_KEY must only be initialized once",
    "PRELOGIN_KDF_KEY должен инициализироваться только один раз"
);
localized_msg!(auth_error_decoding_jwt, "auth.error_decoding_jwt", "Error decoding JWT", "Ошибка декодирования JWT");
localized_msg!(auth_token_invalid, "auth.token_invalid", "Token is invalid", "Токен некорректен");
localized_msg!(auth_issuer_invalid, "auth.issuer_invalid", "Issuer is invalid", "Издатель некорректен");
localized_msg!(auth_token_expired, "auth.token_expired", "Token has expired", "Срок действия токена истек");
localized_msg!(
    auth_invite_expire_delta_calculation_failed,
    "auth.invite_expire_delta_calculation_failed",
    "Unable to calculate time delta for invite expire hours. Check `INVITATION_EXPIRATION_HOURS`.",
    "Не удалось вычислить интервал для срока приглашения. Проверьте `INVITATION_EXPIRATION_HOURS`."
);
localized_msg!(
    auth_invite_expire_date_calculation_failed,
    "auth.invite_expire_date_calculation_failed",
    "Unable to calculate invitation expire date. Check `INVITATION_EXPIRATION_HOURS`.",
    "Не удалось вычислить дату истечения приглашения. Проверьте `INVITATION_EXPIRATION_HOURS`."
);
localized_msg!(
    auth_admin_session_delta_calculation_failed,
    "auth.admin_session_delta_calculation_failed",
    "Unable to calculate time delta for admin session lifetime. Check `ADMIN_SESSION_LIFETIME`.",
    "Не удалось вычислить интервал времени жизни сессии администратора. Проверьте `ADMIN_SESSION_LIFETIME`."
);
localized_msg!(
    auth_admin_session_lifetime_calculation_failed,
    "auth.admin_session_lifetime_calculation_failed",
    "Unable to calculate admin session lifetime. Check `ADMIN_SESSION_LIFETIME`.",
    "Не удалось вычислить время жизни сессии администратора. Проверьте `ADMIN_SESSION_LIFETIME`."
);
localized_msg!(
    auth_collection_id_malformed,
    "auth.collection_id_malformed",
    "Collection Id is malformed!",
    "ID коллекции имеет неверный формат!"
);
localized_msg!(
    auth_collection_not_found_or_not_manager,
    "auth.collection_not_found_or_not_manager",
    "Collection not found",
    "Коллекция не найдена"
);
localized_msg!(
    auth_user_not_manager_for_collection,
    "auth.user_not_manager_for_collection",
    "The current user isn't a manager for this collection",
    "Текущий пользователь не является менеджером этой коллекции"
);
localized_msg!(auth_missing_scope, "auth.missing_scope", "Missing scope", "Отсутствует scope");
localized_msg!(
    auth_invalid_refresh_token,
    "auth.invalid_refresh_token",
    "Invalid refresh token",
    "Некорректный refresh токен"
);
localized_msg!(
    auth_impossible_find_user,
    "auth.impossible_find_user",
    "Impossible to find user",
    "Невозможно найти пользователя"
);
localized_msg!(
    auth_sso_now_disabled_login_password,
    "auth.sso_now_disabled_login_password",
    "SSO is now disabled, Login again using email and master password",
    "SSO отключен, войдите снова через email и мастер-пароль"
);
localized_msg!(
    auth_sso_now_required_login_again,
    "auth.sso_now_required_login_again",
    "SSO is now required, Login again",
    "Теперь требуется SSO, войдите снова"
);
localized_msg!(
    auth_invalid_auth_method_refresh,
    "auth.invalid_auth_method_refresh",
    "Invalid auth method, cannot refresh token",
    "Некорректный метод аутентификации, невозможно обновить токен"
);
localized_msg!(
    auth_failed_discover_token_url,
    "auth.failed_discover_token_url",
    "Failed to discover token_url, cannot proceed",
    "Не удалось обнаружить token_url, невозможно продолжить"
);
localized_msg!(
    auth_failed_discover_user_info_url,
    "auth.failed_discover_user_info_url",
    "Failed to discover user_info url, cannot proceed",
    "Не удалось обнаружить user_info url, невозможно продолжить"
);
localized_msg!(
    auth_pkce_client_challenge_failed,
    "auth.pkce_client_challenge_failed",
    "PKCE client challenge failed",
    "Проверка PKCE challenge клиента не удалась"
);
localized_msg!(
    auth_token_response_missing_id_token,
    "auth.token_response_missing_id_token",
    "Token response did not contain an id_token",
    "Ответ токена не содержит id_token"
);
localized_msg!(
    auth_invalid_code_cannot_retrieve_sso_auth,
    "auth.invalid_code_cannot_retrieve_sso_auth",
    "Invalid code cannot retrieve sso auth",
    "Некорректный код: не удалось получить sso auth"
);
localized_msg!(
    auth_missing_authorization_provider_return,
    "auth.missing_authorization_provider_return",
    "Missing authorization provider return",
    "Отсутствует ответ от провайдера авторизации"
);
localized_msg!(
    auth_neither_id_token_nor_userinfo_email,
    "auth.neither_id_token_nor_userinfo_email",
    "Neither id token nor userinfo contained an email",
    "Ни id token, ни userinfo не содержат email"
);
localized_msg!(
    auth_non_jwt_access_token_empty_expires_in,
    "auth.non_jwt_access_token_empty_expires_in",
    "Non jwt access_token and empty expires_in",
    "Не-JWT access_token и пустой expires_in"
);
localized_msg!(
    auth_no_token_present_while_sso,
    "auth.no_token_present_while_sso",
    "No token present while in SSO",
    "Во время SSO отсутствует токен"
);
localized_msg!(
    auth_invalid_utf8_after_base64_decode,
    "auth.invalid_utf8_after_base64_decode",
    "Invalid utf8 chars after base64 decoding",
    "Некорректные utf8-символы после декодирования base64"
);
localized_msg!(
    auth_failed_decode_using_base64,
    "auth.failed_decode_using_base64",
    "Failed to decode using base64",
    "Не удалось декодировать с использованием base64"
);
localized_msg!(
    auth_unsupported_redirect_uri,
    "auth.unsupported_redirect_uri",
    "Unsupported redirect uri",
    "Неподдерживаемый redirect uri"
);
localized_msg!(auth_unsupported_client, "auth.unsupported_client", "Unsupported client", "Неподдерживаемый клиент");
localized_msg!(
    auth_failed_build_http_client,
    "auth.failed_build_http_client",
    "Failed to build http client",
    "Не удалось создать HTTP-клиент"
);
localized_msg!(
    auth_failed_discover_openid_provider,
    "auth.failed_discover_openid_provider",
    "Failed to discover OpenID provider",
    "Не удалось обнаружить OpenID-провайдера"
);
localized_msg!(
    auth_no_supported_auth_methods,
    "auth.no_supported_auth_methods",
    "No supported auth_methods (only basic or request body)",
    "Нет поддерживаемых auth_methods (только basic или request body)"
);
localized_msg!(
    auth_failed_contact_token_endpoint,
    "auth.failed_contact_token_endpoint",
    "Failed to contact token endpoint",
    "Не удалось обратиться к token endpoint"
);
localized_msg!(
    auth_could_not_read_id_token_claims,
    "auth.could_not_read_id_token_claims",
    "Could not read id_token claims",
    "Не удалось прочитать claims id_token"
);
localized_msg!(
    auth_request_user_info_endpoint_failed,
    "auth.request_user_info_endpoint_failed",
    "Request to user_info endpoint failed",
    "Запрос к user_info endpoint завершился ошибкой"
);
localized_msg_bootstrap!(
    config_password_iterations_min,
    "config.password_iterations_min",
    "PASSWORD_ITERATIONS should be at least 100000 or higher. The default is 600000!",
    "PASSWORD_ITERATIONS должен быть не менее 100000. Значение по умолчанию 600000!"
);
#[cfg(sqlite)]
localized_msg_bootstrap!(
    config_sqlite_database_directory_invalid,
    "config.sqlite_database_directory_invalid",
    "SQLite database directory does not exist or is not a directory",
    "Каталог базы данных SQLite не существует или не является каталогом"
);
localized_msg_bootstrap!(
    config_ip_header_trusted_proxies_invalid_entry,
    "config.ip_header_trusted_proxies_invalid_entry",
    "Invalid IP_HEADER_TRUSTED_PROXIES entry, expected an IP or CIDR range",
    "Некорректная запись IP_HEADER_TRUSTED_PROXIES, ожидается IP или диапазон CIDR"
);
localized_msg_bootstrap!(
    config_database_max_conns_invalid_range,
    "config.database_max_conns_invalid_range",
    "`DATABASE_MAX_CONNS` contains an invalid value. Ensure it is between 1 and 256.",
    "`DATABASE_MAX_CONNS` содержит некорректное значение. Убедитесь, что оно находится в диапазоне от 1 до 256."
);
localized_msg_bootstrap!(
    config_database_min_conns_invalid_range,
    "config.database_min_conns_invalid_range",
    "`DATABASE_MIN_CONNS` contains an invalid value. Ensure it is between 1 and 256.",
    "`DATABASE_MIN_CONNS` содержит некорректное значение. Убедитесь, что оно находится в диапазоне от 1 до 256."
);
localized_msg_bootstrap!(
    config_database_min_conns_lte_max,
    "config.database_min_conns_lte_max",
    "`DATABASE_MIN_CONNS` must be less than or equal to `DATABASE_MAX_CONNS`.",
    "`DATABASE_MIN_CONNS` должен быть меньше или равен `DATABASE_MAX_CONNS`."
);
localized_msg_bootstrap!(
    config_database_timeout_min_1,
    "config.database_timeout_min_1",
    "`DATABASE_TIMEOUT` must be at least 1 second",
    "`DATABASE_TIMEOUT` должен быть не менее 1 секунды"
);
localized_msg_bootstrap!(
    config_database_idle_timeout_min_1,
    "config.database_idle_timeout_min_1",
    "`DATABASE_IDLE_TIMEOUT` must be at least 1 second",
    "`DATABASE_IDLE_TIMEOUT` должен быть не менее 1 секунды"
);
localized_msg_bootstrap!(
    config_unable_write_log_file,
    "config.unable_write_log_file",
    "Unable to write to log file",
    "Не удалось записать в лог-файл"
);
localized_msg_bootstrap!(
    config_signups_domains_whitelist_empty_tokens,
    "config.signups_domains_whitelist_empty_tokens",
    "`SIGNUPS_DOMAINS_WHITELIST` contains empty tokens",
    "`SIGNUPS_DOMAINS_WHITELIST` содержит пустые токены"
);
localized_msg_bootstrap!(
    config_org_creation_users_invalid_emails,
    "config.org_creation_users_invalid_emails",
    "`ORG_CREATION_USERS` contains invalid email addresses",
    "`ORG_CREATION_USERS` содержит некорректные email-адреса"
);
localized_msg_bootstrap!(
    config_push_relay_uri_must_be_https,
    "config.push_relay_uri_must_be_https",
    "`PUSH_RELAY_URI` must start with 'https://'.",
    "`PUSH_RELAY_URI` должен начинаться с 'https://'."
);
localized_msg_bootstrap!(
    config_push_relay_uri_invalid_url,
    "config.push_relay_uri_invalid_url",
    "Invalid URL format for `PUSH_RELAY_URI`.",
    "Неверный формат URL для `PUSH_RELAY_URI`."
);
localized_msg_bootstrap!(
    config_push_identity_uri_must_be_https,
    "config.push_identity_uri_must_be_https",
    "`PUSH_IDENTITY_URI` must start with 'https://'.",
    "`PUSH_IDENTITY_URI` должен начинаться с 'https://'."
);
localized_msg_bootstrap!(
    config_push_identity_uri_invalid_url,
    "config.push_identity_uri_invalid_url",
    "Invalid URL format for `PUSH_IDENTITY_URI`.",
    "Неверный формат URL для `PUSH_IDENTITY_URI`."
);
localized_msg_bootstrap!(
    config_user_attachment_limit_out_of_bounds,
    "config.user_attachment_limit_out_of_bounds",
    "`USER_ATTACHMENT_LIMIT` is out of bounds",
    "`USER_ATTACHMENT_LIMIT` вне допустимых границ"
);
localized_msg_bootstrap!(
    config_org_attachment_limit_out_of_bounds,
    "config.org_attachment_limit_out_of_bounds",
    "`ORG_ATTACHMENT_LIMIT` is out of bounds",
    "`ORG_ATTACHMENT_LIMIT` вне допустимых границ"
);
localized_msg_bootstrap!(
    config_user_send_limit_out_of_bounds,
    "config.user_send_limit_out_of_bounds",
    "`USER_SEND_LIMIT` is out of bounds",
    "`USER_SEND_LIMIT` вне допустимых границ"
);
localized_msg_bootstrap!(
    config_duo_all_options_required,
    "config.duo_all_options_required",
    "All Duo options need to be set for global Duo support",
    "Для глобальной поддержки Duo должны быть заданы все параметры Duo"
);
localized_msg_bootstrap!(
    config_sso_required_options_missing,
    "config.sso_required_options_missing",
    "`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET` and `SSO_AUTHORITY` must be set for SSO support",
    "Для поддержки SSO должны быть заданы `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET` и `SSO_AUTHORITY`"
);
localized_msg_bootstrap!(
    config_yubico_both_credentials_required,
    "config.yubico_both_credentials_required",
    "Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` must be set for Yubikey OTP support",
    "Для поддержки Yubikey OTP должны быть заданы и `YUBICO_CLIENT_ID`, и `YUBICO_SECRET_KEY`"
);
localized_msg_bootstrap!(
    config_smtp_host_and_from_required,
    "config.smtp_host_and_from_required",
    "Both `SMTP_HOST` and `SMTP_FROM` need to be set for email support without `USE_SENDMAIL`",
    "Для поддержки email без `USE_SENDMAIL` должны быть заданы `SMTP_HOST` и `SMTP_FROM`"
);
localized_msg_bootstrap!(
    config_sendmail_command_not_found_in_path,
    "config.sendmail_command_not_found_in_path",
    "sendmail command was not found in $PATH",
    "Команда sendmail не найдена в $PATH"
);
localized_msg_bootstrap!(
    config_sendmail_command_not_found_at_path,
    "config.sendmail_command_not_found_at_path",
    "sendmail command was not found at the configured path",
    "Команда sendmail не найдена по указанному пути"
);
localized_msg_bootstrap!(
    config_sendmail_command_access_failed,
    "config.sendmail_command_access_failed",
    "failed to access sendmail command",
    "Не удалось получить доступ к команде sendmail"
);
localized_msg_bootstrap!(
    config_sendmail_command_is_directory,
    "config.sendmail_command_is_directory",
    "sendmail command path points to a directory",
    "Путь команды sendmail указывает на каталог"
);
localized_msg_bootstrap!(
    config_sendmail_command_not_executable,
    "config.sendmail_command_not_executable",
    "sendmail command is not executable",
    "Команда sendmail не является исполняемой"
);
localized_msg_bootstrap!(
    config_smtp_from_invalid_email,
    "config.smtp_from_invalid_email",
    "SMTP_FROM is not a valid email address",
    "SMTP_FROM не является корректным email-адресом"
);
localized_msg_bootstrap!(
    config_email_token_size_min_6,
    "config.email_token_size_min_6",
    "`EMAIL_TOKEN_SIZE` has a minimum size of 6",
    "`EMAIL_TOKEN_SIZE` должен быть не меньше 6"
);
localized_msg_bootstrap!(
    config_email_2fa_requires_mail_transport,
    "config.email_2fa_requires_mail_transport",
    "To enable email 2FA, a mail transport must be configured",
    "Для включения email 2FA должен быть настроен почтовый транспорт"
);
localized_msg_bootstrap!(
    config_email_2fa_verified_invite_requires_enable,
    "config.email_2fa_verified_invite_requires_enable",
    "To enforce email 2FA on verified invitations, email 2fa has to be enabled!",
    "Чтобы принудить email 2FA для подтвержденных приглашений, email 2fa должен быть включен!"
);
localized_msg_bootstrap!(
    config_email_2fa_fallback_requires_enable,
    "config.email_2fa_fallback_requires_enable",
    "To use email 2FA as automatic fallback, email 2fa has to be enabled!",
    "Чтобы использовать email 2FA как автоматический fallback, email 2fa должен быть включен!"
);
localized_msg_bootstrap!(
    config_http_request_block_regex_invalid,
    "config.http_request_block_regex_invalid",
    "`HTTP_REQUEST_BLOCK_REGEX` is invalid",
    "`HTTP_REQUEST_BLOCK_REGEX` некорректен"
);
localized_msg_bootstrap!(
    config_icon_service_url_must_start_http,
    "config.icon_service_url_must_start_http",
    "Icon service URL must start with \"http\"",
    "URL сервиса иконок должен начинаться с \"http\""
);
localized_msg_bootstrap!(
    config_icon_service_url_missing_placeholder,
    "config.icon_service_url_missing_placeholder",
    "Icon service URL has no placeholder \"{{}}\"",
    "URL сервиса иконок не содержит плейсхолдера \"{{}}\""
);
localized_msg_bootstrap!(
    config_icon_service_url_multiple_placeholders,
    "config.icon_service_url_multiple_placeholders",
    "Icon service URL has more than one placeholder \"{{}}\"",
    "URL сервиса иконок содержит более одного плейсхолдера \"{{}}\""
);
localized_msg_bootstrap!(
    config_icon_redirect_supported_codes,
    "config.icon_redirect_supported_codes",
    "Only HTTP 301/302 and 307/308 redirects are supported",
    "Поддерживаются только HTTP редиректы 301/302 и 307/308"
);
localized_msg_bootstrap!(
    config_invitation_expiration_hours_min_1,
    "config.invitation_expiration_hours_min_1",
    "`INVITATION_EXPIRATION_HOURS` has a minimum duration of 1 hour",
    "`INVITATION_EXPIRATION_HOURS` должен быть не менее 1 часа"
);
localized_msg_bootstrap!(
    config_send_purge_schedule_invalid,
    "config.send_purge_schedule_invalid",
    "`SEND_PURGE_SCHEDULE` is not a valid cron expression",
    "`SEND_PURGE_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_trash_purge_schedule_invalid,
    "config.trash_purge_schedule_invalid",
    "`TRASH_PURGE_SCHEDULE` is not a valid cron expression",
    "`TRASH_PURGE_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_incomplete_2fa_schedule_invalid,
    "config.incomplete_2fa_schedule_invalid",
    "`INCOMPLETE_2FA_SCHEDULE` is not a valid cron expression",
    "`INCOMPLETE_2FA_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_emergency_notification_reminder_schedule_invalid,
    "config.emergency_notification_reminder_schedule_invalid",
    "`EMERGENCY_NOTIFICATION_REMINDER_SCHEDULE` is not a valid cron expression",
    "`EMERGENCY_NOTIFICATION_REMINDER_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_emergency_request_timeout_schedule_invalid,
    "config.emergency_request_timeout_schedule_invalid",
    "`EMERGENCY_REQUEST_TIMEOUT_SCHEDULE` is not a valid cron expression",
    "`EMERGENCY_REQUEST_TIMEOUT_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_event_cleanup_schedule_invalid,
    "config.event_cleanup_schedule_invalid",
    "`EVENT_CLEANUP_SCHEDULE` is not a valid cron expression",
    "`EVENT_CLEANUP_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_auth_request_purge_schedule_invalid,
    "config.auth_request_purge_schedule_invalid",
    "`AUTH_REQUEST_PURGE_SCHEDULE` is not a valid cron expression",
    "`AUTH_REQUEST_PURGE_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_duo_context_purge_schedule_invalid,
    "config.duo_context_purge_schedule_invalid",
    "`DUO_CONTEXT_PURGE_SCHEDULE` is not a valid cron expression",
    "`DUO_CONTEXT_PURGE_SCHEDULE` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_purge_incomplete_sso_auth_invalid,
    "config.purge_incomplete_sso_auth_invalid",
    "`PURGE_INCOMPLETE_SSO_AUTH` is not a valid cron expression",
    "`PURGE_INCOMPLETE_SSO_AUTH` содержит некорректное cron-выражение"
);
localized_msg_bootstrap!(
    config_login_ratelimit_seconds_min_1,
    "config.login_ratelimit_seconds_min_1",
    "`LOGIN_RATELIMIT_SECONDS` must be at least 1 second",
    "`LOGIN_RATELIMIT_SECONDS` должен быть не менее 1 секунды"
);
localized_msg_bootstrap!(
    config_login_ratelimit_max_burst_min_1,
    "config.login_ratelimit_max_burst_min_1",
    "`LOGIN_RATELIMIT_MAX_BURST` must be at least 1",
    "`LOGIN_RATELIMIT_MAX_BURST` должен быть не менее 1"
);
localized_msg_bootstrap!(
    config_admin_ratelimit_seconds_min_1,
    "config.admin_ratelimit_seconds_min_1",
    "`ADMIN_RATELIMIT_SECONDS` must be at least 1 second",
    "`ADMIN_RATELIMIT_SECONDS` должен быть не менее 1 секунды"
);
localized_msg_bootstrap!(
    config_admin_ratelimit_max_burst_min_1,
    "config.admin_ratelimit_max_burst_min_1",
    "`ADMIN_RATELIMIT_MAX_BURST` must be at least 1",
    "`ADMIN_RATELIMIT_MAX_BURST` должен быть не менее 1"
);
localized_msg_bootstrap!(
    config_unauthenticated_ratelimit_seconds_min_1,
    "config.unauthenticated_ratelimit_seconds_min_1",
    "`UNAUTHENTICATED_RATELIMIT_SECONDS` must be at least 1 second",
    "`UNAUTHENTICATED_RATELIMIT_SECONDS` должен быть не менее 1 секунды"
);
localized_msg_bootstrap!(
    config_unauthenticated_ratelimit_max_burst_min_1,
    "config.unauthenticated_ratelimit_max_burst_min_1",
    "`UNAUTHENTICATED_RATELIMIT_MAX_BURST` must be at least 1",
    "`UNAUTHENTICATED_RATELIMIT_MAX_BURST` должен быть не менее 1"
);
localized_msg_bootstrap!(
    config_admin_token_argon2_phc_invalid,
    "config.admin_token_argon2_phc_invalid",
    "The configured Argon2 PHC in `ADMIN_TOKEN` is invalid",
    "Настроенный Argon2 PHC в `ADMIN_TOKEN` некорректен"
);
localized_msg_bootstrap!(
    config_sso_authority_url_invalid,
    "config.sso_authority_url_invalid",
    "Invalid sso_authority URL",
    "Некорректный URL sso_authority"
);
localized_msg_bootstrap!(
    config_sso_callback_path_url_invalid,
    "config.sso_callback_path_url_invalid",
    "Invalid sso_callback_path URL",
    "Некорректный URL sso_callback_path"
);
localized_msg_bootstrap!(
    config_sso_master_password_policy_invalid,
    "config.sso_master_password_policy_invalid",
    "Invalid sso_master_password_policy. Ensure that it is correctly escaped with ''",
    "Некорректный sso_master_password_policy. Убедитесь, что он корректно экранирован с помощью ''"
);
localized_msg_bootstrap!(
    config_sso_master_password_policy_not_object,
    "config.sso_master_password_policy_not_object",
    "Invalid sso_master_password_policy: parsed value is not a JSON object",
    "Некорректный sso_master_password_policy: разобранное значение не является JSON-объектом"
);
localized_msg!(
    accounts_email_change_not_allowed,
    "accounts.email_change_not_allowed",
    "Email change is not allowed.",
    "Смена email не разрешена."
);
localized_msg!(
    accounts_email_already_in_use,
    "accounts.email_already_in_use",
    "Email already in use",
    "Email уже используется"
);
localized_msg!(
    accounts_email_domain_not_allowed,
    "accounts.email_domain_not_allowed",
    "Email domain not allowed",
    "Домен email не разрешен"
);
localized_msg!(
    accounts_email_change_mismatch,
    "accounts.email_change_mismatch",
    "Email change mismatch",
    "Несоответствие смены email"
);
localized_msg!(
    accounts_no_email_change_pending,
    "accounts.no_email_change_pending",
    "No email change pending",
    "Нет ожидающей смены email"
);
localized_msg!(accounts_token_mismatch, "accounts.token_mismatch", "Token mismatch", "Несоответствие токена");
localized_msg!(
    accounts_cannot_verify_email,
    "accounts.cannot_verify_email",
    "Cannot verify email address",
    "Невозможно подтвердить email адрес"
);
localized_msg!(accounts_no_device_found, "accounts.no_device_found", "No device found", "Устройство не найдено");
localized_msg!(
    accounts_email_verification_token_mismatch,
    "accounts.email_verification_token_mismatch",
    "Email verification token does not match email",
    "Токен подтверждения email не соответствует email"
);
localized_msg!(
    accounts_emergency_access_not_enabled,
    "accounts.emergency_access_not_enabled",
    "Emergency access is not enabled.",
    "Экстренный доступ не включен."
);
localized_msg!(
    accounts_claim_email_mismatch,
    "accounts.claim_email_mismatch",
    "Claim email does not match email",
    "Email в клейме не соответствует email"
);
localized_msg!(
    accounts_claim_emer_id_mismatch,
    "accounts.claim_emer_id_mismatch",
    "Claim emer_id does not match accept_emergency_access_id",
    "emer_id в клейме не соответствует accept_emergency_access_id"
);
localized_msg!(
    accounts_claim_org_user_id_mismatch,
    "accounts.claim_org_user_id_mismatch",
    "Claim org_user_id does not match organization_user_id",
    "org_user_id в клейме не соответствует organization_user_id"
);
localized_msg!(
    accounts_registration_missing_required_params,
    "accounts.registration_missing_required_params",
    "Registration is missing required parameters",
    "В регистрации отсутствуют обязательные параметры"
);
localized_msg!(
    accounts_registration_not_allowed_or_exists,
    "accounts.registration_not_allowed_or_exists",
    "Registration not allowed or user already exists",
    "Регистрация запрещена или пользователь уже существует"
);
localized_msg!(
    accounts_password_hints_disabled,
    "accounts.password_hints_disabled",
    "Password hints have been disabled by the administrator. Remove the hint and try again.",
    "Подсказки пароля отключены администратором. Удалите подсказку и попробуйте снова."
);
localized_msg!(
    accounts_name_too_long,
    "accounts.name_too_long",
    "The field Name must be a string with a maximum length of 50.",
    "Поле Name должно быть строкой длиной не более 50 символов."
);
localized_msg!(
    accounts_registration_email_invite_mismatch,
    "accounts.registration_email_invite_mismatch",
    "Registration email does not match invite email",
    "Email регистрации не совпадает с email приглашения"
);
localized_msg!(
    accounts_account_already_initialized,
    "accounts.account_already_initialized",
    "Account already initialized, cannot set password",
    "Учетная запись уже инициализирована, задать пароль нельзя"
);
localized_msg!(
    accounts_avatar_color_invalid,
    "accounts.avatar_color_invalid",
    "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters",
    "Поле AvatarColor должно быть HTML/Hex цветом длиной 7 символов"
);
localized_msg!(accounts_user_not_found, "accounts.user_not_found", "User doesn't exist", "Пользователь не существует");
localized_msg!(accounts_invalid_claim, "accounts.invalid_claim", "Invalid claim", "Некорректный клейм");
localized_msg!(
    accounts_contact_admin_to_delete,
    "accounts.contact_admin_to_delete",
    "Please contact the administrator to delete your account",
    "Свяжитесь с администратором, чтобы удалить учетную запись"
);
localized_msg!(
    accounts_password_hint_not_configured,
    "accounts.password_hint_not_configured",
    "This server is not configured to provide password hints.",
    "Этот сервер не настроен для выдачи подсказок пароля."
);
localized_msg!(
    accounts_password_hint_is,
    "accounts.password_hint_is",
    "Your password hint is: {}",
    "Ваша подсказка пароля: {}"
);
localized_msg!(
    accounts_auth_request_not_found,
    "accounts.auth_request_not_found",
    "AuthRequest doesn't exist",
    "Запрос аутентификации не существует"
);
localized_msg!(
    accounts_device_verification_failed,
    "accounts.device_verification_failed",
    "Device verification failed",
    "Проверка устройства не пройдена"
);
localized_msg!(
    accounts_auth_request_not_found_or_mismatch,
    "accounts.auth_request_not_found_or_mismatch",
    "Record not found or user uuid does not match",
    "Запись не найдена или uuid пользователя не совпадает"
);
localized_msg!(
    accounts_auth_request_duplicate_device,
    "accounts.auth_request_duplicate_device",
    "An authentication request with the same device already exists",
    "Запрос аутентификации для этого устройства уже существует"
);
localized_msg!(
    accounts_auth_request_invalid_device_ip_or_code,
    "accounts.auth_request_invalid_device_ip_or_code",
    "Invalid device, IP or code",
    "Некорректное устройство, IP или код"
);
localized_msg!(
    accounts_device_should_be_present_before_token_assigned,
    "accounts.device_should_be_present_before_token_assigned",
    "Device should be present before a token can be assigned",
    "Устройство должно существовать до назначения токена"
);
localized_msg!(
    accounts_error_saving_device_push_token,
    "accounts.error_saving_device_push_token",
    "An error occurred while trying to save the device push token",
    "Произошла ошибка при сохранении push токена устройства"
);
localized_msg!(
    accounts_associated_org_not_found,
    "accounts.associated_org_not_found",
    "Failed to retrieve the associated organization",
    "Не удалось получить связанную организацию"
);
localized_msg!(
    accounts_invitation_not_found,
    "accounts.invitation_not_found",
    "Failed to retrieve the invitation",
    "Не удалось получить приглашение"
);
localized_msg!(
    accounts_existing_keypair,
    "accounts.existing_keypair",
    "User has existing keypair",
    "У пользователя уже есть существующая ключевая пара"
);
localized_msg!(
    accounts_kdf_auth_unlock_mismatch,
    "accounts.kdf_auth_unlock_mismatch",
    "KDF settings must be equal for authentication and unlock",
    "Параметры KDF должны совпадать для аутентификации и разблокировки"
);
localized_msg!(
    accounts_invalid_master_password_salt,
    "accounts.invalid_master_password_salt",
    "Invalid master password salt",
    "Некорректная salt для мастер-пароля"
);
localized_msg!(accounts_invalid_request, "accounts.invalid_request", "Invalid request!", "Некорректный запрос!");
localized_msg!(
    accounts_pbkdf2_min_iterations,
    "accounts.pbkdf2_min_iterations",
    "PBKDF2 KDF iterations must be at least 100000.",
    "Количество итераций PBKDF2 должно быть не менее 100000."
);
localized_msg!(
    accounts_argon2_min_iterations,
    "accounts.argon2_min_iterations",
    "Argon2 KDF iterations must be at least 1.",
    "Количество итераций Argon2 должно быть не менее 1."
);
localized_msg!(
    accounts_argon2_memory_range,
    "accounts.argon2_memory_range",
    "Argon2 memory must be between 15 MB and 1024 MB.",
    "Память Argon2 должна быть в пределах от 15 MB до 1024 MB."
);
localized_msg!(
    accounts_argon2_memory_required,
    "accounts.argon2_memory_required",
    "Argon2 memory parameter is required.",
    "Параметр памяти Argon2 обязателен."
);
localized_msg!(
    accounts_argon2_parallelism_range,
    "accounts.argon2_parallelism_range",
    "Argon2 parallelism must be between 1 and 16.",
    "Параллелизм Argon2 должен быть в диапазоне от 1 до 16."
);
localized_msg!(
    accounts_argon2_parallelism_required,
    "accounts.argon2_parallelism_required",
    "Argon2 parallelism parameter is required.",
    "Параметр параллелизма Argon2 обязателен."
);
localized_msg!(
    accounts_rotate_kdf_or_email_change_not_supported,
    "accounts.rotate_kdf_or_email_change_not_supported",
    "Changing the kdf variant or email is not supported during key rotation",
    "Изменение варианта kdf или email не поддерживается во время ротации ключей"
);
localized_msg!(
    accounts_rotate_asymmetric_keypair_change_not_supported,
    "accounts.rotate_asymmetric_keypair_change_not_supported",
    "Changing the asymmetric keypair is not possible during key rotation",
    "Изменение асимметричной ключевой пары во время ротации ключей невозможно"
);
localized_msg!(
    accounts_rotate_all_ciphers_required,
    "accounts.rotate_all_ciphers_required",
    "All existing ciphers must be included in the rotation",
    "Все существующие шифры должны быть включены в ротацию"
);
localized_msg!(
    accounts_rotate_all_folders_required,
    "accounts.rotate_all_folders_required",
    "All existing folders must be included in the rotation",
    "Все существующие папки должны быть включены в ротацию"
);
localized_msg!(
    accounts_rotate_all_emergency_access_required,
    "accounts.rotate_all_emergency_access_required",
    "All existing emergency access keys must be included in the rotation",
    "Все существующие ключи экстренного доступа должны быть включены в ротацию"
);
localized_msg!(
    accounts_rotate_all_reset_password_required,
    "accounts.rotate_all_reset_password_required",
    "All existing reset password keys must be included in the rotation",
    "Все существующие ключи сброса пароля должны быть включены в ротацию"
);
localized_msg!(
    accounts_rotate_all_sends_required,
    "accounts.rotate_all_sends_required",
    "All existing sends must be included in the rotation",
    "Все существующие отправки должны быть включены в ротацию"
);
localized_msg!(accounts_folder_not_found, "accounts.folder_not_found", "Folder doesn't exist", "Папка не существует");
localized_msg!(
    accounts_emergency_access_not_found_or_not_owned,
    "accounts.emergency_access_not_found_or_not_owned",
    "Emergency access doesn't exist or is not owned by the user",
    "Экстренный доступ не существует или не принадлежит пользователю"
);
localized_msg!(
    accounts_reset_password_not_found,
    "accounts.reset_password_not_found",
    "Reset password doesn't exist",
    "Сброс пароля не существует"
);
localized_msg!(accounts_send_not_found, "accounts.send_not_found", "Send doesn't exist", "Отправка не существует");
localized_msg!(accounts_cipher_not_found, "accounts.cipher_not_found", "Cipher doesn't exist", "Шифр не существует");
localized_msg!(
    send_delete_only_policy,
    "send.delete_only_policy",
    "Due to an Enterprise Policy, you are only able to delete an existing Send.",
    "Из-за корпоративной политики вы можете только удалить существующую отправку."
);
localized_msg!(
    send_hide_email_policy_forbidden,
    "send.hide_email_policy_forbidden",
    "Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send.",
    "Из-за корпоративной политики вам запрещено скрывать свой email от получателей при создании или редактировании отправки."
);
localized_msg!(send_invalid_type, "send.invalid_type", "Invalid Send type", "Некорректный тип отправки");
localized_msg!(
    send_data_not_provided,
    "send.data_not_provided",
    "Send data not provided",
    "Данные отправки не предоставлены"
);
localized_msg!(
    send_deletion_date_too_far,
    "send.deletion_date_too_far",
    "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.",
    "Нельзя создать отправку с датой удаления так далеко в будущем. Установите дату удаления менее чем через 31 день и повторите попытку."
);
localized_msg!(
    send_email_verification_not_supported,
    "send.email_verification_not_supported",
    "Sends with email verification is not supported",
    "Отправки с проверкой email не поддерживаются"
);
localized_msg!(send_not_found, "send.not_found", "Send not found", "Отправка не найдена");
localized_msg!(
    send_invalid_uuid_or_not_owned,
    "send.invalid_uuid_or_not_owned",
    "Invalid send uuid or does not belong to user",
    "Некорректный UUID отправки или она не принадлежит пользователю"
);
localized_msg!(
    send_file_use_v2,
    "send.file_use_v2",
    "File sends should use /api/sends/file/v2",
    "Для файловых отправок используйте /api/sends/file/v2"
);
localized_msg!(
    send_content_not_file,
    "send.content_not_file",
    "Send content is not a file",
    "Содержимое отправки не является файлом"
);
localized_msg!(send_invalid_length, "send.invalid_length", "Invalid send length", "Некорректная длина отправки");
localized_msg!(
    send_size_negative,
    "send.size_negative",
    "Send size can't be negative",
    "Размер отправки не может быть отрицательным"
);
localized_msg!(
    send_file_uploads_disabled,
    "send.file_uploads_disabled",
    "File uploads are disabled",
    "Загрузка файлов отключена"
);
localized_msg!(
    send_existing_overflow,
    "send.existing_overflow",
    "Existing sends overflow",
    "Переполнение существующих отправок"
);
localized_msg!(send_size_overflow, "send.size_overflow", "Send size overflow", "Переполнение размера отправки");
localized_msg!(
    send_storage_limit_reached,
    "send.storage_limit_reached",
    "Send storage limit reached! Delete some sends to free up space",
    "Достигнут лимит хранилища отправок! Удалите часть отправок, чтобы освободить место"
);
localized_msg!(
    send_storage_limit_exceeded_file,
    "send.storage_limit_exceeded_file",
    "Send storage limit exceeded with this file",
    "Лимит хранилища отправок будет превышен этим файлом"
);
localized_msg!(
    send_not_found_unable_save_file,
    "send.not_found_unable_save_file",
    "Send not found. Unable to save the file.",
    "Отправка не найдена. Не удалось сохранить файл."
);
localized_msg!(
    send_not_file_type,
    "send.not_file_type",
    "Send is not a file type send.",
    "Отправка не является файловым типом."
);
localized_msg!(
    send_unable_decode_json,
    "send.unable_decode_json",
    "Unable to decode send data as json.",
    "Не удалось декодировать данные отправки как JSON."
);
localized_msg!(
    send_file_name_mismatch,
    "send.file_name_mismatch",
    "Send file name does not match.",
    "Имя файла отправки не совпадает."
);
localized_msg!(
    send_file_name_missing_or_mismatch,
    "send.file_name_missing_or_mismatch",
    "Send file name does not match or is not provided.",
    "Имя файла отправки не совпадает или не предоставлено."
);
localized_msg!(
    send_file_mismatch_data,
    "send.file_mismatch_data",
    "Send file does not match send data.",
    "Файл отправки не соответствует данным отправки."
);
localized_msg!(
    send_file_size_overflow,
    "send.file_size_overflow",
    "Send file size overflow.",
    "Переполнение размера файла отправки."
);
localized_msg!(
    send_file_size_mismatch,
    "send.file_size_mismatch",
    "Send file size does not match.",
    "Размер файла отправки не совпадает."
);
localized_msg!(
    send_invalid_send_id_or_not_owned,
    "send.invalid_send_id_or_not_owned",
    "Send send_id is invalid or does not belong to user",
    "Идентификатор send_id некорректен или отправка не принадлежит пользователю"
);
localized_msg!(
    send_not_owned_by_user,
    "send.not_owned_by_user",
    "Send is not owned by user",
    "Отправка не принадлежит пользователю"
);
localized_msg!(
    send_cannot_change_type,
    "send.cannot_change_type",
    "Sends can't change type",
    "Отправка не может менять тип"
);
localized_msg!(
    two_factor_invalid_totp_secret,
    "two_factor.invalid_totp_secret",
    "Invalid TOTP secret",
    "Некорректный TOTP секрет"
);
localized_msg!(
    two_factor_invalid_key_length,
    "two_factor.invalid_key_length",
    "Invalid key length",
    "Некорректная длина ключа"
);
localized_msg!(
    two_factor_totp_code_not_number,
    "two_factor.totp_code_not_number",
    "TOTP code is not a number",
    "Код TOTP не является числом"
);
localized_msg!(
    two_factor_empty_duo_authorization_code,
    "two_factor.empty_duo_authorization_code",
    "Empty Duo authorization code",
    "Пустой код авторизации Duo"
);
localized_msg!(
    two_factor_duo_validation_mismatch,
    "two_factor.duo_validation_mismatch",
    "Error validating Duo authorization, nonce or username mismatch.",
    "Ошибка проверки авторизации Duo: nonce или имя пользователя не совпадают."
);
localized_msg!(
    two_factor_failed_validate_duo_credentials,
    "two_factor.failed_validate_duo_credentials",
    "Failed to validate Duo credentials",
    "Не удалось проверить учетные данные Duo"
);
localized_msg!(
    two_factor_cant_fetch_duo_keys,
    "two_factor.cant_fetch_duo_keys",
    "Can't fetch Duo keys",
    "Не удалось получить ключи Duo"
);
localized_msg!(two_factor_email_disabled, "two_factor.email_disabled", "Email 2FA is disabled", "Email 2FA отключен");
localized_msg!(
    two_factor_auth_request_not_found,
    "two_factor.auth_request_not_found",
    "AuthRequest doesn't exist",
    "AuthRequest не существует"
);
localized_msg!(two_factor_user_not_found, "two_factor.user_not_found", "User not found", "Пользователь не найден");
localized_msg!(
    two_factor_no_auth_request_access_code,
    "two_factor.no_auth_request_access_code",
    "No auth request access code",
    "Нет кода доступа auth request"
);
localized_msg!(
    two_factor_invalid_device_ip_or_code,
    "two_factor.invalid_device_ip_or_code",
    "Invalid device, IP or code",
    "Некорректное устройство, IP или код"
);
localized_msg!(
    two_factor_no_password_hash_submitted,
    "two_factor.no_password_hash_submitted",
    "No password hash has been submitted.",
    "Хэш пароля не был передан."
);
localized_msg!(
    two_factor_no_device_identifier_submitted,
    "two_factor.no_device_identifier_submitted",
    "No device identifier has been submitted.",
    "Идентификатор устройства не был передан."
);
localized_msg!(
    two_factor_not_found,
    "two_factor.not_found",
    "Two factor not found",
    "Двухфакторная аутентификация не найдена"
);
localized_msg!(two_factor_token_empty, "two_factor.token_empty", "Token is empty", "Токен пуст");
localized_msg!(
    two_factor_no_token_available,
    "two_factor.no_token_available",
    "No token available",
    "Токен недоступен"
);
localized_msg!(two_factor_token_invalid, "two_factor.token_invalid", "Token is invalid", "Токен некорректен");
localized_msg!(
    two_factor_decode_email_token_data_failed,
    "two_factor.decode_email_token_data_failed",
    "Could not decode EmailTokenData from string",
    "Не удалось декодировать EmailTokenData из строки"
);
localized_msg!(
    two_factor_auto_enable_email_requires_verified,
    "two_factor.auto_enable_email_requires_verified",
    "Auto-enabling of email 2FA failed because the users email address has not been verified!",
    "Автовключение email 2FA не удалось, потому что email пользователя не подтвержден!"
);
localized_msg!(
    two_factor_user_not_found_exclam,
    "two_factor.user_not_found_exclam",
    "User not found!",
    "Пользователь не найден!"
);
localized_msg!(
    two_factor_decode_protected_action_data_failed,
    "two_factor.decode_protected_action_data_failed",
    "Could not decode ProtectedActionData from string",
    "Не удалось декодировать ProtectedActionData из строки"
);
localized_msg!(
    two_factor_protected_action_token_not_found,
    "two_factor.protected_action_token_not_found",
    "Protected action token not found, try sending the code again or restart the process",
    "Токен защищенного действия не найден: отправьте код заново или перезапустите процесс"
);
localized_msg!(two_factor_token_expired, "two_factor.token_expired", "Token has expired", "Срок действия токена истек");
localized_msg!(
    two_factor_request_otp_wait_seconds,
    "two_factor.request_otp_wait_seconds",
    "Please wait {} seconds before requesting another code.",
    "Подождите {} секунд перед запросом нового кода."
);
localized_msg!(
    two_factor_webauthn_domain_incompatible,
    "two_factor.webauthn_domain_incompatible",
    "Configured `DOMAIN` is not compatible with Webauthn",
    "Настроенный DOMAIN несовместим с WebAuthn"
);
localized_msg!(
    two_factor_cannot_recover_challenge,
    "two_factor.cannot_recover_challenge",
    "Can't recover challenge",
    "Не удалось восстановить challenge"
);
localized_msg!(
    two_factor_webauthn_data_not_found,
    "two_factor.webauthn_data_not_found",
    "Webauthn data not found!",
    "Данные WebAuthn не найдены!"
);
localized_msg!(
    two_factor_webauthn_entry_not_found,
    "two_factor.webauthn_entry_not_found",
    "Webauthn entry not found",
    "Запись WebAuthn не найдена"
);
localized_msg!(
    two_factor_error_parsing_u2f_data,
    "two_factor.error_parsing_u2f_data",
    "Error parsing U2F data",
    "Ошибка разбора данных U2F"
);
localized_msg!(
    two_factor_no_webauthn_devices_registered,
    "two_factor.no_webauthn_devices_registered",
    "No Webauthn devices registered",
    "Устройства WebAuthn не зарегистрированы"
);
localized_msg!(
    two_factor_yubico_support_disabled,
    "two_factor.yubico_support_disabled",
    "Yubico support is disabled",
    "Поддержка Yubico отключена"
);
localized_msg!(
    two_factor_yubico_credentials_not_set,
    "two_factor.yubico_credentials_not_set",
    "`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled",
    "Переменная окружения YUBICO_CLIENT_ID или YUBICO_SECRET_KEY не установлена. OTP YubiKey отключен"
);
localized_msg!(two_factor_key_required, "two_factor.key_required", "A key is required.", "Требуется ключ.");
localized_msg!(
    two_factor_invalid_yubikey_otp_length,
    "two_factor.invalid_yubikey_otp_length",
    "Invalid Yubikey OTP length",
    "Некорректная длина OTP YubiKey"
);
localized_msg!(
    two_factor_invalid_yubikey_otp,
    "two_factor.invalid_yubikey_otp",
    "Invalid Yubikey OTP",
    "Некорректный OTP YubiKey"
);
localized_msg!(
    two_factor_invalid_yubikey_otp_provided,
    "two_factor.invalid_yubikey_otp_provided",
    "Invalid Yubikey OTP provided",
    "Передан некорректный OTP YubiKey"
);
localized_msg!(
    two_factor_given_yubikey_not_registered,
    "two_factor.given_yubikey_not_registered",
    "Given Yubikey is not registered",
    "Указанный YubiKey не зарегистрирован"
);
localized_msg!(
    two_factor_failed_verify_otp,
    "two_factor.failed_verify_otp",
    "Failed to verify OTP",
    "Не удалось проверить OTP"
);
localized_msg!(
    two_factor_failed_verify_yubikey_against_otp_server,
    "two_factor.failed_verify_yubikey_against_otp_server",
    "Failed to verify Yubikey against OTP server",
    "Не удалось проверить YubiKey через OTP сервер"
);
localized_msg!(
    two_factor_totp_key_mismatch_cannot_deactivate,
    "two_factor.totp_key_mismatch_cannot_deactivate",
    "TOTP key does not match recorded value, cannot deactivate",
    "Ключ TOTP не совпадает с сохраненным значением, отключение невозможно"
);
localized_msg!(
    two_factor_failed_decode_verification_token,
    "two_factor.failed_decode_verification_token",
    "Failed to decode verification token",
    "Не удалось декодировать verification токен"
);
localized_msg!(
    two_factor_duo_error_encoding_jwt,
    "two_factor.duo_error_encoding_jwt",
    "Error encoding Duo JWT",
    "Ошибка кодирования Duo JWT"
);
localized_msg!(
    two_factor_duo_error_requesting_health_check,
    "two_factor.duo_error_requesting_health_check",
    "Error requesting Duo health check",
    "Ошибка запроса проверки работоспособности Duo"
);
localized_msg!(
    two_factor_duo_health_check_decode_error,
    "two_factor.duo_health_check_decode_error",
    "Duo health check response decode error",
    "Ошибка декодирования ответа проверки работоспособности Duo"
);
localized_msg!(
    two_factor_duo_health_check_fail_response,
    "two_factor.duo_health_check_fail_response",
    "Duo health check FAIL response",
    "Ответ FAIL от проверки работоспособности Duo"
);
localized_msg!(
    two_factor_duo_health_check_failed_stat,
    "two_factor.duo_health_check_failed_stat",
    "Duo health check failed with unexpected stat",
    "Проверка работоспособности Duo завершилась с неожиданным stat"
);
localized_msg!(
    two_factor_duo_error_parsing_authorization_url,
    "two_factor.duo_error_parsing_authorization_url",
    "Error parsing Duo authorization URL",
    "Ошибка разбора URL авторизации Duo"
);
localized_msg!(
    two_factor_duo_error_exchanging_code,
    "two_factor.duo_error_exchanging_code",
    "Error exchanging Duo code",
    "Ошибка обмена кода Duo"
);
localized_msg!(
    two_factor_duo_failure_response,
    "two_factor.duo_failure_response",
    "Failure response from Duo",
    "Ответ ошибки от Duo"
);
localized_msg!(
    two_factor_duo_error_decoding_id_token_response,
    "two_factor.duo_error_decoding_id_token_response",
    "Error decoding ID token response",
    "Ошибка декодирования ответа ID token"
);
localized_msg!(
    two_factor_duo_failed_decode_token,
    "two_factor.duo_failed_decode_token",
    "Failed to decode Duo token",
    "Не удалось декодировать токен Duo"
);
localized_msg!(
    two_factor_duo_error_parsing_configured_domain_url,
    "two_factor.duo_error_parsing_configured_domain_url",
    "Error parsing configured domain URL",
    "Ошибка разбора настроенного URL домена"
);
localized_msg!(
    two_factor_duo_error_constructing_redirect_url,
    "two_factor.duo_error_constructing_redirect_url",
    "Error constructing Duo redirect URL",
    "Ошибка построения URL редиректа Duo"
);
localized_msg!(
    two_factor_duo_error_saving_auth_context,
    "two_factor.duo_error_saving_auth_context",
    "Error saving Duo authentication context",
    "Ошибка сохранения контекста аутентификации Duo"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_user,
    "two_factor.invalid_verification_token_invalid_user",
    "Invalid verification token: Invalid user",
    "Некорректный verification токен: неверный пользователь"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_state,
    "two_factor.invalid_verification_token_invalid_state",
    "Invalid verification token: Invalid state",
    "Некорректный verification токен: неверное состояние"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_key,
    "two_factor.invalid_verification_token_invalid_key",
    "Invalid verification token: Invalid key",
    "Некорректный verification токен: неверный ключ"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_duo_data,
    "two_factor.invalid_verification_token_invalid_duo_data",
    "Invalid verification token: Invalid duo data",
    "Некорректный verification токен: неверные данные Duo"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_email,
    "two_factor.invalid_verification_token_invalid_email",
    "Invalid verification token: Invalid email",
    "Некорректный verification токен: неверный email"
);
localized_msg!(
    two_factor_invalid_verification_token_invalid_keys,
    "two_factor.invalid_verification_token_invalid_keys",
    "Invalid verification token: Invalid keys",
    "Некорректный verification токен: неверные ключи"
);
localized_msg!(
    api_no_validation_provided,
    "api.no_validation_provided",
    "No validation provided",
    "Проверка не предоставлена"
);
localized_msg!(api_invalid_url, "api.invalid_url", "Invalid URL", "Некорректный URL");
localized_msg!(api_invalid_host, "api.invalid_host", "Invalid host", "Некорректный хост");
localized_msg!(api_invalid_start_date, "api.invalid_start_date", "Invalid start date", "Некорректная начальная дата");
localized_msg!(api_invalid_end_date, "api.invalid_end_date", "Invalid end date", "Некорректная конечная дата");
localized_msg!(api_invalid_event_date, "api.invalid_event_date", "Invalid event date", "Некорректная дата события");
localized_msg!(
    api_template_missing_subject,
    "api.template_missing_subject",
    "Template doesn't contain subject",
    "В шаблоне отсутствует тема"
);
localized_msg!(
    api_template_missing_body,
    "api.template_missing_body",
    "Template doesn't contain body",
    "В шаблоне отсутствует тело"
);
localized_msg!(
    api_template_more_than_one_body,
    "api.template_more_than_one_body",
    "Template contains more than one body",
    "Шаблон содержит больше одного тела"
);
localized_msg!(
    api_failed_build_verify_url_query_params,
    "api.failed_build_verify_url_query_params",
    "Failed to build verify URL query parameters",
    "Не удалось сформировать query-параметры verify URL"
);
localized_msg!(
    api_failed_build_invite_url_query_params,
    "api.failed_build_invite_url_query_params",
    "Failed to build invite URL query parameters",
    "Не удалось сформировать query-параметры invite URL"
);
localized_msg!(
    api_failed_build_emergency_invite_url_query_params,
    "api.failed_build_emergency_invite_url_query_params",
    "Failed to build emergency invite URL query parameters",
    "Не удалось сформировать query-параметры emergency invite URL"
);
localized_msg!(
    api_number_not_fit_i32,
    "api.number_not_fit_i32",
    "Number does not fit in i32",
    "Число не помещается в i32"
);
localized_msg!(
    api_event_retention_date_calculation_failed,
    "api.event_retention_date_calculation_failed",
    "Unable to calculate the event retention date, check 'EVENTS_DAYS_RETAIN'",
    "Не удалось вычислить дату хранения событий, проверьте 'EVENTS_DAYS_RETAIN'"
);
localized_msg!(
    api_failed_get_db_connection_purging_expired_sso_auth,
    "api.failed_get_db_connection_purging_expired_sso_auth",
    "Failed to get DB connection while purging expired sso_auth",
    "Не удалось получить соединение с БД при очистке устаревших sso_auth"
);
localized_msg!(
    api_db_timeout_waiting_connection,
    "api.db_timeout_waiting_connection",
    "Timeout waiting for database connection",
    "Таймаут ожидания соединения с базой данных"
);
localized_msg!(
    api_static_file_not_found,
    "api.static_file_not_found",
    "Static file not found",
    "Статический файл не найден"
);
localized_msg!(
    api_log_level_format_invalid,
    "api.log_level_format_invalid",
    "LOG_LEVEL should follow the expected format",
    "LOG_LEVEL должен соответствовать ожидаемому формату"
);
localized_msg!(
    api_failed_activate_logger,
    "api.failed_activate_logger",
    "Failed to activate logger",
    "Не удалось активировать логгер"
);
localized_msg!(
    push_error_get_token_from_server,
    "push.error_get_token_from_server",
    "Error getting push token from bitwarden server",
    "Ошибка получения push токена с сервера bitwarden"
);
localized_msg!(
    push_unexpected_token_from_server,
    "push.unexpected_token_from_server",
    "Unexpected push token received from bitwarden server",
    "Получен неожиданный push токен от сервера bitwarden"
);
localized_msg!(
    push_error_register_device,
    "push.error_register_device",
    "An error occurred while proceeding registration of a device",
    "Произошла ошибка при регистрации устройства"
);
localized_msg!(
    push_error_save_registered_push_uuid,
    "push.error_save_registered_push_uuid",
    "An error occurred while trying to save the (registered) device push uuid",
    "Произошла ошибка при сохранении push uuid зарегистрированного устройства"
);
localized_msg!(
    push_error_device_unregistration,
    "push.error_device_unregistration",
    "An error occurred during device unregistration",
    "Произошла ошибка при отмене регистрации устройства"
);
#[cfg(not(mysql))]
localized_msg!(
    api_db_url_mysql_feature_not_enabled,
    "api.db_url_mysql_feature_not_enabled",
    "`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled",
    "`DATABASE_URL` указывает на MySQL, но функция 'mysql' не включена"
);
#[cfg(not(postgresql))]
localized_msg!(
    api_db_url_postgresql_feature_not_enabled,
    "api.db_url_postgresql_feature_not_enabled",
    "`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled",
    "`DATABASE_URL` указывает на PostgreSQL, но функция 'postgresql' не включена"
);
#[cfg(not(sqlite))]
localized_msg!(
    api_db_url_sqlite_feature_not_enabled,
    "api.db_url_sqlite_feature_not_enabled",
    "`DATABASE_URL` is a SQLite URL, but the 'sqlite' feature is not enabled",
    "`DATABASE_URL` указывает на SQLite, но функция 'sqlite' не включена"
);
#[cfg(not(sqlite))]
localized_msg!(
    api_db_url_unknown_scheme,
    "api.db_url_unknown_scheme",
    "`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://)",
    "`DATABASE_URL` не соответствует известным схемам базы данных (mysql://, postgresql://, sqlite://)"
);
localized_msg!(
    db_failed_create_pool,
    "db.failed_create_pool",
    "Failed to create pool",
    "Не удалось создать пул соединений"
);
localized_msg!(
    db_error_retrieving_connection_from_pool,
    "db.error_retrieving_connection_from_pool",
    "Error retrieving connection from pool",
    "Ошибка получения соединения из пула"
);
#[cfg(sqlite)]
localized_msg!(db_vacuum_into_failed, "db.vacuum_into_failed", "VACUUM INTO failed", "VACUUM INTO завершился ошибкой");
localized_msg!(
    db_error_saving_sso_auth,
    "db.error_saving_sso_auth",
    "Error saving SSO auth",
    "Ошибка сохранения SSO auth"
);
localized_msg!(
    db_error_deleting_sso_auth,
    "db.error_deleting_sso_auth",
    "Error deleting sso_auth",
    "Ошибка удаления sso_auth"
);
localized_msg!(
    db_error_deleting_expired_sso_nonce,
    "db.error_deleting_expired_sso_nonce",
    "Error deleting expired SSO nonce",
    "Ошибка удаления устаревшего SSO nonce"
);
localized_msg!(
    db_error_saving_twofactor,
    "db.error_saving_twofactor",
    "Error saving twofactor",
    "Ошибка сохранения twofactor"
);
#[cfg(postgresql)]
localized_msg!(
    db_error_deleting_twofactor_for_insert,
    "db.error_deleting_twofactor_for_insert",
    "Error deleting twofactor for insert",
    "Ошибка удаления twofactor перед вставкой"
);
localized_msg!(
    db_error_deleting_twofactor,
    "db.error_deleting_twofactor",
    "Error deleting twofactor",
    "Ошибка удаления twofactor"
);
localized_msg!(
    db_error_deleting_twofactors,
    "db.error_deleting_twofactors",
    "Error deleting twofactors",
    "Ошибка удаления twofactors"
);
localized_msg!(
    db_error_saving_context_twofactor_duo_ctx,
    "db.error_saving_context_twofactor_duo_ctx",
    "Error saving context to twofactor_duo_ctx",
    "Ошибка сохранения контекста в twofactor_duo_ctx"
);
localized_msg!(
    db_error_deleting_from_twofactor_duo_ctx,
    "db.error_deleting_from_twofactor_duo_ctx",
    "Error deleting from twofactor_duo_ctx",
    "Ошибка удаления из twofactor_duo_ctx"
);
localized_msg!(
    db_error_adding_twofactor_incomplete_record,
    "db.error_adding_twofactor_incomplete_record",
    "Error adding twofactor_incomplete record",
    "Ошибка добавления записи twofactor_incomplete"
);
localized_msg!(
    db_error_delete_by_user_and_device_twofactor_incomplete,
    "db.error_delete_by_user_and_device_twofactor_incomplete",
    "Error in twofactor_incomplete::delete_by_user_and_device()",
    "Ошибка в twofactor_incomplete::delete_by_user_and_device()"
);
localized_msg!(
    db_error_delete_all_by_user_twofactor_incomplete,
    "db.error_delete_all_by_user_twofactor_incomplete",
    "Error in twofactor_incomplete::delete_all_by_user()",
    "Ошибка в twofactor_incomplete::delete_all_by_user()"
);
localized_msg!(db_error_saving_archive, "db.error_saving_archive", "Error saving archive", "Ошибка сохранения archive");
localized_msg!(
    db_error_deleting_archive,
    "db.error_deleting_archive",
    "Error deleting archive",
    "Ошибка удаления archive"
);
localized_msg!(
    db_error_saving_attachment,
    "db.error_saving_attachment",
    "Error saving attachment",
    "Ошибка сохранения attachment"
);
localized_msg!(
    db_error_deleting_attachment,
    "db.error_deleting_attachment",
    "Error deleting attachment",
    "Ошибка удаления attachment"
);
localized_msg!(
    db_error_saving_auth_request,
    "db.error_saving_auth_request",
    "Error saving auth_request",
    "Ошибка сохранения auth_request"
);
localized_msg!(
    db_error_deleting_auth_request,
    "db.error_deleting_auth_request",
    "Error deleting auth request",
    "Ошибка удаления auth request"
);
localized_msg!(
    db_error_deleting_auth_requests_for_user,
    "db.error_deleting_auth_requests_for_user",
    "Error deleting auth requests for user",
    "Ошибка удаления auth request для пользователя"
);
localized_msg!(
    db_error_updating_auth_request,
    "db.error_updating_auth_request",
    "Error updating auth request",
    "Ошибка обновления auth request"
);
localized_msg!(db_error_saving_cipher, "db.error_saving_cipher", "Error saving cipher", "Ошибка сохранения cipher");
localized_msg!(db_error_deleting_cipher, "db.error_deleting_cipher", "Error deleting cipher", "Ошибка удаления cipher");
localized_msg!(
    db_cipher_invalid_type,
    "db.cipher_invalid_type",
    "Cipher has an invalid type",
    "У cipher некорректный тип"
);
localized_msg!(
    db_error_saving_collection,
    "db.error_saving_collection",
    "Error saving collection",
    "Ошибка сохранения collection"
);
localized_msg!(
    db_error_deleting_collection,
    "db.error_deleting_collection",
    "Error deleting collection",
    "Ошибка удаления collection"
);
localized_msg!(
    db_error_adding_user_to_collection,
    "db.error_adding_user_to_collection",
    "Error adding user to collection",
    "Ошибка добавления пользователя в collection"
);
localized_msg!(
    db_error_removing_user_from_collection,
    "db.error_removing_user_from_collection",
    "Error removing user from collection",
    "Ошибка удаления пользователя из collection"
);
localized_msg!(
    db_error_deleting_users_from_collection,
    "db.error_deleting_users_from_collection",
    "Error deleting users from collection",
    "Ошибка удаления пользователей из collection"
);
localized_msg!(
    db_error_removing_user_from_collections,
    "db.error_removing_user_from_collections",
    "Error removing user from collections",
    "Ошибка удаления пользователя из collections"
);
localized_msg!(
    db_error_adding_cipher_to_collection,
    "db.error_adding_cipher_to_collection",
    "Error adding cipher to collection",
    "Ошибка добавления cipher в collection"
);
localized_msg!(
    db_error_deleting_cipher_from_collection,
    "db.error_deleting_cipher_from_collection",
    "Error deleting cipher from collection",
    "Ошибка удаления cipher из collection"
);
localized_msg!(
    db_error_removing_cipher_from_collections,
    "db.error_removing_cipher_from_collections",
    "Error removing cipher from collections",
    "Ошибка удаления cipher из collections"
);
localized_msg!(
    db_error_removing_ciphers_from_collection,
    "db.error_removing_ciphers_from_collection",
    "Error removing ciphers from collection",
    "Ошибка удаления ciphers из collection"
);
localized_msg!(db_error_saving_device, "db.error_saving_device", "Error saving device", "Ошибка сохранения device");
localized_msg!(
    db_error_removing_devices_for_user,
    "db.error_removing_devices_for_user",
    "Error removing devices for user",
    "Ошибка удаления устройств пользователя"
);
localized_msg!(
    db_error_removing_push_token,
    "db.error_removing_push_token",
    "Error removing push token",
    "Ошибка удаления push token"
);
localized_msg!(
    db_error_removing_twofactor_remember_tokens,
    "db.error_removing_twofactor_remember_tokens",
    "Error removing two factor remember tokens",
    "Ошибка удаления токенов запоминания 2FA"
);
localized_msg!(db_error_saving_send, "db.error_saving_send", "Error saving send", "Ошибка сохранения send");
localized_msg!(db_error_deleting_send, "db.error_deleting_send", "Error deleting send", "Ошибка удаления send");
localized_msg!(db_error_saving_group, "db.error_saving_group", "Error saving group", "Ошибка сохранения group");
localized_msg!(db_error_deleting_group, "db.error_deleting_group", "Error deleting group", "Ошибка удаления group");
localized_msg!(
    db_error_updating_group_revision,
    "db.error_updating_group_revision",
    "Error updating group revision",
    "Ошибка обновления ревизии group"
);
localized_msg!(
    db_error_adding_group_to_collection,
    "db.error_adding_group_to_collection",
    "Error adding group to collection",
    "Ошибка добавления group в collection"
);
localized_msg!(
    db_error_deleting_collection_group,
    "db.error_deleting_collection_group",
    "Error deleting collection group",
    "Ошибка удаления группы из collection"
);
localized_msg!(
    db_error_adding_user_to_group,
    "db.error_adding_user_to_group",
    "Error adding user to group",
    "Ошибка добавления пользователя в group"
);
localized_msg!(
    db_error_deleting_group_users,
    "db.error_deleting_group_users",
    "Error deleting group users",
    "Ошибка удаления пользователей group"
);
localized_msg!(
    db_error_deleting_user_groups,
    "db.error_deleting_user_groups",
    "Error deleting user groups",
    "Ошибка удаления групп пользователя"
);
localized_msg!(
    db_error_saving_org_policy,
    "db.error_saving_org_policy",
    "Error saving org_policy",
    "Ошибка сохранения org_policy"
);
#[cfg(postgresql)]
localized_msg!(
    db_error_deleting_org_policy_for_insert,
    "db.error_deleting_org_policy_for_insert",
    "Error deleting org_policy for insert",
    "Ошибка удаления org_policy перед вставкой"
);
localized_msg!(
    db_error_deleting_org_policy,
    "db.error_deleting_org_policy",
    "Error deleting org_policy",
    "Ошибка удаления org_policy"
);
localized_msg!(
    db_error_saving_organization,
    "db.error_saving_organization",
    "Error saving organization",
    "Ошибка сохранения organization"
);
localized_msg!(
    db_billing_email_not_valid,
    "db.billing_email_not_valid",
    "BillingEmail is not a valid email address",
    "BillingEmail не является корректным email адресом"
);
localized_msg!(
    db_error_adding_user_to_organization,
    "db.error_adding_user_to_organization",
    "Error adding user to organization",
    "Ошибка добавления пользователя в organization"
);
localized_msg!(
    db_error_removing_user_from_organization,
    "db.error_removing_user_from_organization",
    "Error removing user from organization",
    "Ошибка удаления пользователя из organization"
);
localized_msg!(
    db_error_confirming_invitations,
    "db.error_confirming_invitations",
    "Error confirming invitations",
    "Ошибка подтверждения приглашений"
);
localized_msg!(
    db_error_removing_organization_api_key_from_organization,
    "db.error_removing_organization_api_key_from_organization",
    "Error removing organization api key from organization",
    "Ошибка удаления organization api key из organization"
);
localized_msg!(db_error_saving_user, "db.error_saving_user", "Error saving user", "Ошибка сохранения user");
localized_msg!(
    db_user_email_not_valid,
    "db.user_email_not_valid",
    "User email is not a valid email address",
    "Email пользователя не является корректным email адресом"
);
localized_msg!(db_error_deleting_user, "db.error_deleting_user", "Error deleting user", "Ошибка удаления user");
localized_msg!(
    db_error_updating_revision_date_for_all_users,
    "db.error_updating_revision_date_for_all_users",
    "Error updating revision date for all users",
    "Ошибка обновления даты ревизии для всех пользователей"
);
localized_msg!(
    db_error_updating_user_revision,
    "db.error_updating_user_revision",
    "Error updating user revision",
    "Ошибка обновления ревизии user"
);
localized_msg!(
    db_error_saving_invitation,
    "db.error_saving_invitation",
    "Error saving invitation",
    "Ошибка сохранения invitation"
);
localized_msg!(
    db_invitation_email_not_valid,
    "db.invitation_email_not_valid",
    "Invitation email is not a valid email address",
    "Email приглашения не является корректным email адресом"
);
localized_msg!(
    db_error_deleting_invitation,
    "db.error_deleting_invitation",
    "Error deleting invitation",
    "Ошибка удаления invitation"
);
localized_msg!(
    db_error_saving_sso_user,
    "db.error_saving_sso_user",
    "Error saving SSO user",
    "Ошибка сохранения SSO user"
);
localized_msg!(
    db_error_deleting_sso_user,
    "db.error_deleting_sso_user",
    "Error deleting sso user",
    "Ошибка удаления sso user"
);
localized_msg!(
    db_emergency_access_initiation_date_missing,
    "db.emergency_access_initiation_date_missing",
    "Emergency access initiation date missing!",
    "Отсутствует дата инициации экстренного доступа!"
);
localized_msg!(
    db_emergency_access_deadline_invalid,
    "db.emergency_access_deadline_invalid",
    "Emergency access deadline is invalid",
    "Некорректный срок экстренного доступа"
);
localized_msg!(
    db_error_saving_emergency_access,
    "db.error_saving_emergency_access",
    "Error saving emergency access",
    "Ошибка сохранения emergency access"
);
localized_msg!(
    db_error_updating_emergency_access_status,
    "db.error_updating_emergency_access_status",
    "Error updating emergency access status",
    "Ошибка обновления статуса emergency access"
);
localized_msg!(
    db_error_removing_user_from_emergency_access,
    "db.error_removing_user_from_emergency_access",
    "Error removing user from emergency access",
    "Ошибка удаления пользователя из emergency access"
);
localized_msg!(db_error_saving_event, "db.error_saving_event", "Error saving event", "Ошибка сохранения event");
localized_msg!(db_error_deleting_event, "db.error_deleting_event", "Error deleting event", "Ошибка удаления event");
localized_msg!(
    db_error_cleaning_old_events,
    "db.error_cleaning_old_events",
    "Error cleaning old events",
    "Ошибка очистки старых событий"
);
localized_msg!(
    db_error_adding_favorite,
    "db.error_adding_favorite",
    "Error adding favorite",
    "Ошибка добавления favorite"
);
localized_msg!(
    db_error_removing_favorite,
    "db.error_removing_favorite",
    "Error removing favorite",
    "Ошибка удаления favorite"
);
localized_msg!(
    db_error_removing_favorites_by_cipher,
    "db.error_removing_favorites_by_cipher",
    "Error removing favorites by cipher",
    "Ошибка удаления favorites по cipher"
);
localized_msg!(
    db_error_removing_favorites_by_user,
    "db.error_removing_favorites_by_user",
    "Error removing favorites by user",
    "Ошибка удаления favorites по пользователю"
);
localized_msg!(db_error_saving_folder, "db.error_saving_folder", "Error saving folder", "Ошибка сохранения folder");
localized_msg!(db_error_deleting_folder, "db.error_deleting_folder", "Error deleting folder", "Ошибка удаления folder");
localized_msg!(
    db_error_adding_cipher_to_folder,
    "db.error_adding_cipher_to_folder",
    "Error adding cipher to folder",
    "Ошибка добавления cipher в folder"
);
localized_msg!(
    db_error_removing_cipher_from_folder,
    "db.error_removing_cipher_from_folder",
    "Error removing cipher from folder",
    "Ошибка удаления cipher из folder"
);
localized_msg!(
    db_error_removing_cipher_from_folders,
    "db.error_removing_cipher_from_folders",
    "Error removing cipher from folders",
    "Ошибка удаления cipher из folders"
);
localized_msg!(
    db_error_removing_ciphers_from_folder,
    "db.error_removing_ciphers_from_folder",
    "Error removing ciphers from folder",
    "Ошибка удаления ciphers из folder"
);
localized_msg!(
    mail_sendmail_client_error,
    "mail.sendmail_client_error",
    "Sendmail client error",
    "Ошибка клиента Sendmail"
);
localized_msg!(
    mail_sendmail_response_error,
    "mail.sendmail_response_error",
    "Sendmail response error",
    "Ошибка ответа Sendmail"
);
localized_msg!(mail_sendmail_error, "mail.sendmail_error", "Sendmail error", "Ошибка Sendmail");
localized_msg!(mail_smtp_client_error, "mail.smtp_client_error", "SMTP client error", "Ошибка SMTP-клиента");
localized_msg!(mail_smtp_4xx_error, "mail.smtp_4xx_error", "SMTP 4xx error", "SMTP ошибка 4xx");
localized_msg!(mail_smtp_5xx_error, "mail.smtp_5xx_error", "SMTP 5xx error", "SMTP ошибка 5xx");
localized_msg!(mail_smtp_timeout_error, "mail.smtp_timeout_error", "SMTP timeout error", "SMTP ошибка таймаута");
localized_msg!(
    mail_smtp_encryption_error,
    "mail.smtp_encryption_error",
    "SMTP encryption error",
    "SMTP ошибка шифрования"
);
localized_msg!(mail_smtp_error, "mail.smtp_error", "SMTP error", "Ошибка SMTP");
localized_msg!(
    emergency_access_not_valid,
    "emergency_access.not_valid",
    "Emergency access not valid.",
    "Экстренный доступ недействителен."
);
localized_msg!(
    emergency_access_invalid_type,
    "emergency_access.invalid_type",
    "Invalid emergency access type.",
    "Некорректный тип экстренного доступа."
);
localized_msg!(
    emergency_access_wait_time_out_of_bounds,
    "emergency_access.wait_time_out_of_bounds",
    "Emergency access wait time is out-of-bounds!",
    "Время ожидания экстренного доступа вне допустимых границ!"
);
localized_msg!(
    emergency_access_cannot_set_self,
    "emergency_access.cannot_set_self",
    "You can not set yourself as an emergency contact.",
    "Нельзя указать себя как контакт экстренного доступа."
);
localized_msg!(
    emergency_access_email_domain_not_eligible,
    "emergency_access.email_domain_not_eligible",
    "Email domain not eligible for invitations",
    "Домен email не подходит для приглашений"
);
localized_msg!(
    emergency_access_grantee_already_accepted_or_confirmed,
    "emergency_access.grantee_already_accepted_or_confirmed",
    "The grantee user is already accepted or confirmed for emergency access",
    "Пользователь-получатель уже принял или подтвердил экстренный доступ"
);
localized_msg!(
    emergency_access_email_not_valid,
    "emergency_access.email_not_valid",
    "Email not valid.",
    "Email некорректен."
);
localized_msg!(
    emergency_access_grantee_not_found,
    "emergency_access.grantee_not_found",
    "Grantee user not found.",
    "Пользователь-получатель не найден."
);
localized_msg!(
    emergency_access_claim_email_mismatch,
    "emergency_access.claim_email_mismatch",
    "Claim email does not match current users email",
    "Email в claim не совпадает с текущим email пользователя"
);
localized_msg!(
    emergency_access_invited_user_not_found,
    "emergency_access.invited_user_not_found",
    "Invited user not found",
    "Приглашенный пользователь не найден"
);
localized_msg!(
    emergency_access_grantor_not_found,
    "emergency_access.grantor_not_found",
    "Grantor user not found.",
    "Пользователь-грантор не найден."
);
localized_msg!(
    emergency_access_invitation_error,
    "emergency_access.invitation_error",
    "Emergency access invitation error.",
    "Ошибка приглашения экстренного доступа."
);
localized_msg!(
    emergency_access_kdf_mismatch_grantor,
    "emergency_access.kdf_mismatch_grantor",
    "KDF settings do not match the grantor account",
    "Параметры KDF не совпадают с учетной записью грантора"
);
localized_msg!(
    emergency_access_invalid_request,
    "emergency_access.invalid_request",
    "Invalid request!",
    "Некорректный запрос!"
);
localized_msg!(
    emergency_access_not_enabled,
    "emergency_access.not_enabled",
    "Emergency access is not enabled.",
    "Экстренный доступ не включен."
);
localized_msg!(
    emergency_access_status_changed_already,
    "emergency_access.status_changed_already",
    "Emergency access status was changed already",
    "Статус экстренного доступа уже был изменен"
);
localized_msg!(
    emergency_access_error_updating_status,
    "emergency_access.error_updating_status",
    "Error updating emergency access status",
    "Ошибка обновления статуса экстренного доступа"
);
localized_msg!(
    emergency_access_user_email_mismatch_invite,
    "emergency_access.user_email_mismatch_invite",
    "User email does not match invite.",
    "Email пользователя не совпадает с приглашением."
);
localized_msg!(
    emergency_access_contact_already_accepted,
    "emergency_access.contact_already_accepted",
    "Emergency contact already accepted.",
    "Контакт экстренного доступа уже принял приглашение."
);
localized_msg!(
    emergency_access_grantee_user_not_exists,
    "emergency_access.grantee_user_not_exists",
    "Grantee user does not exist",
    "Пользователь-получатель не существует"
);
localized_msg!(
    emergency_access_grantee_user_already_invited,
    "emergency_access.grantee_user_already_invited",
    "Grantee user already invited",
    "Пользователь-получатель уже приглашен"
);
localized_msg!(folder_invalid, "folder.invalid", "Invalid folder", "Некорректная папка");
localized_msg!(
    folder_not_found_or_not_owned,
    "folder.not_found_or_not_owned",
    "Folder does not exist or belongs to another user",
    "Папка не существует или принадлежит другому пользователю"
);
localized_msg!(
    org_error_lookup_organization_short,
    "org.error_lookup_organization_short",
    "Error looking up organization",
    "Ошибка при поиске организации"
);
localized_msg!(org_not_found_short, "org.not_found_short", "Organization not found.", "Организация не найдена.");
localized_msg!(
    org_user_already_accepted_invite,
    "org.user_already_accepted_invite",
    "User already accepted the invitation",
    "Пользователь уже принял приглашение"
);
localized_msg!(
    org_user_already_in_organization,
    "org.user_already_in_organization",
    "User already in organization",
    "Пользователь уже в организации"
);
localized_msg!(
    org_error_sending_invite,
    "org.error_sending_invite",
    "Error sending invite",
    "Ошибка отправки приглашения"
);
localized_msg!(
    org_error_sending_user_reset_password_email,
    "org.error_sending_user_reset_password_email",
    "Error sending user reset password email",
    "Ошибка отправки email о сбросе пароля пользователя"
);
localized_msg!(
    org_policy_cannot_because_2fa_required,
    "org.policy_cannot_because_2fa_required",
    "Cannot proceed because 2FA is required",
    "Невозможно выполнить действие, так как требуется 2FA"
);
localized_msg!(
    org_policy_cannot_because_other_org_policy_forbids,
    "org.policy_cannot_because_other_org_policy_forbids",
    "Cannot proceed because another organization policy forbids it",
    "Невозможно выполнить действие, так как это запрещено политикой другой организации"
);
localized_msg!(cipher_not_found, "cipher.not_found", "Cipher doesn't exist", "Шифр не существует");
localized_msg!(
    cipher_not_owned_by_user,
    "cipher.not_owned_by_user",
    "Cipher is not owned by user",
    "Шифр не принадлежит пользователю"
);
localized_msg!(
    cipher_personal_vault_restricted,
    "cipher.personal_vault_restricted",
    "Due to an Enterprise Policy, you are restricted from saving items to your personal vault.",
    "Из-за корпоративной политики вам запрещено сохранять элементы в личном хранилище."
);
localized_msg!(
    cipher_client_copy_outdated,
    "cipher.client_copy_outdated",
    "The client copy of this cipher is out of date. Resync the client and try again.",
    "Локальная копия этого шифра устарела. Синхронизируйте клиент и попробуйте снова."
);
localized_msg!(
    cipher_organization_mismatch,
    "cipher.organization_mismatch",
    "Organization mismatch. Please resync the client before updating the cipher",
    "Несоответствие организации. Синхронизируйте клиент перед обновлением шифра"
);
localized_msg!(
    cipher_no_permission_add_item_to_org,
    "cipher.no_permission_add_item_to_org",
    "You don't have permission to add item to organization",
    "У вас нет прав добавлять элемент в организацию"
);
localized_msg!(
    cipher_no_permission_add_cipher_direct_to_org,
    "cipher.no_permission_add_cipher_direct_to_org",
    "You don't have permission to add cipher directly to organization",
    "У вас нет прав добавлять шифр напрямую в организацию"
);
localized_msg!(cipher_invalid_type, "cipher.invalid_type", "Invalid type", "Некорректный тип");
localized_msg!(cipher_data_missing, "cipher.data_missing", "Data missing", "Отсутствуют данные");
localized_msg!(
    cipher_notes_exceeds_max_len,
    "cipher.notes_exceeds_max_len",
    "The field Notes exceeds the maximum encrypted value length of {} characters.",
    "Поле Notes превышает максимальную длину зашифрованного значения: {} символов."
);
localized_msg!(
    cipher_password_history_null_only_strings,
    "cipher.password_history_null_only_strings",
    "The password history contains a `null` value. Only strings are allowed.",
    "История паролей содержит значение `null`. Допускаются только строки."
);
localized_msg!(
    cipher_model_state_invalid,
    "cipher.model_state_invalid",
    "The model state is invalid.",
    "Состояние модели некорректно."
);
localized_msg!(
    cipher_import_validation_errors,
    "cipher.import_validation_errors",
    "Import validation errors",
    "Ошибки валидации импорта"
);
localized_msg!(
    cipher_not_write_accessible,
    "cipher.not_write_accessible",
    "Cipher is not write accessible",
    "Шифр недоступен для записи"
);
localized_msg!(
    cipher_collection_cannot_be_changed,
    "cipher.collection_cannot_be_changed",
    "Collection cannot be changed",
    "Коллекцию нельзя изменить"
);
localized_msg!(
    cipher_not_owned_by_org,
    "cipher.not_owned_by_org",
    "Cipher is not owned by an organization",
    "Шифр не принадлежит организации"
);
localized_msg!(
    cipher_invalid_collection_id,
    "cipher.invalid_collection_id",
    "Invalid collection ID provided",
    "Указан некорректный ID коллекции"
);
localized_msg!(
    cipher_no_rights_modify_collection,
    "cipher.no_rights_modify_collection",
    "No rights to modify the collection",
    "Недостаточно прав для изменения коллекции"
);
localized_msg!(
    cipher_organization_id_required,
    "cipher.organization_id_required",
    "Cipher OrganizationId is required.",
    "Требуется OrganizationId для шифра."
);
localized_msg!(
    cipher_at_least_one_collection_required,
    "cipher.at_least_one_collection_required",
    "You must select at least one collection.",
    "Нужно выбрать хотя бы одну коллекцию."
);
localized_msg!(
    cipher_at_least_one_cipher_required,
    "cipher.at_least_one_cipher_required",
    "You must select at least one cipher.",
    "Нужно выбрать хотя бы один шифр."
);
localized_msg!(
    cipher_request_missing_ids,
    "cipher.request_missing_ids",
    "Request missing ids field",
    "В запросе отсутствует поле ids"
);
localized_msg!(cipher_not_accessible, "cipher.not_accessible", "Cipher is not accessible", "Шифр недоступен");
localized_msg!(
    cipher_neither_user_nor_org_owned,
    "cipher.neither_user_nor_org_owned",
    "Cipher is neither owned by a user nor an organization",
    "Шифр не принадлежит ни пользователю, ни организации"
);
localized_msg!(
    cipher_attachments_disabled,
    "cipher.attachments_disabled",
    "Attachments are disabled",
    "Вложения отключены"
);
localized_msg!(
    cipher_attachment_size_overflow,
    "cipher.attachment_size_overflow",
    "Attachment size overflow",
    "Переполнение размера вложения"
);
localized_msg!(
    cipher_attachment_storage_limit_reached,
    "cipher.attachment_storage_limit_reached",
    "Attachment storage limit reached! Delete some attachments to free up space",
    "Достигнут лимит хранилища вложений! Удалите часть вложений, чтобы освободить место"
);
localized_msg!(
    cipher_attachment_size_negative,
    "cipher.attachment_size_negative",
    "Attachment size can't be negative",
    "Размер вложения не может быть отрицательным"
);
localized_msg!(
    cipher_max_file_size_525mb,
    "cipher.max_file_size_525mb",
    "Max file size is 525 MB.",
    "Максимальный размер файла 525 MB."
);
localized_msg!(
    cipher_attachment_storage_limit_exceeded_file,
    "cipher.attachment_storage_limit_exceeded_file",
    "Attachment storage limit exceeded with this file",
    "Лимит хранилища вложений будет превышен этим файлом"
);
localized_msg!(
    cipher_attachment_size_mismatch,
    "cipher.attachment_size_mismatch",
    "Attachment size mismatch",
    "Несоответствие размера вложения"
);
localized_msg!(
    cipher_attachment_data_size_overflow,
    "cipher.attachment_data_size_overflow",
    "Attachment data size overflow",
    "Переполнение размера данных вложения"
);
localized_msg!(
    cipher_invalid_attachment_size_max,
    "cipher.invalid_attachment_size_max",
    "Invalid attachment size max",
    "Некорректный максимальный размер вложения"
);
localized_msg!(
    cipher_invalid_attachment_size_min,
    "cipher.invalid_attachment_size_min",
    "Invalid attachment size min",
    "Некорректный минимальный размер вложения"
);
localized_msg!(
    cipher_no_filename_provided,
    "cipher.no_filename_provided",
    "No filename provided",
    "Имя файла не предоставлено"
);
localized_msg!(
    cipher_no_attachment_key_provided,
    "cipher.no_attachment_key_provided",
    "No attachment key provided",
    "Ключ вложения не предоставлен"
);
localized_msg!(
    cipher_attachment_not_belong_to_cipher,
    "cipher.attachment_not_belong_to_cipher",
    "Attachment doesn't belong to cipher",
    "Вложение не принадлежит этому шифру"
);
localized_msg!(
    cipher_attachment_not_found,
    "cipher.attachment_not_found",
    "Attachment doesn't exist",
    "Вложение не найдено"
);
localized_msg!(
    cipher_no_permission_purge_org_vault,
    "cipher.no_permission_purge_org_vault",
    "You don't have permission to purge the organization vault",
    "У вас нет прав очищать хранилище организации"
);
localized_msg!(
    cipher_cannot_be_deleted_by_user,
    "cipher.cannot_be_deleted_by_user",
    "Cipher can't be deleted by user",
    "Пользователь не может удалить этот шифр"
);
localized_msg!(
    cipher_cannot_be_restored_by_user,
    "cipher.cannot_be_restored_by_user",
    "Cipher can't be restored by user",
    "Пользователь не может восстановить этот шифр"
);
localized_msg!(
    cipher_attachment_from_other_cipher,
    "cipher.attachment_from_other_cipher",
    "Attachment from other cipher",
    "Вложение относится к другому шифру"
);
localized_msg!(
    cipher_cannot_delete_by_user,
    "cipher.cannot_delete_by_user",
    "Cipher cannot be deleted by user",
    "Этот шифр нельзя удалить пользователю"
);
localized_msg!(
    cipher_not_accessible_for_current_user,
    "cipher.not_accessible_for_current_user",
    "Cipher is not accessible for the current user",
    "Шифр недоступен текущему пользователю"
);
localized_msg!(
    cipher_couldnt_move_from_previous_folder,
    "cipher.couldnt_move_from_previous_folder",
    "Couldn't move from previous folder",
    "Не удалось переместить из предыдущей папки"
);
localized_msg!(org_not_found, "org.not_found", "Organization not found", "Организация не найдена");
localized_msg!(
    org_member_required,
    "org.member_required",
    "You need to be a Member of the Organization to call this endpoint",
    "Для вызова этого endpoint необходимо быть участником организации"
);
localized_msg!(
    org_user_not_part,
    "org.user_not_part",
    "User is not part of organization",
    "Пользователь не состоит в организации"
);
localized_msg!(org_invalid_type, "org.invalid_type", "Invalid type", "Некорректный тип");
localized_msg!(
    org_only_owners_invite_privileged,
    "org.only_owners_invite_privileged",
    "Only Owners can invite Managers, Admins or Owners",
    "Только владельцы могут приглашать менеджеров, администраторов или владельцев"
);
localized_msg!(
    org_user_not_member,
    "org.user_not_member",
    "The specified user isn't a member of the organization",
    "Указанный пользователь не является участником организации"
);
localized_msg!(
    org_only_owners_confirm_privileged,
    "org.only_owners_confirm_privileged",
    "Only Owners can confirm Managers, Admins or Owners",
    "Только владельцы могут подтверждать менеджеров, администраторов или владельцев"
);
localized_msg!(
    org_user_invalid_state,
    "org.user_invalid_state",
    "User in invalid state",
    "Пользователь в недопустимом состоянии"
);
localized_msg!(
    org_only_owners_grant_remove_privileged,
    "org.only_owners_grant_remove_privileged",
    "Only Owners can grant and remove Admin or Owner privileges",
    "Только владельцы могут выдавать или удалять права администратора/владельца"
);
localized_msg!(
    org_only_owners_edit_owner_users,
    "org.only_owners_edit_owner_users",
    "Only Owners can edit Owner users",
    "Только владельцы могут редактировать пользователей-владельцев"
);
localized_msg!(
    org_cannot_delete_last_owner,
    "org.cannot_delete_last_owner",
    "Can't delete the last owner",
    "Нельзя удалить последнего владельца"
);
localized_msg!(
    org_user_not_invited,
    "org.user_not_invited",
    "The user hasn't been invited to the organization.",
    "Пользователь не был приглашен в организацию."
);
localized_msg!(
    org_user_already_accepted_or_confirmed,
    "org.user_already_accepted_or_confirmed",
    "The user is already accepted or confirmed to the organization",
    "Пользователь уже принял приглашение или подтвержден в организации"
);
localized_msg!(org_user_not_found, "org.user_not_found", "User not found.", "Пользователь не найден.");
localized_msg!(
    org_invitations_not_allowed,
    "org.invitations_not_allowed",
    "Invitations are not allowed.",
    "Приглашения не разрешены."
);
localized_msg!(
    org_key_or_userid_not_set,
    "org.key_or_userid_not_set",
    "Key or UserId is not set, unable to process request",
    "Ключ или UserId не задан, невозможно обработать запрос"
);
localized_msg!(
    org_user_to_delete_not_member,
    "org.user_to_delete_not_member",
    "User to delete isn't member of the organization",
    "Удаляемый пользователь не является участником организации"
);
localized_msg!(
    org_only_owners_delete_admin_owner,
    "org.only_owners_delete_admin_owner",
    "Only Owners can delete Admins or Owners",
    "Только владельцы могут удалять администраторов или владельцев"
);
localized_msg!(
    org_cannot_revoke_yourself,
    "org.cannot_revoke_yourself",
    "You cannot revoke yourself",
    "Нельзя отозвать самого себя"
);
localized_msg!(
    org_only_owners_revoke_owners,
    "org.only_owners_revoke_owners",
    "Only owners can revoke other owners",
    "Только владельцы могут отзывать других владельцев"
);
localized_msg!(
    org_must_have_confirmed_owner,
    "org.must_have_confirmed_owner",
    "Organization must have at least one confirmed owner",
    "В организации должен быть хотя бы один подтвержденный владелец"
);
localized_msg!(
    org_user_already_revoked,
    "org.user_already_revoked",
    "User is already revoked",
    "Пользователь уже отозван"
);
localized_msg!(
    org_user_not_found_in_org,
    "org.user_not_found_in_org",
    "User not found in organization",
    "Пользователь не найден в организации"
);
localized_msg!(
    org_cannot_restore_yourself,
    "org.cannot_restore_yourself",
    "You cannot restore yourself",
    "Нельзя восстановить самого себя"
);
localized_msg!(
    org_only_owners_restore_owners,
    "org.only_owners_restore_owners",
    "Only owners can restore other owners",
    "Только владельцы могут восстанавливать других владельцев"
);
localized_msg!(
    org_user_already_active,
    "org.user_already_active",
    "User is already active",
    "Пользователь уже активен"
);
localized_msg!(org_groups_disabled, "org.groups_disabled", "Group support is disabled", "Поддержка групп отключена");
localized_msg!(org_group_not_found, "org.group_not_found", "Group not found", "Группа не найдена");
localized_msg!(
    org_password_reset_not_enrolled,
    "org.password_reset_not_enrolled",
    "Password reset not or not correctly enrolled",
    "Сброс пароля не подключен или настроен некорректно"
);
localized_msg!(
    org_user_must_be_confirmed_for_reset,
    "org.user_must_be_confirmed_for_reset",
    "Organization user must be confirmed for password reset functionality",
    "Пользователь организации должен быть подтвержден для функции сброса пароля"
);
localized_msg!(
    org_kdf_settings_do_not_match_user,
    "org.kdf_settings_do_not_match_user",
    "KDF settings do not match the user account",
    "Настройки KDF не совпадают с учетной записью пользователя"
);
localized_msg!(
    org_no_permission_reset_user_password,
    "org.no_permission_reset_user_password",
    "No permission to reset this user's password",
    "Нет прав для сброса пароля этого пользователя"
);
localized_msg!(
    org_password_reset_not_supported_email_disabled,
    "org.password_reset_not_supported_email_disabled",
    "Password reset is not supported on an email-disabled instance.",
    "Сброс пароля не поддерживается, если email отключен на инстансе."
);
localized_msg!(org_policy_not_found, "org.policy_not_found", "Policy not found", "Политика не найдена");
localized_msg!(
    org_reset_password_policy_not_enabled,
    "org.reset_password_policy_not_enabled",
    "Reset password policy not enabled",
    "Политика сброса пароля не включена"
);
localized_msg!(
    org_reset_password_withdraw_blocked_by_policy,
    "org.reset_password_withdraw_blocked_by_policy",
    "Reset password can't be withdrawn due to an enterprise policy",
    "Нельзя отключить сброс пароля из-за политики организации"
);
localized_msg!(
    org_cannot_leave_last_owner,
    "org.cannot_leave_last_owner",
    "The last owner can't leave",
    "Последний владелец не может покинуть организацию"
);
localized_msg!(
    org_no_permission_create_collections,
    "org.no_permission_create_collections",
    "You don't have permission to create collections",
    "У вас нет прав для создания коллекций"
);
localized_msg!(org_collection_not_found, "org.collection_not_found", "Collection not found", "Коллекция не найдена");
localized_msg!(
    org_keys_already_exist,
    "org.keys_already_exist",
    "Organization Keys already exist",
    "Ключи организации уже существуют"
);
localized_msg!(
    org_invitation_issued_to_different_account,
    "org.invitation_issued_to_different_account",
    "Invitation was issued to a different account",
    "Приглашение было выдано для другой учетной записи"
);
localized_msg!(
    org_error_accepting_invitation,
    "org.error_accepting_invitation",
    "Error accepting the invitation",
    "Ошибка при принятии приглашения"
);
localized_msg!(
    org_claim_mismatch_user_id,
    "org.claim_mismatch_user_id",
    "Claim does not match user_id",
    "Клейм не соответствует user_id"
);
localized_msg!(
    org_claim_mismatch_org_id,
    "org.claim_mismatch_org_id",
    "Claim does not match the org_id",
    "Клейм не соответствует org_id"
);
localized_msg!(
    org_claim_mismatch_member_id,
    "org.claim_mismatch_member_id",
    "Claim does not match the member_id",
    "Клейм не соответствует member_id"
);
localized_msg!(
    org_reset_password_key_required,
    "org.reset_password_key_required",
    "Reset password key is required, but not provided.",
    "Ключ сброса пароля обязателен, но не предоставлен."
);
localized_msg!(org_invalid_group, "org.invalid_group", "Invalid group", "Некорректная группа");
localized_msg!(org_invalid_member, "org.invalid_member", "Invalid member", "Некорректный участник");
localized_msg!(org_invalid_collection, "org.invalid_collection", "Invalid collection", "Некорректная коллекция");
localized_msg!(
    org_user_not_allowed_create,
    "org.user_not_allowed_create",
    "User not allowed to create organizations",
    "Пользователю запрещено создавать организации"
);
localized_msg!(
    org_single_org_policy_prohibits_membership,
    "org.single_org_policy_prohibits_membership",
    "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization.",
    "Вы не можете создать организацию. Вы состоите в организации, политика которой запрещает быть участником других организаций."
);
localized_msg!(
    org_error_lookup_organization,
    "org.error_lookup_organization",
    "Error looking up organization.",
    "Ошибка при поиске организации."
);
localized_msg!(
    org_error_lookup_user,
    "org.error_lookup_user",
    "Error looking up user.",
    "Ошибка при поиске пользователя."
);
localized_msg!(
    org_member_id_required,
    "org.member_id_required",
    "Member id is required",
    "Требуется идентификатор участника"
);
localized_msg!(
    org_token_org_mismatch,
    "org.token_org_mismatch",
    "Token doesn't match request organization",
    "Токен не соответствует запрошенной организации"
);
localized_msg!(
    org_single_org_policy_required_for_reset,
    "org.single_org_policy_required_for_reset",
    "Single Organization policy is not enabled. It is mandatory for this policy to be enabled.",
    "Политика Single Organization не включена. Для этого действия она должна быть включена."
);
localized_msg!(
    org_account_recovery_policy_blocks_disable,
    "org.account_recovery_policy_blocks_disable",
    "Account recovery policy is enabled. It is not allowed to disable this policy.",
    "Политика восстановления учетной записи включена. Отключение этой политики не допускается."
);

#[cfg(test)]
mod tests {
    use super::{
        locale_candidates, normalize_locale, preferred_from_accept_language, resolve_locale, to_client_culture,
    };

    #[test]
    fn normalize_empty_to_en() {
        assert_eq!(normalize_locale("  "), "en");
    }

    #[test]
    fn normalize_underscored_locale() {
        assert_eq!(normalize_locale("RU_ru"), "ru-ru");
    }

    #[test]
    fn candidates_keep_region_and_language() {
        assert_eq!(locale_candidates("pt-BR"), vec!["pt-br", "pt", "en"]);
    }

    #[test]
    fn candidates_from_language_only() {
        assert_eq!(locale_candidates("ru"), vec!["ru", "en"]);
    }

    #[test]
    fn parse_accept_language_first_entry() {
        assert_eq!(preferred_from_accept_language("uk-UA,uk;q=0.9,en;q=0.8"), Some("uk-ua".to_owned()));
    }

    #[test]
    fn resolve_locale_priority_user_then_accept_then_default() {
        assert_eq!(resolve_locale(Some("ru_RU"), Some("uk-UA,uk;q=0.9"), "en"), "ru-ru");
        assert_eq!(resolve_locale(None, Some("uk-UA,uk;q=0.9"), "en"), "uk-ua");
        assert_eq!(resolve_locale(None, None, "en"), "en");
    }

    #[test]
    fn client_culture_uses_uppercase_region() {
        assert_eq!(to_client_culture("en-us"), "en-US");
        assert_eq!(to_client_culture("ru"), "ru");
    }
}
