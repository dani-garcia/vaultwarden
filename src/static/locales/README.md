# Built-in locale modules

Built-in catalogs are split by language and loaded from this tree at compile time.
All locale directories are auto-discovered from:

- `src/static/locales/<locale>/*.json`

This means adding a new language under `src/static/locales/<locale>/` does not require updating hardcoded locale lists in Rust code.

Current built-in modules:

- `api.json`
- `admin.json`
- `identity.json`
- `auth.json`
- `accounts.json`
- `org.json`
- `ciphers.json`
- `sends.json`
- `two_factor.json`
- `emergency_access.json`
- `config.json`

Each JSON file is a flat key-value dictionary.

## Admin UI locale files

Admin UI dictionaries are loaded from:

- `src/static/locales/<locale>/admin_ui.json`

Release static serving for `/vw_static/locales/<locale>/admin_ui.json` auto-discovers these files from all built-in locale directories.

## Runtime extensions

Runtime overrides/extensions from `DATA_FOLDER/locales` support both layouts:

- Single file per locale: `DATA_FOLDER/locales/<locale>.json`
- Modular directory per locale: `DATA_FOLDER/locales/<locale>/*.json`

Runtime values are merged in lexical filename order and override built-in keys.
This allows adding new languages and shipping custom translation modules without recompilation.
