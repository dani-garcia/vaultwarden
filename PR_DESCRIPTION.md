### Title: feat: Add extensible i18n architecture for admin interface and templates

## Summary
This PR introduces an extensible i18n architecture for server-rendered templates, backend notifications, and Admin UI strings. The core design keeps default behavior deterministic and zero-cost with compile-time embedded catalogs, while enabling runtime locale overrides for self-hosters.

## Motivation
Vaultwarden has historically lacked localized coverage in the `/admin` interface and template-driven surfaces. This PR:
- Centralizes locale dictionaries under `src/static/locales/<locale>/`.
- Removes hardcoded locale lists by leveraging directory auto-discovery at compile time.
- Enforces strict translation coverage and schema parity using lightweight CI quality gates.

## Key Features
1. **Extensible Compile-Time Locale Discovery**:
   - Base catalogs are embedded via `include_dir`.
   - New languages added under `src/static/locales/<locale>/` are picked up automatically without modifying Rust source files.
2. **Runtime Override Support**:
   - Self-hosters can supply custom translations via `DATA_FOLDER/locales` (single-file `<locale>.json` or directory `<locale>/*.json`).
3. **Admin Frontend Serving**:
   - `admin_ui.json` dictionaries are automatically exposed at `/vw_static/locales/<locale>/admin_ui.json` and consumed by the admin client script.
4. **Fallback & Graceful Degradation**:
   - Robust fallback chain (`full-locale` -> `base-lang` -> `en`).
   - Missing keys render the key identifier safely instead of failing the render.
5. **Zero-Dependency CI Guards**:
   - Standalone Python standard-library scripts prevent missing keys, duplicate registrations, and inline dictionary regressions.

## Compatibility & Breaking Changes
- **Fully backward compatible**: Existing deployments, database backends, and environment configurations behave identically.
- **API integrity preserved**: Client-facing API payloads and error formats for official Bitwarden apps remain intact.

## Testing Performed
- **Validation Scripts (Python stdlib)**:
  - `python3 tools/check_template_locale_duplicates.py` (Passed)
  - `python3 tools/check_template_i18n_keys.py` (Passed)
  - `python3 tools/check_admin_i18n_keys.py` (Passed)
- **Engine Database Feature Matrix**:
  - `cargo check --features sqlite` (Passed)
  - `cargo check --features postgresql` (Passed)
  - `cargo check --features mysql` (Passed)
- **Formatting & Lints**:
  - `cargo fmt --all --check` (Passed)
  - `cargo clippy --all-targets -- -D warnings` (Passed)
- **Runtime Verification**:
  - Tested `/admin` localization with various `Accept-Language` headers (`ru`, `en-US`, unsupported fallbacks).
  - Verified static dictionary delivery under `/vw_static/locales/`.

## Documentation
A full architectural overview and contributor guide is provided in `docs/i18n.md`.
