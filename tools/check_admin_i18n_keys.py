#!/usr/bin/env python3
"""Validate Admin UI translation key coverage.

This script extracts i18n keys referenced by ``src/static/scripts/admin*.js``
and verifies they exist in every discovered
``src/static/locales/<locale>/admin_ui.json`` dictionary.
It also ensures inline fallback dictionaries are not reintroduced into admin
templates.

Exit status:
- 0: all checks passed
- 1: missing keys, missing required locales, or inline dictionary violations
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "src" / "static" / "scripts"
LOCALES_DIR = ROOT / "src" / "static" / "locales"
REQUIRED_LOCALES = {"en", "ru"}
TEMPLATE_FILES = [
    *sorted((ROOT / "src" / "static" / "templates" / "admin").glob("**/base.hbs")),
]

KEY_PATTERN = re.compile(r't(?:Admin|Users|Orgs|Settings|Diag)\("([a-z0-9_]+)"\)')
INLINE_DICT_MARKER = "window.VW_ADMIN_I18N = {"


def read_admin_js_keys() -> set[str]:
    keys: set[str] = set()
    for script_path in sorted(SCRIPTS_DIR.glob("admin*.js")):
        content = script_path.read_text(encoding="utf-8")
        keys.update(KEY_PATTERN.findall(content))
    return keys


def read_locale_keys(locale_path: Path) -> set[str]:
    with locale_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    if not isinstance(payload, dict):
        raise ValueError(f"Locale file must contain JSON object: {locale_path}")

    return set(payload.keys())


def discover_locale_files() -> dict[str, Path]:
    locales: dict[str, Path] = {}
    for locale_dir in sorted(LOCALES_DIR.iterdir()):
        if not locale_dir.is_dir():
            continue
        locale_file = locale_dir / "admin_ui.json"
        if locale_file.exists():
            locales[locale_dir.name] = locale_file
    return locales


def check_no_inline_dicts() -> list[str]:
    violations: list[str] = []
    for template_path in TEMPLATE_FILES:
        if not template_path.exists():
            continue
        content = template_path.read_text(encoding="utf-8")
        if INLINE_DICT_MARKER in content:
            violations.append(str(template_path.relative_to(ROOT)))
    return violations


def main() -> int:
    js_keys = read_admin_js_keys()
    if not js_keys:
        print("ERROR: No admin i18n keys found in src/static/scripts/admin*.js")
        return 1

    failed = False

    locale_files = discover_locale_files()
    if not locale_files:
        print("ERROR: No admin_ui.json locale files found in src/static/locales/<locale>/")
        failed = True

    missing_required_locales = sorted(REQUIRED_LOCALES - set(locale_files.keys()))
    if missing_required_locales:
        failed = True
        print("ERROR: Missing required locale dictionaries:")
        for locale in missing_required_locales:
            print(f"  - src/static/locales/{locale}/admin_ui.json")

    for locale, locale_path in locale_files.items():
        locale_keys = read_locale_keys(locale_path)
        missing = sorted(js_keys - locale_keys)

        if missing:
            failed = True
            print(f"ERROR: Missing keys in {locale_path.relative_to(ROOT)}:")
            for key in missing:
                print(f"  - {key}")
        else:
            print(f"OK: {locale} locale covers all {len(js_keys)} admin JS keys")

    inline_violations = check_no_inline_dicts()
    if inline_violations:
        failed = True
        print("ERROR: Inline admin dictionaries are not allowed in templates:")
        for file_path in inline_violations:
            print(f"  - {file_path}")
    else:
        print("OK: No inline admin dictionaries in admin base templates")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
