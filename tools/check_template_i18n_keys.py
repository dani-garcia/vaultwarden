#!/usr/bin/env python3
"""Validate template translation key coverage.

This script collects keys used by the Handlebars helper ``{{t "..."}}``
in ``src/static/templates`` and verifies that every discovered locale catalog
under ``src/static/locales/<locale>/*.json`` defines those keys.

Exit status:
- 0: all checks passed
- 1: at least one key is missing or required locales are absent
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "src" / "static" / "templates"
LOCALES_DIR = ROOT / "src" / "static" / "locales"
REQUIRED_LOCALES = {"en", "ru"}

# Supports: {{t "key"}}, {{ t "key" locale=lang }}
KEY_PATTERN = re.compile(r"\{\{\s*t\s+\"([a-z0-9_.-]+)\"")


def discover_locale_catalogs() -> dict[str, dict[str, str]]:
    catalogs: dict[str, dict[str, str]] = {}

    for locale_dir in sorted(LOCALES_DIR.iterdir()):
        if not locale_dir.is_dir():
            continue

        merged: dict[str, str] = {}
        json_files = sorted(p for p in locale_dir.glob("*.json") if p.is_file())
        for file_path in json_files:
            with file_path.open("r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                raise ValueError(f"Locale file must contain JSON object: {file_path.relative_to(ROOT)}")
            for key, value in payload.items():
                if isinstance(key, str) and isinstance(value, str):
                    merged[key] = value

        if merged:
            catalogs[locale_dir.name] = merged

    return catalogs


def collect_template_keys() -> set[str]:
    keys: set[str] = set()
    for template_path in sorted(TEMPLATES_DIR.rglob("*.hbs")):
        content = template_path.read_text(encoding="utf-8")
        keys.update(KEY_PATTERN.findall(content))
    return keys


def main() -> int:
    template_keys = collect_template_keys()

    if not template_keys:
        print("OK: No template i18n helper keys found")
        return 0

    catalogs = discover_locale_catalogs()
    failed = False

    missing_required = sorted(REQUIRED_LOCALES - set(catalogs.keys()))
    if missing_required:
        failed = True
        print("ERROR: Missing required locale catalogs under src/static/locales/<locale>/*.json:")
        for locale in missing_required:
            print(f"  - {locale}")

    for locale, catalog in sorted(catalogs.items()):
        locale_keys = set(catalog.keys())
        missing = sorted(template_keys - locale_keys)
        if missing:
            failed = True
            print(f"ERROR: Missing template i18n keys in locale '{locale}':")
            for key in missing:
                print(f"  - {key}")
        else:
            print(f"OK: locale '{locale}' covers all {len(template_keys)} template i18n keys")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
