#!/usr/bin/env python3
"""Prevent locale-specific Handlebars template duplication.

This script enforces the shared-template + dictionary-based i18n model by
failing when locale-specific template files (for example ``templates/ru/...``)
or locale-specific template registrations are found.

Exit status:
- 0: no forbidden locale template files or registrations
- 1: forbidden locale template files or registrations found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "src" / "static" / "templates"
CONFIG_RS = ROOT / "src" / "config.rs"
LOCALE_DIR_PATTERN = re.compile(r"^[a-z]{2}(?:-[A-Za-z]{2})?$")


def collect_forbidden_template_files() -> list[Path]:
    forbidden: list[Path] = []

    for template_path in sorted(TEMPLATES_DIR.rglob("*.hbs")):
        rel = template_path.relative_to(TEMPLATES_DIR)
        parent_parts = rel.parts[:-1]
        if not parent_parts:
            continue

        # Forbid locale directories at template root: templates/ru/*.hbs
        if LOCALE_DIR_PATTERN.match(parent_parts[0]):
            forbidden.append(template_path)
            continue

        # Forbid locale directories under a template namespace: templates/email/ru/*.hbs
        if len(parent_parts) >= 2 and LOCALE_DIR_PATTERN.match(parent_parts[1]):
            forbidden.append(template_path)

    return forbidden


def collect_forbidden_template_registrations() -> list[str]:
    if not CONFIG_RS.exists():
        return []

    content = CONFIG_RS.read_text(encoding="utf-8")
    # Matches entries like: reg!("email/ru/verify_email", ".html");
    pattern = re.compile(r'reg!\(\s*"[^"/]+/([a-z]{2}(?:-[A-Za-z]{2})?)/[^"]+"')
    matches = []

    for match in pattern.finditer(content):
        locale = match.group(1)
        if LOCALE_DIR_PATTERN.match(locale):
            matches.append(match.group(0))

    return sorted(set(matches))


def main() -> int:
    failed = False

    forbidden_files = collect_forbidden_template_files()
    if forbidden_files:
        failed = True
        print("ERROR: Found forbidden locale-specific templates (use shared templates + i18n dictionaries):")
        for file_path in forbidden_files:
            print(f"  - {file_path.relative_to(ROOT)}")

    forbidden_regs = collect_forbidden_template_registrations()
    if forbidden_regs:
        failed = True
        print("ERROR: Found forbidden locale-specific template registrations in src/config.rs:")
        for reg in forbidden_regs:
            print(f"  - {reg}")

    if failed:
        return 1

    print("OK: No locale-specific template files or registrations found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
