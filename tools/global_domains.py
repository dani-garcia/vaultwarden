#!/usr/bin/env python3
#
# This script generates a global equivalent domains JSON file from
# the upstream Bitwarden source repo.
#
import json
import re
import sys
import urllib.request

from collections import OrderedDict

if not 2 <= len(sys.argv) <= 3:
    print(f"usage: {sys.argv[0]} <OUTPUT-FILE> [GIT-REF]")
    print()
    print("This script generates a global equivalent domains JSON file from")
    print("the upstream Bitwarden source repo.")
    sys.exit(1)

OUTPUT_FILE = sys.argv[1]
GIT_REF = 'main' if len(sys.argv) == 2 else sys.argv[2]

BASE_URL = f'https://github.com/bitwarden/server/raw/{GIT_REF}'
ENUMS_URL = f'{BASE_URL}/src/Core/Enums/GlobalEquivalentDomainsType.cs'
DOMAIN_LISTS_URL = f'{BASE_URL}/src/Core/Utilities/StaticStore.cs'

# Enum lines look like:
#
#   EnumName0 = 0,
#   EnumName1 = 1,
#
ENUM_RE = re.compile(
    r'\s*'             # Leading whitespace (optional).
    r'([_0-9a-zA-Z]+)' # Enum name (capture group 1).
    r'\s*=\s*'         # '=' with optional surrounding whitespace.
    r'([0-9]+)'        # Enum value (capture group 2).
)

# Global domains lines look like:
#
#   GlobalDomains.Add(GlobalEquivalentDomainsType.EnumName, new List<string> { "x.com", "y.com" });
#
DOMAIN_LIST_RE = re.compile(
    r'\s*'             # Leading whitespace (optional).
    r'GlobalDomains\.Add\(GlobalEquivalentDomainsType\.'
    r'([_0-9a-zA-Z]+)' # Enum name (capture group 1).
    r'\s*,\s*new List<string>\s*{'
    r'([^}]+)'         # Domain list (capture group 2).
    r'}\);'
)

enums = dict()
domain_lists = OrderedDict()

# Read in the enum names and values.
with urllib.request.urlopen(ENUMS_URL) as response:
    for ln in response.read().decode('utf-8').split('\n'):
        m = ENUM_RE.match(ln)
        if m:
            enums[m.group(1)] = int(m.group(2))

# Read in the domain lists.
with urllib.request.urlopen(DOMAIN_LISTS_URL) as response:
    for ln in response.read().decode('utf-8').split('\n'):
        m = DOMAIN_LIST_RE.match(ln)
        if m:
            # Strip double quotes and extraneous spaces in each domain.
            domain_lists[m.group(1)] = [d.strip(' "') for d in m.group(2).split(",")]

# Build the global domains data structure.
global_domains = []
for name, domain_list in domain_lists.items():
    entry = OrderedDict()
    entry["type"] = enums[name]
    entry["domains"] = domain_list
    entry["excluded"] = False
    global_domains.append(entry)

# Write out the global domains JSON file.
with open(file=OUTPUT_FILE, mode='w', encoding='utf-8') as f:
    json.dump(global_domains, f, indent=2)
