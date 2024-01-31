#!/usr/bin/env sh

# Use the value of the corresponding env var (if present),
# or a default value otherwise.
: "${DATA_FOLDER:="/data"}"
: "${ROCKET_PORT:="80"}"
: "${ENV_FILE:="/.env"}"

CONFIG_FILE="${DATA_FOLDER}"/config.json

# Check if the $ENV_FILE file exist and is readable
# If that is the case, load it into the environment before running any check
if [ -r "${ENV_FILE}" ]; then
    # shellcheck disable=SC1090
    . "${ENV_FILE}"
fi

# Given a config key, return the corresponding config value from the
# config file. If the key doesn't exist, return an empty string.
get_config_val() {
    key="$1"
    # Extract a line of the form:
    #   "domain": "https://bw.example.com/path",
    grep "\"${key}\":" "${CONFIG_FILE}" |
    # To extract just the value (https://bw.example.com/path), delete:
    # (1) everything up to and including the first ':',
    # (2) whitespace and '"' from the front,
    # (3) ',' and '"' from the back.
    sed -e 's/[^:]\+://' -e 's/^[ "]\+//' -e 's/[,"]\+$//'
}

# Extract the base path from a domain URL. For example:
# - `` -> ``
# - `https://bw.example.com` -> ``
# - `https://bw.example.com/` -> ``
# - `https://bw.example.com/path` -> `/path`
# - `https://bw.example.com/multi/path` -> `/multi/path`
get_base_path() {
    echo "$1" |
    # Delete:
    # (1) everything up to and including '://',
    # (2) everything up to '/',
    # (3) trailing '/' from the back.
    sed -e 's|.*://||' -e 's|[^/]\+||' -e 's|/*$||'
}

# Read domain URL from config.json, if present.
if [ -r "${CONFIG_FILE}" ]; then
    domain="$(get_config_val 'domain')"
    if [ -n "${domain}" ]; then
        # config.json 'domain' overrides the DOMAIN env var.
        DOMAIN="${domain}"
    fi
fi

addr="${ROCKET_ADDRESS}"
if [ -z "${addr}" ] || [ "${addr}" = '0.0.0.0' ] || [ "${addr}" = '::' ]; then
    addr='localhost'
fi
base_path="$(get_base_path "${DOMAIN}")"
if [ -n "${ROCKET_TLS}" ]; then
    s='s'
fi
curl --insecure --fail --silent --show-error \
     "http${s}://${addr}:${ROCKET_PORT}${base_path}/alive" || exit 1
