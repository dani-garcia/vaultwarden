#!/usr/bin/env bash
# iOS Autofill simulator / test environment for PR #7728.
#
# Two layers:
#   1. cargo tests — SDK deny_unknown_fields + Rocket local HTTP for well-known
#   2. live binary — WEB_VAULT_ENABLED=false, DOMAIN with a path prefix, curl origin-root
#
# Usage:
#   ./scripts/sim-ios-autofill.sh           # unit + HTTP tests
#   ./scripts/sim-ios-autofill.sh --live    # also boot sqlite VW and curl well-known
set -euo pipefail
cd "$(dirname "$0")/.."

FEATURES="${TDD_FEATURES:-sqlite}"
LIVE=0
if [[ "${1:-}" == "--live" ]]; then
  LIVE=1
fi

echo "==> SDK + Rocket well-known simulator"
cargo test --features "${FEATURES}" --bins sdk_simulator -- --nocapture
cargo test --features "${FEATURES}" --bins sdk_has_fido2 -- --nocapture
cargo test --features "${FEATURES}" --bins ios_autofill_sim -- --nocapture

if [[ "${LIVE}" -ne 1 ]]; then
  echo "==> skip live server (pass --live to curl a launched binary)"
  exit 0
fi

PORT="${SIM_PORT:-18282}"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/vw-ios-autofill.XXXXXX")"
cleanup() {
  if [[ -n "${VW_PID:-}" ]] && kill -0 "${VW_PID}" 2>/dev/null; then
    kill "${VW_PID}" 2>/dev/null || true
    wait "${VW_PID}" 2>/dev/null || true
  fi
  rm -rf "${DATA}"
}
trap cleanup EXIT

echo "==> build sqlite binary"
cargo build --features "${FEATURES}" --bin vaultwarden

echo "==> launch WEB_VAULT_ENABLED=false DOMAIN=.../vw on :${PORT}"
export DATA_FOLDER="${DATA}"
export DATABASE_URL="sqlite://${DATA}/db.sqlite3"
export WEB_VAULT_ENABLED=false
export DOMAIN="http://127.0.0.1:${PORT}/vw"
export ROCKET_ADDRESS=127.0.0.1
export ROCKET_PORT="${PORT}"
export DISABLE_ADMIN_TOKEN=true
export I_REALLY_WANT_VOLATILE_STORAGE=true
export LOG_LEVEL=warn

cargo run --features "${FEATURES}" --bin vaultwarden >/dev/null 2>"${DATA}/vw.log" &
VW_PID=$!

ok=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/vw/alive" >/dev/null 2>&1; then
    ok=1
    break
  fi
  if ! kill -0 "${VW_PID}" 2>/dev/null; then
    echo "vaultwarden exited early:" >&2
    cat "${DATA}/vw.log" >&2 || true
    exit 1
  fi
  sleep 0.5
done
if [[ "${ok}" -ne 1 ]]; then
  echo "timed out waiting for /vw/alive" >&2
  cat "${DATA}/vw.log" >&2 || true
  exit 1
fi

python3 - "${PORT}" <<'PY'
import json, sys, urllib.request

port = sys.argv[1]
base = f"http://127.0.0.1:{port}"

def get(path):
    with urllib.request.urlopen(base + path) as res:
        return res.status, json.load(res)

status, aasa_root = get("/.well-known/apple-app-site-association")
assert status == 200, status
apps = aasa_root["webcredentials"]["apps"]
assert "LTZ2PFU5D6.com.8bit.bitwarden.autofill" in apps, apps

status, aasa_path = get("/vw/.well-known/apple-app-site-association")
assert status == 200, status
assert aasa_path == aasa_root

status, webauthn = get("/.well-known/webauthn")
assert status == 200, status
assert webauthn.get("origins"), webauthn

status, webauthn_path = get("/vw/.well-known/webauthn")
assert status == 200, status
assert webauthn_path == webauthn

print("live HTTP: AASA + related-origins OK at / and /vw (web vault off)")
PY
