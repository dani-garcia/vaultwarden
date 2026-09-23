#!/usr/bin/env bash
# Runs the live-server integration tests of bitwarden/sdk-internal against vaultwarden.
#
# Usage: tools/sdk-live-tests/run.sh --sdk-dir <path> [--skip-sdk-build]
#
# Every test vector of the SDK (test-vectors/users/) that the tests can log in with gets a fresh
# server and database, since the tests rotate the account's keys. Stops at the first failure; the
# server logs are in target/sdk-live-tests/. Building the SDK needs its Rust toolchain with the
# wasm32-unknown-unknown target and rust-src, Node.js, and binaryen (`npm i -g binaryen`).
set -euo pipefail

VW_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${VW_DIR}/target/sdk-live-tests"
URL="http://127.0.0.1:8099"
SKIP=3 # register_vector.py's exit code for a vector the tests can't use

SDK_DIR=""
BUILD_SDK=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sdk-dir) SDK_DIR="$(cd "$2" && pwd)"; shift 2 ;;
    --skip-sdk-build) BUILD_SDK=0; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "${SDK_DIR}" ]] || { echo "--sdk-dir is required" >&2; exit 2; }
TESTS_DIR="${SDK_DIR}/crates/bitwarden-wasm-internal/integration-tests"

(cd "${VW_DIR}" && cargo build --features sqlite)
if [[ ${BUILD_SDK} -eq 1 ]]; then
  bash "${SDK_DIR}/crates/bitwarden-wasm-internal/build.sh"
  (cd "${TESTS_DIR}" && npm ci)
fi

trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

for vector_file in "${SDK_DIR}"/test-vectors/users/*.json; do
  vector="$(basename "${vector_file}" .json)"
  echo "=== ${vector}"
  data_dir="${OUT_DIR}/${vector}"
  rm -rf "${data_dir}" && mkdir -p "${data_dir}"

  DATA_FOLDER="${data_dir}" DATABASE_URL="sqlite://${data_dir}/db.sqlite3" \
    ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8099 DOMAIN="${URL}" WEB_VAULT_ENABLED=false \
    SIGNUPS_ALLOWED=true SIGNUPS_VERIFY=false LOGIN_RATELIMIT_MAX_BURST=1000 \
    "${VW_DIR}/target/debug/vaultwarden" > "${data_dir}/vaultwarden.log" 2>&1 &
  server=$!
  curl -sf --retry 30 --retry-connrefused --retry-delay 1 "${URL}/alive" > /dev/null

  status=0
  credentials="$(python3 "${VW_DIR}/tools/sdk-live-tests/register_vector.py" "${vector_file}" "${URL}")" || status=$?
  if [[ ${status} -eq 0 ]]; then
    (cd "${TESTS_DIR}" && BW_LIVE_SERVER_URL="${URL}" BW_LIVE_EMAIL="$(sed -n 1p <<< "${credentials}")" \
      BW_LIVE_PASSWORD="$(sed -n 2p <<< "${credentials}")" npm run test:live)
  elif [[ ${status} -ne ${SKIP} ]]; then
    exit "${status}"
  fi

  kill "${server}" && wait "${server}" || true
done
echo "All test vectors passed"
