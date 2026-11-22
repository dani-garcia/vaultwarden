#!/usr/bin/env bash
# Runs the live-server end-to-end tests of bitwarden/sdk-internal (e2e/wasm) against vaultwarden.
#
# Usage: tools/sdk-live-tests/run.sh --sdk-dir <path> [--skip-sdk-build] [--mode vectors|seeder] [-- <vitest args>]
#
# --skip-sdk-build uses the package already in the SDK's crates/bitwarden-wasm-internal/npm: an earlier build, or a
# published @bitwarden/sdk-internal unpacked there.
#
# The server is built with `unsafe_test_mode`, whose test seeder (src/api/test_seeder.rs) creates the test accounts.
# - vectors: for SDK versions whose live tests log in to one given account. Every user test vector with a master
#   password gets a fresh server, is seeded there with its vault, and the tests run on it (they rotate its keys).
# - seeder: for SDK versions whose tests seed their own accounts through BW_LIVE_SEEDER_URL. One server, one run.
# The mode follows what the SDK's e2e/wasm/live/config.ts reads, unless --mode says otherwise. Arguments after `--` go
# to vitest, e.g. `-- tests/user-crypto-management/rotate-user-keys.live.test.ts` to run one file.
#
# Every vector runs even after a failure; a summary follows, and the exit code is 1 if any failed. The server logs are
# in <target dir>/sdk-live-tests/. BW_LIVE_CLIENT_VERSION defaults to 2026.10.1, the minimum for V2 accounts.
#
# Needs: Node.js >= 22.12, curl, python3, and to build the SDK its Rust toolchain with the wasm32-unknown-unknown target
# and rust-src.
set -euo pipefail

VW_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-${VW_DIR}/target}"
OUT_DIR="${TARGET_DIR}/sdk-live-tests"
PORT=8099
URL="http://127.0.0.1:${PORT}"
SEEDER_URL="${URL}/test/seeder"
SEEDER_USERNAME="sdk-live-tests"
SEEDER_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
SKIP=3 # seed_vector.py's exit code for a vector the tests can't use
export BW_LIVE_CLIENT_VERSION="${BW_LIVE_CLIENT_VERSION:-2026.10.1}"

SDK_DIR=""
BUILD_SDK=1
MODE=""
VITEST_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sdk-dir) SDK_DIR="$(cd "$2" && pwd)"; shift 2 ;;
    --skip-sdk-build) BUILD_SDK=0; shift ;;
    --mode) MODE="$2"; shift 2 ;;
    --) shift; VITEST_ARGS=("$@"); break ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "${SDK_DIR}" ]] || { echo "--sdk-dir is required" >&2; exit 2; }
TESTS_DIR="${SDK_DIR}/e2e/wasm"
[[ -f "${TESTS_DIR}/live/config.ts" ]] || { echo "${TESTS_DIR}/live/config.ts not found: no live tests in this SDK" >&2; exit 2; }
if [[ -z "${MODE}" ]]; then
  if grep -q BW_LIVE_SEEDER_URL "${TESTS_DIR}/live/config.ts"; then MODE=seeder; else MODE=vectors; fi
fi
[[ "${MODE}" == vectors || "${MODE}" == seeder ]] || { echo "--mode must be vectors or seeder" >&2; exit 2; }
echo "Mode: ${MODE}, client version ${BW_LIVE_CLIENT_VERSION}"

(cd "${VW_DIR}" && cargo build --features sqlite,unsafe_test_mode)
if [[ ${BUILD_SDK} -eq 1 ]]; then
  bash "${SDK_DIR}/crates/bitwarden-wasm-internal/build.sh"
fi
(cd "${TESTS_DIR}" && npm ci)

server=""
trap 'if [[ -n "${server}" ]]; then kill "${server}" 2>/dev/null || true; fi' EXIT

# Starts a server on an empty database in $OUT_DIR/$1
start_server() {
  local data_dir="${OUT_DIR}/$1"
  rm -rf "${data_dir}" && mkdir -p "${data_dir}"
  if curl -s -o /dev/null "${URL}/alive"; then
    echo "Something already answers on port ${PORT}" >&2
    return 1
  fi
  ENV_FILE=/dev/null DATA_FOLDER="${data_dir}" DATABASE_URL="sqlite://${data_dir}/db.sqlite3" \
    ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT="${PORT}" DOMAIN="${URL}" WEB_VAULT_ENABLED=false \
    SIGNUPS_ALLOWED=true SIGNUPS_VERIFY=false LOGIN_RATELIMIT_MAX_BURST=1000 \
    TEST_SEEDER_USERNAME="${SEEDER_USERNAME}" TEST_SEEDER_PASSWORD="${SEEDER_PASSWORD}" \
    "${TARGET_DIR}/debug/vaultwarden" > "${data_dir}/vaultwarden.log" 2>&1 &
  server=$!
  local i
  for i in $(seq 1 60); do
    if ! kill -0 "${server}" 2>/dev/null; then break; fi
    if curl -sf -o /dev/null "${URL}/alive"; then return 0; fi
    sleep 1
  done
  echo "The server didn't start; the end of ${data_dir}/vaultwarden.log:" >&2
  tail -50 "${data_dir}/vaultwarden.log" >&2
  stop_server
  return 1
}

stop_server() {
  if [[ -n "${server}" ]]; then
    kill "${server}" 2>/dev/null || true
    wait "${server}" 2>/dev/null || true
    server=""
  fi
}

run_tests() {
  (cd "${TESTS_DIR}" && BW_LIVE_SERVER_URL="${URL}" "$@" npm run test:live -- "${VITEST_ARGS[@]}")
}

results=()
failed=0
if [[ "${MODE}" == seeder ]]; then
  if start_server seeder && run_tests env BW_LIVE_SEEDER_URL="${SEEDER_URL}" \
    BW_LIVE_SEEDER_USERNAME="${SEEDER_USERNAME}" BW_LIVE_SEEDER_PASSWORD="${SEEDER_PASSWORD}"; then
    results+=("seeder: pass")
  else
    results+=("seeder: FAIL")
    failed=1
  fi
  stop_server
else
  for vector_file in "${SDK_DIR}"/test-vectors/users/*.json; do
    vector="$(basename "${vector_file}" .json)"
    echo "=== ${vector}"
    if ! start_server "${vector}"; then
      results+=("${vector}: FAIL (server didn't start)")
      failed=1
      continue
    fi
    status=0
    credentials="$(python3 -I "${VW_DIR}/tools/sdk-live-tests/seed_vector.py" "${vector_file}" "${SEEDER_URL}" \
      "${SEEDER_USERNAME}" "${SEEDER_PASSWORD}")" || status=$?
    if [[ ${status} -eq ${SKIP} ]]; then
      results+=("${vector}: skip (${credentials})")
    elif [[ ${status} -ne 0 ]]; then
      results+=("${vector}: FAIL (seeding)")
      failed=1
    elif run_tests env BW_LIVE_EMAIL="$(sed -n 1p <<< "${credentials}")" \
      BW_LIVE_PASSWORD="$(sed -n 2p <<< "${credentials}")"; then
      results+=("${vector}: pass")
    else
      results+=("${vector}: FAIL")
      failed=1
    fi
    stop_server
  done
fi

echo
echo "=== Summary (logs in ${OUT_DIR})"
printf '%s\n' "${results[@]}"
exit "${failed}"
