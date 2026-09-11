#!/usr/bin/env bash
#
# Smoke test for the organization Public API event log endpoint.
#
# Boots a throwaway Vaultwarden instance against a temporary SQLite database
# seeded with two organizations and a handful of events, mints an organization
# API token for the first org, then exercises GET /public/events.
#
# It covers the date range filter, the newest-first ordering, the page size and
# continuation token, the organization scoping boundary, rejection of malformed
# dates, and the empty response returned when org events are disabled.
#
# The script exits non-zero if any assertion fails, so it is usable as a check.
#
# Requirements: bash, curl, jq, sqlite3, and either a prebuilt binary passed via
# the VW_BIN environment variable or a cargo toolchain to build one.
#
# Usage:
#   scripts/smoke_public_api_events.sh
#   VW_BIN=/path/to/vaultwarden PORT=8123 scripts/smoke_public_api_events.sh

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

PORT="${PORT:-8081}"
VW_BIN="${VW_BIN:-$REPO_ROOT/target/debug/vaultwarden}"
API="http://127.0.0.1:$PORT"

# ---- fixtures -------------------------------------------------------------
ORG=22222222-2222-4222-8222-222222222222
ORG2=99999999-9999-4999-8999-999999999999
USER=11111111-1111-4111-8111-111111111111
MEMBER=33333333-3333-4333-8333-333333333333
GROUP=44444444-4444-4444-8444-444444444444
APIKEYUUID=77777777-7777-4777-8777-777777777777
APIKEY=smoketestapikey1234567890

# Whole range that covers every seeded event, and a narrow one that does not.
FULL_START=2026-01-01T00:00:00Z
FULL_END=2026-12-31T23:59:59Z
NARROW_START=2026-03-02T12:00:00Z

# ---- prerequisites --------------------------------------------------------
for tool in curl jq sqlite3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' is not installed" >&2
        exit 2
    fi
done

if [ ! -x "$VW_BIN" ]; then
    if command -v cargo >/dev/null 2>&1; then
        echo "Building vaultwarden (sqlite feature); this can take a while..."
        cargo build --features sqlite
    else
        echo "ERROR: no binary at '$VW_BIN' and no cargo toolchain to build one." >&2
        echo "Set VW_BIN to a prebuilt binary or install a Rust toolchain." >&2
        exit 2
    fi
fi

# ---- workspace + cleanup --------------------------------------------------
TMP=$(mktemp -d)
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

export DATA_FOLDER="$TMP"
export DATABASE_URL="sqlite://$TMP/db.sqlite3"
export ADMIN_TOKEN="smoketestadmintoken"
export ORG_EVENTS_ENABLED=true
export WEB_VAULT_ENABLED=false
export ROCKET_PORT="$PORT"
export ROCKET_ADDRESS=127.0.0.1
export DOMAIN="http://localhost:$PORT"

# ---- server helpers -------------------------------------------------------
start_server() {
    local logfile="$1"
    "$VW_BIN" >"$logfile" 2>&1 &
    SERVER_PID=$!
    local i
    for i in $(seq 1 90); do
        if grep -q "Rocket has launched" "$logfile" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "ERROR: server exited during startup. Log:" >&2
            cat "$logfile" >&2
            return 1
        fi
        sleep 1
    done
    echo "ERROR: server did not launch within 90s. Log:" >&2
    cat "$logfile" >&2
    return 1
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

mint_token() {
    curl -sS -X POST "$API/identity/connect/token" \
        -d 'grant_type=client_credentials' \
        -d "client_id=organization.$ORG" \
        -d "client_secret=$APIKEY" \
        -d 'scope=api.organization' \
        -d 'device_identifier=dddddddd-dddd-4ddd-8ddd-dddddddddddd' \
        -d 'device_name=smoketest' \
        -d 'device_type=14' | jq -r '.access_token // empty'
}

# ---- assertion helpers ----------------------------------------------------
FAILS=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; FAILS=$((FAILS + 1)); }

check_eq() { # label actual expected
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1 (expected [$3], got [$2])"
    fi
}

check_ne() { # label actual not_expected
    if [ "$2" != "$3" ]; then
        pass "$1"
    else
        fail "$1 (did not expect [$3])"
    fi
}

# req METHOD PATH [TOKEN] -> sets HTTP_CODE, body written to $TMP/body
req() {
    local method="$1" path="$2" token="${3:-}"
    if [ -n "$token" ]; then
        HTTP_CODE=$(curl -sS -o "$TMP/body" -w '%{http_code}' \
            -X "$method" -H "Authorization: Bearer $token" "$API$path")
    else
        HTTP_CODE=$(curl -sS -o "$TMP/body" -w '%{http_code}' -X "$method" "$API$path")
    fi
}

jqval() { jq -r "$1" "$TMP/body"; }

jqcheck() { # label filter expected
    check_eq "$1" "$(jqval "$2")" "$3"
}

events_url() { # start end [continuationToken]
    local url="/api/public/events?start=$1&end=$2"
    if [ -n "${3:-}" ]; then
        url="$url&continuationToken=$3"
    fi
    printf '%s' "$url"
}

# ---- boot once to run migrations, then seed, then boot to serve -----------
echo "== Booting once to create the database schema =="
start_server "$TMP/boot1.log"
stop_server

echo "== Seeding two organizations and their events =="
sqlite3 "$TMP/db.sqlite3" <<SQL
INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter)
VALUES ('$USER',1,'2026-01-01 00:00:00','2026-01-01 00:00:00',0,'alice@example.com','Alice Example',X'00',X'00',100000,'','stamp-1','[]','[]',0,100000);

INSERT INTO organizations (uuid,name,billing_email,private_key,public_key) VALUES
('$ORG','Test Org','billing@example.com',NULL,NULL),
('$ORG2','Other Org','other@example.com',NULL,NULL);

INSERT INTO organization_api_key (uuid,org_uuid,atype,api_key,revision_date) VALUES
('$APIKEYUUID','$ORG',0,'$APIKEY','2026-01-01 00:00:00');

INSERT INTO users_organizations (uuid,user_uuid,org_uuid,invited_by_email,access_all,akey,status,atype,reset_password_key,external_id) VALUES
('$MEMBER','$USER','$ORG',NULL,0,'',2,2,NULL,'ext-member-1');

INSERT INTO groups (uuid,organizations_uuid,name,access_all,external_id,creation_date,revision_date) VALUES
('$GROUP','$ORG','Engineering',0,'ext-group-1','2026-01-01 00:00:00','2026-01-01 00:00:00');

-- Three events for the first organization, oldest first. The group event
-- deliberately has no acting user, the way a Public API write records one.
INSERT INTO event (uuid,event_type,user_uuid,org_uuid,cipher_uuid,collection_uuid,group_uuid,org_user_uuid,act_user_uuid,device_type,ip_address,event_date,policy_uuid,provider_uuid,provider_user_uuid,provider_org_uuid)
VALUES
('e0000001-0000-4000-8000-000000000001',1600,NULL,'$ORG',NULL,NULL,NULL,NULL,'$USER',14,'10.0.0.1','2026-03-01 10:00:00',NULL,NULL,NULL,NULL),
('e0000002-0000-4000-8000-000000000002',1400,NULL,'$ORG',NULL,NULL,'$GROUP',NULL,NULL,NULL,'10.0.0.2','2026-03-02 11:00:00',NULL,NULL,NULL,NULL),
('e0000003-0000-4000-8000-000000000003',1500,NULL,'$ORG',NULL,NULL,NULL,'$MEMBER','$USER',14,'10.0.0.3','2026-03-03 12:00:00',NULL,NULL,NULL,NULL);

-- One event for the other organization, which must never be visible.
INSERT INTO event (uuid,event_type,user_uuid,org_uuid,cipher_uuid,collection_uuid,group_uuid,org_user_uuid,act_user_uuid,device_type,ip_address,event_date,policy_uuid,provider_uuid,provider_user_uuid,provider_org_uuid)
VALUES ('e0000009-0000-4000-8000-000000000009',1600,NULL,'$ORG2',NULL,NULL,NULL,NULL,NULL,NULL,'10.0.0.9','2026-03-03 12:00:00',NULL,NULL,NULL,NULL);
SQL

echo "== Booting to serve =="
start_server "$TMP/boot2.log"

echo "== Minting an organization API token =="
TOKEN=$(mint_token)
if [ -z "$TOKEN" ]; then
    echo "FAIL: could not mint an organization API token" >&2
    exit 1
fi
pass "minted organization API token"

echo ""
echo "== Event list =="

req GET "$(events_url "$FULL_START" "$FULL_END")" "$TOKEN"
check_eq "events -> 200" "$HTTP_CODE" "200"
jqcheck "events is a list object" '.object' "list"
jqcheck "events returns only this organization's events" '.data | length' "3"
jqcheck "short page has no continuationToken" '.continuationToken' "null"

# Ordered newest first, so the most recent seeded event comes back first.
jqcheck "newest event first" '.data[0].type' "1500"
jqcheck "newest event organizationId" '.data[0].organizationId' "$ORG"
jqcheck "newest event organizationUserId" '.data[0].organizationUserId' "$MEMBER"
jqcheck "newest event actingUserId" '.data[0].actingUserId' "$USER"
jqcheck "oldest event last" '.data[2].type' "1600"

# An event with no acting user must still be returned, with a null actingUserId.
jqcheck "actor-less event is returned" '.data[1].type' "1400"
jqcheck "actor-less event has null actingUserId" '.data[1].actingUserId' "null"
jqcheck "actor-less event keeps its groupId" '.data[1].groupId' "$GROUP"
jqcheck "actor-less event has null deviceType" '.data[1].deviceType' "null"

echo ""
echo "== Date range filter =="

req GET "$(events_url "$NARROW_START" "$FULL_END")" "$TOKEN"
check_eq "narrowed range -> 200" "$HTTP_CODE" "200"
jqcheck "narrowed range drops older events" '.data | length' "1"
jqcheck "narrowed range keeps the newest event" '.data[0].type' "1500"

echo ""
echo "== Malformed dates are rejected, not fatal =="

for bad in "start=notadate&end=$FULL_END" "start=$FULL_START&end=notadate"; do
    req GET "/api/public/events?$bad" "$TOKEN"
    check_ne "malformed date does not fault the server ($bad)" "$HTTP_CODE" "500"
    check_eq "malformed date is a client error ($bad)" "$HTTP_CODE" "400"
done

req GET "$(events_url "$FULL_START" "$FULL_END" notadate)" "$TOKEN"
check_ne "malformed continuationToken does not fault the server" "$HTTP_CODE" "500"
check_eq "malformed continuationToken is a client error" "$HTTP_CODE" "400"

# The server must still be serving after all of that.
req GET "/alive"
check_eq "server still serving after malformed input" "$HTTP_CODE" "200"

echo ""
echo "== Page size and continuation token =="

# Add enough events to overflow a single page. PAGE_SIZE is 30.
sqlite3 "$TMP/db.sqlite3" <<SQL
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 40)
INSERT INTO event (uuid,event_type,user_uuid,org_uuid,cipher_uuid,collection_uuid,group_uuid,org_user_uuid,act_user_uuid,device_type,ip_address,event_date,policy_uuid,provider_uuid,provider_user_uuid,provider_org_uuid)
SELECT printf('e1%06d-0000-4000-8000-000000000001', n),1600,NULL,'$ORG',NULL,NULL,NULL,NULL,NULL,NULL,'10.0.1.1',
       datetime('2026-04-01 00:00:00', '+' || n || ' minutes'),NULL,NULL,NULL,NULL
FROM seq;
SQL

req GET "$(events_url "$FULL_START" "$FULL_END")" "$TOKEN"
check_eq "full page -> 200" "$HTTP_CODE" "200"
jqcheck "full page is capped at the page size" '.data | length' "30"
check_ne "full page exposes a continuationToken" "$(jqval '.continuationToken')" "null"
jqcheck "continuationToken is the date of the last event on the page" \
    '.continuationToken == (.data[-1].date)' "true"

# Feeding the token back must walk further back in time, not repeat the page.
NEXT=$(jqval '.continuationToken')
FIRST_DATE=$(jqval '.data[0].date')
req GET "$(events_url "$FULL_START" "$FULL_END" "$NEXT")" "$TOKEN"
check_eq "paged request -> 200" "$HTTP_CODE" "200"
check_ne "second page starts after the first" "$(jqval '.data[0].date')" "$FIRST_DATE"

echo ""
echo "== Organization scoping boundary =="

req GET "$(events_url "$FULL_START" "$FULL_END")" "$TOKEN"
jqcheck "no event belongs to another organization" \
    "[.data[] | select(.organizationId != \"$ORG\")] | length" "0"

echo ""
echo "== Authentication required =="

req GET "$(events_url "$FULL_START" "$FULL_END")"
check_eq "no token -> 401" "$HTTP_CODE" "401"

req GET "$(events_url "$FULL_START" "$FULL_END")" "not-a-real-token"
check_eq "bogus token -> 401" "$HTTP_CODE" "401"

echo ""
echo "== Events disabled returns an empty list =="

stop_server
export ORG_EVENTS_ENABLED=false
start_server "$TMP/boot3.log"

TOKEN=$(mint_token)
if [ -z "$TOKEN" ]; then
    echo "FAIL: could not mint an organization API token after restart" >&2
    exit 1
fi

req GET "$(events_url "$FULL_START" "$FULL_END")" "$TOKEN"
check_eq "events disabled -> 200" "$HTTP_CODE" "200"
jqcheck "events disabled returns an empty list" '.data | length' "0"
jqcheck "events disabled still returns a list object" '.object' "list"

echo ""
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: $FAILS assertion(s) failed."
    exit 1
fi
echo "RESULT: all assertions passed."
