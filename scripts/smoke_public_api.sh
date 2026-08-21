#!/usr/bin/env bash
#
# Smoke test for the organization Public API read endpoints.
#
# Boots a throwaway Vaultwarden instance against a temporary SQLite database
# seeded with two organizations (each with its own members, groups, collections
# and access associations), mints an organization API token for the first org,
# then exercises every read endpoint and asserts on the response shapes.
#
# It also asserts the organization scoping boundary: ids that belong to the
# second organization must return HTTP 404 through the first org's token, and a
# request with no token must return HTTP 401.
#
# The script exits non-zero if any assertion fails, so it is usable as a check.
#
# Requirements: bash, curl, jq, sqlite3, and either a prebuilt binary passed via
# the VW_BIN environment variable or a cargo toolchain to build one.
#
# Usage:
#   scripts/smoke_public_api.sh
#   VW_BIN=/path/to/vaultwarden PORT=8123 scripts/smoke_public_api.sh

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

PORT="${PORT:-8079}"
VW_BIN="${VW_BIN:-$REPO_ROOT/target/debug/vaultwarden}"
API="http://127.0.0.1:$PORT"

# ---- fixtures -------------------------------------------------------------
ORG=22222222-2222-4222-8222-222222222222
ORG2=99999999-9999-4999-8999-999999999999
USER=11111111-1111-4111-8111-111111111111
USER2=88888888-8888-4888-8888-888888888888
MEMBER=33333333-3333-4333-8333-333333333333
MEMBER2=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
GROUP=44444444-4444-4444-8444-444444444444
GROUP2=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
COLLECTION=55555555-5555-4555-8555-555555555555
COLLECTION2=66666666-6666-4666-8666-666666666666
APIKEYUUID=77777777-7777-4777-8777-777777777777
APIKEY=smoketestapikey1234567890

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
export ORG_GROUPS_ENABLED=true
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

# ---- boot once to run migrations, then seed, then boot to serve -----------
echo "== Booting once to create the database schema =="
start_server "$TMP/boot1.log"
stop_server

echo "== Seeding two organizations with members, groups and collections =="
sqlite3 "$TMP/db.sqlite3" <<SQL
INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter)
VALUES
('$USER',1,'2026-01-01 00:00:00','2026-01-01 00:00:00',0,'alice@example.com','Alice Example',X'00',X'00',100000,'','stamp-1','[]','[]',0,100000),
('$USER2',1,'2026-01-01 00:00:00','2026-01-01 00:00:00',0,'bob@example.com','Bob Other',X'00',X'00',100000,'','stamp-2','[]','[]',0,100000);

INSERT INTO organizations (uuid,name,billing_email,private_key,public_key) VALUES
('$ORG','Test Org','billing@example.com',NULL,NULL),
('$ORG2','Other Org','other@example.com',NULL,NULL);

INSERT INTO organization_api_key (uuid,org_uuid,atype,api_key,revision_date) VALUES
('$APIKEYUUID','$ORG',0,'$APIKEY','2026-01-01 00:00:00');

INSERT INTO users_organizations (uuid,user_uuid,org_uuid,invited_by_email,access_all,akey,status,atype,reset_password_key,external_id) VALUES
('$MEMBER','$USER','$ORG',NULL,0,'',2,2,NULL,'ext-member-1'),
('$MEMBER2','$USER2','$ORG2',NULL,0,'',2,2,NULL,'ext-member-2');

INSERT INTO groups (uuid,organizations_uuid,name,access_all,external_id,creation_date,revision_date) VALUES
('$GROUP','$ORG','Engineering',0,'ext-group-1','2026-01-01 00:00:00','2026-01-01 00:00:00'),
('$GROUP2','$ORG2','Other Group',0,'ext-group-2','2026-01-01 00:00:00','2026-01-01 00:00:00');

INSERT INTO groups_users (groups_uuid,users_organizations_uuid) VALUES
('$GROUP','$MEMBER');

INSERT INTO collections (uuid,org_uuid,name,external_id) VALUES
('$COLLECTION','$ORG','2.encryptedCiphertextName==','ext-collection-1'),
('$COLLECTION2','$ORG2','2.otherOrgCiphertext==','ext-collection-2');

INSERT INTO users_collections (user_uuid,collection_uuid,read_only,hide_passwords,manage) VALUES
('$USER','$COLLECTION',1,0,0);

INSERT INTO collections_groups (collections_uuid,groups_uuid,read_only,hide_passwords,manage) VALUES
('$COLLECTION','$GROUP',0,0,1);
SQL

echo "== Booting to serve =="
start_server "$TMP/boot2.log"

echo "== Minting an organization API token =="
TOKEN=$(curl -sS -X POST "$API/identity/connect/token" \
    -d 'grant_type=client_credentials' \
    -d "client_id=organization.$ORG" \
    -d "client_secret=$APIKEY" \
    -d 'scope=api.organization' \
    -d 'device_identifier=dddddddd-dddd-4ddd-8ddd-dddddddddddd' \
    -d 'device_name=smoketest' \
    -d 'device_type=14' | jq -r '.access_token // empty')

if [ -z "$TOKEN" ]; then
    echo "FAIL: could not mint an organization API token" >&2
    exit 1
fi
pass "minted organization API token"

echo ""
echo "== Read endpoints =="

# 1. Members list (without collections/groups).
req GET "/api/public/members" "$TOKEN"
check_eq "members list -> 200" "$HTTP_CODE" "200"
jqcheck "members list is a list object" '.object' "list"
jqcheck "members list has continuationToken null" '.continuationToken' "null"
jqcheck "members list has one member" '.data | length' "1"
jqcheck "member object discriminator" '.data[0].object' "member"
jqcheck "member id" '.data[0].id' "$MEMBER"
jqcheck "member userId" '.data[0].userId' "$USER"
jqcheck "member email" '.data[0].email' "alice@example.com"
jqcheck "member name" '.data[0].name' "Alice Example"
jqcheck "member type" '.data[0].type' "2"
jqcheck "member status" '.data[0].status' "2"
jqcheck "member externalId" '.data[0].externalId' "ext-member-1"
jqcheck "member resetPasswordEnrolled" '.data[0].resetPasswordEnrolled' "false"
jqcheck "members list omits collections" '.data[0] | has("collections")' "false"

# 2. Member detail (with direct collection grants).
req GET "/api/public/members/$MEMBER" "$TOKEN"
check_eq "member detail -> 200" "$HTTP_CODE" "200"
jqcheck "member detail id" '.id' "$MEMBER"
jqcheck "member detail carries one collection grant" '.collections | length' "1"
jqcheck "member detail collection id" '.collections[0].id' "$COLLECTION"
jqcheck "member detail collection readOnly" '.collections[0].readOnly' "true"
jqcheck "member detail collection hidePasswords" '.collections[0].hidePasswords' "false"
jqcheck "member detail collection manage" '.collections[0].manage' "false"

# 3. Member group ids.
req GET "/api/public/members/$MEMBER/group-ids" "$TOKEN"
check_eq "member group-ids -> 200" "$HTTP_CODE" "200"
jqcheck "member group-ids is a bare array of one" 'length' "1"
jqcheck "member group-ids contains the group" '.[0]' "$GROUP"

# 4. Groups list.
req GET "/api/public/groups" "$TOKEN"
check_eq "groups list -> 200" "$HTTP_CODE" "200"
jqcheck "groups list is a list object" '.object' "list"
jqcheck "groups list has one group" '.data | length' "1"
jqcheck "group object discriminator" '.data[0].object' "group"
jqcheck "group id" '.data[0].id' "$GROUP"
jqcheck "group name is plaintext" '.data[0].name' "Engineering"
jqcheck "group accessAll" '.data[0].accessAll' "false"
jqcheck "group externalId" '.data[0].externalId' "ext-group-1"

# 5. Group detail (with collection grants).
req GET "/api/public/groups/$GROUP" "$TOKEN"
check_eq "group detail -> 200" "$HTTP_CODE" "200"
jqcheck "group detail id" '.id' "$GROUP"
jqcheck "group detail carries one collection grant" '.collections | length' "1"
jqcheck "group detail collection id" '.collections[0].id' "$COLLECTION"
jqcheck "group detail collection readOnly" '.collections[0].readOnly' "false"
jqcheck "group detail collection manage" '.collections[0].manage' "true"

# 6. Group member ids.
req GET "/api/public/groups/$GROUP/member-ids" "$TOKEN"
check_eq "group member-ids -> 200" "$HTTP_CODE" "200"
jqcheck "group member-ids is a bare array of one" 'length' "1"
jqcheck "group member-ids contains the membership" '.[0]' "$MEMBER"

# 7. Collections list (id + externalId only, no name).
req GET "/api/public/collections" "$TOKEN"
check_eq "collections list -> 200" "$HTTP_CODE" "200"
jqcheck "collections list is a list object" '.object' "list"
jqcheck "collections list has one collection" '.data | length' "1"
jqcheck "collection object discriminator" '.data[0].object' "collection"
jqcheck "collection id" '.data[0].id' "$COLLECTION"
jqcheck "collection externalId" '.data[0].externalId' "ext-collection-1"
jqcheck "collection omits the encrypted name" '.data[0] | has("name")' "false"

# 8. Collection detail (with group grants).
req GET "/api/public/collections/$COLLECTION" "$TOKEN"
check_eq "collection detail -> 200" "$HTTP_CODE" "200"
jqcheck "collection detail id" '.id' "$COLLECTION"
jqcheck "collection detail externalId" '.externalId' "ext-collection-1"
jqcheck "collection detail omits the encrypted name" 'has("name")' "false"
jqcheck "collection detail carries one group grant" '.groups | length' "1"
jqcheck "collection detail group id" '.groups[0].id' "$GROUP"
jqcheck "collection detail group manage" '.groups[0].manage' "true"

echo ""
echo "== Organization scoping boundary =="

# Ids that exist but belong to the other organization must not resolve.
req GET "/api/public/members/$MEMBER2" "$TOKEN"
check_eq "cross-org member -> 404" "$HTTP_CODE" "404"
req GET "/api/public/groups/$GROUP2" "$TOKEN"
check_eq "cross-org group -> 404" "$HTTP_CODE" "404"
req GET "/api/public/collections/$COLLECTION2" "$TOKEN"
check_eq "cross-org collection -> 404" "$HTTP_CODE" "404"

echo ""
echo "== Authentication required =="
req GET "/api/public/members"
check_eq "no token -> 401" "$HTTP_CODE" "401"

echo ""
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: $FAILS assertion(s) failed."
    exit 1
fi
echo "RESULT: all assertions passed."
