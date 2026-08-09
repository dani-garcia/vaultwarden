#!/usr/bin/env bash
#
# Smoke test for the organization Public API member and group write endpoints.
#
# Boots a throwaway Vaultwarden instance against a temporary SQLite database
# seeded with two organizations, mints an organization API token for the first
# org, then exercises every write endpoint and asserts on the resulting state.
#
# Beyond the happy paths it asserts the guards that protect organization
# integrity: the last confirmed owner cannot be demoted, revoked or deleted;
# collections, groups and members from another organization are rejected; ids
# belonging to the second organization return HTTP 404; and a request with no
# token returns HTTP 401. It also asserts that a group update leaves member
# assignments alone, and that every write is recorded in the event log with no
# acting user, since a Public API client is not a user.
#
# The script exits non-zero if any assertion fails, so it is usable as a check.
#
# Requirements: bash, curl, jq, sqlite3, and either a prebuilt binary passed via
# the VW_BIN environment variable or a cargo toolchain to build one.
#
# Usage:
#   scripts/smoke_public_api_write.sh
#   VW_BIN=/path/to/vaultwarden PORT=8123 scripts/smoke_public_api_write.sh

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

PORT="${PORT:-8082}"
VW_BIN="${VW_BIN:-$REPO_ROOT/target/debug/vaultwarden}"
API="http://127.0.0.1:$PORT"

# ---- fixtures -------------------------------------------------------------
ORG=22222222-2222-4222-8222-222222222222
ORG2=99999999-9999-4999-8999-999999999999
USER=11111111-1111-4111-8111-111111111111
USER2=88888888-8888-4888-8888-888888888888
USER3=cccccccc-cccc-4ccc-8ccc-cccccccccccc
# MEMBER is the only confirmed owner, so it is the one the guards protect.
MEMBER=33333333-3333-4333-8333-333333333333
MEMBER2=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
MEMBER3=dddddddd-dddd-4ddd-8ddd-dddddddddddd
GROUP=44444444-4444-4444-8444-444444444444
GROUP2=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
COLLECTION=55555555-5555-4555-8555-555555555555
COLLECTION2=66666666-6666-4666-8666-666666666666
APIKEYUUID=77777777-7777-4777-8777-777777777777
APIKEY=smoketestapikey1234567890

NEW_EMAIL=newmember@example.com

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
export ORG_EVENTS_ENABLED=true
export INVITATIONS_ALLOWED=true
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

# reqj METHOD PATH TOKEN JSON -> same, with a JSON request body
reqj() {
    local method="$1" path="$2" token="$3" body="$4"
    if [ -n "$token" ]; then
        HTTP_CODE=$(curl -sS -o "$TMP/body" -w '%{http_code}' \
            -X "$method" -H "Authorization: Bearer $token" \
            -H 'Content-Type: application/json' -d "$body" "$API$path")
    else
        HTTP_CODE=$(curl -sS -o "$TMP/body" -w '%{http_code}' \
            -X "$method" -H 'Content-Type: application/json' -d "$body" "$API$path")
    fi
}

jqval() { jq -r "$1" "$TMP/body"; }

jqcheck() { # label filter expected
    check_eq "$1" "$(jqval "$2")" "$3"
}

sqlcheck() { # label sql expected
    check_eq "$1" "$(sqlite3 "$TMP/db.sqlite3" "$2")" "$3"
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
('$USER2',1,'2026-01-01 00:00:00','2026-01-01 00:00:00',0,'bob@example.com','Bob Other',X'00',X'00',100000,'','stamp-2','[]','[]',0,100000),
('$USER3',1,'2026-01-01 00:00:00','2026-01-01 00:00:00',0,'carol@example.com','Carol Example',X'00',X'00',100000,'','stamp-3','[]','[]',0,100000);

INSERT INTO organizations (uuid,name,billing_email,private_key,public_key) VALUES
('$ORG','Test Org','billing@example.com',NULL,NULL),
('$ORG2','Other Org','other@example.com',NULL,NULL);

INSERT INTO organization_api_key (uuid,org_uuid,atype,api_key,revision_date) VALUES
('$APIKEYUUID','$ORG',0,'$APIKEY','2026-01-01 00:00:00');

-- atype 0 is Owner and 2 is User; status 2 is Confirmed.
INSERT INTO users_organizations (uuid,user_uuid,org_uuid,invited_by_email,access_all,akey,status,atype,reset_password_key,external_id) VALUES
('$MEMBER','$USER','$ORG',NULL,0,'',2,0,NULL,'ext-member-1'),
('$MEMBER2','$USER2','$ORG2',NULL,0,'',2,2,NULL,'ext-member-2'),
('$MEMBER3','$USER3','$ORG',NULL,0,'',2,2,NULL,'ext-member-3');

INSERT INTO groups (uuid,organizations_uuid,name,access_all,external_id,creation_date,revision_date) VALUES
('$GROUP','$ORG','Engineering',0,'ext-group-1','2026-01-01 00:00:00','2026-01-01 00:00:00'),
('$GROUP2','$ORG2','Other Group',0,'ext-group-2','2026-01-01 00:00:00','2026-01-01 00:00:00');

INSERT INTO collections (uuid,org_uuid,name,external_id) VALUES
('$COLLECTION','$ORG','2.encryptedCiphertextName==','ext-collection-1'),
('$COLLECTION2','$ORG2','2.otherOrgCiphertext==','ext-collection-2');
SQL

echo "== Booting to serve =="
start_server "$TMP/boot2.log"

echo "== Minting an organization API token =="
TOKEN=$(curl -sS -X POST "$API/identity/connect/token" \
    -d 'grant_type=client_credentials' \
    -d "client_id=organization.$ORG" \
    -d "client_secret=$APIKEY" \
    -d 'scope=api.organization' \
    -d 'device_identifier=eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' \
    -d 'device_name=smoketest' \
    -d 'device_type=14' | jq -r '.access_token // empty')

if [ -z "$TOKEN" ]; then
    echo "FAIL: could not mint an organization API token" >&2
    exit 1
fi
pass "minted organization API token"

echo ""
echo "== Create a group =="

reqj POST "/api/public/groups" "$TOKEN" \
    "{\"name\":\"Platform\",\"externalId\":\"ext-new-group\",\"collections\":[{\"id\":\"$COLLECTION\",\"readOnly\":true,\"hidePasswords\":false,\"manage\":false}]}"
check_eq "create group -> 200" "$HTTP_CODE" "200"
jqcheck "created group discriminator" '.object' "group"
jqcheck "created group name" '.name' "Platform"
jqcheck "created group externalId" '.externalId' "ext-new-group"
jqcheck "created group accessAll defaults to false" '.accessAll' "false"
NEWGROUP=$(jqval '.id')

req GET "/api/public/groups/$NEWGROUP" "$TOKEN"
check_eq "created group is readable -> 200" "$HTTP_CODE" "200"
jqcheck "created group kept its collection grant" '.collections | length' "1"
jqcheck "created group collection id" '.collections[0].id' "$COLLECTION"
jqcheck "created group collection readOnly" '.collections[0].readOnly' "true"

echo ""
echo "== Group input validation =="

reqj POST "/api/public/groups" "$TOKEN" \
    "{\"name\":\"Bad\",\"collections\":[{\"id\":\"$COLLECTION2\"}]}"
check_eq "group with another org's collection -> 400" "$HTTP_CODE" "400"

echo ""
echo "== Update a group =="

reqj PUT "/api/public/groups/$NEWGROUP" "$TOKEN" \
    "{\"name\":\"Platform Team\",\"externalId\":\"ext-new-group-2\",\"collections\":[]}"
check_eq "update group -> 200" "$HTTP_CODE" "200"
jqcheck "updated group name" '.name' "Platform Team"
jqcheck "updated group externalId" '.externalId' "ext-new-group-2"

req GET "/api/public/groups/$NEWGROUP" "$TOKEN"
jqcheck "update replaced the collection grants" '.collections | length' "0"

echo ""
echo "== Group member ids =="

reqj PUT "/api/public/groups/$NEWGROUP/member-ids" "$TOKEN" "{\"memberIds\":[\"$MEMBER3\"]}"
check_eq "set group member-ids -> 200" "$HTTP_CODE" "200"

req GET "/api/public/groups/$NEWGROUP/member-ids" "$TOKEN"
jqcheck "group has one member" 'length' "1"
jqcheck "group member is the expected membership" '.[0]' "$MEMBER3"

reqj PUT "/api/public/groups/$NEWGROUP/member-ids" "$TOKEN" "{\"memberIds\":[\"$MEMBER2\"]}"
check_eq "group member-ids from another org -> 400" "$HTTP_CODE" "400"

# Members are owned by the member-ids endpoint, so a group update must leave
# them alone. The internal endpoint clears them, this one deliberately does not.
reqj PUT "/api/public/groups/$NEWGROUP" "$TOKEN" "{\"name\":\"Platform Team\",\"collections\":[]}"
check_eq "update group again -> 200" "$HTTP_CODE" "200"
req GET "/api/public/groups/$NEWGROUP/member-ids" "$TOKEN"
jqcheck "group update left member assignments intact" 'length' "1"

echo ""
echo "== Create a member =="

reqj POST "/api/public/members" "$TOKEN" \
    "{\"email\":\"$NEW_EMAIL\",\"type\":2,\"externalId\":\"ext-new-member\",\"collections\":[{\"id\":\"$COLLECTION\",\"readOnly\":true,\"hidePasswords\":false,\"manage\":false}],\"groups\":[\"$GROUP\"]}"
check_eq "create member -> 200" "$HTTP_CODE" "200"
jqcheck "created member discriminator" '.object' "member"
jqcheck "created member email" '.email' "$NEW_EMAIL"
jqcheck "created member type" '.type' "2"
jqcheck "created member externalId" '.externalId' "ext-new-member"
jqcheck "created member is invited" '.status' "0"
NEWMEMBER=$(jqval '.id')

req GET "/api/public/members/$NEWMEMBER" "$TOKEN"
jqcheck "created member kept its collection grant" '.collections | length' "1"
jqcheck "created member collection readOnly" '.collections[0].readOnly' "true"

req GET "/api/public/members/$NEWMEMBER/group-ids" "$TOKEN"
jqcheck "created member joined the group" 'length' "1"
jqcheck "created member group id" '.[0]' "$GROUP"

echo ""
echo "== Member input validation =="

reqj POST "/api/public/members" "$TOKEN" "{\"email\":\"$NEW_EMAIL\",\"type\":2}"
check_eq "duplicate member email -> 400" "$HTTP_CODE" "400"

reqj POST "/api/public/members" "$TOKEN" \
    "{\"email\":\"other@example.com\",\"type\":2,\"groups\":[\"$GROUP2\"]}"
check_eq "member with another org's group -> 400" "$HTTP_CODE" "400"

reqj POST "/api/public/members" "$TOKEN" "{\"email\":\"bad@example.com\",\"type\":99}"
check_eq "member with an unknown type -> 400" "$HTTP_CODE" "400"

echo ""
echo "== Update a member =="

reqj PUT "/api/public/members/$NEWMEMBER" "$TOKEN" \
    "{\"type\":2,\"externalId\":\"ext-updated\",\"collections\":[{\"id\":\"$COLLECTION\",\"readOnly\":false,\"hidePasswords\":true,\"manage\":false}],\"groups\":[]}"
check_eq "update member -> 200" "$HTTP_CODE" "200"
jqcheck "updated member externalId" '.externalId' "ext-updated"

req GET "/api/public/members/$NEWMEMBER" "$TOKEN"
jqcheck "update replaced the collection grants" '.collections | length' "1"
jqcheck "updated collection readOnly" '.collections[0].readOnly' "false"
jqcheck "updated collection hidePasswords" '.collections[0].hidePasswords' "true"

req GET "/api/public/members/$NEWMEMBER/group-ids" "$TOKEN"
jqcheck "update cleared the group assignments" 'length' "0"

echo ""
echo "== Member group ids =="

reqj PUT "/api/public/members/$NEWMEMBER/group-ids" "$TOKEN" "{\"groupIds\":[\"$GROUP\"]}"
check_eq "set member group-ids -> 200" "$HTTP_CODE" "200"
req GET "/api/public/members/$NEWMEMBER/group-ids" "$TOKEN"
jqcheck "member group-ids applied" '.[0]' "$GROUP"

reqj PUT "/api/public/members/$NEWMEMBER/group-ids" "$TOKEN" "{\"groupIds\":[\"$GROUP2\"]}"
check_eq "member group-ids from another org -> 400" "$HTTP_CODE" "400"

echo ""
echo "== Reinvite =="

req POST "/api/public/members/$NEWMEMBER/reinvite" "$TOKEN"
check_eq "reinvite an invited member -> 200" "$HTTP_CODE" "200"

echo ""
echo "== Revoke and restore =="

req POST "/api/public/members/$MEMBER3/revoke" "$TOKEN"
check_eq "revoke a member -> 200" "$HTTP_CODE" "200"
req GET "/api/public/members/$MEMBER3" "$TOKEN"
jqcheck "revoked member has a revoked status" '.status < 0' "true"

req POST "/api/public/members/$MEMBER3/revoke" "$TOKEN"
check_eq "revoking twice -> 400" "$HTTP_CODE" "400"

req POST "/api/public/members/$MEMBER3/restore" "$TOKEN"
check_eq "restore a member -> 200" "$HTTP_CODE" "200"
req GET "/api/public/members/$MEMBER3" "$TOKEN"
jqcheck "restored member is confirmed again" '.status' "2"

req POST "/api/public/members/$MEMBER3/restore" "$TOKEN"
check_eq "restoring an active member -> 400" "$HTTP_CODE" "400"

echo ""
echo "== The last confirmed owner is protected =="

reqj PUT "/api/public/members/$MEMBER" "$TOKEN" "{\"type\":2}"
check_eq "demoting the last owner -> 400" "$HTTP_CODE" "400"

req DELETE "/api/public/members/$MEMBER" "$TOKEN"
check_eq "deleting the last owner -> 400" "$HTTP_CODE" "400"

req POST "/api/public/members/$MEMBER/revoke" "$TOKEN"
check_eq "revoking the last owner -> 400" "$HTTP_CODE" "400"

req GET "/api/public/members/$MEMBER" "$TOKEN"
jqcheck "the last owner is untouched, type" '.type' "0"
jqcheck "the last owner is untouched, status" '.status' "2"

echo ""
echo "== Organization scoping boundary =="

reqj PUT "/api/public/members/$MEMBER2" "$TOKEN" "{\"type\":2}"
check_eq "updating a member of another org -> 404" "$HTTP_CODE" "404"
req DELETE "/api/public/members/$MEMBER2" "$TOKEN"
check_eq "deleting a member of another org -> 404" "$HTTP_CODE" "404"
req POST "/api/public/members/$MEMBER2/revoke" "$TOKEN"
check_eq "revoking a member of another org -> 404" "$HTTP_CODE" "404"
reqj PUT "/api/public/groups/$GROUP2" "$TOKEN" "{\"name\":\"Hijacked\"}"
check_eq "updating a group of another org -> 404" "$HTTP_CODE" "404"
req DELETE "/api/public/groups/$GROUP2" "$TOKEN"
check_eq "deleting a group of another org -> 404" "$HTTP_CODE" "404"

echo ""
echo "== Delete =="

req DELETE "/api/public/members/$NEWMEMBER" "$TOKEN"
check_eq "delete member -> 200" "$HTTP_CODE" "200"
req GET "/api/public/members/$NEWMEMBER" "$TOKEN"
check_eq "deleted member is gone -> 404" "$HTTP_CODE" "404"

req DELETE "/api/public/groups/$NEWGROUP" "$TOKEN"
check_eq "delete group -> 200" "$HTTP_CODE" "200"
req GET "/api/public/groups/$NEWGROUP" "$TOKEN"
check_eq "deleted group is gone -> 404" "$HTTP_CODE" "404"

echo ""
echo "== Authentication required =="

reqj POST "/api/public/groups" "" "{\"name\":\"NoToken\"}"
check_eq "create group with no token -> 401" "$HTTP_CODE" "401"
req DELETE "/api/public/members/$MEMBER3"
check_eq "delete member with no token -> 401" "$HTTP_CODE" "401"
req GET "/api/public/members/$MEMBER3" "$TOKEN"
check_eq "the unauthenticated delete changed nothing" "$HTTP_CODE" "200"

echo ""
echo "== Writes are recorded in the event log without an acting user =="

stop_server

# 1400 GroupCreated, 1401 GroupUpdated, 1402 GroupDeleted,
# 1500 OrganizationUserInvited, 1502 OrganizationUserUpdated,
# 1503 OrganizationUserRemoved, 1511 Revoked, 1512 Restored.
for pair in "1400:group created" "1401:group updated" "1402:group deleted" \
            "1500:member invited" "1502:member updated" "1503:member removed" \
            "1511:member revoked" "1512:member restored"; do
    code="${pair%%:*}"
    label="${pair#*:}"
    got=$(sqlite3 "$TMP/db.sqlite3" \
        "SELECT COUNT(*) > 0 FROM event WHERE org_uuid='$ORG' AND event_type=$code;")
    check_eq "event logged: $label" "$got" "1"
done

sqlcheck "no Public API event records an acting user" \
    "SELECT COUNT(*) FROM event WHERE org_uuid='$ORG' AND act_user_uuid IS NOT NULL;" "0"
sqlcheck "no Public API event records a device type" \
    "SELECT COUNT(*) FROM event WHERE org_uuid='$ORG' AND device_type IS NOT NULL;" "0"
sqlcheck "Public API events still record the client address" \
    "SELECT COUNT(*) FROM event WHERE org_uuid='$ORG' AND ip_address IS NULL;" "0"

echo ""
if [ "$FAILS" -ne 0 ]; then
    echo "RESULT: $FAILS assertion(s) failed."
    exit 1
fi
echo "RESULT: all assertions passed."
