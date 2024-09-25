#!/bin/bash

export PATH=/opt/keycloak/bin:/opt/openjdk/jdk-${JAVA_VERSION}/bin:$PATH
export JAVA_HOME=/opt/openjdk/jdk-${JAVA_VERSION}

STATUS_CODE=0
while [[ "$STATUS_CODE" != "404" ]] ; do
    echo "Will retry in 2 seconds"
    sleep 2

    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}"  "$DUMMY_AUTHORITY")

    if [[ "$STATUS_CODE" = "200" ]]; then
        echo "Setup should already be done. Will not run."
        exit 0
    fi
done

set -e

kcadm.sh config credentials --server "http://${KC_HTTP_HOST}:${KC_HTTP_PORT}" --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" --client admin-cli

kcadm.sh create realms -s realm="$TEST_REALM" -s enabled=true -s "accessTokenLifespan=600"
kcadm.sh create clients -r test -s "clientId=$SSO_CLIENT_ID" -s "secret=$SSO_CLIENT_SECRET" -s "redirectUris=[\"$DOMAIN/*\"]" -i

TEST_USER_ID=$(kcadm.sh create users -r "$TEST_REALM" -s "username=$TEST_USER" -s "firstName=$TEST_USER" -s "lastName=$TEST_USER" -s "email=$TEST_USER_MAIL"  -s emailVerified=true -s enabled=true -i)
kcadm.sh update users/$TEST_USER_ID/reset-password -r "$TEST_REALM" -s type=password -s "value=$TEST_USER_PASSWORD" -n

TEST_USER2_ID=$(kcadm.sh create users -r "$TEST_REALM" -s "username=$TEST_USER2" -s "firstName=$TEST_USER2" -s "lastName=$TEST_USER2" -s "email=$TEST_USER2_MAIL"  -s emailVerified=true -s enabled=true -i)
kcadm.sh update users/$TEST_USER2_ID/reset-password -r "$TEST_REALM" -s type=password -s "value=$TEST_USER2_PASSWORD" -n

TEST_USER3_ID=$(kcadm.sh create users -r "$TEST_REALM" -s "username=$TEST_USER3" -s "firstName=$TEST_USER3" -s "lastName=$TEST_USER3" -s "email=$TEST_USER3_MAIL"  -s emailVerified=true -s enabled=true -i)
kcadm.sh update users/$TEST_USER3_ID/reset-password -r "$TEST_REALM" -s type=password -s "value=$TEST_USER3_PASSWORD" -n

# Dummy realm to mark end of setup
kcadm.sh create realms -s realm="$DUMMY_REALM" -s enabled=true -s "accessTokenLifespan=600"
