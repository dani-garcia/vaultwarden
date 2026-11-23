#!/bin/bash

echo $REPO_URL
echo $COMMIT_HASH

if [[ ! -z "$REPO_URL" ]] && [[ ! -z "$COMMIT_HASH" ]] ; then
    rm -rf /web-vault

    mkdir -p vw_web_builds;
    cd vw_web_builds;

    git -c init.defaultBranch=main init
    git remote add origin "$REPO_URL"
    git fetch --depth 1 origin "$COMMIT_HASH"
    git -c advice.detachedHead=false checkout FETCH_HEAD

    npm ci --ignore-scripts

    cd apps/web
    npm run dist:oss:selfhost
    printf '{"version":"%s"}' "$COMMIT_HASH" > build/vw-version.json

    mv build /web-vault
fi

# Lower the KDF iterations default for faster tests.
sed -i 's/(6e5,2e6,6e5)/(1e5,2e6,1e5)/' /web-vault/app/main.*.js

# Generate a self signed cert
mkdir -p /data/ssl; cd /data/ssl

openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
