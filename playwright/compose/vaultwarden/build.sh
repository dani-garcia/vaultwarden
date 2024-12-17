#!/bin/bash

echo $REPO_URL
echo $COMMIT_HASH

if [[ ! -z "$REPO_URL" ]] && [[ ! -z "$COMMIT_HASH" ]] ; then
    rm -rf /web-vault

    mkdir bw_web_builds;
    cd bw_web_builds;

    git -c init.defaultBranch=main init
    git remote add origin "$REPO_URL"
    git fetch --depth 1 origin "$COMMIT_HASH"
    git -c advice.detachedHead=false checkout FETCH_HEAD

    export VAULT_VERSION=$(cat Dockerfile | grep "ARG VAULT_VERSION" | cut -d "=" -f2)
    ./scripts/checkout_web_vault.sh
    ./scripts/patch_web_vault.sh
    ./scripts/build_web_vault.sh
    printf '{"version":"%s"}' "$COMMIT_HASH" > ./web-vault/apps/web/build/vw-version.json

    mv ./web-vault/apps/web/build /web-vault
fi
