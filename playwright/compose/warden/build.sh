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
