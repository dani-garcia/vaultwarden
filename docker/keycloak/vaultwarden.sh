#!/usr/bin/env sh

# Remove CSS to hide SSO Link
sed -i 's#a\[routerlink="/sso"\],##' /web-vault/app/main.*.css
