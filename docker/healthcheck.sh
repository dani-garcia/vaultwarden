#!/usr/bin/env sh

if [ -z "$ROCKET_TLS"]
then
  curl --fail http://localhost:${ROCKET_PORT:-"80"}/alive || exit 1
else
  curl --insecure --fail https://localhost:${ROCKET_PORT:-"80"}/alive || exit 1
fi