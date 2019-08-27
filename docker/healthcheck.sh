#!/usr/bin/env sh

if [ -z "$ROCKET_TLS"]
then
  curl --fail http://localhost/alive || exit 1
else
  curl --fail https://localhost/alive || exit 1
fi