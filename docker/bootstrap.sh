#!/usr/bin/env bash

# add any certs the user might have bind mounted
update-ca-certificates

# start bitwarden
/bitwarden_rs
