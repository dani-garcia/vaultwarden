#!/bin/sh

if [ -r /etc/bitwarden_rs.sh ]; then
    . /etc/bitwarden_rs.sh
fi

if [ -d /etc/bitwarden_rs.d ]; then
    for f in /etc/bitwarden_rs.d/*.sh; do
        if [ -r $f ]; then
            . $f
        fi
    done
fi

exec /bitwarden_rs "${@}"
