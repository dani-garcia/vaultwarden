#!/bin/sh

if [ -r /etc/vaultwarden.sh ]; then
    . /etc/vaultwarden.sh
fi

if [ -d /etc/vaultwarden.d ]; then
    for f in /etc/vaultwarden.d/*.sh; do
        if [ -r $f ]; then
            . $f
        fi
    done
fi

exec /vaultwarden "${@}"
