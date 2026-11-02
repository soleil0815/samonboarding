#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
# Start of the container. The application itself never runs as root.
#
# Started as root (the docker-compose.yml does that with "user: 0:0" and only the rights DAC_READ_SEARCH, CHOWN,
# SETUID and SETGID): give the data folder to the application user once if needed (e.g. a fresh ./data created by
# "docker compose up" belongs to root, an existing one may belong to another user), then switch to that user for good
# with setpriv. After the switch the process has no rights left (no-new-privileges stays in force). The folder rights
# (700) are set by the program itself as the owner.
# Started as the application user (image default, e.g. an older docker-compose.yml): start directly.
set -eu
APP_UID=10001
APP_GID=10001
DATA=/app/data

# Health check of the image (HEALTHCHECK): Docker runs it as the container user - with "user: 0:0" that is root.
# It never runs as root either: give up all rights first. An empty HTTPS_PORT= in .env means the default (9500).
if [ "${1:-}" = healthcheck ]; then
    PORT="${HTTPS_PORT:-9500}"
    set -- python -I -c "import ssl, urllib.request; urllib.request.urlopen('https://localhost:$PORT/api/public-config', timeout=3, context=ssl._create_unverified_context())"
    if [ "$(id -u)" = 0 ]; then
        exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --inh-caps=-all -- "$@"
    fi
    exec "$@"
fi

if [ "$(id -u)" = 0 ]; then
    mkdir -p "$DATA"
    if [ "$(stat -c %u "$DATA")" != "$APP_UID" ] || [ "$(stat -c %g "$DATA")" != "$APP_GID" ]; then
        if ! chown -R "$APP_UID:$APP_GID" "$DATA" 2>/dev/null; then
            echo "The data folder could not be given to the application user ($APP_UID)." >&2
            echo "Run once in the folder of the docker-compose.yml:  sudo chown -R $APP_UID:$APP_GID data" >&2
            exit 1
        fi
        echo "Data folder handed over to the application user ($APP_UID)."
    fi
    exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --inh-caps=-all -- "$@"
fi
exec "$@"
