#!/bin/sh
# Start of the container. The application itself never runs as root.
#
# Started as root (the docker-compose.yml does that with "user: 0:0" and only the rights CHOWN, SETUID and SETGID):
# give the data folder to the application user once if needed (e.g. a fresh ./data created by "docker compose up"
# belongs to root), then switch to that user for good with setpriv. After the switch the process has no special
# rights left (no-new-privileges stays in force).
# Started as the application user (image default, e.g. an older docker-compose.yml): start directly.
set -eu
APP_UID=10001
APP_GID=10001
DATA=/app/data

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
    chmod 700 "$DATA"
    exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --inh-caps=-all -- "$@"
fi
exec "$@"
