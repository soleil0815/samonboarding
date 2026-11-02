#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
# SAMONBOARDING - update helper for the manual way (container managers such as Dockhand, Watchtower or Tugtainer do
# not need it). Runs with /bin/sh (dash, busybox ash), also on a NAS (e.g. Synology). It never unpacks ZIPs, never
# places program files and never builds anything - the program is completely in the image.
#
#   sudo sh update.sh                      update to the version in .env (empty = latest)
#   sudo sh update.sh --version 2.0        switch to a version (written to .env as SAMONBOARDING_VERSION)
#   sudo sh update.sh --latest             back to the newest version (SAMONBOARDING_VERSION emptied)
#   sudo sh update.sh --offline FILE       without internet: image file from the release (docker load), then start
#   sudo sh update.sh --restore data/backups/vor-<version>-<time>.tar.gz [--version X]
#                                          put a backup of data/ back (the current state is saved first)
#   sudo sh update.sh --cleanup            remove files of older installations that are no longer needed
#   -y / --yes                             answer questions with yes (e.g. starting the previous version again)
#
# Update: remember the running image as "samonboarding:previous", pull the wanted version, docker compose up -d,
# wait for the health check. If the new version does not start, the previous image is started again (with a
# question, with -y automatically). If the image brings a newer docker-compose.yml, it is put in place and the old
# one is kept as docker-compose.yml.alt. Before a version change the program backs up data/ itself.
set -eu

IMAGE_REPO="${SAMONB_IMAGE_REPO:-ghcr.io/soleil0815/samonboarding}"
SERVICE="samonboarding"
PREVIOUS="samonboarding:previous"
APP_UID=10001
WAIT="${SAMONB_WAIT:-240}"      # seconds to wait for "healthy"
PAUSE="${SAMONB_SLEEP:-3}"      # seconds between checks
ETC="${SAMONB_ETC:-/etc}"       # only for the cleanup of the old internet block (tests use a temporary folder)

say() { printf '%s\n' "$*"; }
ok() { printf '  OK  %s\n' "$*"; }
warn() { printf '  !   %s\n' "$*" >&2; }
fail() { printf '\n  X   %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

ASSUME_YES=0
ACTION=update
WANT_VERSION=""
SET_VERSION=0
OFFLINE_FILE=""
RESTORE_FILE=""

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes|--ja) ASSUME_YES=1 ;;
        --version)
            [ $# -ge 2 ] || fail "--version needs a value, e.g. --version 2.0"
            WANT_VERSION="$2"; SET_VERSION=1; shift ;;
        --version=*) WANT_VERSION="${1#--version=}"; SET_VERSION=1 ;;
        --latest) WANT_VERSION=""; SET_VERSION=1 ;;
        --offline)
            [ $# -ge 2 ] || fail "--offline needs the image file from the release"
            OFFLINE_FILE="$2"; shift ;;
        --restore)
            [ $# -ge 2 ] || fail "--restore needs a backup file from data/backups"
            RESTORE_FILE="$2"; ACTION=restore; shift ;;
        --cleanup) ACTION=cleanup ;;
        --pull|--no-backup|--no-cache|--prune) ;;  # options of older versions: no longer needed, ignored
        --lock) fail "--lock no longer exists: versions are pinned on GitHub; the image is complete." ;;
        -h|--help) usage; exit 0 ;;
        *.zip|*.ZIP) fail "ZIP files are no longer used: the program is completely in the image. Simply: sudo sh update.sh" ;;
        *) fail "Unknown option: $1 (sh update.sh --help)" ;;
    esac
    shift
done

case "$WANT_VERSION" in
    *[!0-9A-Za-z._-]*) fail "Version not understood: $WANT_VERSION (examples: 2.0, 2.0.1, 2.0.1-s2)" ;;
    ""|latest|[0-9]*.[0-9]*) ;;
    *) fail "Version not understood: $WANT_VERSION (examples: 2.0, 2.0.1, 2.0.1-s2)" ;;
esac
[ "$WANT_VERSION" != latest ] || WANT_VERSION=""

# Work in the folder of this script (where docker-compose.yml, .env and data/ are)
cd "$(dirname "$0")"
HERE="$(pwd -P)"

# An older update.sh (up to 1.48) starts this one after fetching the image and leaves a temporary folder behind
if [ -n "${SAMONB_TMP:-}" ]; then
    case "$SAMONB_TMP" in
        "$HERE"/.update-*)
            # only a folder directly in this folder: no further "/", no "..", no link
            case "${SAMONB_TMP#"$HERE"/.update-}" in
                ""|*/*|*..*) ;;
                *) if [ -d "$SAMONB_TMP" ] && [ ! -L "$SAMONB_TMP" ]; then rm -rf "$SAMONB_TMP"; fi ;;
            esac ;;
    esac
fi

ask() {  # ask "question" default(yes|no) - with -y always yes; without a terminal the default
    if [ "$ASSUME_YES" = 1 ]; then return 0; fi
    if [ ! -t 0 ]; then [ "$2" = yes ]; return; fi
    printf '%s [y/n] ' "$1"
    read -r answer || answer=""
    case "$answer" in y|Y|j|J|yes|ja) return 0 ;; *) return 1 ;; esac
}

command -v docker >/dev/null 2>&1 || fail "docker was not found."
if docker compose version >/dev/null 2>&1; then
    dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
    dc() { docker-compose "$@"; }
else
    fail "Docker Compose was not found (docker compose or docker-compose)."
fi

# --- .env ------------------------------------------------------------------------------------------------------------
env_get() {  # value of KEY in .env (last line wins), '' if missing
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tail -n 1 | tr -d '\r'
}
env_set() {  # set KEY=VALUE in .env (replace or append), keeps all other lines and the file rights
    tmp="$(mktemp "$HERE/.env.XXXXXX")"
    if grep -q "^$1=" .env; then
        sed "s|^$1=.*|$1=$2|" .env > "$tmp"
    else
        cat .env > "$tmp"
        printf '%s=%s\n' "$1" "$2" >> "$tmp"
    fi
    cat "$tmp" > .env
    rm -f "$tmp"
}

compose_version() {  # SAMONBOARDING_COMPOSE of a docker-compose.yml (0 = older file without it)
    v="$(sed -n 's/.*SAMONBOARDING_COMPOSE: *"\{0,1\}\([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -n 1)"
    printf '%s' "${v:-0}"
}

current_container() { dc ps -q "$SERVICE" 2>/dev/null | head -n 1; }

image_label() {  # program version of an image
    docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true
}

LAST_STATUS="?"
wait_healthy() {
    waited=0
    while [ "$waited" -lt "$WAIT" ]; do
        cid="$(current_container)"
        if [ -n "$cid" ]; then
            LAST_STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)"
            restarts="$(docker inspect --format '{{.RestartCount}}' "$cid" 2>/dev/null || echo 0)"
            case "$LAST_STATUS" in
                healthy) return 0 ;;
                unhealthy|exited|dead) return 1 ;;
            esac
            if [ "${restarts:-0}" -ge 3 ] 2>/dev/null; then LAST_STATUS="restarting"; return 1; fi
        fi
        sleep "$PAUSE"
        waited=$((waited + PAUSE))
    done
    LAST_STATUS="no answer after ${WAIT}s ($LAST_STATUS)"
    return 1
}

show_logs() {
    cid="$(current_container)"
    [ -z "$cid" ] || { warn "Last messages of the container:"; docker logs --tail 30 "$cid" 2>&1 | sed 's/^/      /' >&2 || true; }
}

# --- docker-compose.yml from the image --------------------------------------------------------------------------------
COMPOSE_REPLACED=0
take_compose_from_image() {  # $1 = image reference
    tmpd="$(mktemp -d "$HERE/.update-XXXXXX")"
    cid="$(docker create "$1" 2>/dev/null || true)"
    if [ -n "$cid" ]; then
        docker cp "$cid:/app/docker-compose.yml" "$tmpd/docker-compose.yml" >/dev/null 2>&1 || true
        docker rm "$cid" >/dev/null 2>&1 || true
    fi
    if [ -s "$tmpd/docker-compose.yml" ]; then
        have="$(compose_version docker-compose.yml)"
        new="$(compose_version "$tmpd/docker-compose.yml")"
        if [ "$new" -gt "$have" ]; then
            cp -p docker-compose.yml docker-compose.yml.alt
            cat "$tmpd/docker-compose.yml" > docker-compose.yml
            COMPOSE_REPLACED=1
            ok "docker-compose.yml updated (version $have -> $new), the old one is kept as docker-compose.yml.alt"
        fi
    fi
    rm -rf "$tmpd"
}

# --- update ----------------------------------------------------------------------------------------------------------
do_update() {
    [ -f docker-compose.yml ] || fail "docker-compose.yml is missing in $HERE."
    [ -f .env ] || fail ".env is missing: copy env.example (from the release) or .env.example as .env and fill it in (see README)."
    cp -p .env "$HERE/.env.update-bak"

    # .env of versions up to 1.48: SAMONBOARDING_IMAGE=ghcr.io/...:<tag> -> SAMONBOARDING_VERSION
    old_image="$(env_get SAMONBOARDING_IMAGE)"
    if [ -n "$old_image" ]; then
        case "$old_image" in
            "$IMAGE_REPO":*)
                tag="${old_image##*:}"
                [ "$tag" != latest ] || tag=""
                if [ "$SET_VERSION" = 0 ] && [ -z "$(env_get SAMONBOARDING_VERSION)" ]; then env_set SAMONBOARDING_VERSION "$tag"; fi
                sed "s|^SAMONBOARDING_IMAGE=|# replaced by SAMONBOARDING_VERSION: SAMONBOARDING_IMAGE=|" .env > "$HERE/.env.tmp" \
                    && cat "$HERE/.env.tmp" > .env && rm -f "$HERE/.env.tmp"
                ok "SAMONBOARDING_IMAGE in .env replaced by SAMONBOARDING_VERSION=${tag:-} (empty = latest)"
                ;;
            *) warn "SAMONBOARDING_IMAGE=$old_image in .env is no longer used (the docker-compose.yml takes $IMAGE_REPO)." ;;
        esac
    fi

    if [ -n "$OFFLINE_FILE" ]; then
        [ -f "$OFFLINE_FILE" ] || fail "Image file not found: $OFFLINE_FILE"
        step "Loading the image file (without internet)"
        loaded="$(docker load -i "$OFFLINE_FILE" | sed -n 's/^Loaded image: //p' | grep "^$IMAGE_REPO:" | head -n 1)"
        [ -n "$loaded" ] || fail "The file does not contain a SAMONBOARDING image ($IMAGE_REPO)."
        WANT_VERSION="${loaded##*:}"; SET_VERSION=1
        ok "Loaded: $loaded"
    fi
    [ "$SET_VERSION" = 0 ] || env_set SAMONBOARDING_VERSION "$WANT_VERSION"
    version="$(env_get SAMONBOARDING_VERSION)"
    ref="$IMAGE_REPO:${version:-latest}"

    old_cid="$(current_container)"
    old_ref=""
    if [ -n "$old_cid" ]; then
        old_image_id="$(docker inspect --format '{{.Image}}' "$old_cid" 2>/dev/null || true)"
        old_ref="$(docker inspect --format '{{.Config.Image}}' "$old_cid" 2>/dev/null || true)"
        if [ -n "$old_image_id" ]; then
            docker tag "$old_image_id" "$PREVIOUS"
            ok "Running version remembered as $PREVIOUS ($(image_label "$PREVIOUS"))"
        fi
    fi

    if [ -z "$OFFLINE_FILE" ]; then
        step "Fetching $ref"
        if ! docker pull "$ref"; then
            cat .env.update-bak > .env; rm -f .env.update-bak
            warn "For a private repository, log in once (password = token with read:packages): docker login ghcr.io"
            fail "docker pull failed - nothing changed."
        fi
    fi
    ok "Image: SAMONBOARDING $(image_label "$ref")"
    take_compose_from_image "$ref"

    step "Starting"
    if dc up -d --remove-orphans && wait_healthy; then
        rm -f .env.update-bak
        ok "SAMONBOARDING $(image_label "$ref") is running (healthy)"
        docker image prune -f --filter "label=de.helfi.samonboarding=1" >/dev/null 2>&1 || true
        return 0
    fi
    warn "The new version does not start cleanly: $LAST_STATUS"
    show_logs
    if [ -z "$old_ref" ] || ! docker image inspect "$PREVIOUS" >/dev/null 2>&1; then
        fail "There is no previous version to go back to. Details: docker compose logs"
    fi
    if ! ask "Start the previous version ($(image_label "$PREVIOUS")) again?" yes; then
        fail "The new version is left as it is. Back later with: sudo sh update.sh --version $(image_label "$PREVIOUS")"
    fi
    step "Starting the previous version again"
    cat .env.update-bak > .env; rm -f .env.update-bak
    if [ "$COMPOSE_REPLACED" = 1 ]; then
        mv -f docker-compose.yml.alt docker-compose.yml
    elif [ -n "${SAMONB_PULL_BACKUP:-}" ] && [ -f "$SAMONB_PULL_BACKUP" ]; then
        # an older update.sh (up to 1.48) replaced docker-compose.yml before starting this one and kept a backup
        tar -xzf "$SAMONB_PULL_BACKUP" docker-compose.yml 2>/dev/null && ok "previous docker-compose.yml restored"
    fi
    docker tag "$PREVIOUS" "$old_ref"
    if dc up -d --force-recreate --remove-orphans && wait_healthy; then
        fail "New version NOT applied - the previous one ($(image_label "$PREVIOUS")) is running again."
    fi
    show_logs
    fail "The previous version does not start either ($LAST_STATUS). If the new version had already converted the data, put back the backup it made: sudo sh update.sh --restore data/backups/vor-<new version>-<time>.tar.gz"
}

# --- restore ----------------------------------------------------------------------------------------------------------
do_restore() {
    file="$RESTORE_FILE"
    case "$file" in
        data/backups/*|./data/backups/*|"$HERE"/data/backups/*) ;;
        *) fail "Only backups from data/backups can be restored." ;;
    esac
    case "$file" in *..*) fail "Invalid path: $file" ;; esac
    [ -f "$file" ] || fail "Backup not found: $file"
    list="$(tar -tzf "$file" 2>/dev/null)" || fail "$file is not a readable backup (tar.gz)."
    if printf '%s\n' "$list" | grep -Eq '^/|(^|/)\.\.(/|$)'; then fail "$file contains unsafe paths - not restored."; fi
    # only plain files and folders: no links, hard links or device files (they could point out of data/)
    types="$(tar -tvzf "$file" 2>/dev/null | cut -c1)" || fail "$file is not a readable backup (tar.gz)."
    if printf '%s\n' "$types" | grep -q '[^-d]'; then fail "$file contains links or special files - not restored."; fi
    say "The data in data/ is replaced by $file."
    say "The current state is saved first (data/backups/vor-wiederherstellen-<time>.tar.gz)."
    ask "Restore now?" no || fail "Nothing changed."
    step "Stopping the container"
    dc stop >/dev/null 2>&1 || true
    stamp="$(date '+%Y%m%d-%H%M%S')"
    (
        cd data
        set --
        for entry in * .[!.]* ..?*; do
            [ -e "$entry" ] || [ -L "$entry" ] || continue
            [ "$entry" = backups ] || set -- "$@" "$entry"
        done
        if [ $# -gt 0 ]; then tar -czf "backups/vor-wiederherstellen-$stamp.tar.gz" "$@"; fi
        chmod 600 "backups/vor-wiederherstellen-$stamp.tar.gz" 2>/dev/null || true
        for entry in "$@"; do rm -rf "./$entry"; done
    ) || fail "The current state could not be saved - nothing restored."
    if ! tar -xzf "$file" -C data; then
        if [ "$(id -u)" = 0 ]; then chown -R "$APP_UID:$APP_UID" data || true; fi
        fail "Restoring failed - the previous state is in data/backups/vor-wiederherstellen-$stamp.tar.gz"
    fi
    if [ "$(id -u)" = 0 ]; then chown -R "$APP_UID:$APP_UID" data; fi
    ok "Backup restored ($file)"
    [ "$SET_VERSION" = 0 ] || env_set SAMONBOARDING_VERSION "$WANT_VERSION"
    step "Starting"
    if dc up -d --remove-orphans && wait_healthy; then
        ok "SAMONBOARDING is running (healthy)"
        return 0
    fi
    show_logs
    fail "Not started ($LAST_STATUS). Is the version in .env (SAMONBOARDING_VERSION) the one that fits this backup?"
}

# --- cleanup of older installations -----------------------------------------------------------------------------------
# Program files of installations up to 1.48 (ZIP or git, built here). Never: data, backups, .env, docker-compose.yml
# (also .alt / override), folders mounted by a container - also not via links.
KNOWN_FILES="samonboarding tests scripts .github static node_modules .git app.py Dockerfile docker-entrypoint.sh
pyproject.toml requirements.txt requirements.in requirements-dev.txt requirements.txt.vorher package.json
package-lock.json tailwind.config.js tailwind.input.css images.lock os-packages.lock README.md README.en.md
CHANGELOG.md CHANGELOG.en.md DATENSCHUTZ.md DATA-PROTECTION.en.md LICENSE SECURITY.md docker-compose.image.yml
.dockerignore .gitattributes .gitignore .trivyignore .dateiliste .paketpruefung-abgelehnt .ruff_cache
.pytest_cache"
PROTECTED_NAMES="data backups .env docker-compose.yml docker-compose.yml.alt docker-compose.override.yml update.sh"

resolve() {  # full path with all links resolved (also for paths that do not exist yet: their folder)
    # $2 = depth: a loop of links (a -> b -> a) gives up after 40 steps instead of crashing
    if [ "${2:-0}" -gt 40 ]; then return 1; fi
    if [ -d "$1" ]; then (cd -P "$1" 2>/dev/null && pwd -P); return; fi
    d="$(dirname "$1")"; b="$(basename "$1")"
    if [ -L "$1" ]; then
        target="$(readlink "$1")"
        case "$target" in /*) ;; *) target="$d/$target" ;; esac
        resolve "$target" $((${2:-0} + 1))
        return
    fi
    printf '%s/%s\n' "$(cd -P "$d" 2>/dev/null && pwd -P)" "$b"
}

PROTECTED=""
protect() { r="$(resolve "$1" 2>/dev/null || true)"; [ -z "$r" ] || PROTECTED="$PROTECTED
$r"; }

overlaps_protected() {  # is $1 (resolved) a protected path, inside one, or does it contain one?
    printf '%s\n' "$PROTECTED" | while IFS= read -r p; do
        [ -n "$p" ] || continue
        case "$1" in "$p"|"$p"/*) echo yes; break ;; esac
        case "$p" in "$1"/*) echo yes; break ;; esac
    done | grep -q yes
}

MOUNTINFO="${SAMONB_MOUNTINFO:-/proc/self/mountinfo}"  # tests use a prepared file

is_mount_or_has_mount() {  # is the resolved path $1 itself a mount point, or is one mounted below it?
    [ -r "$MOUNTINFO" ] || return 1
    # field 5 is the mount point; spaces etc. are written as \040 (octal) - printf %b turns them back
    cut -d ' ' -f 5 "$MOUNTINFO" | while IFS= read -r m; do
        m="$(printf '%b' "$(printf '%s' "$m" | sed 's/\\\([0-7][0-7][0-7]\)/\\0\1/g')")"
        case "$m" in "$1"|"$1"/*) echo yes; break ;; esac
    done | grep -q yes
}

crosses_mount() {  # is the folder $1 (or anything inside) on another file system or a mount point (also bind mounts)?
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    real="$(cd -P "$1" 2>/dev/null && pwd -P)" || return 0
    if is_mount_or_has_mount "$real"; then return 0; fi
    base="$(stat -c %d "$HERE" 2>/dev/null)" || return 0
    find "$1" -type d -exec stat -c %d {} + 2>/dev/null | grep -qvx "$base"
}

do_cleanup() {
    for name in $PROTECTED_NAMES; do protect "$HERE/$name"; done
    # folders mounted into any container (e.g. data in another place) are protected as well
    for c in $(docker ps -aq 2>/dev/null); do
        docker inspect --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null | while IFS= read -r src; do
            [ -n "$src" ] && printf '%s\n' "$src"
        done
    done > "$HERE/.cleanup-mounts.$$" 2>/dev/null || true
    while IFS= read -r src; do protect "$src"; done < "$HERE/.cleanup-mounts.$$"
    rm -f "$HERE/.cleanup-mounts.$$"

    candidates=""
    for name in $KNOWN_FILES; do
        [ -e "$HERE/$name" ] || [ -L "$HERE/$name" ] || continue
        candidates="$candidates $name"
    done
    skipped=""
    for path in "$HERE"/*.zip "$HERE"/*.ZIP "$HERE"/samonboarding-[0-9]* "$HERE"/.update-* "$HERE"/.env.update-bak; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        name="$(basename "$path")"
        # the lists below are split at spaces: names with spaces, wildcards or other special characters are never
        # put in them (a "*" would otherwise stand for every file in this folder, data/ included)
        case "$name" in
            *[!A-Za-z0-9._+-]*) skipped="$skipped
      $name (unusual name - please delete by hand if no longer needed)"; continue ;;
        esac
        candidates="$candidates $name"
    done

    set -f  # no wildcard expansion while working with the lists
    delete=""
    for name in $candidates; do
        path="$HERE/$name"
        real="$(resolve "$path" || true)"
        if [ -z "$real" ]; then
            skipped="$skipped
      $name (links could not be resolved)"
            continue
        fi
        case "$real" in "$HERE"/*) ;; *) skipped="$skipped
      $name (points outside this folder: $real)"; continue ;; esac
        if overlaps_protected "$real"; then
            skipped="$skipped
      $name (contains or leads to protected data: $real)"
            continue
        fi
        if crosses_mount "$path"; then
            skipped="$skipped
      $name (another file system is mounted inside)"
            continue
        fi
        delete="$delete $name"
    done

    units=""
    for unit in samonboarding-internetsperre.path samonboarding-internetsperre.timer samonboarding-internetsperre.service; do
        [ ! -f "$ETC/systemd/system/$unit" ] || units="$units $unit"
    done

    step "Cleanup in $HERE"
    if [ -z "$delete" ] && [ -z "$units" ]; then
        ok "Nothing to clean up."
        [ -z "$skipped" ] || say "  Left alone:$skipped"
        return 0
    fi
    say "  No longer needed (the program is completely in the image):"
    for name in $delete; do say "      $name"; done
    for unit in $units; do say "      $ETC/systemd/system/$unit (internet block of versions up to 1.37)"; done
    [ -z "$skipped" ] || say "  Left alone:$skipped"
    say "  Never touched: data/, backups/, .env, docker-compose.yml (and .alt/.override), update.sh, mounted folders."
    ask "Delete the files listed above?" no || { say "Nothing deleted."; return 0; }
    for name in $delete; do
        # checked again directly before deleting (something may have changed while the question was open)
        real="$(resolve "$HERE/$name" || true)"
        case "$real" in "$HERE"/*) ;; *) warn "left alone: $name (changed in the meantime)"; continue ;; esac
        if overlaps_protected "$real" || crosses_mount "$HERE/$name"; then
            warn "left alone: $name (changed in the meantime)"
            continue
        fi
        if [ -L "$HERE/$name" ]; then rm -f "$HERE/$name"; else rm -rf "${HERE:?}/$name"; fi
        ok "deleted: $name"
    done
    if [ -n "$units" ]; then
        for unit in $units; do
            if command -v systemctl >/dev/null 2>&1 && [ "$ETC" = /etc ]; then systemctl disable --now "$unit" >/dev/null 2>&1 || true; fi
            rm -f "$ETC/systemd/system/$unit"
            ok "removed: $unit"
        done
        if command -v systemctl >/dev/null 2>&1 && [ "$ETC" = /etc ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
    fi
    if [ "$ETC" = /etc ] && command -v iptables >/dev/null 2>&1; then
        for k in SAMONB-EGRESS-A SAMONB-EGRESS-B SAMONB-EGRESS SAMONB-HOST-A SAMONB-HOST-B SAMONB-HOST; do
            for base in DOCKER-USER INPUT; do
                while iptables -C "$base" -i br-samonb -j "$k" >/dev/null 2>&1; do
                    iptables -D "$base" -i br-samonb -j "$k" >/dev/null 2>&1 || break
                done
            done
            if iptables -L "$k" -n >/dev/null 2>&1; then
                iptables -F "$k" >/dev/null 2>&1 && iptables -X "$k" >/dev/null 2>&1 && ok "removed: iptables chain $k"
            fi
        done
    fi
}

case "$ACTION" in
    update) do_update ;;
    restore) do_restore ;;
    cleanup) do_cleanup ;;
esac
