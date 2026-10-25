#!/usr/bin/env bash
# =============================================================================
# SAMONBOARDING - rebuild and restart the container
#
#   sudo sh update.sh samonboarding-1.2.3.zip
#                             INSTALL A NEW VERSION: copy the ZIP into the project folder and run this command.
#                             Shows what changes, asks ONCE, backs up, replaces the program files, builds,
#                             starts, checks - and cleans up afterwards (ZIP, temporary files, old images).
#                             If the new version does not start, the previous one is restored. (-y/--yes: no prompt)
#   sudo sh update.sh --pull  GET THE NEWEST IMAGE FROM GITHUB (ghcr.io) instead of building here: back up data/,
#                             docker pull, restart, check - the previous image comes back if the start fails.
#   sudo sh update.sh         Back up data/, build the image here, restart the container, check the status
#   sudo sh update.sh --lock  pin all versions again within the base (scripts/pins.py, needs python3)
#                             and build afterwards - e.g. for security updates of the packages
#   ... --no-cache            build without the Docker build cache (everything from scratch)
#   ... --no-backup           do not back up data/
#   ... --prune               remove old, unused images afterwards
#   ... --help                this help
#
# Your settings (.env), data/ and a docker-compose.override.yml (if any) are left unchanged.
# =============================================================================

# Started with "sh update.sh" (dash)? Then restart with bash right away - the script needs bash.
# Also restart if "sh" itself is bash in POSIX mode (e.g. Synology): some features are missing there.
case ":${SHELLOPTS:-}:" in *:posix:*) _samonb_posix=1 ;; *) _samonb_posix=0 ;; esac
if [ -z "${BASH_VERSION:-}" ] || { [ "$_samonb_posix" = 1 ] && [ -z "${SAMONB_BASH_NEU:-}" ]; }; then
    command -v bash >/dev/null 2>&1 || { echo "Error: bash is required." >&2; exit 1; }
    exec env SAMONB_BASH_NEU=1 bash "$0" "$@"
fi
[ "$_samonb_posix" = 0 ] || set +o posix
set -euo pipefail

# When a ZIP is installed, this script replaces itself. bash reads scripts while running them -
# so in that case it runs from a copy (and remembers the project folder).
if [ -z "${SAMONB_KOPIE:-}" ]; then
    for _a in "$@"; do
        case "$_a" in
            *.zip|*.ZIP|--pull)  # --pull: update.sh may be replaced by the one from the image
                _kopie="$(mktemp "${TMPDIR:-/tmp}/samonboarding-update.XXXXXX")"
                cp "$0" "$_kopie"
                exec env SAMONB_KOPIE="$_kopie" SAMONB_PROJEKT="$(dirname "$(readlink -f "$0")")" bash "$_kopie" "$@" ;;
        esac
    done
fi

# Options (make ZIP paths absolute before changing into the project folder)
ZIPS=()
ASSUME_YES=0
DO_LOCK=0
DO_BACKUP=1
DO_PRUNE=0
DO_PULL=0
BUILD_ARGS=(--pull)  # always the current base images (newest patch version, security updates)
PASS_ARGS=()
for arg in "$@"; do
    case "$arg" in
        *.zip|*.ZIP) ZIPS+=("$(readlink -f "$arg" 2>/dev/null || echo "$arg")") ;;
        -y|--yes|--ja) ASSUME_YES=1 ;;
        --lock) DO_LOCK=1; PASS_ARGS+=("$arg") ;;
        --no-cache) BUILD_ARGS+=("--no-cache"); PASS_ARGS+=("$arg") ;;
        --no-backup) DO_BACKUP=0; PASS_ARGS+=("$arg") ;;
        --prune) DO_PRUNE=1; PASS_ARGS+=("$arg") ;;
        --pull) DO_PULL=1 ;;
        -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; echo "Error: unknown option: $arg" >&2; exit 1 ;;
    esac
done

SELF="$(readlink -f "$0")"  # for the second pass (before the cd - a relative path would no longer fit afterwards)
cd "${SAMONB_PROJEKT:-$(dirname "$SELF")}"
case "$PWD" in
    *[!A-Za-z0-9/._-]*)
        echo "Error: the project path '$PWD' contains spaces or special characters. Please move it to a folder like /opt/samonboarding." >&2
        exit 1 ;;
esac

SERVICE="samonboarding"
APP_UID=10001  # user inside the container (see Dockerfile)
REJECTED_FILE=".paketpruefung-abgelehnt"  # marks new package requirements that failed the check
BACKUP_DIR="backups"
KEEP_BACKUPS="${KEEP_BACKUPS:-3}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"


if [ -t 1 ]; then
    C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_BOLD=$'\e[1m'; C_OFF=$'\e[0m'
else
    C_OK=""; C_WARN=""; C_ERR=""; C_BOLD=""; C_OFF=""
fi
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_OFF"; }
ok()   { printf '%s✔ %s%s\n' "$C_OK" "$*" "$C_OFF"; }
warn() { printf '%s! %s%s\n' "$C_WARN" "$*" "$C_OFF"; }
fail() { printf '%s✖ %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }

usage() { sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; }


# -----------------------------------------------------------------------------
# Requirements
# -----------------------------------------------------------------------------
step "Checking requirements"
command -v docker >/dev/null 2>&1 || fail "docker is not installed."
docker info >/dev/null 2>&1 || fail "Docker is not running or this user may not use Docker (sudo or group 'docker')."
# Docker Compose is NOT required. If present it is used (plugin "docker compose" or "docker-compose", e.g. on a
# Synology); otherwise update.sh does the same with plain docker commands (see dc_ohne_compose).
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    COMPOSE=()
fi

# Without Compose: the same settings as in docker-compose.yml, using docker build / network / run
PLAIN_NAME="samonboarding"           # container name
PLAIN_IMAGE="ghcr.io/soleil0815/samonboarding:latest"   # image name (SAMONBOARDING_IMAGE in .env, see below)
dc_ohne_compose() {
    local cmd="$1"; shift
    case "$cmd" in
        version) echo "without Compose" ;;
        config) echo "$PLAIN_IMAGE" ;;  # only "config --images" is needed
        build)
            docker build "$@" --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --build-arg NODE_IMAGE="$NODE_IMAGE" \
                --build-arg DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-}" -t "$PLAIN_IMAGE" . ;;
        ps)
            local all=()
            [ "${1:-}" = "-a" ] && all=(-a)
            docker ps ${all[@]+"${all[@]}"} -q --filter "name=^${PLAIN_NAME}\$" ;;
        stop) docker stop "$PLAIN_NAME" >/dev/null 2>&1 || true ;;
        logs)
            local tail=()
            [ "${1:-}" = "--tail" ] && tail=(--tail "$2")
            docker logs ${tail[@]+"${tail[@]}"} "$PLAIN_NAME" ;;
        exec)
            [ "${1:-}" = "-T" ] && shift
            shift  # service name
            docker exec "$PLAIN_NAME" "$@" ;;
        up)
            local subnet
            subnet="$(env_value DOCKER_SUBNET)"
            local vorhanden
            vorhanden="$(docker network inspect samonboarding --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
            if [ -n "$vorhanden" ] && [ "$vorhanden" != "${subnet:-172.30.80.0/24}" ]; then
                warn "The Docker network 'samonboarding' has the subnet $vorhanden, .env says ${subnet:-172.30.80.0/24}."
                warn "To apply it: stop the container and run 'docker network rm samonboarding'."
            fi
            if ! docker network inspect samonboarding >/dev/null 2>&1; then
                docker network create --driver bridge --subnet "${subnet:-172.30.80.0/24}" \
                    -o com.docker.network.bridge.name=br-samonb samonboarding >/dev/null
            fi
            docker rm -f "$PLAIN_NAME" >/dev/null 2>&1 || true
            # docker takes quotes in --env-file literally (Compose removes them) - so remove them first
            local envf
            envf="$(mktemp)"
            local key
            for key in $(sed -n 's/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\)=.*/\2/p' .env | sort -u); do
                printf '%s=%s\n' "$key" "$(env_value "$key")"
            done > "$envf"
            docker run -d --name "$PLAIN_NAME" --env-file "$envf" \
                -p "${HTTPS_PORT}:${HTTPS_PORT}" -v "$PWD/data:/app/data" \
                --restart unless-stopped --security-opt no-new-privileges:true --cap-drop ALL \
                --network samonboarding \
                --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
                "$PLAIN_IMAGE" >/dev/null || { rm -f "$envf"; return 1; }
            rm -f "$envf" ;;
        *) fail "Internal error: '$cmd' is not supported without Docker Compose." ;;
    esac
}

dc() {
    if [ "${#COMPOSE[@]}" -gt 0 ]; then "${COMPOSE[@]}" "$@"; else dc_ohne_compose "$@"; fi
}
COMPOSE_VERSION="$(dc version --short 2>/dev/null | sed 's/^v//' || true)"
case "$COMPOSE_VERSION" in
    1.*) warn "Docker Compose $COMPOSE_VERSION is very old (version 1). It should work, version 2 is tested;"
         warn "automatic rollback of a new version is not available with it." ;;
    "without Compose")
         warn "Docker Compose not found - update.sh starts the container directly with docker (same settings)."
         [ ! -f docker-compose.override.yml ] || warn "docker-compose.override.yml is NOT used without Docker Compose." ;;
esac
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), Compose: ${COMPOSE_VERSION:-?}"

# Tools that are not available everywhere (e.g. Synology): with fallbacks
gleich() {  # do two files have the same content?
    if command -v cmp >/dev/null 2>&1; then cmp -s "$1" "$2"; else [ "$(cksum < "$1")" = "$(cksum < "$2")" ]; fi
}
sha256_16() {  # first 16 characters of the SHA-256 checksum of a file
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -c1-16
    else
        openssl dgst -sha256 -r "$1" | cut -c1-16
    fi
}
mit_zeitlimit() {  # timeout, if available
    if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi
}
neueste_zip() {  # highest version number first, otherwise alphabetical
    if printf '1\n2\n' | sort -V >/dev/null 2>&1; then sort -V | tail -n1; else sort | tail -n1; fi
}

# After installing: remove temporary files and the script copy
aufraeumen_tmp() {
    [ -n "${SAMONB_TMP:-}" ] && rm -rf "$SAMONB_TMP"
    [ -n "${SAMONB_KOPIE:-}" ] && rm -f "$SAMONB_KOPIE"
    return 0
}

# Restore the program files of the previous version (after installing a ZIP)
PROGRAMM_ZURUECK_ERLEDIGT=0
programm_zurueck() {
    [ "$PROGRAMM_ZURUECK_ERLEDIGT" = 0 ] || return 0
    if [ -n "${SAMONB_PULL_BACKUP:-}" ] && [ -f "$SAMONB_PULL_BACKUP" ]; then
        # --pull replaced only update.sh and docker-compose.yml - put exactly these back
        PROGRAMM_ZURUECK_ERLEDIGT=1
        tar -xzf "$SAMONB_PULL_BACKUP"
        ok "Previous update.sh and docker-compose.yml restored."
        return 0
    fi
    [ -n "${SAMONB_PROG_BACKUP:-}" ] && [ -f "$SAMONB_PROG_BACKUP" ] || return 0
    PROGRAMM_ZURUECK_ERLEDIGT=1
    warn "Restoring the previous program files ($SAMONB_PROG_BACKUP)."
    local liste
    liste="$(tar -tzf "$SAMONB_PROG_BACKUP" | sed 's#^\./##')"
    if [ -f .dateiliste ]; then
        while IFS= read -r f; do
            [ -n "$f" ] && ! grep -qxF -- "$f" <<< "$liste" && rm -f -- "$f"
        done < .dateiliste
    fi
    grep -qxF ".dateiliste" <<< "$liste" || rm -f .dateiliste
    tar -xzf "$SAMONB_PROG_BACKUP"
    rm -f requirements.txt.vorher
    ok "Previous program files restored. The ZIP is kept."
}

# Any abort (error, Ctrl+C) before the new version runs: discard new packages, restore the previous program files,
# remove temporary files. From "Container is running (healthy)" on, the new version stays.
NEUE_VERSION_LAEUFT=0
beim_beenden() {
    local rc=$?
    if [ "$rc" != 0 ] && [ "$NEUE_VERSION_LAEUFT" = 0 ]; then
        [ ! -f requirements.txt.vorher ] || mv -f requirements.txt.vorher requirements.txt
        programm_zurueck || true
    fi
    aufraeumen_tmp
}
trap beim_beenden EXIT

# -----------------------------------------------------------------------------
# Install a new version from a ZIP (sudo sh update.sh samonboarding-x.y.z.zip)
# -----------------------------------------------------------------------------
# Never touched: settings, data, backups and your own additions
GESCHUETZT_RE='^(data|backups)(/|$)|^\.env$|^\.env\..*|^docker-compose\.override\.yml$|^\.paketpruefung-abgelehnt$|^requirements\.txt\.vorher$|^\.dateiliste$|^\.update-|\.zip$'
# Folders that contain only program files (for the cleanup if there is no .dateiliste yet)
PROGRAMM_ORDNER=(samonboarding tests scripts .github)

python_image_aus_lock() { sed -n 's/^PYTHON_IMAGE=//p' images.lock 2>/dev/null | tail -n1; }

# Read the ZIP: unzip, otherwise python3, otherwise via the Python image (Docker is there anyway)
zip_liste() {
    if command -v unzip >/dev/null 2>&1; then
        unzip -Z1 "$1"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$1"
    else
        docker run --rm -v "$1":/z.zip:ro "$(python_image_aus_lock)" \
            python -I -c 'import zipfile; print("\n".join(zipfile.ZipFile("/z.zip").namelist()))'
    fi
}

zip_auspacken() {
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "$1" -d "$2"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -m zipfile -e "$1" "$2"
    else
        docker run --rm --user "$(id -u):$(id -g)" -v "$1":/z.zip:ro -v "$2":/o "$(python_image_aus_lock)" \
            python -I -m zipfile -e /z.zip /o
    fi
}

version_von() { sed -n 's/^VERSION = "\(.*\)"/\1/p' "$1" 2>/dev/null; }

dateien_von() { (cd "$1" && find . -type f ! -path '*/__pycache__/*' | sed 's#^\./##' | LC_ALL=C sort); }

zip_einspielen() {
    local zip="$1" tmpd names top neu alt_v neu_v antwort sicherung
    step "Installing new version: $(basename "$zip")"
    [ -f "$zip" ] || fail "The file '$zip' does not exist. Is the ZIP in the project folder ($PWD)?"
    [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1 || fail "Installing needs root privileges: sudo sh update.sh $(basename "$zip")"

    names="$(zip_liste "$zip")" || fail "The ZIP file cannot be read (damaged?)."
    # Safety: no absolute paths, no '..', no backslashes, exactly one top-level folder
    if printf '%s\n' "$names" | grep -Eq '^/|(^|/)\.\.(/|$)|\\'; then
        fail "The ZIP contains invalid paths - aborted, nothing changed."
    fi
    top="$(printf '%s\n' "$names" | sed 's#/.*##' | sed '/^$/d' | LC_ALL=C sort -u)"
    case "$top" in
        *$'\n'*|"") fail "The ZIP must contain exactly one top-level folder (e.g. samonboarding-1.2.3/)." ;;
    esac

    tmpd="$(mktemp -d "$PWD/.update-XXXXXX")"
    SAMONB_TMP="$tmpd"  # removed on every abort (also Ctrl+C)
    zip_auspacken "$zip" "$tmpd" || { rm -rf "$tmpd"; fail "The ZIP could not be extracted."; }
    neu="$tmpd/$top"
    if find "$tmpd" -type l | grep -q .; then
        rm -rf "$tmpd"; fail "The ZIP contains symbolic links - aborted, nothing changed."
    fi
    for f in update.sh Dockerfile docker-compose.yml requirements.in samonboarding/config.py samonboarding/main.py; do
        [ -f "$neu/$f" ] || { rm -rf "$tmpd"; fail "This is not a SAMONBOARDING version ($f is missing in the ZIP)."; }
    done
    # Never taken from a ZIP (settings, data)
    rm -rf "$neu/data" "$neu/backups" "$neu/.env" "$neu/docker-compose.override.yml" "$neu/.dateiliste" \
        "$neu/.paketpruefung-abgelehnt" "$neu/requirements.txt.vorher"
    find "$neu" -name __pycache__ -type d -prune -exec rm -rf {} +

    alt_v="$(version_von samonboarding/config.py)"
    neu_v="$(version_von "$neu/samonboarding/config.py")"

    # Keep versions pinned on this server as long as they fit the new version
    local behalten=()
    if [ -f requirements.txt ] && grep -q "^# requirements.in: $(sha256_16 "$neu/requirements.in")\$" requirements.txt; then
        cp requirements.txt "$neu/requirements.txt"; behalten+=("requirements.txt (Python packages checked on this server)")
    fi
    if [ -f images.lock ] && [ -f "$neu/images.lock" ] \
        && [ "$(sed 's/@sha256:.*//' images.lock | grep -v '^#')" = "$(sed 's/@sha256:.*//' "$neu/images.lock" | grep -v '^#')" ]; then
        cp images.lock "$neu/images.lock"; behalten+=("images.lock (base images with digest)")
    fi
    if [ -f package-lock.json ] && [ -f package.json ] && gleich package.json "$neu/package.json"; then
        cp package-lock.json "$neu/package-lock.json"; behalten+=("package-lock.json")
    fi

    # Overview
    dateien_von "$neu" > "$tmpd/neu.liste"
    if [ -f .dateiliste ]; then
        LC_ALL=C sort .dateiliste > "$tmpd/alt.liste"
    else
        # No file list yet (first ZIP update): only files that clearly belong to the program - your own
        # files (e.g. your own script in scripts/) stay
        {
            [ -d samonboarding ] && find samonboarding -type f \( -name '*.py' -o -name '*.html' -o -name '*.json' \
                -o -name '*.md' \) ! -path '*/__pycache__/*'
            [ -d tests ] && find tests -type f \( -name 'test_*.py' -o -name '_paths.py' -o -name 'smoke_app.py' \
                -o -path 'tests/ui/*.js' -o -path 'tests/scenarios/*.py' \) ! -path '*/__pycache__/*'
            [ -d scripts ] && find scripts -type f \( -name 'internet-sperre.sh' -o -name 'samonboarding-internetsperre.*' \)
            [ -d .github ] && find .github -type f -name '*.yml'
            true
        } | LC_ALL=C sort > "$tmpd/alt.liste"
    fi
    LC_ALL=C comm -23 "$tmpd/alt.liste" "$tmpd/neu.liste" | grep -Ev "$GESCHUETZT_RE" > "$tmpd/weg.liste" || true
    local geaendert=0 neu_n=0
    while IFS= read -r f; do
        if [ ! -e "$f" ]; then neu_n=$((neu_n + 1)); elif ! gleich "$f" "$neu/$f"; then geaendert=$((geaendert + 1)); fi
    done < "$tmpd/neu.liste"

    echo
    echo "  Installed:     SAMONBOARDING ${alt_v:-?}"
    echo "  New version:   SAMONBOARDING ${neu_v:-?}"
    case "$(printf '%s\n%s\n' "$alt_v" "$neu_v" | neueste_zip)" in
        "$alt_v") [ "$alt_v" = "$neu_v" ] && warn "  Same version - will be installed again." \
                                      || warn "  WARNING: the ZIP contains an OLDER version." ;;
    esac
    echo "  Files:         $geaendert changed, $neu_n new, $(wc -l < "$tmpd/weg.liste") obsolete (will be removed)"
    if [ -s "$tmpd/weg.liste" ]; then
        echo "  Will be removed (no longer part of the new version):"
        head -n 20 "$tmpd/weg.liste" | sed 's/^/    /'
        [ "$(wc -l < "$tmpd/weg.liste")" -le 20 ] || echo "    ... and $(( $(wc -l < "$tmpd/weg.liste") - 20 )) more"
    fi
    echo "  Left unchanged: .env, data/, backups/, docker-compose.override.yml"
    for b in ${behalten[@]+"${behalten[@]}"}; do echo "  Kept (fits the new version): $b"; done
    echo "  Steps: back up program and data/ -> replace files -> build -> start -> check"
    echo "  Afterwards: the ZIP, temporary files and old images are removed. If the new version does not start,"
    echo "              the previous program files are restored."
    echo
    if [ "$ASSUME_YES" != 1 ]; then
        if ! { true < /dev/tty; } 2>/dev/null; then
            rm -rf "$tmpd"; fail "Cannot ask for confirmation (no terminal) - use --yes to install without asking."
        fi
        printf '%sInstall the new version now? [y/N] %s' "$C_BOLD" "$C_OFF"
        read -r antwort < /dev/tty || antwort=""
        case "$antwort" in
            y|Y|yes|Yes|YES|j|J|ja|Ja|JA) ;;
            *) rm -rf "$tmpd"; echo "Aborted - nothing changed."; exit 0 ;;
        esac
    fi

    # Back up the current program files (for the rollback)
    mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    sicherung="$BACKUP_DIR/programm-${alt_v:-unbekannt}-$(date '+%Y%m%d-%H%M%S').tar.gz"
    tar -czf "$sicherung" --exclude=./data --exclude=./backups --exclude='./.update-*' --exclude='./*.zip' \
        --exclude=./.env --exclude='*/__pycache__' . || { rm -rf "$tmpd"; fail "Backup of the program files failed - nothing changed."; }
    chmod 600 "$sicherung"
    SAMONB_PROG_BACKUP="$sicherung"  # from here on, every abort restores the previous program files
    # keep at least the backup just created
    { ls -1t "$BACKUP_DIR"/programm-*.tar.gz 2>/dev/null || true; } | tail -n +"$(( (KEEP_BACKUPS < 1 ? 1 : KEEP_BACKUPS) + 1 ))" | xargs -r rm -f
    ok "Current program files backed up: $sicherung"

    # Replace: remove obsolete files, copy new ones
    while IFS= read -r f; do [ -n "$f" ] && rm -f -- "$f"; done < "$tmpd/weg.liste"
    for d in "${PROGRAMM_ORDNER[@]}"; do
        [ -d "$d" ] || continue
        find "$d" -name __pycache__ -type d -prune -exec rm -rf {} +
    done
    cp -a "$neu"/. ./
    chmod +x update.sh scripts/*.sh 2>/dev/null || true
    for d in "${PROGRAMM_ORDNER[@]}"; do [ -d "$d" ] && find "$d" -mindepth 1 -type d -empty -delete; done
    cp "$tmpd/neu.liste" .dateiliste
    ok "SAMONBOARDING ${neu_v:-?} installed ($geaendert changed, $neu_n new, $(wc -l < "$tmpd/weg.liste") removed)"

    # Continue with the script of the NEW version (build, start, check, clean up)
    exec env SAMONB_ZIP="$zip" SAMONB_TMP="$tmpd" SAMONB_PROG_BACKUP="$sicherung" bash "$PWD/update.sh" ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}
}

if [ "${#ZIPS[@]}" -gt 0 ]; then
    [ "$DO_PULL" = 0 ] || fail "--pull and a ZIP file cannot be combined."
    # With "samonboarding-*.zip" matching several files, take the newest version
    ZIP_DATEI="$(printf '%s\n' "${ZIPS[@]}" | neueste_zip)"
    [ "${#ZIPS[@]}" = 1 ] || warn "Several ZIP files found - using the newest: $(basename "$ZIP_DATEI")"
    zip_einspielen "$ZIP_DATEI"
fi

for f in Dockerfile docker-compose.yml requirements.txt package.json images.lock samonboarding/config.py; do
    [ -f "$f" ] || fail "$f is missing - please run update.sh in the project folder (all files of the new version extracted?)."
done

if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    warn ".env did not exist and was created from .env.example."
    fail "Please edit .env first (at least AD_DOMAIN, AD_DC_IP, CUSTOM_OPERATOR_GROUP) and run update.sh again."
fi
ok ".env found"

VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' samonboarding/config.py)"
[ -z "${SAMONB_IMAGE_VERSION:-}" ] || VERSION="$SAMONB_IMAGE_VERSION"  # --pull: the version of the image counts

# Value from .env as Docker Compose reads it: optional "export ", quotes removed, " # comment" removed
env_value() {
    sed -n "s/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}$1=//p" .env | tail -n1 | tr -d '\r' \
        | sed -e 's/^"\([^"]*\)"[[:space:]]*\(#.*\)\{0,1\}$/\1/;t' \
            -e "s/^'\([^']*\)'[[:space:]]*\(#.*\)\{0,1\}\$/\1/;t" \
            -e 's/[[:space:]]\{1,\}#.*$//' -e 's/[[:space:]]*$//'
}
HTTPS_PORT="$(env_value HTTPS_PORT)"
case "$HTTPS_PORT" in ""|*[!0-9]*) HTTPS_PORT=9500 ;; esac
# Commands that need root (permissions on data/, removing the old internet block): directly as root, otherwise sudo
as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        fail "Root privileges are required - start update.sh with sudo."
    fi
}

# Provide the base images (tag or tag@sha256:...) from images.lock to docker compose
load_images() {
    PYTHON_IMAGE="$(sed -n 's/^PYTHON_IMAGE=//p' images.lock | tail -n1)"
    NODE_IMAGE="$(sed -n 's/^NODE_IMAGE=//p' images.lock | tail -n1)"
    [ -n "$PYTHON_IMAGE" ] && [ -n "$NODE_IMAGE" ] || fail "images.lock is incomplete."
    DEBIAN_SNAPSHOT="$(sed -n 's/^DEBIAN_SNAPSHOT=//p' images.lock | tail -n1)"  # only needed for building here
    export PYTHON_IMAGE NODE_IMAGE DEBIAN_SNAPSHOT
}
load_images
SAMONBOARDING_IMAGE="$(env_value SAMONBOARDING_IMAGE)"
PLAIN_IMAGE="${SAMONBOARDING_IMAGE:-$PLAIN_IMAGE}"
export SAMONBOARDING_IMAGE="$PLAIN_IMAGE"  # docker-compose.yml uses the same name

# -----------------------------------------------------------------------------
# --pull: take the ready-made image from GitHub (built and tested there) instead of building here
# -----------------------------------------------------------------------------
IMAGE_GEHOLT="${SAMONB_IMAGE_GEHOLT:-0}"
image_holen() {
    local img ver cid tmpd f neu=0 sicherung
    img="$PLAIN_IMAGE"  # not from docker-compose.yml: an older one there does not know the image from GitHub yet
    step "Fetching the newest image from GitHub ($img)"
    if ! docker pull "$img"; then
        warn "For a private repository, log in to GitHub's registry once (password = token with read:packages):"
        warn "  docker login ghcr.io -u soleil0815"
        fail "docker pull failed - nothing changed. Is the image there (GitHub -> Actions -> 'Image' green)?"
    fi
    ver="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$img" 2>/dev/null || true)"
    ok "Image fetched: SAMONBOARDING ${ver:-?}"
    [ -z "$ver" ] || VERSION="$ver"

    # update.sh and docker-compose.yml of the same version come with the image
    tmpd="$(mktemp -d "$PWD/.update-XXXXXX")"
    SAMONB_TMP="$tmpd"
    cid="$(docker create "$img" 2>/dev/null || true)"
    if [ -n "$cid" ]; then
        for f in update.sh docker-compose.yml; do docker cp "$cid:/app/$f" "$tmpd/$f" >/dev/null 2>&1 || true; done
        docker rm "$cid" >/dev/null 2>&1 || true
    fi
    for f in update.sh docker-compose.yml; do
        if [ -s "$tmpd/$f" ] && ! gleich "$f" "$tmpd/$f"; then neu=1; fi
    done
    if [ "$neu" = 1 ]; then
        mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
        sicherung="$BACKUP_DIR/programm-${VERSION:-unbekannt}-$(date '+%Y%m%d-%H%M%S').tar.gz"
        tar -czf "$sicherung" update.sh docker-compose.yml || fail "Backup of update.sh failed - nothing changed."
        chmod 600 "$sicherung"
        for f in update.sh docker-compose.yml; do [ ! -s "$tmpd/$f" ] || cp -f "$tmpd/$f" "$f"; done
        chmod +x update.sh 2>/dev/null || true
        ok "update.sh and docker-compose.yml updated to the version of the image"
        # Continue with the new update.sh (restart, check, clean up)
        exec env SAMONB_IMAGE_GEHOLT=1 SAMONB_IMAGE_VERSION="$ver" SAMONB_PULL_BACKUP="$sicherung" SAMONB_TMP="$tmpd" \
            bash "$PWD/update.sh" \
            ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}
    fi
    IMAGE_GEHOLT=1
}
if [ "$DO_PULL" = 1 ] && [ "$IMAGE_GEHOLT" = 0 ]; then
    [ -z "${SAMONB_ZIP:-}" ] || fail "--pull and a ZIP file cannot be combined."
    [ "$DO_LOCK" = 0 ] || fail "--pull and --lock cannot be combined (with --pull the packages are pinned on GitHub)."
    image_holen
fi

# -----------------------------------------------------------------------------
# Pin versions: the same script as the weekly security update on GitHub (scripts/pins.py), only within the base
# (same Debian release, same Python and Node series, every package within its major version, below 1.0 within its
# minor version). Normally GitHub does this every week - then simply: sudo sh update.sh --pull
# -----------------------------------------------------------------------------
in_hash() { sha256_16 requirements.in; }

# Does requirements.txt still match requirements.in? (marker in the header line)
python_lock_in_sync() {
    grep -q "^# requirements.in: $(in_hash)\$" requirements.txt 2>/dev/null
}

pins() {
    command -v python3 >/dev/null 2>&1 \
        || fail "python3 is needed for pinning (scripts/pins.py). Or take the image pinned on GitHub: sudo sh update.sh --pull"
    [ -f scripts/pins.py ] || fail "scripts/pins.py is missing - this version is incomplete."
    python3 scripts/pins.py "$@"
}

LOCK_OS_AFTER=0
if [ "$IMAGE_GEHOLT" = 1 ]; then
    :  # ready-made image from GitHub - nothing to pin or build here
elif [ "$DO_LOCK" = 1 ]; then
    step "Pinning all versions again (within the base)"
    cp requirements.txt requirements.txt.vorher 2>/dev/null || true  # for the rollback if the new container fails
    rm -f "$REJECTED_FILE"
    pins update || fail "Versions not pinned (see the message above) - nothing changed."
    load_images
    LOCK_OS_AFTER=1
elif [ ! -f package-lock.json ] || [ ! -f os-packages.lock ]; then
    fail "package-lock.json or os-packages.lock is missing - this version is incomplete."
fi

# -----------------------------------------------------------------------------
# Remember the current image: if the new version does not start cleanly, it is put back into service.
# This only works with an image that already runs without root (from 1.31) - an older one could not access data/.
# -----------------------------------------------------------------------------
OLD_CID="$(dc ps -a -q "$SERVICE" 2>/dev/null | head -n 1 || true)"
OLD_IMAGE=""
OLD_USER=""
if [ -n "$OLD_CID" ]; then
    OLD_IMAGE="$(docker inspect --format '{{.Image}}' "$OLD_CID" 2>/dev/null || true)"
    [ -z "$OLD_IMAGE" ] || OLD_USER="$(docker image inspect --format '{{.Config.User}}' "$OLD_IMAGE" 2>/dev/null || true)"
fi
IMAGE_NAME="$(dc config --images 2>/dev/null | head -n 1 || true)"
ROLLBACK_OK=0
if [ -n "$OLD_IMAGE" ] && [ -n "$OLD_USER" ] && [ -n "$IMAGE_NAME" ]; then
    ROLLBACK_OK=1
fi

# Running a newer image from GitHub (--pull) than the files here? Then building here would install OLD code.
if [ "$IMAGE_GEHOLT" = 0 ] && [ -n "$OLD_IMAGE" ] && [ "$DO_PULL" = 0 ]; then
    LAUFENDE_VERSION="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$OLD_IMAGE" 2>/dev/null || true)"
    LAUFENDE_VERSION="${LAUFENDE_VERSION%%-s*}"  # 1.48.0-s2 = program 1.48.0 with newer packages
    if printf '%s' "$LAUFENDE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' && [ "$LAUFENDE_VERSION" != "$VERSION" ] \
        && [ "$(printf '%s\n%s\n' "$VERSION" "$LAUFENDE_VERSION" | neueste_zip)" = "$LAUFENDE_VERSION" ]; then
        fail "SAMONBOARDING $LAUFENDE_VERSION from GitHub is running, the files here are $VERSION - building here would install the older version. Use: sudo sh update.sh --pull"
    fi
fi

# requirements.in changed by hand without pinning again? Then the lock list does not fit - better stop than build
# something untested.
RELOCK_AFTER=0
if [ "$IMAGE_GEHOLT" = 0 ] && [ "$DO_LOCK" = 0 ] && ! python_lock_in_sync; then
    fail "requirements.in was changed, but requirements.txt was not pinned again. Run: sudo sh update.sh --lock"
fi

# -----------------------------------------------------------------------------
# Back up data/ - only once the container is stopped, so that the SQLite databases are not copied mid-write
# -----------------------------------------------------------------------------
daten_sichern() {
    [ "$DO_BACKUP" = 1 ] && [ -d data ] || return 0
    step "Backing up data/"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    archive="$BACKUP_DIR/data-$(date '+%Y%m%d-%H%M%S').tar.gz"
    set +e
    tar_out="$(tar -czf "$archive" data/ 2>&1)"  # with "/" also if data/ is a link (NAS)
    tar_rc=$?
    set -e
    if [ "$tar_rc" = 0 ] || [ "$tar_rc" = 1 ]; then
        chmod 600 "$archive"
        ok "$archive"
        [ "$tar_rc" = 0 ] || warn "Note: data/ was written to during the backup ($tar_out)."
    else
        warn "Backup not possible: $tar_out"
        warn "Start with sudo or use --no-backup."
        rm -f "$archive"
    fi
    # keep only the last KEEP_BACKUPS backups (they contain personal data - GDPR), at least the one just made
    { ls -1t "$BACKUP_DIR"/data-*.tar.gz 2>/dev/null || true; } \
        | tail -n +"$(( (KEEP_BACKUPS < 1 ? 1 : KEEP_BACKUPS) + 1 ))" | xargs -r rm -f
}

# -----------------------------------------------------------------------------
# Build and start
# -----------------------------------------------------------------------------
UP_ARGS=(-d --remove-orphans)
if [ "$IMAGE_GEHOLT" = 1 ]; then
    UP_ARGS+=(--no-build)  # never build over the image from GitHub
elif step "Building the image (SAMONBOARDING $VERSION)" && echo "  Python: $PYTHON_IMAGE" && echo "  Node:   $NODE_IMAGE" \
    && ! dc build ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}; then
    printf '\n'
    warn "The build failed. Common causes:"
    warn " - no internet connection while building (npm, pip, Docker Hub)"
    warn " - snapshot.debian.org or Docker Hub not reachable, or a pinned version is not available any more"
    programm_zurueck
    fail "Build failed - the running container was NOT changed."
else
    ok "Image built"
    if [ "$LOCK_OS_AFTER" = 1 ]; then
        arch="$(docker image inspect --format '{{.Architecture}}' "$IMAGE_NAME")"
        pins os-lock "$IMAGE_NAME" --arch "$arch" || fail "os-packages.lock could not be written."
    fi
fi

# -----------------------------------------------------------------------------
# Up to version 1.37 there was an internet block (iptables rules and systemd services on the host). It is removed
# completely - but only once the new version runs: if a rollback is needed, the previous version still needs its
# block (it does not start otherwise).
# -----------------------------------------------------------------------------
sperre_entfernen() {
    local unit k basis gefunden=0 reload=0
    if command -v systemctl >/dev/null 2>&1; then
        for unit in samonboarding-internetsperre.path samonboarding-internetsperre.timer \
            samonboarding-internetsperre.service; do
            if [ -f "/etc/systemd/system/$unit" ]; then
                as_root systemctl disable --now "$unit" >/dev/null 2>&1 || true
                as_root rm -f "/etc/systemd/system/$unit"
                gefunden=1
                reload=1
            fi
        done
        [ "$reload" = 0 ] || as_root systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1 || as_root sh -c 'command -v iptables' >/dev/null 2>&1; then
        for k in SAMONB-EGRESS-A SAMONB-EGRESS-B SAMONB-EGRESS SAMONB-HOST-A SAMONB-HOST-B SAMONB-HOST; do
            for basis in DOCKER-USER INPUT; do
                while as_root iptables -C "$basis" -i br-samonb -j "$k" >/dev/null 2>&1; do
                    as_root iptables -D "$basis" -i br-samonb -j "$k" >/dev/null 2>&1 || break
                    gefunden=1
                done
            done
            if as_root iptables -L "$k" -n >/dev/null 2>&1; then
                if as_root iptables -F "$k" >/dev/null 2>&1 && as_root iptables -X "$k" >/dev/null 2>&1; then
                    gefunden=1
                else
                    warn "iptables chain $k could not be removed - by hand: sudo iptables -F $k; sudo iptables -X $k"
                fi
            fi
        done
    fi
    as_root rm -f data/netziele.txt data/netziele.txt.tmp /run/samonboarding-internetsperre.lock 2>/dev/null || true
    rmdir scripts 2>/dev/null || true  # empty folder of the old block (your own files in it stay)
    if [ "$gefunden" = 1 ]; then
        ok "Internet block of the previous version removed (rules and services)"
    fi
}

# The container runs without root (user APP_UID). data/ must belong to it, the source code must be readable.
step "Setting permissions for the container user ($APP_UID)"
# Stop first: otherwise the old container could still create files as another user between chown and restart
dc stop "$SERVICE" >/dev/null 2>&1 || true
daten_sichern
# A container from the other mode (with/without Docker Compose) would block the port
for _id in $(docker ps -q --filter "label=com.docker.compose.service=$SERVICE" 2>/dev/null) \
    $(docker ps -q --filter "name=^${PLAIN_NAME}\$" 2>/dev/null); do
    if [ "${#COMPOSE[@]}" -gt 0 ] && [ -z "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$_id" 2>/dev/null)" ]; then
        docker stop "$_id" >/dev/null 2>&1 || true  # started without Compose, now with Compose
    elif [ "${#COMPOSE[@]}" = 0 ] && [ -n "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$_id" 2>/dev/null)" ]; then
        docker stop "$_id" >/dev/null 2>&1 || true  # started with Compose, now without
    fi
done
mkdir -p data
as_root chown -R "$APP_UID:$APP_UID" data/ || fail "data/ could not be given to the container user (sudo?)."
as_root chmod 700 data/
ok "data/ belongs to $APP_UID, readable only by it"

wait_healthy() {
    local cid status
    cid="$(dc ps -q "$SERVICE")"
    [ -n "$cid" ] || { echo "not started"; return 1; }
    printf 'Waiting for "healthy" (max. %ss) ' "$HEALTH_TIMEOUT" >&2
    status="starting"
    for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)"
        case "$status" in
            healthy|unhealthy|exited|dead) break ;;
        esac
        printf '.' >&2
        sleep 1
    done
    printf '\n' >&2
    echo "$status"
    [ "$status" = healthy ]
}

step "Restarting the container"
status="start failed (see the message above, e.g. port in use)"
if ! dc up "${UP_ARGS[@]}" || ! status="$(wait_healthy)"; then
    warn "Status: $status - last messages of the container:"
    dc logs --tail 40 "$SERVICE" || true
    if [ -f requirements.txt.vorher ]; then
        mv requirements.txt.vorher requirements.txt  # do not apply the new packages ...
        # ... and do not try again on the next update - unless new program code came along (ZIP):
        # then that may be the cause, and the packages are checked again later
        [ -n "${SAMONB_PROG_BACKUP:-}" ] || in_hash > "$REJECTED_FILE"
    fi
    programm_zurueck
    if [ "$ROLLBACK_OK" = 1 ]; then
        warn "The new version does not start cleanly - putting the previous one back into service."
        docker tag "$OLD_IMAGE" "$IMAGE_NAME"
        dc up -d --no-build --remove-orphans || true
        if back="$(wait_healthy)"; then
            fail "New version NOT applied - the previous one is running again (healthy). Cause: see above."
        fi
        fail "New version NOT applied, and the previous one does not start either ($back). Please check: docker logs"
    fi
    fail "The container is not running cleanly (a rollback is only possible from version 1.31). Details: docker logs"
fi
rm -f requirements.txt.vorher
NEUE_VERSION_LAEUFT=1
ok "Container is running (healthy)"
sperre_entfernen

if [ "$DO_PRUNE" = 1 ]; then
    step "Removing old images"
    docker image prune -f >/dev/null && ok "Unused images removed"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
step "Done"
echo "  SAMONBOARDING $VERSION"
echo "  Address: https://${HOST_IP:-<server>}:${HTTPS_PORT}"

# Second pass: a version without root is running now - the new Python packages can be checked and applied with
# rollback
if [ "$RELOCK_AFTER" = 1 ]; then
    step "Second pass: updating Python packages"
    # The program files are the new version now - a failed start in the second pass only rolls back the packages,
    # not the program files (hence SAMONB_PROG_BACKUP is cleared)
    aufraeumen_tmp
    exec env SAMONB_ZWEITER_DURCHGANG=1 SAMONB_PROG_SICHERUNG="${SAMONB_PROG_BACKUP:-}" SAMONB_PROG_BACKUP= \
        SAMONB_TMP= SAMONB_KOPIE= bash "$SELF" --no-backup
fi

# After --pull: temporary files and old images of this application away (only if everything worked)
if [ "$IMAGE_GEHOLT" = 1 ]; then
    step "Cleaning up"
    aufraeumen_tmp
    if docker image prune -f --filter "label=de.helfi.samonboarding=1" >/dev/null 2>&1; then
        ok "Old SAMONBOARDING images removed"
    fi
    [ -z "${SAMONB_PULL_BACKUP:-}" ] || echo "  Backup of the previous update.sh: $SAMONB_PULL_BACKUP"
fi

# Cleanup after installing a ZIP (only if everything worked)
if [ -n "${SAMONB_ZIP:-}" ]; then
    step "Cleaning up"
    if [ -f "$SAMONB_ZIP" ] && [ "$(dirname "$SAMONB_ZIP")" = "$PWD" ]; then
        rm -f -- "$SAMONB_ZIP" && ok "ZIP file removed: $(basename "$SAMONB_ZIP")"
    elif [ -f "$SAMONB_ZIP" ]; then
        echo "  The ZIP is outside the project folder and is kept: $SAMONB_ZIP"
    fi
    aufraeumen_tmp && ok "Temporary files removed"
    # Only images of this application (label in the Dockerfile) that no longer have a name - nothing else
    if docker image prune -f --filter "label=de.helfi.samonboarding=1" >/dev/null 2>&1; then
        ok "Old SAMONBOARDING images removed"
    fi
    echo "  Backup of the previous program files: ${SAMONB_PROG_BACKUP:-${SAMONB_PROG_SICHERUNG:-none}}"
fi
