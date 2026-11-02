# ---------------------------------------------------------------------------
# Stage 1: build CSS and fonts (Tailwind, Manrope, JetBrains Mono, Font Awesome - all local, with their licence texts)
# ---------------------------------------------------------------------------
# Base images with fixed version AND digest: always passed from images.lock (update.sh, GitHub workflow,
# "python3 scripts/pins.py build-args"). There is deliberately no default, so no build uses a changing tag.
ARG NODE_IMAGE
ARG PYTHON_IMAGE

FROM ${NODE_IMAGE} AS assets
WORKDIR /build

# Exact versions from package.json; with package-lock.json all sub-packages too (npm ci = exactly the lock file)
COPY package.json package-lock.json* ./
RUN test -f package-lock.json || { echo "package-lock.json is missing (python3 scripts/pins.py update)"; exit 1; } \
 && npm ci --no-audit --no-fund --ignore-scripts

COPY tailwind.config.js tailwind.input.css ./
COPY samonboarding/web ./samonboarding/web

# Tailwind scans the HTML file for the classes used and generates only the CSS needed
RUN npx tailwindcss -c tailwind.config.js -i tailwind.input.css -o dist/app.css --minify \
 && mkdir -p dist/vendor/fontawesome dist/vendor/fonts/files dist/vendor/licenses \
 && cp node_modules/@fontsource/manrope/LICENSE dist/vendor/licenses/LICENSE-Manrope.txt \
 && cp node_modules/@fontsource/jetbrains-mono/LICENSE dist/vendor/licenses/LICENSE-JetBrains-Mono.txt \
 && cp node_modules/@fortawesome/fontawesome-free/LICENSE.txt dist/vendor/licenses/LICENSE-Font-Awesome.txt \
 && cp node_modules/tailwindcss/LICENSE dist/vendor/licenses/LICENSE-Tailwind-CSS.txt \
 && cp -r node_modules/@fortawesome/fontawesome-free/css node_modules/@fortawesome/fontawesome-free/webfonts dist/vendor/fontawesome/ \
 && for w in 400 500 600 700 800; do \
      cat node_modules/@fontsource/manrope/$w.css >> dist/vendor/fonts/fonts.css; \
      cp node_modules/@fontsource/manrope/files/manrope-*-$w-normal.woff* dist/vendor/fonts/files/; \
    done \
 && for w in 400 500; do \
      cat node_modules/@fontsource/jetbrains-mono/$w.css >> dist/vendor/fonts/fonts.css; \
      cp node_modules/@fontsource/jetbrains-mono/files/jetbrains-mono-*-$w-normal.woff* dist/vendor/fonts/files/; \
    done \
 && test -s dist/app.css \
 && test -f dist/vendor/fontawesome/webfonts/fa-solid-900.woff2 \
 && test -f dist/vendor/fontawesome/css/all.min.css \
 && ls dist/vendor/fonts/files | grep -q 'manrope-latin-400-normal.woff2' \
 && ls dist/vendor/fonts/files | grep -q 'jetbrains-mono-latin-400-normal.woff2'

# ---------------------------------------------------------------------------
# Stage 2: the application itself
# ---------------------------------------------------------------------------
# Official, lightweight Python image with a fixed version
FROM ${PYTHON_IMAGE}

# All Debian packages of the image (including those of the base image) to the state of the Debian snapshot from
# images.lock: snapshot.debian.org delivers the archive exactly as it was at that time, so the same snapshot always
# gives exactly the same package versions (os-packages.lock). Only the Debian release of the base image is used
# (e.g. "trixie" with its security updates) - never a newer release. apt checks the signatures as usual.
# Time zone for logs, audit log and mails (can be changed with TZ in .env)
ARG DEBIAN_SNAPSHOT
ENV TZ=Europe/Berlin
RUN set -eu; \
    test -n "${DEBIAN_SNAPSHOT:-}" || { echo "DEBIAN_SNAPSHOT is missing (images.lock)"; exit 1; }; \
    . /etc/os-release; \
    key=""; for f in /usr/share/keyrings/debian-archive-keyring.pgp /usr/share/keyrings/debian-archive-keyring.gpg; do \
      if [ -f "$f" ]; then key="$f"; break; fi; done; \
    test -n "$key" || { echo "Debian archive keyring missing"; exit 1; }; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    for archive in debian debian-security; do \
      if [ "$archive" = debian ]; then suites="$VERSION_CODENAME $VERSION_CODENAME-updates"; \
      else suites="$VERSION_CODENAME-security"; fi; \
      printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/%s/%s\nSuites: %s\nComponents: main\nSigned-By: %s\n\n' \
        "$archive" "$DEBIAN_SNAPSHOT" "$suites" "$key" >> /etc/apt/sources.list.d/snapshot.sources; \
    done; \
    apt_opts="-o Acquire::Check-Valid-Until=false -o Acquire::Retries=5 -o Acquire::http::Timeout=60"; \
    apt-get $apt_opts update; \
    DEBIAN_FRONTEND=noninteractive apt-get $apt_opts full-upgrade -y --no-install-recommends; \
    test -f /usr/share/zoneinfo/Europe/Berlin || DEBIAN_FRONTEND=noninteractive apt-get $apt_opts install -y --no-install-recommends tzdata; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Marker: when cleaning up, update.sh only removes old images with this label
LABEL de.helfi.samonboarding="1"

# Working directory in the container
WORKDIR /app

# Install the Python packages: exactly the versions from the lock list, without extra dependencies;
# pip check verifies that everything fits together
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
# pip, setuptools and wheel are only needed for installing, not at runtime. pip brings its own copies of urllib3,
# certifi and msgpack, which are often outdated (Trivy findings) - so all of it is removed after the check,
# including the copy of pip in ensurepip.
RUN pip install --no-cache-dir --no-deps -r requirements.txt && pip check \
 && (pip uninstall -y setuptools wheel >/dev/null 2>&1 || true) && pip check \
 && python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3*/ensurepip/_bundled \
 && ! python -c "import pip" 2>/dev/null

# Copy the rest of the source code into the container
COPY . .

# Local CSS, fonts and icons from stage 1 (served by the application under /static)
COPY --from=assets /build/dist /app/static

# Own user without privileges: the application does NOT run as root. Port 9500 needs no special privileges.
# data/ belongs to this user: docker-entrypoint.sh hands a mounted ./data over to it if needed (only when the container
# is started as root, as the docker-compose.yml does), then switches to this user for good.
# The image default stays this user, so an older docker-compose.yml keeps working as before.
ARG APP_UID=10001
RUN groupadd --gid ${APP_UID} samonboarding \
 && useradd --uid ${APP_UID} --gid ${APP_UID} --no-create-home --home-dir /app --shell /usr/sbin/nologin samonboarding \
 && chmod -R a+rX /app \
 && chmod 755 /app/docker-entrypoint.sh /app/update.sh \
 && test -x /usr/bin/setpriv \
 && mkdir -p /app/data && chown ${APP_UID}:${APP_UID} /app/data && chmod 700 /app/data
USER ${APP_UID}:${APP_UID}

# HTTPS only: there is no HTTP port. Certificate from data/tls/ or self-signed on the first start
EXPOSE 9500

# Health check in the image itself - also applies without Docker Compose (docker run). docker-entrypoint.sh gives up
# the rights first (Docker runs it as the container user, with the docker-compose.yml that is root).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/docker-entrypoint.sh", "healthcheck"]

# Start of the container (docker-entrypoint.sh), then the application (uvicorn with TLS, see samonboarding/serve.py).
# The image also carries the current docker-compose.yml, .env.example and update.sh (/app) - update.sh takes them from
# there.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "-m", "samonboarding.serve"]
