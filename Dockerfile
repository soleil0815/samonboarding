# ---------------------------------------------------------------------------
# Stage 1: build CSS and fonts (Tailwind, Manrope, JetBrains Mono, Font Awesome - all local)
# ---------------------------------------------------------------------------
# Base images with fixed versions (default from images.lock; update.sh passes them including digest)
ARG NODE_IMAGE=node:22.17.0-bookworm-slim
ARG PYTHON_IMAGE=python:3.11.13-slim-bookworm

FROM ${NODE_IMAGE} AS assets
WORKDIR /build

# Exact versions from package.json; with package-lock.json all sub-packages too (npm ci = exactly the lock file)
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else echo "NOTE: no package-lock.json - create it with sh update.sh --lock" && npm install --no-audit --no-fund; fi

COPY tailwind.config.js tailwind.input.css ./
COPY samonboarding/web ./samonboarding/web

# Tailwind scans the HTML file for the classes used and generates only the CSS needed
RUN npx tailwindcss -c tailwind.config.js -i tailwind.input.css -o dist/app.css --minify \
 && mkdir -p dist/vendor/fontawesome dist/vendor/fonts/files \
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

# Time zone for logs, audit log and mails (can be changed with TZ in .env)
ENV TZ=Europe/Berlin
RUN test -f /usr/share/zoneinfo/Europe/Berlin \
 || (apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*)

# Marker: when cleaning up, update.sh only removes old images with this label
LABEL de.helfi.samonboarding="1"

# Working directory in the container
WORKDIR /app

# Install the Python packages: exactly the versions from the lock list, without extra dependencies;
# pip check verifies that everything fits together
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps -r requirements.txt && pip check

# Copy the rest of the source code into the container
COPY . .

# Local CSS, fonts and icons from stage 1 (served by the application under /static)
COPY --from=assets /build/dist /app/static

# Own user without privileges: the application does NOT run as root. data/ belongs to it (update.sh sets this on
# the host too, because data/ is mounted from there). Port 9500 needs no special privileges.
ARG APP_UID=10001
RUN groupadd --gid ${APP_UID} samonboarding \
 && useradd --uid ${APP_UID} --gid ${APP_UID} --no-create-home --home-dir /app --shell /usr/sbin/nologin samonboarding \
 && chmod -R a+rX /app \
 && mkdir -p /app/data && chown ${APP_UID}:${APP_UID} /app/data && chmod 700 /app/data
USER ${APP_UID}:${APP_UID}

# HTTPS only: there is no HTTP port. Certificate from data/tls/ or self-signed on the first start
EXPOSE 9500

# Health check in the image itself - also applies without Docker Compose (docker run)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, ssl, urllib.request; urllib.request.urlopen('https://localhost:%s/api/public-config' % os.environ.get('HTTPS_PORT', '9500'), timeout=3, context=ssl._create_unverified_context())"]

# Start command of the container (uvicorn with TLS, see samonboarding/serve.py)
CMD ["python", "-m", "samonboarding.serve"]
