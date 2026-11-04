# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Starts SAMONBOARDING over HTTPS only:  python -m samonboarding.serve

There is no unencrypted HTTP port. For the certificate see samonboarding/tls.py; a certificate uploaded in the UI
applies immediately to new connections (without restart).
"""

import contextlib
import logging
import os
import sys

from . import config, datastate, tls

CIPHERS = tls.CIPHERS


def data_writable():
    """The program runs without root: data/ must be owned by the container user. With the current docker-compose.yml
    the start script (docker-entrypoint.sh) sets this up itself."""
    probe = os.path.join(str(config.DATA_DIR), ".schreibtest")
    with contextlib.suppress(OSError):
        os.chmod(str(config.DATA_DIR), 0o700)  # only for the program user (who is the owner)
    try:
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except OSError as e:
        logging.getLogger(__name__).critical(
            "data/ ist fuer den Container-Benutzer (UID %s) nicht beschreibbar: %s. Auf dem Server einmal "
            "'sudo chown -R %s:%s data' im Ordner der docker-compose.yml ausfuehren oder die aktuelle "
            "docker-compose.yml verwenden (sie stellt den Besitzer beim Start selbst ein).",
            os.getuid(),
            e,
            os.getuid(),
            os.getgid(),
        )
        return False


def main():
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not data_writable():
        sys.exit(1)
    try:
        result = datastate.prepare()
    except datastate.DataTooNew as e:
        logging.getLogger(__name__).critical("%s", e)
        sys.exit(3)
    logging.getLogger(__name__).info("Datenstand: %s", result)
    notice = datastate.compose_notice()
    if notice:
        logging.getLogger(__name__).warning(
            "docker-compose.yml ist veraltet (Stand %s, benoetigt %s): 'sh update.sh' ausfuehren oder die "
            "docker-compose.yml aus dem aktuellen Release holen und 'docker compose up -d' ausfuehren.",
            notice["have"],
            notice["need"],
        )
    cert_file, key_file, _self_signed = tls.ensure_certificate()
    server_config = uvicorn.Config(
        "samonboarding.main:app",
        host="0.0.0.0",  # noqa: S104 - inside the container; only docker-compose.yml exposes the port externally
        port=config.HTTPS_PORT,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_ciphers=CIPHERS,
        access_log=False,  # do not log IP addresses per request (data minimization)
        server_header=False,
        proxy_headers=False,
    )
    server_config.load()  # creates the server's SSLContext ...
    tls.activate(server_config.ssl)  # ... and hooks live certificate swapping into it
    uvicorn.Server(server_config).run()


if __name__ == "__main__":
    main()
