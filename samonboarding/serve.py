# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Startet SAMONBOARDING nur ueber HTTPS:  python -m samonboarding.serve

Es gibt keinen unverschluesselten HTTP-Port. Zertifikat siehe samonboarding/tls.py; ein in der Oberflaeche
hochgeladenes Zertifikat gilt sofort fuer neue Verbindungen (ohne Neustart).
"""

import logging
import os
import sys

from . import config, datastate, tls

CIPHERS = tls.CIPHERS


def data_writable():
    """Das Programm laeuft ohne root: data/ muss dem Container-Benutzer gehoeren. Mit der aktuellen docker-compose.yml
    stellt das Startskript (docker-entrypoint.sh) das selbst ein."""
    probe = os.path.join(str(config.DATA_DIR), ".schreibtest")
    try:
        os.chmod(str(config.DATA_DIR), 0o700)  # nur fuer den Programmbenutzer (er ist der Besitzer)
    except OSError:
        pass
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
        host="0.0.0.0",
        port=config.HTTPS_PORT,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_ciphers=CIPHERS,
        access_log=False,  # keine IP-Adressen je Anfrage protokollieren (Datensparsamkeit)
        server_header=False,
        proxy_headers=False,
    )
    server_config.load()  # erzeugt den SSLContext des Servers ...
    tls.activate(server_config.ssl)  # ... und haengt den Austausch im laufenden Betrieb daran
    uvicorn.Server(server_config).run()


if __name__ == "__main__":
    main()
