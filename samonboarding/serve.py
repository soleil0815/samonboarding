"""Startet SAMONBOARDING nur ueber HTTPS:  python -m samonboarding.serve

Es gibt keinen unverschluesselten HTTP-Port. Zertifikat siehe samonboarding/tls.py; ein in der Oberflaeche
hochgeladenes Zertifikat gilt sofort fuer neue Verbindungen (ohne Neustart).
"""

import logging
import os
import sys

from . import config, tls

CIPHERS = tls.CIPHERS


def data_writable():
    """Der Container laeuft ohne root: data/ muss dem Container-Benutzer gehoeren (update.sh erledigt das)."""
    probe = os.path.join(str(config.DATA_DIR), ".schreibtest")
    try:
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except OSError as e:
        logging.getLogger(__name__).critical(
            "data/ ist fuer den Container-Benutzer (UID %s) nicht beschreibbar: %s. Auf dem Server einmal "
            "'sudo chown -R %s:%s data' im Projektordner ausfuehren oder 'sudo sh update.sh' verwenden.",
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
