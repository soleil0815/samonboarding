# Fremdkomponenten / Third-party components

SAMONBOARDING selbst steht unter AGPL-3.0-or-later (`LICENSE`, `NOTICE`). Es nutzt folgende Komponenten mit eigenen Lizenzen:
SAMONBOARDING itself is licensed under AGPL-3.0-or-later (`LICENSE`, `NOTICE`). It uses the following components under their own licences:

## Python-Bibliotheken / Python libraries

Feste Versionen aus `requirements.txt`, beim Docker-Build aus PyPI installiert. / Pinned in `requirements.txt`, installed from PyPI at build time.

| Komponente / Component | Lizenz / Licence | Zweck / Purpose |
|---|---|---|
| FastAPI | MIT | Web-Framework / web framework |
| Starlette | BSD-3-Clause | Grundlage von FastAPI / base of FastAPI |
| Pydantic, pydantic-core | MIT | Prüfung der Eingaben / input validation |
| Uvicorn | BSD-3-Clause | Webserver / web server |
| ldap3 | LGPL-3.0-or-later | LDAP-Zugriff, unverändert als Bibliothek genutzt / LDAP access, used unchanged as a library |
| smbprotocol, pyspnego | MIT | Dateiserver über SMB / file servers via SMB |
| pypsrp | MIT | Exchange über PowerShell Remoting / Exchange via PowerShell remoting |
| cryptography | Apache-2.0 oder/or BSD-3-Clause | TLS, Zertifikate / TLS, certificates |
| requests, opentelemetry-api | Apache-2.0 | Unterabhängigkeiten / sub-dependencies |
| certifi | MPL-2.0 | Stammzertifikate / root certificates |
| typing-extensions | PSF-2.0 | Unterabhängigkeit / sub-dependency |
| pyasn1 | BSD-2-Clause | Unterabhängigkeit / sub-dependency |
| click, idna, pycparser | BSD-3-Clause | Unterabhängigkeiten / sub-dependencies |
| annotated-doc, annotated-types, anyio, cffi, charset-normalizer, h11, typing-inspection, urllib3 | MIT | Unterabhängigkeiten / sub-dependencies |

Die genauen Versionen stehen in `requirements.txt`, die Lizenztexte liegen den installierten Paketen im Image bei (`/usr/local/lib/python3*/site-packages/*.dist-info`).
Exact versions are in `requirements.txt`; the licence texts ship with the installed packages in the image (`/usr/local/lib/python3*/site-packages/*.dist-info`).

## Oberfläche: Schriften, Icons, CSS / Interface: fonts, icons, CSS

Beim Docker-Build aus npm geholt (feste Versionen in `package.json` und `package-lock.json`) und lokal ausgeliefert, zur Laufzeit wird nichts aus dem Internet geladen. Die Lizenztexte liegen im Image unter `/app/static/vendor/licenses/`.
Fetched from npm at build time (pinned in `package.json` and `package-lock.json`) and served locally; nothing is loaded from the internet at runtime. The licence texts are in the image under `/app/static/vendor/licenses/`.

| Komponente / Component | Lizenz / Licence | Datei im Image / File in the image |
|---|---|---|
| Manrope (Schrift / font, @fontsource/manrope) | SIL Open Font License 1.1 | `LICENSE-Manrope.txt` |
| JetBrains Mono (Schrift / font, @fontsource/jetbrains-mono) | SIL Open Font License 1.1 | `LICENSE-JetBrains-Mono.txt` |
| Font Awesome Free (@fortawesome/fontawesome-free) | Icons CC BY 4.0, Schriften / fonts SIL OFL 1.1, Code MIT | `LICENSE-Font-Awesome.txt` |
| Tailwind CSS (tailwindcss; erzeugt nur das CSS beim Build / only generates the CSS at build time) | MIT | `LICENSE-Tailwind-CSS.txt` |

## Docker-Basisimage / Docker base image

`python:3.13-slim-trixie` (Debian 13; genaue Version und Digest in `images.lock`, Debian-Pakete in `os-packages.lock`). Enthält Software unter verschiedenen freien Lizenzen; Details im Image unter `/usr/share/doc/*/copyright`. Das Node-Image aus `images.lock` wird nur beim Bau genutzt und ist nicht im fertigen Image enthalten.
Contains software under various free licences; details in the image under `/usr/share/doc/*/copyright`. The Node image from `images.lock` is only used for building and is not part of the final image.

## Marken / Trademarks

Microsoft, Windows, Active Directory, Exchange und Microsoft 365 sind Marken der Microsoft Corporation. Samba ist eine Marke der Software Freedom Conservancy. Die Nennung erfolgt ausschließlich beschreibend; es besteht keine Verbindung zu diesen Unternehmen.
Microsoft, Windows, Active Directory, Exchange and Microsoft 365 are trademarks of Microsoft Corporation. Samba is a trademark of Software Freedom Conservancy. They are named for descriptive purposes only; there is no affiliation with these companies.
