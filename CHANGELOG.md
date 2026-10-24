# Changelog

Alle wichtigen Änderungen an SAMONBOARDING, neueste zuerst.
Update auf dem Server: `sudo sh update.sh --pull`.

## 1.44.0 – 2026-10-24
- Automatisch erzeugte Passwörter (Onboarding, Passwort-Reset) enthalten keine leicht verwechselbaren Zeichen mehr: 0 O o 1 l I.

## 1.43.1 – 2026-10-24
- Auf GitHub gibt es nur noch einen Workflow („Image“). Er prüft Formatierung (ruff) und Tests und baut danach das Image. Der doppelte Lauf „Tests“ entfällt.

## 1.43.0 – 2026-10-24
- **`sudo sh update.sh --pull` holt jetzt das fertige Image von GitHub** (`ghcr.io/soleil0815/samonboarding`) und startet es. Auf dem Server wird nichts gebaut, und git wird nicht gebraucht.
  - Vorher sichert das Skript `data/`. Startet die neue Version nicht, nimmt es das vorherige Image wieder in Betrieb.
  - `update.sh` und `docker-compose.yml` werden passend zur Version aus dem Image übernommen.
- `docker-compose.yml` nennt das Image (`SAMONBOARDING_IMAGE`). Lokales Bauen mit `sudo sh update.sh` geht weiterhin.
- Der Weg über `git pull` aus 1.40 bis 1.42 ist entfernt.

## 1.42.0 / 1.42.1 – 2026-10-24
- Übergangsversionen für das Update per git, abgelöst durch 1.43.0.

## 1.41.0 – 2026-10-24
- GitHub baut bei jedem Push das fertige Image und veröffentlicht es als `ghcr.io/soleil0815/samonboarding` (`:latest` und `:<version>`), für amd64 und arm64.
  - Vorher werden die Python-Pakete festgeschrieben und mit allen Tests geprüft.
- Neu: `docker-compose.image.yml` für Dockhand, Portainer & Co.

## 1.40.0 – 1.40.2 – 2026-10-23
- Projekt für GitHub vorbereitet: `.gitattributes`, `update.sh` als ausführbar markiert, eine ZIP enthält nie einen `.git`-Ordner.
- Lizenz: GNU AGPL v3 oder neuer (`LICENSE`). Die Anmeldeseite verlinkt auf den Quellcode.
- Alle Befehle in Doku und Meldungen als `sh update.sh …` (funktioniert auch ohne Ausführungsrecht).
- Alles zu Dockhand entfernt (Label `dockhand.update=false`).

## 1.39.0 – 2026-10-23
- Installationsdateien auf Englisch: `update.sh` (alle Ausgaben), `.env.example`, `Dockerfile`, `docker-compose.yml`. Die Namen der Einstellungen in der `.env` sind unverändert.
- Bestätigung mit `y` (`j` geht weiterhin), `--yes` zusätzlich zu `--ja`.

## 1.38.0 – 2026-10-23
- Internet-Sperre (iptables und systemd auf dem Host) komplett entfernt. `update.sh` räumt eine vorhandene Sperre automatisch ab, sobald die neue Version läuft.
- Die Einstellungen `INTERNET_SPERRE`, `ZUSATZ_ZIELE`, `DATEISERVER_NETZE` und `DNS_SERVER` entfallen.

## 1.37.0 – 2026-10-22
- Schneller: Es wird nur der geöffnete Bereich geladen. Die Kontolisten bleiben je Sitzung bis zu 60 Sekunden im Arbeitsspeicher, nicht in einer Datenbank.
  - Jede Änderung leert diesen Speicher sofort.
  - „Konten aktualisieren“ liest immer frisch vom DC.
- Die Schutzprüfung der Listen braucht nur noch wenige Sammelabfragen statt einer Abfrage je Konto.
- Umbenannte, verschobene oder gelöschte OUs und Gruppen werden erkannt (über die objectGUID).
  - Administratoren sehen einen Hinweis.
  - „Neue Namen übernehmen“ passt alle betroffenen Einstellungen und Templates an.
- Behoben: Mitglieder eingebauter Gruppen bekamen in der Liste kein Schloss. Die Aktion selbst war immer gesperrt.
- Behoben: Nach einem DC-Ausfall wurde die Ersatzliste zwischengespeichert.

## 1.36.0 – 2026-10-22
- Code-Review:
  - LDAP-Suchen erkennen Abbrüche und Fehler.
  - Zeitlimits für den DC.
  - DN-Vergleich nach Bestandteilen.
- Löschen:
  - Prüfung auf Ordner, die auch andere Konten nutzen.
  - Admin-Passwort und Rolle werden vor dem Löschen erneut geprüft.
- Wiederherstellen nur noch über die GUID. Ein Onboarding, das abbricht, wird sauber zurückgerollt.
- SMTP: neuer Modus „Ohne Verschlüsselung“ für interne Relays. Im Modus „Auto“ wird ohne STARTTLS nichts gesendet.
- Namensbildung: Ø, Æ, Œ, Ł, Đ und Þ werden umgeschrieben.

## 1.35.1 – 2026-10-22
- Behoben: `update.sh` brach auf der Synology mit „syntax error near unexpected token `('“ ab (bash im POSIX-Modus).

## 1.35.0 – 2026-10-22
- Docker Compose wird nicht mehr benötigt. Ohne Compose startet `update.sh` den Container direkt mit `docker` und denselben Einstellungen, zum Beispiel auf einer Synology.
- Ersatz für Werkzeuge, die auf dem NAS fehlen (cmp, sha256sum, timeout, sort -V).

## Ältere Versionen (zusammengefasst)
- Neue Version per ZIP einspielen: `sudo sh update.sh samonboarding-x.y.z.zip`, mit Rückfrage, Sicherung, Zurücksetzen und Aufräumen.
- Container läuft ohne root (Benutzer 10001). Python-Pakete, npm-Pakete und Basis-Images mit fester Version, neue Pakete werden mit den Tests geprüft.
- Handbuch auf Deutsch und Englisch in der Hilfe. Link zu helfi.space.
- HTTPS mit eigenem oder selbstsigniertem Zertifikat, Berichte in SQLite, Datenschutz (DSGVO) mit Aufbewahrungsfristen und Auskunft.
- Module: Onboarding mit Templates, Benutzerverwaltung, Passwort zurücksetzen, Offboarding mit Wiederherstellen, Konten löschen (nur Administratoren, mit Simulation und Passwortbestätigung).
