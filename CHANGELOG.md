# Changelog

Alle wichtigen Änderungen an SAMONBOARDING, neueste zuerst. Die Oberfläche zeigt sie unter *Hilfe → Neuigkeiten*.
Update auf dem Server: `sudo sh update.sh` oder `docker compose pull && docker compose up -d`.

Einträge, die mit „Sicherheit:“ oder „Behoben:“ beginnen, werden in der Oberfläche entsprechend markiert.

## 2.0.2 – 2026-11-03
- Neues Logo: zwei Personen statt Schild – zeigt auf einen Blick, dass es um die Verwaltung von Benutzerkonten geht. Gilt für Anmeldung, Seitenleiste, mobile Ansicht und das Symbol im Browser-Tab.

## 2.0.1-s1 – 2026-11-02
- Sicherheit: Sicherheitsupdate ohne Programmänderung: gleiches Programm, aktualisierte Pakete.
- Basis-Images:
  - Python (python): `3.13.18-slim-trixie@76baad603769` → `3.13.18-slim-trixie@ae14d4ce8771`
- Python-Pakete:
  - anyio `4.15.1` → `4.16.0`

## 2.0.1 – Code-Audit – 2026-11-02
- Sicherheit: `update.sh --cleanup` konnte bei einem Dateinamen mit `*` oder Leerzeichen (z. B. `neu * .zip`) auch `data/`, `docker-compose.yml` und `update.sh` löschen. Ungewöhnliche Namen werden jetzt nur gemeldet; vor jedem Löschen wird erneut geprüft.
- Sicherheit: `update.sh --cleanup` erkennt eingehängte Ordner jetzt zuverlässig (auch Bind-Mounts vom selben Datenträger und einen Mount direkt auf einem alten Programmordner) und lässt sie stehen.
- Sicherheit: `update.sh --restore` spielt nur Sicherungen mit gewöhnlichen Dateien und Ordnern zurück (keine Links oder Gerätedateien). Weitere Härtung: Versionsangaben nur aus Ziffern, Buchstaben, `.`, `_` und `-`; Link-Schleifen brechen `--cleanup` nicht mehr ab.
- Sicherheit: Lehnt der DC auf Port 636 das Zertifikat ab (mit `LDAP_CA_FILE`), gibt es keinen Rückfall auf unverschlüsseltes LDAP mehr, auch nicht mit `LDAP_ALLOW_PLAIN=true`.
- Sicherheit: Konten löschen: Ein Ordner wird auch dann nicht gelöscht, wenn der Basisordner eines anderen Kontos darin liegt, wenn ein anderes Konto `%username%` wörtlich im AD-Attribut stehen hat, wenn der Pfad aus dem AD einen Kurznamen mit `~` enthält oder wenn derselbe Ordner auch als Ordnerumleitung eingetragen ist und einem anderen Konto gehört.
- Behoben: Konten löschen: Zeigen zwei Speicherorte auf denselben Ordner (z. B. Ordnerumleitung in den Basisordner), wird er nur einmal gelöscht und gezählt; das AD-Konto wird danach wie erwartet gelöscht.
- Sicherheit: Benachrichtigungs-Mails (mit Startpasswort) gehen nur noch an die Adresse aus dem AD-Attribut `mail` des Angemeldeten. Ohne dieses Attribut wird keine Mail verschickt, statt `<Benutzer>@<AD-Domäne>` anzunehmen.
- Sicherheit: Der Gesundheitscheck des Containers läuft nicht mehr als root, sondern gibt vorher alle Rechte ab. Ein leeres `HTTPS_PORT=` in der `.env` gilt dabei wie überall als 9500 (vorher wurde der Container „unhealthy“).
- Datenschutz: Die eigenen Sicherungen in `data/backups` werden gelöscht, sobald sie älter als die längste Aufbewahrungsfrist sind; `offboarding.db` überschreibt gelöschte Einträge (`secure_delete`), wie dokumentiert.
- Behoben: Bricht eine Datenmigration beim Start ab, legt jeder Neustart keine weitere Sicherung mehr an; die saubere Sicherung von vor dem Wechsel bleibt erhalten.
- Behoben: Der Menüpunkt *E-Mail-Benachrichtigung* ist für Operatoren ausgeblendet (der Server gibt ihnen die Einstellungen nicht). PDF der Zugangsdaten: Hinweis statt stillem Abbruch, wenn ein Pop-up-Blocker das Fenster verhindert. Zwei fehlende englische Übersetzungen ergänzt.
- Doku korrigiert: `TZ` (leer heißt UTC), Rechte der Operatoren, Beispielwerte, Vorlage `env.example`, Browser-Speicher.

## 2.0.0-s1 – 2026-10-31
- Sicherheit: Sicherheitsupdate ohne Programmänderung: gleiches Programm, aktualisierte Pakete.
- Basis-Images:
  - Python (python): `3.13.17-slim-trixie@d98cc29d3266` → `3.13.18-slim-trixie@76baad603769`
  - Node (node): `24.22.1-trixie-slim@43b9ba1142b8` → `24.22.2-trixie-slim@54f84b4cf843`
- Debian-Pakete:
  - tzdata `2026e-0+deb13u1` → `2026f-0+deb13u1`
- Python-Pakete:
  - opentelemetry-api `1.45.1` → `1.45.2`
  - pyasn1 `0.6.4` → `0.6.5`
  - pydantic `2.14.1` → `2.14.2`
  - pydantic_core `2.50.1` → `2.50.2`
- npm-Pakete (nur beim Bauen der Oberfläche, nicht im Image):
  - postcss `8.5.31` → `8.5.32`

## 2.0.0 – 2026-10-29
- **Umstellung auf den Docker-Standard:** Das Programm steckt komplett im Image. Auf dem Server liegen nur noch `docker-compose.yml`, `.env` und der Ordner `data/`. Installation: Dateien aus dem Release holen, `.env` ausfüllen, `docker compose up -d`. Updates mit einer Container-Verwaltung (Dockhand, Watchtower, Tugtainer …) oder mit `docker compose pull && docker compose up -d`.
- Sicherheit: Vor jedem Versionswechsel sichert das Programm beim Start selbst den Datenordner (`data/backups/vor-<Version>-<Datum>.tar.gz`, die letzten 10 bleiben) und bringt die Daten danach auf den neuen Stand. Startet eine ältere Version auf Daten einer neueren, bricht sie mit einer klaren Meldung ab und nennt die Sicherung, statt mit Folgefehlern weiterzulaufen.
- Sicherheit: Der Container startet nur kurz als root (mit den Rechten DAC_READ_SEARCH, CHOWN, SETUID, SETGID), übergibt `data/` an den Programmbenutzer 10001 und läuft danach dauerhaft ohne Sonderrechte. Ein frischer Datenordner funktioniert damit ohne Handarbeit.
- Die `docker-compose.yml` bleibt stabil: keine Bau-Angaben mehr, Vorgaben stehen im Programm. Sie hat eine Kennung (`SAMONBOARDING_COMPOSE`); ist sie veraltet, zeigt die Oberfläche Administratoren einen Hinweis. Das Image bringt die aktuelle Datei mit. `docker-compose.image.yml` entfällt.
- Version festlegen mit `SAMONBOARDING_VERSION` in der `.env`: leer = neueste, `2.0` = neueste 2.0.x samt Sicherheitsupdates, `2.0.0` = genau diese.
- Neues `update.sh` für den Weg von Hand (läuft mit `/bin/sh`, auch auf einem NAS): merkt sich die laufende Version, holt die neue, startet sie und kehrt bei einem Fehlstart zurück. Dazu `--version`, `--offline` (Image-Datei aus dem Release, ohne Internet), `--restore` (Sicherung zurückspielen) und `--cleanup` (alte Programmdateien entfernen, nie Daten). ZIP, Bauen auf dem Server und `--lock` entfallen.
- Jedes Release hat jetzt `docker-compose.yml`, `env.example` und die Image-Dateien für amd64 und arm64 als Anhang.
- Neue Versionen kommen nur noch über einen Pull Request; ein Merge prüft nur, veröffentlicht wird von Hand. Zusätzlich gibt es den Tag `<Haupt>.<Unterversion>` (z. B. `2.0`).
- Beispielwerte in Doku und Vorlagen neutral (`firma.local`, `10.0.10.x`).

## 1.48.1 – 2026-10-28
- Zu jeder veröffentlichten Version legt GitHub jetzt auch eine Release-Seite an (`v<Version>`, z. B. `v1.48.1` oder `v1.48.1-s1`), mit dem Changelog-Eintrag auf Deutsch und Englisch, bei Sicherheitsupdates samt Liste der geänderten Pakete. Eine Release-Seite wird einmal angelegt und danach nicht mehr verändert.

## 1.48.0 – 2026-10-25
- Sicherheit: Reproduzierbarer Bau. Basis-Images sind mit fester Version und Prüfsumme (Digest) festgelegt, die Debian-Pakete über einen festen Stand von snapshot.debian.org (`os-packages.lock`), alle Python- und npm-Pakete einschließlich der indirekten mit exakter Version. Das Skript `scripts/pins.py` legt die Versionen neu fest.
- Sicherheit: Wöchentliches Sicherheitsupdate auf GitHub (montags, auch von Hand startbar). Es bringt Basis-Image, alle Debian-Pakete und alle Abhängigkeiten auf den neuesten Stand, aber nur innerhalb des Unterbaus:
  - gleiche Debian-Version („trixie“), gleiche Python- (3.13) und Node-Reihe (24)
  - jedes Paket innerhalb seiner Hauptversion, vor 1.0 innerhalb der Unterversion; Kalenderversionen wie Stammzertifikate ohne Grenze
  - Bau ohne Zwischenspeicher, Tests im Image (amd64 und arm64), HTTPS-Startprüfung und Trivy
  - veröffentlicht nur, wenn alles bestanden ist, als `<Version>-s<Zähler>` (z. B. `1.48.0-s1`), mit einem Eintrag hier samt Liste der geänderten Pakete. Hat sich nichts geändert, passiert nichts.
- Sicherheit: Trivy läuft nicht mehr als GitHub Action, sondern als feste Version, deren Prüfsumme (SHA-256) vor der Nutzung kontrolliert wird. Hingenommene Funde stehen mit Begründung und Ablaufdatum in `.trivyignore`.
- Sicherheit: Das veröffentlichte Image wird täglich mit Trivy geprüft. So fallen Schwachstellen auf, die erst nach dem Release bekannt werden.
- Wöchentliche Prüfung, wie lange Debian, Python und Node noch Sicherheitsupdates bekommen (endoflife.date): ab 12 Monaten vorher ein Hinweis, ab 6 Monaten ein roter Lauf. Der Unterbau wird nie automatisch angehoben.
- Veröffentlichte Versionen werden nie überschrieben, `latest` zeigt immer auf die höchste Version. Jeder Job bekommt nur die Rechte, die er braucht.
- Neuigkeiten in der Oberfläche zeigen Sicherheitsupdates (`-s1`, `-s2` …) als eigene Einträge.

## 1.47.1 – 2026-10-25
- Zum Bauen der Oberfläche wird jetzt Node 24 verwendet (Updates bis April 2028) statt Node 22, das im April 2027 ausläuft. Node ist nur beim Bauen dabei, nicht im fertigen Image; die erzeugte Oberfläche ist unverändert.

## 1.47.0 – 2026-10-24
- Sicherheit: Das Image basiert jetzt auf Debian 13 „Trixie“ mit Python 3.13 (vorher Debian 12 mit Python 3.11). Damit bekommt es deutlich länger Sicherheitsupdates, Python 3.13 bis 2029. Der wöchentliche Neubau spielt sie automatisch ein. Bedienung und Einstellungen bleiben gleich.
- Sicherheit: Alles im Image bleibt aktuell. Der wöchentliche Neubau holt jetzt auch die neueste Python-3.13-Version und die neuesten Versionen aller Python-Pakete. Bisher festgeschriebene Versionen (uvicorn, ldap3, smbprotocol, pypsrp) sind freigegeben, nur Sprünge auf eine neue Hauptversion bleiben ausgeschlossen. Alles wird vor der Veröffentlichung getestet und geprüft.
- Ein halbes Jahr bevor Debian 13, Python 3.13 oder Node 22 keine Updates mehr bekommen, meldet GitHub das per Mail. Erst dann wird der Unterbau angehoben.
- README: Hinweise vor dem Einsatz (ohne Gewähr, zuerst testen, getestet mit Samba AD, feste Version für den Betrieb). Neu: `SECURITY.md` für die vertrauliche Meldung von Sicherheitslücken.
- Sicherheit: Das Paketprogramm `pip` wird nur noch beim Bauen gebraucht und ist aus dem fertigen Image entfernt. Es brachte eigene, veraltete Kopien von urllib3, certifi und msgpack mit, die Trivy als Lücken gemeldet hatte.

## 1.46.1 – 2026-10-24
- Sicherheit: Jedes Image wird vor der Veröffentlichung auf GitHub mit Trivy auf bekannte Schwachstellen geprüft. Findet Trivy eine schwere Lücke (CRITICAL/HIGH), für die es schon eine Korrektur gibt, wird das Image nicht veröffentlicht. Zusätzlich baut GitHub das Image jeden Montag mit den neuesten Paketen und Debian-Sicherheitsupdates neu. Es durchläuft dieselben Tests und dieselbe Prüfung und wird nur bei Erfolg unter `latest` veröffentlicht. Auf den Server kommt es erst mit `sh update.sh --pull`.
- Sicherheit: Beim Bauen werden jetzt die aktuellen Debian-Sicherheitsupdates eingespielt (unter anderem OpenSSL, GnuTLS, Kerberos, PAM, Perl). Die nicht benötigten Pakete `setuptools` und `wheel` sind aus dem Image entfernt. Die erste Trivy-Prüfung hatte hier mehrere schwere Lücken gefunden.

## 1.46.0 – 2026-10-24
- Sicherheit: Mitglieder von Schlüsseladministratoren, Organisationsschlüsseladministratoren, Richtlinien-Ersteller-Besitzer und Zertifikatherausgeber gelten jetzt ebenfalls als geschützt. Bisher durften Operatoren deren Passwort zurücksetzen.
- Sicherheit: Computer- und Dienstkonten (gMSA) lassen sich nicht mehr über Passwort-Reset, Offboarding, Verschieben oder Löschen bearbeiten, auch nicht mit einem gezielt übergebenen DN.
- Sicherheit: Beim Löschen von Ordnern:
  - Benutzernamen mit „~“ (mögliche Windows-Kurznamen) werden übersprungen.
  - Ordner, die im Ordner eines anderen Kontos liegen, werden nicht gelöscht.
  - Wird ein Unterordner während des Löschens durch eine Verknüpfung ersetzt, wird ihr nicht gefolgt.
- Sicherheit: Die Sperre nach fehlgeschlagenen Anmeldungen lässt sich nicht mehr mit vielen gleichzeitigen Versuchen umgehen.
- Sicherheit: Auf GitHub sieht der Build-Schritt mit den neu installierten Paketen den Zugangsschlüssel nicht mehr. Die verwendeten GitHub-Actions sind auf feste Versionen festgelegt. Images werden nur vom Branch `main` veröffentlicht.
- Behoben: Doppelklick auf „Anlegen“, „Passwort zurücksetzen“, Offboarding oder Löschen löst die Aktion nicht mehr zweimal aus.
- Behoben: Das Gruppenfenster zeigt nach schnellem Wechsel zwischen zwei Personen nicht mehr die Gruppen der falschen Person.
- Behoben: Beim Onboarding wird auch ein bereits vergebener Anmeldename (UPN) erkannt.
- Behoben: Steht in der Ziel-OU schon ein gleichnamiges Objekt, bricht das Offboarding ab, bevor etwas verändert wird.
- Behoben: Eine abgebrochene Wiederherstellung lässt sich wiederholen.
- Behoben: `update.sh`:
  - Die Sicherung von `data/` entsteht erst bei angehaltenem Container.
  - Ein lokaler Build ersetzt keine neuere Version von GitHub mehr.
  - Nach `--pull` wird die richtige Version angezeigt.
- Behoben: Fällt beim Laden ein Bereich aus, werden die übrigen trotzdem geladen.

## 1.45.0 – 2026-10-24
- Neuigkeiten in der Oberfläche: Unter *Hilfe → Neuigkeiten* steht, was sich in den installierten Versionen geändert hat. Gibt es seit dem letzten Lesen eine neue Version, zeigt ein kleiner Punkt das an; bei Sicherheitsupdates ist er orange.

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
- Behoben: Fehler aus dem Code-Review:
  - LDAP-Suchen erkennen Abbrüche und Fehler.
  - Zeitlimits für den DC.
  - DN-Vergleich nach Bestandteilen.
- Sicherheit: Beim Löschen werden Admin-Passwort und Rolle unmittelbar vorher erneut geprüft. Ordner, die auch andere Konten nutzen, werden nicht gelöscht.
- Wiederherstellen nur noch über die GUID. Ein Onboarding, das abbricht, wird sauber zurückgerollt.
- Sicherheit: Im SMTP-Modus „Auto“ wird ohne STARTTLS nichts mehr gesendet. Für interne Relays ohne TLS gibt es den Modus „Ohne Verschlüsselung“.
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
