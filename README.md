# SAMONBOARDING

*English version: [README.en.md](README.en.md)* · **Handbuch: [HANDBUCH.md](samonboarding/web/manual/HANDBUCH.md)** · **Datenschutz (DSGVO): [DATENSCHUTZ.md](DATENSCHUTZ.md)** · Webseite: [helfi.space](https://helfi.space) · Lizenz: [AGPL-3.0-or-later](LICENSE)

Webanwendung für die tägliche Benutzerverwaltung im Active Directory (**Samba AD** oder **Windows Server AD**):

| Modul | Was es macht |
|---|---|
| **Onboarding** | Legt neue Benutzer anhand eines Templates an (Namensschema, OU, Passwort, Gruppen, weitere Attribute) |
| **Offboarding** | Deaktiviert ein Konto, entfernt es aus allen Gruppen und verschiebt es in eine Ziel-OU |
| **Passwort zurücksetzen** | Setzt Passwörter zurück (Zufall oder manuell), kann Kontosperren aufheben und Änderung beim nächsten Login erzwingen |
| **Benutzerverwaltung** | Verschiebt Konten zwischen erlaubten OUs und pflegt Gruppenmitgliedschaften |
| **Wiederherstellen** | Macht ein versehentliches Offboarding rückgängig (OU, Gruppen, aktiv) |
| **Konten löschen** | Nur Administratoren: löscht deaktivierte Konten samt Profil, Ordnerumleitung und Basisordner, immer erst als Simulation |
| **E-Mail-Benachrichtigung** | Optional: Mail an den ausführenden Mitarbeiter (SMTP) |

Die Anwendung läuft als Docker-Container (FastAPI + ldap3), die Oberfläche ist komplett eingebaut und braucht kein Internet.

---

## Inhalt

1. [So funktioniert es](#1-so-funktioniert-es)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Installation](#3-installation)
4. [Konfiguration](#4-konfiguration)
5. [Active Directory vorbereiten](#5-active-directory-vorbereiten)
6. [Ersteinrichtung in der Oberfläche](#6-ersteinrichtung-in-der-oberfläche)
7. [Die Module im Detail](#7-die-module-im-detail)
8. [Betrieb](#8-betrieb)
9. [Sicherheitshinweise](#9-sicherheitshinweise)
10. [Fehlersuche](#10-fehlersuche)
11. [Entwicklung](#11-entwicklung)

---

## 1. So funktioniert es

```
 Browser  ──HTTPS──▶  SAMONBOARDING (Docker, Port 9500)  ──LDAPS 636──▶  Domain Controller
                                   │
                                   └──SMTP (optional)──▶  Mailserver
```

Diese fünf Punkte erklären das ganze Konzept:

1. **Es gibt kein Dienstkonto.** Jeder meldet sich mit seinem *eigenen* AD-Konto an. Alle Aktionen laufen im Namen dieses Benutzers. Was das AD ihm nicht erlaubt, kann er auch hier nicht tun. Die Rechte werden also im AD vergeben (Delegierung), nicht in der Anwendung.
2. **Die Verbindung zum DC ist verschlüsselt (LDAPS, Port 636).** Das ist nötig, weil AD das Setzen von Passwörtern nur über eine verschlüsselte Verbindung erlaubt.
3. **Zwei Rollen**, abhängig von den Gruppen des angemeldeten Benutzers (verschachtelte Mitgliedschaften zählen mit):

   | Rolle | Voraussetzung | Darf |
   |---|---|---|
   | **Administrator** | Mitglied in `Domänen-Admins`, `Organisations-Admins` oder `Administratoren` (erkannt an der SID, auch mit englischen Namen) | alles, inklusive Einstellungen, Templates, SMTP und Freigabe der OUs |
   | **Account Operator** | Mitglied in `Account Operators` **oder** in der selbst festgelegten Gruppe (`CUSTOM_OPERATOR_GROUP`) | Onboarding, Offboarding, Passwort-Reset und Benutzerverwaltung, aber nur in den vom Administrator freigegebenen OUs |

   Alle anderen werden beim Login abgewiesen.
4. **Freigegebene OUs.** Der Administrator legt in der Oberfläche fest, in welchen OUs gearbeitet werden darf. Der Server prüft das bei jeder Aktion zusätzlich, nicht nur die Oberfläche.
5. **Nur HTTPS, Sitzungen nur im Arbeitsspeicher.** Die Anwendung ist ausschließlich über HTTPS erreichbar. Sitzungen (inklusive Passwort, das für die Aktionen im AD gebraucht wird) enden bei der Abmeldung, nach **30 Minuten ohne Aktivität** oder beim Neustart des Containers. Jede Aktion wird in den **Berichten** festgehalten (SQLite, ohne Passwörter).

---

### Oberfläche

Die Navigation folgt dem Lebenszyklus eines Kontos: **Eintritt** (Onboarding), **Pflege** (Benutzerverwaltung, Passwort zurücksetzen), **Austritt** (Offboarding) und **Löschung**. Darunter liegen Einrichtung (Templates, E-Mail-Benachrichtigung, AD-Struktur) und Hilfe. Rückmeldungen erscheinen als Meldung unten rechts. Fehler und lange Meldungen bleiben stehen, bis sie geschlossen werden. Auf Tablet und Handy klappt die Navigation über das Menü-Symbol oben links auf.

**Sprache:** Die Oberfläche gibt es auf **Deutsch und Englisch**. Umgeschaltet wird mit *DE / EN* unten in der Seitenleiste oder oben rechts auf der Anmeldeseite. Die Wahl merkt sich der Browser; beim ersten Aufruf gilt die Sprache des Browsers. Meldungen des Servers und die Benachrichtigungs-Mails kommen in der gewählten Sprache. Namen, OUs, Gruppen und Pfade aus dem AD werden nie übersetzt. Die englischen Texte stehen in `samonboarding/web/i18n.json` (deutscher Text → englischer Text, mit Platzhaltern `{0}` für Werte).

Farben und Schriften stehen in `samonboarding/web/theme.json`. Nach einer Änderung dort das Image neu bauen (`docker compose up -d --build`).

## 2. Voraussetzungen

- Ein Linux-Server (oder eine VM) mit **Docker Engine**. **Docker Compose ist nicht nötig:** Ist es vorhanden (`docker compose` oder `docker-compose`, in jeder Version, z. B. auf einer **Synology**), nutzt `update.sh` es. Sonst startet `update.sh` den Container direkt mit `docker` und denselben Einstellungen (Netz, Port, `data/`, Rechte, Neustart, Gesundheitsprüfung); nur eine `docker-compose.override.yml` wird dann nicht berücksichtigt.
- Der Server erreicht den Domain Controller über **TCP 636** (LDAPS) und kann dessen Namen auflösen
- Ein **Domain Controller** mit aktiviertem LDAPS (siehe [Abschnitt 5](#5-active-directory-vorbereiten))
- Optional: ein SMTP-Server für Benachrichtigungen

---

## 3. Installation

### Schritt 1: Dateien bereitstellen

**Von GitHub:**

```bash
sudo apt install git          # falls noch nicht vorhanden
sudo git clone https://github.com/soleil0815/samonboarding.git /opt/samonboarding
cd /opt/samonboarding
```

Gebaut werden muss auf dem Server nichts: GitHub baut bei jeder neuen Version das fertige Image (`ghcr.io/soleil0815/samonboarding`), und `sudo sh update.sh --pull` holt und startet es (Schritt 3).

**Alternativ als ZIP:** Die ZIP einer Version in einen Ordner wie `/opt/samonboarding` entpacken. Darin müssen diese Dateien und Ordner direkt nebeneinander liegen:

```
/opt/samonboarding/
├── app.py
├── Dockerfile
├── docker-compose.yml      ← wird mit jeder Version ersetzt, nicht anpassen
├── .env.example            ← Vorlage für deine Einstellungen
├── .env                    ← deine Einstellungen (legst du in Schritt 2 an, bleibt bei Updates)
├── requirements.txt
├── tailwind.config.js
├── tailwind.input.css
├── .dockerignore
└── samonboarding/          ← kompletter Ordner mit allen Modulen und web/index.html
```

Prüfung: `ls samonboarding/web` muss `index.html` zeigen. Fehlt der Ordner `samonboarding/`, bricht der Build mit der Meldung `"/samonboarding/web": not found` ab.

### Schritt 2: Einstellungen in `.env` eintragen

Deine Einstellungen stehen in der Datei **`.env`**, nicht in der `docker-compose.yml`. Die `.env` gehört dir: Neue Versionen bringen nur eine aktualisierte `.env.example` mit, deine `.env` wird nie überschrieben.

```bash
cp .env.example .env
nano .env
```

Mindestens diese Werte anpassen:

```ini
AD_DOMAIN=firma.local
AD_DC_IP=192.168.1.10
CUSTOM_OPERATOR_GROUP=CO-ADMIN
```

Alle weiteren Einstellungen (Port, Zeitzone, Zertifikat, Löschfristen …) stehen kommentiert in der `.env.example`, die Bedeutung in [Abschnitt 4](#4-konfiguration). Kommentare bitte nur in eigene Zeilen schreiben (mit `#` am Zeilenanfang), nicht hinter einen Wert.

Brauchst du etwas, das nicht über die `.env` geht (z. B. einen eigenen DNS-Server für den Container), lege eine **`docker-compose.override.yml`** an. Docker liest sie automatisch zusätzlich ein, und auch sie wird bei Updates nicht ersetzt.

### Schritt 3: Starten

```bash
sudo sh update.sh --pull     # fertiges Image von GitHub holen und starten (empfohlen)
# oder: sudo sh update.sh    # Image hier auf dem Server selbst bauen
```

Mit `--pull` wird nichts gebaut, der Start dauert nur so lange wie der Download. Ohne `--pull` prüft `update.sh` die Voraussetzungen, legt beim ersten Mal die npm-Sperrdatei an, baut das Image mit den festgelegten Versionen, startet den Container und wartet, bis er „healthy“ ist. Am Ende zeigt es die Adresse an. Der erste Build dauert einige Minuten. Ohne Skript geht es auch mit `sudo chown -R 10001:10001 data` und `docker compose up -d --build` (der Container läuft als Benutzer 10001, nicht als root, und braucht dafür Schreibrechte auf `data/`).

### Schritt 4: Prüfen

```bash
docker compose ps          # Status sollte "running" bzw. "healthy" sein
docker compose logs -f     # Logs live ansehen (Strg+C beendet die Anzeige)
```

**Kein Internet im Betrieb:** Die Anwendung baut von sich aus keine Verbindungen ins Internet auf, nur zu DC, Dateiserver, SMTP und ggf. Exchange (siehe [Abschnitt 9](#9-sicherheitshinweise)). Wer den Container zusätzlich abschotten will, beschränkt den ausgehenden Verkehr des Docker-Netzes `samonboarding` (Subnetz `DOCKER_SUBNET`) in der Firewall des Hosts, Routers oder der Synology.

### Schritt 5: Anmelden

Öffne `https://<server>:9500` im Browser und melde dich mit einem AD-Konto an, das Administrator ist. Beim ersten Start erzeugt die Anwendung ein **selbstsigniertes Zertifikat**, der Browser zeigt deshalb einmal eine Warnung. Ein eigenes Zertifikat lädst du danach in der Oberfläche unter **Zertifikat** hoch (siehe [HTTPS](#https)). Erlaubt sind diese Schreibweisen:

- `benutzername`
- `benutzername@firma.local`
- `FIRMA\benutzername`

Weiter geht es mit der [Ersteinrichtung](#6-ersteinrichtung-in-der-oberfläche).

---

### Alternative: fertiges Image von GitHub (Dockhand, Portainer & Co.)

Bei jedem Push auf `main` baut GitHub das Image selbst (`.github/workflows/image.yml`) und veröffentlicht es als `ghcr.io/soleil0815/samonboarding:latest` und `ghcr.io/soleil0815/samonboarding:<version>`. Vorher schreibt GitHub die Python-Pakete fest und lässt alle Tests mit genau diesen Paketen laufen; schlägt etwas fehl, wird kein Image veröffentlicht. Auf dem Server wird dann nichts gebaut, und `update.sh` wird nicht gebraucht.

1. **Stack anlegen** mit dem Inhalt von `docker-compose.image.yml` (in Dockhand: neuer Stack, Datei einfügen oder aus dem Repository).
2. **Einstellungen** als Variablen des Stacks eintragen, dieselben Namen wie in `.env.example`. Pflicht sind `AD_DOMAIN` und `AD_DC_IP`, meist auch `CUSTOM_OPERATOR_GROUP` und `TLS_HOSTNAMES`.
3. **Zugang zur Registry:** Ist das Repository privat, ist auch das Image privat. Dann in Dockhand die Registry `ghcr.io` mit Benutzer `soleil0815` und einem Token mit dem Recht *read:packages* hinterlegen (GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)). Alternativ das Paket auf GitHub unter *Packages → samonboarding → Package settings* öffentlich machen.
4. **Starten.** Die Daten liegen im Docker-Volume `samonboarding-data`; es bekommt beim ersten Start automatisch den richtigen Besitzer.
5. **Updates:** neue Version auf GitHub → Image wird gebaut → in Dockhand das Image neu ziehen bzw. die automatische Aktualisierung einschalten. Eine bestimmte Version festhalten: Variable `SAMONBOARDING_VERSION=1.41.0`.

Was dabei **nicht** automatisch passiert (das macht nur `update.sh`): Sicherung von `data/` vor dem Update und Rückkehr zur vorherigen Version bei einem Fehlstart. Zurück geht es von Hand über `SAMONBOARDING_VERSION`. Sicherung des Volumes:

```bash
docker run --rm --user 0 -v samonboarding-data:/app/data:ro -v "$PWD":/backup --entrypoint tar \
  ghcr.io/soleil0815/samonboarding:latest czf /backup/samonboarding-data-$(date +%F).tar.gz -C /app data
```

Umzug einer bestehenden Installation (`/opt/samonboarding/data`) in das Volume, einmalig und bei gestopptem alten Container:

```bash
docker run --rm --user 0 -v /opt/samonboarding/data:/von:ro -v samonboarding-data:/app/data --entrypoint sh \
  ghcr.io/soleil0815/samonboarding:latest -c 'cp -a /von/. /app/data/ && chown -R 10001:10001 /app/data'
```

## 4. Konfiguration

Ob das Verzeichnis ein **Samba AD** oder ein **Windows Server AD** ist, wird beim Anmelden automatisch erkannt (RootDSE) und oben neben der Rolle angezeigt. Eine Einstellung ist dafür nicht nötig.

Alle Einstellungen stehen in der Datei **`.env`** (Vorlage: `.env.example`). Nach einer Änderung: `docker compose up -d` (der Container wird dabei neu erstellt). Ein leerer Wert bedeutet: Standardwert.

| Variable | Standard | Bedeutung |
|---|---|---|
| `AD_DOMAIN` | `yourdomain.local` | DNS-Name der Domäne (nicht der NetBIOS-Name). Daraus wird die Suchbasis gebildet: `firma.local` → `DC=firma,DC=local` |
| `AD_DC_IP` | `192.168.1.10` | IP-Adresse oder Name des Domain Controllers |
| `CUSTOM_OPERATOR_GROUP` | leer | sAMAccountName einer zusätzlichen Gruppe, deren Mitglieder Operatoren sind. Die eingebaute Gruppe *Konten-Operatoren* (Account Operators) gilt immer, erkannt an ihrer SID |
| `LDAP_CA_FILE` | leer | Pfad (im Container) zu einer CA-Datei im PEM-Format. Gesetzt: Das Zertifikat des DC wird geprüft |
| `LDAP_ALLOW_PLAIN` | `false` | `true` = Fallback auf unverschlüsseltes LDAP (Port 389), falls 636 nicht erreichbar ist. Passwörter gehen dann im Klartext übers Netz – nur im Notfall |
| `SESSION_IDLE_MINUTES` | `30` | Abmeldung nach so vielen Minuten ohne Aktivität |
| `SESSION_MAX_HOURS` | `12` | Höchstdauer einer Sitzung, auch bei durchgehender Aktivität. Danach neu anmelden (die Rolle wird dabei neu bestimmt) |
| `HTTPS_PORT` | `9500` | Port für HTTPS im Container. Einen HTTP-Port gibt es nicht |
| `TLS_HOSTNAMES` | leer | Namen und IPs für das selbstsignierte Zertifikat, Komma-getrennt (z. B. `samonboarding.firma.local,192.168.1.20`) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | `data/tls/cert.pem`, `data/tls/key.pem` | Eigenes Zertifikat und Schlüssel (PEM) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Fehlversuche je Benutzer und IP, bis zeitweise gesperrt wird |
| `LOGIN_LOCK_MINUTES` | `5` | Dauer der Sperre in Minuten |
| `DATA_DIR` | `<Projekt>/data` | Speicherort für Daten (im Container `/app/data`) |
| `TZ` | `Europe/Berlin` | Zeitzone für Berichte und Mails (z. B. `Europe/Vienna`, `UTC`) |
| `DOCKER_SUBNET` | `172.30.80.0/24` | Subnetz des Docker-Netzes des Containers. Nur ändern, wenn es sich mit deinem Netz überschneidet |
| `AUDIT_RETENTION_DAYS` | `365` | Datenschutz: Berichte (Änderungen), die älter sind, werden täglich gelöscht. `0` = unbegrenzt |
| `LOG_RETENTION_DAYS` | `90` | Datenschutz: Protokoll-Einträge, die älter sind, werden täglich gelöscht. `0` = unbegrenzt |
| `OFFBOARD_RETENTION_DAYS` | `180` | Datenschutz: Wiederherstellungs-Einträge werden so viele Tage nach dem Offboarding gelöscht. `0` = unbegrenzt |

Hinweise:

- **Zertifikatsprüfung:** Standardmäßig vertraut die Anwendung dem LDAPS-Zertifikat des DC automatisch, auch einem selbstsignierten (Samba) oder einem aus der eigenen Firmen-CA. Es muss nichts importiert werden. Die Verbindung ist trotzdem verschlüsselt. Für mehr Sicherheit setzt du `LDAP_CA_FILE` (siehe [Abschnitt 5](#5-active-directory-vorbereiten)). Dann muss `AD_DC_IP` der Name sein, der im Zertifikat steht.
- **Namensauflösung:** Wenn du einen Namen statt einer IP bei `AD_DC_IP` einträgst, muss der Docker-Host diesen Namen auflösen können. Wenn nicht, trage den DNS-Server des AD in eine `docker-compose.override.yml` ein (bleibt bei Updates erhalten):

  ```yaml
  services:
    samonboarding:
      dns:
        - 192.168.1.10
  ```
- Liegt eine Datei `data/config.json` vor, **hat sie Vorrang** vor den Umgebungsvariablen `AD_DOMAIN` und `AD_DC_IP`. Die Anwendung legt diese Datei nicht selbst an.

---

## 5. Active Directory vorbereiten

Die Vorbereitung besteht immer aus denselben drei Dingen:

1. **LDAPS** auf dem Domain Controller (Port 636)
2. Optional: eine **Operator-Gruppe** (`CUSTOM_OPERATOR_GROUP`)
3. **Rechte** für die Operatoren auf den betroffenen OUs

Der Test, ob LDAPS erreichbar ist (vom Docker-Host aus):

```bash
openssl s_client -connect 192.168.1.10:636 -showcerts </dev/null
```

Wird ein Zertifikat angezeigt, ist LDAPS aktiv. Kommt `connection refused` oder ein Timeout, ist Port 636 nicht offen oder blockiert.

### 5.1 Samba AD

**LDAPS:** Samba aktiviert TLS standardmäßig und erzeugt beim Provisionieren ein selbstsigniertes Zertifikat. Üblicherweise liegt es in `/var/lib/samba/private/tls/` (`ca.pem`, `cert.pem`, `key.pem`; je nach Installation kann der Pfad abweichen). Das genügt für den Start. Bei einem Test mit `openssl s_client` solltest du ein Zertifikat sehen.

**Operator-Gruppe anlegen (optional):**

```bash
samba-tool group add CO-ADMIN
samba-tool group addmembers CO-ADMIN benutzer1,benutzer2
samba-tool group listmembers CO-ADMIN
```

Der Gruppenname ist der `sAMAccountName` und kommt bei `CUSTOM_OPERATOR_GROUP` in die `.env`. Alternativ gehören Operatoren zur eingebauten Gruppe `Account Operators`:

```bash
samba-tool group addmembers "Account Operators" benutzer1
```

**Rechte:** Die eingebaute Gruppe `Account Operators` hat normalerweise Rechte zum Verwalten von Benutzern und Gruppen. Wenn du eine eigene Gruppe (`CO-ADMIN`) verwendest, muss sie diese Rechte auf den OUs bekommen, mit denen gearbeitet wird. Das geht mit `samba-tool dsacl set` oder von einem Windows-Client mit RSAT aus (siehe Samba-Dokumentation). Am einfachsten ist es, Operatoren in `Account Operators` zu lassen.

**Passwortrichtlinie:** Zurückgesetzte und neue Passwörter müssen die Richtlinie erfüllen. Anzeigen:

```bash
samba-tool domain passwordsettings show
```

**Zertifikatsprüfung aktivieren (optional):**

1. `ca.pem` vom DC nach `./data/ca.pem` kopieren
2. In der `.env`: `LDAP_CA_FILE=/app/data/ca.pem` und bei `AD_DC_IP` den DNS-Namen des DC eintragen (zum Beispiel `dc1.firma.local`)
3. Welcher Name im Zertifikat steht, zeigt `openssl x509 -in cert.pem -noout -subject -ext subjectAltName`

### 5.2 Windows Server AD

**LDAPS:** Der Domain Controller braucht ein Zertifikat mit dem Verwendungszweck *Serverauthentifizierung*, in dem der DNS-Name des DC steht. Am einfachsten geht das mit einer **Active Directory-Zertifikatdienste (AD CS)**-Unternehmens-CA. Domain Controller bekommen dann automatisch ein passendes Zertifikat, und LDAPS ist auf Port 636 verfügbar. Ohne CA kannst du ein Zertifikat auch manuell ausstellen und im Computerzertifikatspeicher des DC (Eigene Zertifikate) installieren.

Test auf dem DC oder einem Server in der Domäne:

```powershell
Test-NetConnection dc1.firma.local -Port 636
```

Oder mit dem Programm `ldp.exe`: *Verbindung → Verbinden…*, Port `636`, Haken bei *SSL*.

**Operator-Gruppe anlegen (optional):**

```powershell
New-ADGroup -Name "CO-ADMIN" -GroupScope Global -GroupCategory Security -Path "OU=Gruppen,DC=firma,DC=local"
Add-ADGroupMember -Identity "CO-ADMIN" -Members benutzer1,benutzer2
```

**Rechte delegieren** (für `CO-ADMIN` oder eine andere eigene Gruppe): In *Active Directory-Benutzer und -Computer* mit Rechtsklick auf die OU → *Objektverwaltung zuweisen…* und diese Aufgaben auswählen:

| Aufgabe | Wofür |
|---|---|
| Benutzerkonten erstellen, löschen und verwalten | Onboarding, Offboarding (Deaktivieren, Verschieben) |
| Benutzerkennwörter zurücksetzen und Kennwortänderung bei der nächsten Anmeldung erzwingen | Passwort-Reset, Sperre aufheben |
| Alle Benutzerinformationen lesen | Anzeige der Benutzerlisten |
| Mitgliedschaft in einer Gruppe ändern | Gruppen beim Onboarding, Offboarding und in der Benutzerverwaltung |

Wichtig:

- Die Rechte gelten **pro OU**. Delegiere sie für alle Quell-OUs, Ziel-OUs und Gruppen-OUs, die du später in der Oberfläche freigibst. Zum Verschieben braucht der Operator das Recht zum Erstellen in der Ziel-OU.
- Die eingebaute Gruppe `Account Operators` hat solche Rechte schon standardmäßig, aber **nicht** für geschützte Konten (zum Beispiel Mitglieder von `Domain Admins`).

**Zertifikatsprüfung aktivieren (optional):**

1. Das Stammzertifikat der CA exportieren (Format *Base-64-codiert X.509*) und als `./data/ca.pem` speichern
2. In der `.env`: `LDAP_CA_FILE=/app/data/ca.pem` und bei `AD_DC_IP` den **vollständigen DNS-Namen** des DC (zum Beispiel `dc1.firma.local`), der im Zertifikat steht
3. Der Docker-Host muss diesen Namen auflösen können (siehe Hinweis zu `dns:` in [Abschnitt 4](#4-konfiguration))

---

## 6. Ersteinrichtung in der Oberfläche

Melde dich als **Administrator** an. Die Einstellungen sind in den jeweiligen Menüpunkten als Kasten *„(Nur Admin)"* zu finden.

1. **AD Infrastruktur** öffnen: Hier müssen OUs und Gruppen aufgelistet sein. Wenn die Liste leer ist, stimmt die Verbindung nicht (siehe [Fehlersuche](#10-fehlersuche)).
2. **Offboarding:** Quell-OUs wählen (aus diesen darf offgeboardet werden) und die Ziel-OU für deaktivierte Konten festlegen. Speichern.
3. **Passwort zurücksetzen:** Quell-OUs wählen, aus denen Passwörter zurückgesetzt werden dürfen. Speichern.
4. **Benutzerverwaltung:** Quell-OUs (Scan-Bereich), erlaubte Ziel-OUs (Verschieben) und Gruppen-OUs (Gruppen-Auswahl) wählen. Speichern.
5. **Templates:** Mindestens ein Template für das Onboarding anlegen (siehe unten).
6. **SMTP Benachrichtigung** (optional): Server eintragen, speichern, mit dem Test-Button eine Mail senden.
7. **Als Operator testen:** Mit einem Operator-Konto anmelden und je ein Onboarding, Passwort-Reset und Offboarding mit einem Testbenutzer durchspielen.

Bedienung der Auswahl: Die OUs und Gruppen erscheinen als **Baum mit Haken**. Mit den Pfeilen klappst du Zweige auf und zu, mit dem Suchfeld filterst du. Bei **Quell-OUs und Gruppen-OUs** gilt eine gewählte OU **samt allen Unter-OUs**. Bei den **erlaubten Ziel-OUs** gilt genau die gewählte OU.

Solange für ein Modul keine Quell-OUs gewählt sind, bleibt dessen Liste leer, und es erscheint der Hinweis, dass keine OUs konfiguriert sind.

### Templates

Ein Template beschreibt, wie ein neuer Benutzer angelegt wird:

| Feld | Bedeutung |
|---|---|
| Template Name | Name des Templates (Pflichtfeld) |
| Username Makro | Aufbau des Benutzernamens (`sAMAccountName`), siehe Tabelle unten |
| Ziel OU (DN) | OU, in der das Konto angelegt wird (Eingabe als DN oder Auswahl aus der AD-Liste) |
| E-Mail-Adresse / Postfach | Ob die E-Mail-Adresse Pflicht, optional oder gar nicht abgefragt wird und ob ein Exchange-Postfach entsteht (siehe [unten](#e-mail-adresse-und-postfach-je-template-einstellbar)) |
| Passwort-Modus | *Automatisches Zufallspasswort* (12 Zeichen, ohne verwechselbare Zeichen wie 0/O oder 1/l/I) oder *Festes Standardpasswort* (dann muss das Feld *Standardpasswort* ausgefüllt sein) |
| Benutzer muss Passwort beim nächsten Login ändern | Erzwingt die Änderung beim ersten Login |
| Kennwort läuft nie ab | Setzt das entsprechende Konto-Flag |
| AD Gruppen zuweisen | Gruppen, in die der Benutzer aufgenommen wird (Baum mit Haken) |
| Weitere Felder | Optional: Anzeigename, Abteilung, Firma, Stellenbezeichnung, Vorgesetzter (Manager-DN), Büro, Telefon, Adresse, Land u. a. |
| Profil (wie im RSAT-Reiter „Profil“) | **Profilpfad**, **Anmeldeskript** und **Basisordner** (siehe unten) |

**Basisordner** wie in RSAT: *Lokaler Pfad* (nur der Pfad, z. B. `C:\Users\%username%`) oder *Verbinden von* mit Laufwerk (`D:` bis `Z:`, Standard `Z:`) und Netzwerkpfad (`\\server\home$\%username%`). Ein Laufwerk ist nur mit Netzwerkpfad möglich, das prüft die Anwendung beim Speichern. Standardmäßig wird nur das AD-Attribut gesetzt (`homeDirectory`, `homeDrive`). Mit der Option **Ordner beim Anlegen des Benutzers automatisch erstellen** legt die Anwendung den Basisordner zusätzlich selbst an (siehe [Basisordner automatisch anlegen](#basisordner-automatisch-anlegen)). Profilpfad, Anmeldeskript und Basisordner sind auf 260 Zeichen begrenzt (AD-Grenze).

In den Textfeldern kann der Platzhalter `%username%` stehen. Er wird durch den neuen Benutzernamen ersetzt, zum Beispiel für den Pfad `\\server\home\%username%`.

**Namens-Makros** (Beispiele):

| Makro | Name | Ergebnis |
|---|---|---|
| `%LASTNAME%%FIRSTNAME%[3]` (Standard) | Max Mustermann | `MUSTERMANNMAX` |
| `%FIRSTNAME[1]%.%LASTNAME%` | Anna Schmidt | `A.SCHMIDT` |
| `%LASTNAME[5]%%FIRSTNAME[2]%` | Eva Öztürk | `OEZTUEV` |

- `%FIRSTNAME%` und `%LASTNAME%` stehen für Vor- und Nachname, mit `[n]` werden nur die ersten *n* Zeichen verwendet
- Der Name wird in Großbuchstaben gebildet, Umlaute werden umgesetzt (Ä → AE, ß → SS), Akzente entfallen, Leerzeichen und Bindestriche werden entfernt
- Erlaubt sind nur `A–Z`, `0–9`, `.`, `_`, `-`, **maximal 20 Zeichen**
- Ist der Name schon vergeben, wird eine Zahl angehängt (`…2`, `…3`)

---

## 7. Die Module im Detail

### Onboarding

1. Template wählen, Vor- und Nachname sowie (je nach Einstellung) die E-Mail-Adresse eingeben
2. Das Konto wird in der Ziel-OU des Templates angelegt (Name: *Vorname Nachname*, UPN: `benutzername@firma.local`)
3. Das Konto wird zunächst **deaktiviert** angelegt, das Passwort gesetzt und dann aktiviert. Gelingt das Setzen des Passworts nicht, wird das halbfertige Konto wieder gelöscht
4. Gruppen des Templates werden zugewiesen. Schlägt das für einzelne Gruppen fehl, erscheint eine Warnung
5. Die Zugangsdaten erscheinen im Ausgabefenster (kopieren oder als PDF drucken). Wenn SMTP aktiv ist, geht eine Mail an den ausführenden Mitarbeiter

#### E-Mail-Adresse und Postfach: je Template einstellbar

Im Dialog eines Templates (Menüpunkt **Templates**) legt der Administrator unter *E-Mail-Adresse / Postfach* fest, was beim Onboarding mit diesem Template passiert. So können Templates für verschiedene Umgebungen nebeneinander bestehen:

| Einstellung | Wann sinnvoll | Verhalten |
|---|---|---|
| **Eigener Mailserver ohne Exchange** (Standard) | Die Adresse muss im AD stehen | Pflichtfeld, ohne Adresse wird nicht angelegt |
| **E-Mail-Adresse optional** | Gemischte Umgebung | Feld vorhanden, darf leer bleiben |
| **Exchange im eigenen Haus** | Postfach soll automatisch entstehen | Feld ausgeblendet, das Postfach wird per Exchange angelegt (siehe nächster Abschnitt) |
| **Microsoft 365 / Exchange Online** | Postfach entsteht über die Lizenz | Feld ausgeblendet, das Attribut `mail` wird nicht gesetzt |

Beim Onboarding richtet sich das Formular nach dem gewählten Template: Wechselt man das Template, erscheint oder verschwindet das Feld *E-Mail-Adresse* entsprechend. Der Server erzwingt die Einstellung ebenfalls (bei *Exchange* und *Microsoft 365* wird eine mitgeschickte Adresse ignoriert). In Mail und Ausgabefenster fehlt die Zeile *E-Mail*, wenn keine Adresse vergeben wurde.

Im Dialog steht außerdem ein **Hinweis**, den die Anwendung aus dem AD liest: Ein Eintrag *Microsoft Exchange* im Konfigurationsbereich zeigt Exchange, ein Konto `MSOL_*` bzw. `AAD_*` zeigt Microsoft Entra Connect (Azure-Synchronisation). Das ist nur eine Empfehlung. Eine reine Cloud-Umgebung muss im AD keine Spuren hinterlassen.

**Ältere Templates** ohne diese Einstellung bleiben *Pflichtfeld*. Hatte man in Version 1.15 die globale Einstellung *Nicht abfragen* gewählt, erben Templates ohne eigene Angabe diesen Wert als *Microsoft 365*, bis sie einmal gespeichert werden.

**Microsoft 365:** Die Anwendung legt dort selbst kein Postfach an. Es entsteht, wenn dem Benutzer eine Lizenz zugewiesen wird. Das lässt sich automatisieren: Im Template die Gruppe eintragen, die per *gruppenbasierter Lizenzierung* die Lizenz vergibt. Nach der nächsten Synchronisation (meist etwa 30 Minuten) ist das Postfach da.

#### Postfach auf einem Exchange-Server im eigenen Haus anlegen

Für Templates mit der Einstellung *Exchange im eigenen Haus* führt die Anwendung nach dem Anlegen des Kontos `Enable-Mailbox` auf deinem Exchange-Server aus. Die Verbindung wird einmal im Menüpunkt **Templates**, Kasten *Exchange im eigenen Haus*, eingerichtet:

| Feld | Bedeutung |
|---|---|
| Exchange-Anbindung aktivieren | Schalter, standardmäßig **aus**. Ist er aus, bekommt ein Template mit *Exchange im eigenen Haus* nur eine Warnung und das Postfach wird nicht angelegt |
| Exchange-Server | Servername ohne `https://` (z. B. `exchange01.firma.local`), erreichbar vom Container aus |
| Port, HTTPS, Zertifikat prüfen | Standard `443`, HTTPS an, Prüfung an. Die Prüfung nur ausschalten, wenn das Zertifikat nicht anders vertraut werden kann |
| Anmeldeart | *Automatisch (negotiate)*, bei Problemen *NTLM* oder *Kerberos* probieren |
| Postfach-Datenbank | leer = Exchange wählt selbst |
| Domänencontroller | leer = derselbe DC, mit dem die Anwendung das Konto angelegt hat. So muss Exchange nicht auf die Replikation warten |

Ablauf und Regeln:

- Die Anwendung verbindet sich mit `https://<server>/PowerShell` (Exchange-Verwaltungsshell) und verwendet dazu die **Zugangsdaten des angemeldeten Benutzers**. Dieser braucht in Exchange die Rolle *Mail Recipients* (z. B. über die Rollengruppe *Recipient Management*). Gespeichert werden keine Exchange-Zugangsdaten
- **Verbindung testen** prüft Erreichbarkeit, Anmeldung und ob `Enable-Mailbox` für das Konto verfügbar ist, mit den Eingaben im Formular (auch ungespeichert)
- Wird kein Postfach angelegt (Fehler, Server nicht erreichbar), bleibt das **Konto bestehen**. Es erscheint eine Warnung, das Postfach kann dann in Exchange nachgeholt werden. Nichts wird zurückgerollt
- Die E-Mail-Adresse vergibt Exchange nach seiner Adressrichtlinie. Die Anwendung liest sie danach aus dem AD und zeigt sie im Ergebnis. Das Formular fragt sie bei diesem Template nicht ab
- Das Anlegen kann einige Sekunden dauern, die Seite dabei nicht schließen
- Dafür wird das Python-Paket `pypsrp` verwendet (in `requirements.txt`). Fehlt es, erscheint eine Meldung im Test
- Jede Änderung der Einstellung und jeder Verbindungstest stehen in den Berichten, ohne Passwörter

Diese Funktion lässt sich nur mit einem echten Exchange-Server vollständig prüfen. Erst mit einem Testkonto ausprobieren.

#### Basisordner automatisch anlegen

Ist im Template ein Netzwerkpfad als Basisordner eingetragen und die Option *Ordner beim Anlegen des Benutzers automatisch erstellen* gesetzt, passiert nach dem Anlegen des Kontos Folgendes:

1. Die Anwendung legt **nur den letzten Ordner** des Pfads an. Der übergeordnete Ordner (z. B. `\\server\home$`) muss existieren
2. Das neue Konto bekommt **Vollzugriff** (mit Vererbung auf Unterordner und Dateien). Alle übrigen Berechtigungen, auch die vom übergeordneten Ordner geerbten, bleiben unverändert. Danach wird gelesen, ob der Eintrag wirklich gesetzt ist
3. Existiert der Ordner schon, wird er **nicht angefasst** (er könnte jemand anderem gehören). Es erscheint ein Hinweis
4. Der Ordner wird mit den Zugangsdaten der angemeldeten Person angelegt, die dafür auf dem Server das Recht zum Erstellen und zum Ändern der Berechtigungen braucht
5. Ein Fehler (Server nicht erreichbar, kein Recht) verhindert **nie** das Anlegen des Kontos. Er erscheint als Hinweis im Ergebnisfenster und in den Berichten (`homeFolder`)

Voraussetzung ist wie beim Löschen, dass der Container den Dateiserver auf TCP 445 erreicht. Hat der Ordner gar keine Berechtigungsliste (selten, „Jeder hat Zugriff“), wird sie nicht verändert.

### Offboarding

Aus der Liste der Quell-OUs ein Konto wählen. Es wird **deaktiviert**, aus **allen Gruppen entfernt** und in die **Ziel-OU** verschoben. Das eigene Konto kann nicht offgeboardet werden.

**Mehrfachauswahl:** Über die Kontrollkästchen lassen sich bis zu 25 Konten auf einmal offboarden (Kopf-Kästchen = alle sichtbaren). Vor dem Start erscheint eine Bestätigung mit Anzahl und Namen. Die Konten werden nacheinander verarbeitet, ein Fehler bei einem Konto (z. B. geschützt, außerhalb der Quell-OU) stoppt die anderen nicht. Am Ende steht, was geklappt hat und was nicht. Jedes Konto hat einen eigenen Audit-Eintrag, die Benachrichtigungs-Mail ist eine Sammelmail.

**Geschützte Konten:** Privilegierte Konten werden vom Server grundsätzlich abgelehnt (*403*), für alle Rollen. Als privilegiert gelten Mitglieder (auch über verschachtelte Gruppen oder als primäre Gruppe) von *Domänen-Admins*, *Schema-Admins*, *Organisations-Admins* und den eingebauten Gruppen *Administratoren*, *Konten-/Server-/Druck-/Sicherungs-Operatoren* sowie das integrierte Administratorkonto (RID 500) und `krbtgt`. In der Liste erscheinen solche Konten mit Schloss und ohne Auswahl. Die Prüfung liest für jedes Konto die echten Gruppen (`tokenGroups`) und nicht nur das Merkmal `adminCount`, das nicht jedes Verzeichnis pflegt. Beim Ausführen wird erneut geprüft. Soll ein solches Konto trotzdem bearbeitet werden, zuerst die Mitgliedschaft im AD entfernen.

**Wiederherstellen (Offboarding rückgängig machen):** Vor jedem Offboarding merkt sich die Anwendung, in welcher OU das Konto lag, in welchen Gruppen es war und ob es aktiv war. Unter *Offgeboardete Konten wiederherstellen* (unten auf der Offboarding-Seite) steht jedes so offgeboardete Konto mit dem Knopf **Wiederherstellen**:

1. Eine **Vorschau** zeigt, was passiert: zurück in die OU, wieder in diese Gruppen, wieder aktiv. Nichts wird dabei verändert
2. Fehlt die alte OU oder liegt sie nicht mehr in den Quell-OUs des Offboardings, wählst du eine andere OU aus der Liste
3. Nach **Wiederherstellen** wird das Konto verschoben, den Gruppen wieder zugewiesen und aktiviert. Das Passwort hat das Offboarding nicht verändert, es gilt weiter

Konto und Gruppen werden über ihre feste AD-Kennung (`objectGUID`) gesucht, auch wenn sie inzwischen umbenannt oder verschoben wurden. Eine gelöschte Gruppe wird übersprungen (Hinweis), eine Gruppe ohne Schreibrechte wird einzeln gemeldet, der Rest wird trotzdem wiederhergestellt. Ein Konto, das vor dem Offboarding schon deaktiviert war, bleibt deaktiviert.

Wiederherstellen darf, wer auch offboarden darf. Administratoren können einen Eintrag zusätzlich **verwerfen** (z. B. wenn das Konto von Hand zurückgeholt wurde). Ein Eintrag verschwindet, sobald das Konto wiederhergestellt, gelöscht oder verworfen wurde. Gespeichert wird in `data/offboarding.db` (SQLite, keine zusätzliche Software nötig), ohne Passwörter. Konten, die vor Version 1.19 offgeboardet wurden, haben keinen Eintrag. Jede Wiederherstellung steht in den Berichten (`offboarding-restore`), bei aktivierter Offboarding-Mail gibt es eine Benachrichtigung.

### Passwort zurücksetzen

Konto aus den freigegebenen OUs wählen, dann *Zufallspasswort* (12 Zeichen) oder *manuell* (mindestens 6 Zeichen, die Passwortrichtlinie des AD gilt). Optional: Änderung beim nächsten Login erzwingen und eine Kontensperre aufheben. Das neue Passwort erscheint einmalig im Ausgabefenster.

### Benutzerverwaltung

- **Verschieben:** Konto in eine der erlaubten Ziel-OUs verschieben
- **Gruppen:** Gruppenmitgliedschaften aus den freigegebenen Gruppen-OUs hinzufügen oder entfernen

Alle Benutzerlisten sind alphabetisch nach Anzeigenamen sortiert.

### Konten löschen (nur Administratoren)

Der Menüpunkt **Konten löschen** ist nur für Administratoren sichtbar. Account Operatoren sehen ihn nicht, und der Server weist ihre Anfragen zusätzlich mit *403* ab. Geschützte (privilegierte) Konten, siehe Offboarding, lassen sich auch hier weder simulieren noch löschen.

**Einrichtung (Konfiguration auf der Seite, nur Admin):**

1. **OU der deaktivierten Konten** wählen (vorbelegt mit der Ziel-OU des Offboardings). Nur Konten in dieser OU, die auch deaktiviert sind, kommen in die Liste.
2. Für jeden Speicherort, den du nutzt, den Haken setzen und die **Basispfade** als UNC-Pfad eintragen (einer pro Zeile). **Speicherorte sind optional:** Gibt es in deiner Domäne keine Profile, Basisordner oder Ordnerumleitungen auf Servern, lässt du alle Haken weg. Dann löscht die Anwendung nur das AD-Konto, es findet kein Dateizugriff statt (auch `smbprotocol` wird dafür nicht gebraucht). Simulation, Bestätigung per Passwort und alle Schutzmechanismen gelten trotzdem. Ein aktivierter Speicherort braucht mindestens einen Basispfad:

   | Speicherort | Gesucht wird | Besonderheit |
   |---|---|---|
   | Roamingprofil | `<Basispfad>\<Benutzername>.V2` | Nur Ordner mit einer der eingetragenen **Endungen** (`V2`, `V6`, …). Ohne passende Endung wird nichts vorgeschlagen |
   | Ordnerumleitung | `<Basispfad>\<Benutzername>` | Steht in keinem Konto-Attribut, sondern in der GPO, daher der feste Basispfad |
   | Basisordner | `<Basispfad>\<Benutzername>` | Zusätzlich der Pfad aus `homeDirectory` des Kontos |

   Bei Profil und Basisordner kann der Pfad aus dem AD-Konto (`profilePath`, `homeDirectory`) mitverwendet werden. Er gilt nur, wenn er **unterhalb eines Basispfads** liegt. `%username%` wird ersetzt, andere Variablen werden abgelehnt.
3. Optional je Speicherort: **Besitz übernehmen, wenn der Zugriff fehlt** (siehe unten)
4. Speichern, dann **Verbindung zu den Basispfaden testen**. Der Test meldet je Basispfad, ob der Server erreichbar und der Inhalt lesbar ist.

**Simulation:** In der Liste auf *Simulation* klicken. Angezeigt werden das AD-Konto (Name, DN, Gruppenanzahl) und je Pfad Status, Quelle, Anzahl Dateien und Ordner sowie die Größe. Die Simulation verändert nichts.

**Löschen:** Sieht die Simulation gut aus, erscheint darunter das Feld *Endgültig löschen*. Zur Bestätigung den Benutzernamen eintippen, dein **eigenes Passwort** eingeben und den Dialog bestätigen. Das Passwort wird mit dem der aktuellen Sitzung verglichen. Ein falsches Passwort verbraucht den Plan nicht. Nach 5 Fehlversuchen ist das Löschen für diese Sitzung etwa 5 Minuten gesperrt, jeder Fehlversuch steht in den Berichten (`deletion-password-fail`, ohne das Passwort). Ablauf:

1. Der Plan aus der Simulation gilt **10 Minuten**, nur für diese Sitzung und dieses Konto, und nur **einmal**
2. Vor dem Löschen wird alles **erneut geprüft**. Hat sich seit der Simulation etwas geändert (neuer Ordner, Zugriff entzogen, Konto wieder aktiv), passiert nichts, und die Simulation muss wiederholt werden
3. Zuerst werden die **Ordner** gelöscht (Dateien zuerst, dann Ordner von innen nach außen), danach das **AD-Konto**
4. Schlägt bei einem Ordner etwas fehl (z. B. eine gesperrte Datei, siehe Fehlersuche), bleibt das **AD-Konto bestehen**. Die Ergebnisliste zeigt je Ordner, was gelöscht wurde und was nicht. Nach der Fehlerbehebung die Simulation wiederholen. Es wird dann nur noch der Rest gefunden
5. Jeder Löschvorgang steht mit allen Ordnern und Zahlen in den Berichten (`deletion-execute`)

**Mehrere Konten auf einmal:** In der Liste links Haken setzen (oder oben *alle sichtbaren* wählen, höchstens **25 pro Durchlauf**) und *Auswahl simulieren* klicken.

- Die **Sammel-Simulation** ist rein lesend. Jedes Konto erscheint als *Bereit* oder *Blockiert* (mit Grund, z. B. noch aktiv, kein Zugriff, geteilter Ordner), die Pfade lassen sich aufklappen. Blockierte Konten werden nie mitgelöscht
- Zur Bestätigung die **Anzahl** der bereiten Konten eintippen und das eigene **Passwort** eingeben. Die Anzahl fängt versehentliches Auslösen ab, das Passwort stellt sicher, dass wirklich du es bist
- Gelöscht wird als **Hintergrundauftrag** mit Fortschrittsanzeige. Die Seite darf offen bleiben, der Auftrag läuft aber auch ohne sie auf dem Server weiter
- Jedes Konto durchläuft denselben Ablauf wie das Einzellöschen (Neuprüfung, erst Ordner, dann AD-Konto). Schlägt eines fehl, bleibt es bestehen, die übrigen laufen weiter. Am Ende zeigt eine Tabelle das Ergebnis je Konto
- Die Berichte enthalten je Konto einen Eintrag (`deletion-execute`) und einen Sammeleintrag (`deletion-batch`). Die Lösch-Mail ist dabei **eine Zusammenfassung** pro Durchlauf
- Die Simulation läuft in einer Anfrage nacheinander. Bei 25 sehr großen Profilen kann das etwas dauern. Werden Aufträge über einen Reverse Proxy geleitet, dessen Zeitlimit großzügig wählen
- Wird der Container während eines Auftrags neu gestartet, endet er dort. Bereits gelöschte Konten stehen in den Berichten, der Rest bleibt bestehen und lässt sich neu simulieren

**Besitzübernahme (optional, je Speicherort):** Windows legt Profilordner oft so an, dass nur der Benutzer selbst Zugriff hat. Statt die Rechte auf dem Server von Hand zu ändern, kann die Anwendung das übernehmen. Ist die Option für einen Speicherort aktiv, gilt:

- Die **Simulation** prüft nur, ob der Besitz übernommen werden könnte (Handle mit dem Recht *Besitzer ändern*), und ändert nichts. Betroffene Ordner erscheinen mit dem Status *Besitz nötig*. Ihr Inhalt ist vorab nicht zählbar, die Zahlen sind dann Mindestwerte
- Beim **Löschen** wird nur bei einem Eintrag, der mit *Zugriff verweigert* scheitert, der Besitzer auf `Administratoren` gesetzt und dieser Gruppe Vollzugriff gegeben. Danach wird **einmal** erneut versucht. Es werden nur Ordner und Dateien angefasst, die ohnehin gelöscht werden
- Jede Übernahme wird gezählt: im Ergebnis („Besitz übernommen: n×“) und in den Berichten (`takeovers`, `takeoverPaths`)
- Der angemeldete Administrator braucht auf dem Dateiserver das Windows-Recht *Eigentum an Dateien oder Objekten übernehmen* (Domänen-Admins und lokale Administratoren haben es standardmäßig). Fehlt es, bleibt der Ordner ein Hindernis und die Simulation meldet *Kein Zugriff*
- Ohne die Option bleibt alles wie beschrieben: fehlender Zugriff verhindert das Löschen

Gelöscht wird **endgültig, ohne Papierkorb**. Das AD-Konto lässt sich nur über den AD-Papierkorb wiederherstellen (falls aktiviert), die Dateien nur aus einer Sicherung oder den Schattenkopien des Dateiservers. Bei sehr großen Profilen kann das Löschen einige Minuten dauern, die Seite dabei nicht schließen.

**Schutzmechanismen:**

- Es werden nur Pfade **unterhalb** der eingetragenen Basispfade berücksichtigt. Der Basispfad selbst und die Freigabe sind nie ein Ziel
- Abgelehnt werden `..`, Platzhalter (`* ?`), `:` (Streams), `%`, Punkt oder Leerzeichen am Ende und Pfade, die nicht mit `\\` beginnen
- Wird derselbe Pfad im AD auch bei **anderen Konten** eingetragen (z. B. ein gemeinsamer Abteilungsordner als Basisordner), wird er ausgeschlossen
- Verknüpfungen (Junctions, Symlinks) werden **nie verfolgt**: Es wird nur die Verknüpfung selbst entfernt, der Inhalt des Ziels bleibt unberührt. Die Simulation zeigt, wie viele Verknüpfungen enthalten sind. Ist der Zielordner selbst eine Verknüpfung, wird er übersprungen
- Schreibgeschützte Dateien löscht die SMB-Bibliothek, indem sie das Attribut vorher entfernt
- Das eigene Konto und noch aktive Konten werden abgelehnt
- Jede Simulation, jede Löschung und jede Änderung der Einstellungen steht in den Berichten

**Voraussetzungen im Netz:**

- Der Container erreicht die Dateiserver auf **TCP 445** (SMB)
- Der angemeldete Administrator braucht auf den Ordnern **Lese- und Löschrechte**. Der Dateiserver entscheidet darüber, die Anwendung umgeht nichts. Windows legt Profilordner oft so an, dass nur der Benutzer selbst Zugriff hat. Dann hilft die GPO *„Administratorgruppe zu servergespeicherten Benutzerprofilen hinzufügen“* oder eine passende Berechtigung auf der Freigabe. Ohne Zugriff meldet die Simulation *„Kein Zugriff“*
- Der **E-Mail-Versand nach dem Löschen** (SMTP-Einstellung *Löschen eines Kontos*) ist abschaltbar und aus, solange du ihn nicht aktivierst. Die Mail geht an die angemeldete Person und nennt Konto, Ergebnis, Ordner, Dateianzahl und Besitzübernahmen. Sie wird auch bei unvollständigem Löschen gesendet. Passwörter enthält sie nicht
- Es ist **kein Samba-Server im Container** nötig. Die Anwendung nutzt nur einen SMB-Client (Python-Paket `smbprotocol`, ist in `requirements.txt` enthalten)
- Die Anmeldung am Dateiserver erfolgt per NTLM mit den Zugangsdaten des Administrators. Dafür sollte der Dateiserver per Name oder IP erreichbar sein und SMB-Signing unterstützen

---

## 8. Betrieb

### Kontolisten und Zwischenspeicher

Die Oberfläche lädt nur den Bereich, der gerade offen ist. Die Kontolisten hält der Server je Sitzung bis zu **60 Sekunden im Arbeitsspeicher** (`samonboarding/listcache.py`), jede Änderung leert sie sofort; **Konten aktualisieren** / **Neu einlesen** liest immer frisch (`?frisch=1`). Bewusst gibt es **keine Kopie der AD-Konten in einer Datenbank**: Jeder sieht nur, was er mit seinen eigenen AD-Rechten sehen darf, nichts landet auf der Festplatte, und Entscheidungen wie *geschützt?* oder *in der freigegebenen OU?* werden vor jeder Aktion live am DC geprüft. Die Schutzprüfung der Liste braucht wenige Sammelabfragen statt einer Abfrage je Konto.

### Umbenannte oder verschobene OUs und Gruppen

Einstellungen und Templates speichern OUs und Gruppen als DN. Zu jedem Verweis merkt sich die Anwendung die objectGUID (`data/verweise.json`). Wird eine OU/Gruppe im AD umbenannt, verschoben oder gelöscht, sehen Administratoren oben einen Hinweis; **Neue Namen übernehmen** passt alle betroffenen Einstellungen an (wird in den Berichten als `config-references` vermerkt). Gelöschte Objekte müssen von Hand ersetzt werden. Rollen hängen an SIDs, die Wiederherstellung nach dem Offboarding an GUIDs – beide sind von Umbenennungen nicht betroffen. Details: Handbuch, Abschnitt *Ersteinrichtung*.

### Berichte und Protokoll

Alles wird in **`data/reports.db`** (SQLite) geschrieben, ohne Passwörter. Administratoren sehen es in der Oberfläche unter **Berichte**:

| Bereich | Inhalt | Automatisch gelöscht nach |
|---|---|---|
| **Änderungen** | Wer hat wann was getan: Anmeldung, Onboarding, Offboarding, Passwort-Reset, Gruppen, Löschen, Einstellungen, mit Ergebnis und Details | 365 Tagen (`AUDIT_RETENTION_DAYS`) |
| **Protokoll** | Meldungen des Programms ab Stufe *Info* (z. B. Verbindungsfehler, Warnungen) | 90 Tagen (`LOG_RETENTION_DAYS`) |

- Suche, Filter (Erfolgreich/Fehlgeschlagen bzw. Warnungen/Fehler) und *Mehr laden* für ältere Einträge
- **Manuell löschen:** unten auf der Seite „älter als 30/90/180 Tage“ oder „alle Einträge“ wählen und mit dem eigenen Passwort bestätigen. Das Löschen selbst wird in den Änderungen vermerkt
- Gelöschte Einträge werden in der Datenbankdatei überschrieben (`secure_delete`) und lassen sich nicht wiederherstellen
- Ein vorhandenes `audit.log` aus älteren Versionen wird beim ersten Start übernommen und danach entfernt

Die Ausgabe des Containers (`docker compose logs -f`) gibt es weiterhin, begrenzt auf 3 × 10 MB. Zugriffe einzelner Browser (IP-Adressen) werden nicht protokolliert.

Auskunft für eine betroffene Person (Art. 15 DSGVO), also alles, was die Anwendung über ein Konto gespeichert hat: in der Oberfläche unter *Datenschutz* oder per

```bash
docker compose exec samonboarding python -m samonboarding.privacy auskunft mustermann
```

### Update

Die Installationsdateien (`update.sh` mit allen Ausgaben, `.env.example`, `Dockerfile`, `docker-compose.yml`) sind ab Version 1.39.0 auf Englisch. Die Namen der Einstellungen in der `.env` sind gleich geblieben, eine bestehende `.env` funktioniert unverändert.

**Fertiges Image von GitHub (empfohlen):**

```bash
cd /opt/samonboarding
sudo sh update.sh --pull
```

Das Skript holt das neueste Image von `ghcr.io/soleil0815/samonboarding` (`docker pull`) – gebaut und getestet hat es GitHub, auf dem Server wird nichts gebaut. Davor sichert es `data/`, danach startet es den Container neu und prüft, ob er „healthy“ wird. `update.sh` und `docker-compose.yml` werden dabei auf den Stand des Images gebracht. **Startet die neue Version nicht, nimmt das Skript automatisch das vorherige Image wieder in Betrieb.** `.env`, `data/` und `backups/` bleiben unverändert. `git` wird dafür nicht gebraucht, ein `git clone` muss also nie aktualisiert werden. Ein bestimmtes Image statt des neuesten: `SAMONBOARDING_IMAGE=ghcr.io/soleil0815/samonboarding:1.43.0` in der `.env`.

Ist das Repository privat, ist auch das Image privat. Dann einmalig als root anmelden (Benutzer `soleil0815`, Passwort = ein Token mit dem Recht *read:packages*):

```bash
sudo docker login ghcr.io -u soleil0815
```

**Als ZIP:** Die ZIP der neuen Version in den Projektordner laden (z. B. `/opt/samonboarding`) und dort eingeben:

```bash
sudo sh update.sh samonboarding-*.zip
```

Das Skript prüft die ZIP (nur ein Hauptordner, keine unzulässigen Pfade oder Verknüpfungen, wirklich SAMONBOARDING), zeigt installierte und neue Version sowie wie viele Dateien sich ändern, hinzukommen und entfallen, und fragt **einmal** nach (`y` eingeben, `j` geht auch). Dann sichert es die bisherigen Programmdateien nach `backups/programm-<version>-<datum>.tar.gz`, tauscht die Dateien aus, entfernt Dateien, die es in der neuen Version nicht mehr gibt, und macht mit dem Skript der neuen Version weiter (Sicherung von `data/`, bauen, starten, prüfen). Zum Schluss räumt es auf: ZIP, Zwischendateien und alte SAMONBOARDING-Images werden entfernt. Schlägt der Build fehl oder startet die neue Version nicht, kommen die vorherigen Programmdateien zurück und die ZIP bleibt liegen.

Nie angefasst werden `.env`, `data/`, `backups/` und eine `docker-compose.override.yml`. Auf dem Server festgeschriebene Paketversionen (`requirements.txt`, `images.lock`, `package-lock.json`) bleiben, solange sie zur neuen Version passen. Ohne Rückfrage (z. B. für Skripte): `sudo sh update.sh samonboarding-*.zip --yes`. Entpacken klappt mit `unzip`, sonst mit `python3` oder über das Docker-Image – es muss nichts nachinstalliert werden.

Von Hand geht es weiterhin: neue Version entpacken (alle Dateien ersetzen außer `data/`, `.env`, `backups/` und einer eventuellen `docker-compose.override.yml`), dann:

```bash
sh update.sh
```

Das Skript sichert zuerst `data/` nach `backups/` (die letzten 3 Sicherungen bleiben, `KEEP_BACKUPS=5 sh update.sh` behält mehr), baut das Image, startet den Container neu und prüft, ob er „healthy“ wird. Schlägt der Build fehl, läuft der bisherige Container unverändert weiter. **Startet die neue Version nicht sauber, startet das Skript automatisch wieder das vorherige Image.**

**Neue Paketvorgaben:** Ändert eine neue Version `requirements.in` (z. B. eine Mindestversion wegen einer Sicherheitslücke), schreibt `update.sh` die Python-Pakete automatisch neu fest. Dafür installiert es die neuen Pakete in einem Prüf-Container und lässt die Testsuite laufen, einmal mit den bisherigen und einmal mit den neuen Paketen. Nur wenn mit den neuen Paketen kein Test zusätzlich fehlschlägt, gleich viele Tests laufen und ein Rauchtest der echten Anwendung (`tests/smoke_app.py`) besteht, werden die exakten Versionen in `requirements.txt` übernommen. Sonst bleibt alles bei den bisherigen Versionen, mit einem Hinweis; die abgelehnten Vorgaben werden in `.paketpruefung-abgelehnt` vermerkt und erst mit `sudo sh update.sh --lock` erneut versucht. Läuft noch eine Version mit root (vor 1.31) oder ist es die Erstinstallation, richtet das Skript zuerst die neue Version mit den bisherigen Paketen ein und aktualisiert die Pakete dann automatisch in einem zweiten Durchgang – erst dann ist ein Zurücksetzen möglich.

| Option | Wirkung |
|---|---|
| `--lock` | Alle Versionen neu festschreiben (Python-Pakete, npm-Pakete, Basis-Images mit Digest) und danach bauen, z. B. für Sicherheitsupdates |
| `--no-cache` | Ohne Docker-Build-Cache bauen |
| `--no-backup` | Keine Sicherung von `data/` |
| `--prune` | Danach unbenutzte Images entfernen |
| `--pull` | Fertiges Image der neuesten Version von GitHub holen und starten (nichts wird gebaut) |
| `--yes` | Ohne Rückfrage (beim Einspielen einer ZIP) |

Nur Einstellungen in der `.env` geändert: `docker compose up -d` genügt.

### Reproduzierbare Versionen

Jeder Build verwendet exakt dieselben Versionen:

| Datei | Inhalt |
|---|---|
| `images.lock` | Basis-Images mit fester Version (Python `3.11.13`, Node `22.17.0`); nach `sh update.sh --lock` zusätzlich mit Digest (`@sha256:…`) |
| `requirements.txt` | Sperrliste aller Python-Pakete inklusive Abhängigkeiten, jeweils `==Version`. Installiert wird mit `--no-deps`, danach prüft `pip check`, ob alles zusammenpasst |
| `requirements.in` | Die direkten Python-Pakete (Absicht). Daraus erzeugt `sh update.sh --lock` die Sperrliste |
| `package.json`, `package-lock.json` | npm-Pakete für CSS, Schriften und Icons, exakt mit allen Unterpaketen (`npm ci`) |
| `requirements-dev.txt` | Test-Werkzeuge (pytest, ruff) mit exakten Versionen |

Aktualisiert wird nur bewusst mit `sh update.sh --lock`. Das Skript zeigt an, welche Python-Pakete sich ändern. Die geänderten Dateien am besten mit ins Git übernehmen.

Beim Update bleiben `data/`, `.env` und eine eventuelle `docker-compose.override.yml` erhalten; alle anderen Dateien einfach durch die neue Version ersetzen. Neue Optionen findest du in der `.env.example`. Alle Benutzer sind danach abgemeldet.

**Internet-Sperre entfällt (ab 1.38.0):** Hat eine ältere Version die Internet-Sperre eingerichtet, entfernt `update.sh` sie automatisch, sobald die neue Version läuft und „healthy“ ist (iptables-Ketten `SAMONB-EGRESS*`/`SAMONB-HOST*`, die systemd-Units `samonboarding-internetsperre.service`/`.path`/`.timer` und `data/netziele.txt`). Die Zeilen `INTERNET_SPERRE`, `ZUSATZ_ZIELE`, `DATEISERVER_NETZE` und `DNS_SERVER` in einer bestehenden `.env` werden ignoriert und können gelöscht werden. `update.sh` braucht weiterhin root-Rechte (als root oder mit `sudo`), für die Rechte auf `data/` und dieses Aufräumen.

### Sicherung

Sichere den Ordner `data/`. Er enthält:

- `smtp_config.json`, `templates.json` und die Konfigurationen der Module
- `offboarding.db` (gespeicherte Zustände für das Wiederherstellen nach dem Offboarding)
- `reports.db` (Berichte: Änderungen und Protokoll)
- `tls/` (HTTPS-Zertifikat und Schlüssel)

### HTTPS

Die Anwendung spricht **nur HTTPS** (Port 9500). Es gibt keinen unverschlüsselten Port, Anfragen ohne HTTPS werden abgewiesen. Erlaubt sind TLS 1.2 und 1.3 mit modernen Verfahren. Das Sitzungs-Cookie ist `Secure`, `HttpOnly` und `SameSite=Strict` und endet mit dem Browser.

**Zertifikat:**

1. **Ohne eigenes Zertifikat** erzeugt die Anwendung beim ersten Start ein selbstsigniertes (10 Jahre gültig) in `data/tls/`. Der Browser warnt einmal. Damit der Name im Zertifikat passt, `TLS_HOSTNAMES` in der `.env` setzen oder in der Oberfläche unter **Zertifikat** ein neues selbstsigniertes mit den richtigen Namen erzeugen.
2. **Eigenes Zertifikat** (z. B. von der internen CA, empfohlen): in der Oberfläche unter **Einrichtung → Zertifikat** hochladen (nur Administratoren). Es gilt **sofort, ohne Neustart**. Neue Verbindungen bekommen das neue Zertifikat; einmal die Seite neu laden.
   - **PFX/P12** mit Passwort, z. B. aus der Windows-Zertifikatsverwaltung (*Exportieren → Ja, privaten Schlüssel exportieren*). Zwischenzertifikate werden mit übernommen.
   - **Zertifikat + Schlüssel** als PEM oder DER (`.pem`, `.crt`, `.cer`, `.key`), der Schlüssel auch passwortgeschützt. Zwischenzertifikate optional als eigene Datei oder in der Zertifikatsdatei.
   - Vor dem Übernehmen wird geprüft: Passen Zertifikat und Schlüssel zusammen? Ist es gültig (nicht abgelaufen)? Ist der Schlüssel stark genug (RSA ab 2048 Bit oder ECDSA)? Nimmt der Server es an? Hinweise gibt es, wenn es bald abläuft, keine alternativen Namen (SAN) enthält oder Zwischenzertifikate fehlen.
   - Das bisherige Zertifikat bleibt als `cert.pem.prev` / `key.pem.prev` in `data/tls/` erhalten. Jede Änderung steht in den Berichten.
   - Die Seite zeigt das aktuelle Zertifikat mit Namen, Aussteller, Ablaufdatum und Fingerabdruck. 30 Tage vor dem Ablauf erscheint täglich eine Warnung im Protokoll.

Mit einem eigenen Zertifikat sendet die Anwendung zusätzlich HSTS (für einen Tag), damit der Browser die Seite nur noch per HTTPS öffnet. Bei einem selbstsignierten Zertifikat nicht, sonst ließe sich die Warnung nicht mehr wegklicken.

Ohne Oberfläche geht es weiterhin über Dateien (danach neu starten):

```bash
cp onboarding.crt data/tls/cert.pem    # PEM, inklusive Zwischenzertifikate
cp onboarding.key data/tls/key.pem     # PEM, ohne Passwort
docker compose restart
```

Ein Reverse Proxy ist nicht mehr nötig. Wer trotzdem einen verwendet, leitet an `https://<container>:9500` weiter.

---

## 9. Sicherheitshinweise

- Nur im internen Netz betreiben, **nicht** ins Internet stellen
- **Rollen über SIDs:** Administrator ist, wer in *Domänen-Admins*, *Organisations-Admins* oder *Administratoren* ist; Operator, wer in *Konten-Operatoren* oder der eigenen Gruppe (`CUSTOM_OPERATOR_GROUP`) ist. Erkannt wird das an den festen SIDs der Gruppen, nicht am Namen. Das funktioniert damit auch auf deutschen DCs, und eine selbst angelegte Gruppe namens „Domain Admins“ gibt keine Rechte
- **Was Operatoren nicht dürfen:** Geschützte Konten (Domänen-Admins & Co.) können nur Administratoren zurücksetzen, verschieben, ändern oder wiederherstellen, und nur Administratoren dürfen Konten in privilegierte Gruppen aufnehmen (z. B. Sicherungs-Operatoren, Schema-Admins). Offboarding und Löschen geschützter Konten sind für alle gesperrt
- **Prüfung am echten DN:** Freigegebene OUs werden an dem DN geprüft, den der DC zurückliefert. DN-Sonderformen wie `<GUID=…>` oder `<SID=…>` werden abgelehnt
- **Löschen nur passender Ordner:** Ein Pfad aus dem AD-Attribut (Basisordner, Profilpfad) wird nur gelöscht, wenn der Ordnername zum Benutzernamen passt (`mueller` oder `mueller.V6`). Steht dort der Ordner eines anderen, wird er übersprungen
- **Anfragen nur von der eigenen Seite:** Schreibende Anfragen mit fremdem `Origin` werden abgewiesen, zusätzlich zum Cookie mit `SameSite=Strict`. Wer doch einen Reverse Proxy einsetzt, muss den `Host`-Header unverändert durchreichen. Anfragen über 6 MB werden abgelehnt, und die automatische API-Dokumentation (`/docs`) ist abgeschaltet
- **Dateirechte:** Konfiguration (mit SMTP-Passwort), Datenbanken und Zertifikatsschlüssel werden nur für den Eigentümer lesbar gespeichert (0600)
- **SMTP-Passwort:** Wird Server oder Benutzername geändert, muss das Passwort neu eingegeben werden. So lässt sich das gespeicherte Passwort nicht an einen fremden Server schicken
- **Datenschutz in der Oberfläche:** Der Link *Datenschutz* (Anmeldeseite unten, Seitenleiste unter *Hilfe*) zeigt kurz, was gespeichert wird und die aktuellen Löschfristen. Administratoren können dort die Auskunft nach Art. 15 DSGVO für ein Konto als JSON herunterladen (wird in den Berichten vermerkt)
- **Datenschutz:** Welche Daten wo liegen, Löschfristen, eingebaute Maßnahmen und eine Vorlage für das Verzeichnis von Verarbeitungstätigkeiten stehen in [DATENSCHUTZ.md](DATENSCHUTZ.md)
- **Keine Verbindungen ins Internet im Betrieb:** Tailwind-CSS, Schriften (Manrope, JetBrains Mono) und Icons (Font Awesome) werden beim Docker-Build ins Image gepackt und vom eigenen Server ausgeliefert. Es gibt keine CDNs, kein Google Fonts, keine Telemetrie und keine Update-Prüfung. Zusätzlich verbietet ein Content-Security-Policy-Header dem Browser, irgendetwas von fremden Servern zu laden. Internet braucht nur der **Build** (npm, pip, Docker-Basisimages). Verbindungen gehen im Betrieb nur zu deinen eigenen Diensten: Domänencontroller, Dateiserver, SMTP und ggf. Exchange
- Die Anwendung läuft nur über HTTPS (siehe oben). Am besten ein eigenes Zertifikat hinterlegen und `LDAP_ALLOW_PLAIN` auf `false` lassen (Standard)
- Operatoren nur die Rechte geben, die sie brauchen (Delegierung auf einzelne OUs)
- Der Ordner `data/` enthält das **SMTP-Passwort im Klartext** und eventuell feste Template-Passwörter. Rechte einschränken (`chmod 700 data`) und Sicherungen schützen
- Benachrichtigungs-Mails enthalten bei Onboarding und Passwort-Reset das neue Passwort im Klartext und gehen an den ausführenden Mitarbeiter. Die Mails für Offboarding, Passwort-Reset, Benutzerverwaltung und Löschen lassen sich in den SMTP-Einstellungen einzeln abschalten. Die Onboarding-Mail wird gesendet, sobald SMTP aktiviert ist. Wenn das nicht gewünscht ist, SMTP nicht aktivieren
- Die Anwendung schützt vor Passwort-Raten durch eine zeitweise Sperre je Benutzer und IP (Standard: 5 Versuche, 5 Minuten). Eine Kontensperre im AD ist davon unabhängig, plane die AD-Richtlinie entsprechend
- Die Löschfunktion ist Administratoren vorbehalten (Menü ausgeblendet, Server prüft die Rolle). Dateiserver-Zugriffe laufen mit den Rechten des angemeldeten Administrators. Gelöschte Dateien lassen sich nicht wiederherstellen. Plane Sicherungen bzw. Schattenkopien auf dem Dateiserver ein
- **Kein root im Container:** Die Anwendung läuft als Benutzer 10001 ohne Linux-Capabilities und ohne die Möglichkeit, Rechte hinzuzugewinnen (`no-new-privileges`). `data/` gehört diesem Benutzer und ist nur für ihn lesbar (`update.sh` setzt das)
- Das Image enthält keine Daten aus `data/` (`.dockerignore`). Pushe es trotzdem nicht in öffentliche Registrys

---

## 10. Fehlersuche

| Meldung / Symptom | Ursache und Lösung |
|---|---|
| *Domain Controller … nicht erreichbar* | Port 636 vom Docker-Host nicht erreichbar, Firewall oder falsche `AD_DC_IP`. Test: `openssl s_client -connect DC:636` (siehe [Abschnitt 5](#5-active-directory-vorbereiten)). Bei einem Namen: DNS prüfen |
| *LDAP-Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.* | Benutzername oder Passwort falsch, Konto gesperrt oder deaktiviert. Ein Versuch pro Anmeldung zählt gegen die AD-Kontosperre |
| *Zugriff verweigert: Sie müssen Mitglied der Gruppe …* | Der Benutzer ist weder Administrator noch Operator. Gruppenmitgliedschaft prüfen. Bei `CUSTOM_OPERATOR_GROUP` zählt der **sAMAccountName**. Neue Mitgliedschaften gelten nach einer neuen Anmeldung |
| *SMTP-Server … nicht erreichbar* / Mails gehen nicht raus | Servername und Port in den SMTP-Einstellungen prüfen und ob Netzwerk bzw. Firewall die Verbindung vom Docker-Host zum Mailserver erlauben. Danach mit *Test-Mail senden* prüfen |
| *Zu viele fehlgeschlagene Anmeldungen* | Temporäre Sperre der Anwendung (HTTP 429). Etwa 5 Minuten warten |
| *Passwort setzen fehlgeschlagen* | Das Passwort erfüllt die Richtlinie nicht, die Verbindung ist nicht per LDAPS verschlüsselt (Port 636 prüfen, `LDAP_ALLOW_PLAIN=false`) oder dem Benutzer fehlen Rechte auf der OU |
| Listen sind leer | Für das Modul sind noch keine Quell-OUs gewählt ([Abschnitt 6](#6-ersteinrichtung-in-der-oberfläche)) oder das Konto liegt nicht in diesen OUs |
| *Das Konto liegt nicht in einer … freigegebenen Quell-OU* | Das Ziel liegt außerhalb der konfigurierten OUs. Als Administrator die OUs erweitern |
| Aktion schlägt mit *insufficientAccessRights* fehl | Dem angemeldeten Benutzer fehlen Rechte im AD auf der OU (Delegierung, [Abschnitt 5](#5-active-directory-vorbereiten)) |
| Zertifikatsfehler (mit `LDAP_CA_FILE`) | Falsche CA-Datei oder `AD_DC_IP` ist nicht der Name aus dem Zertifikat |
| Oberfläche ohne Formatierung oder Icons | Das Image wurde ohne lokale Dateien gebaut. In den Logs steht *„Lokale Assets … fehlen"*. Neu bauen mit `docker compose build --no-cache` |
| Änderung von `AD_DOMAIN` oder `AD_DC_IP` wirkt nicht | Prüfen, ob `data/config.json` existiert. Sie hat Vorrang und muss dann angepasst oder gelöscht werden |
| *Sitzung ungueltig - bitte neu anmelden.* | Das Passwort des Benutzers wurde im AD geändert oder die Sitzung ist abgelaufen |
| *Dieses Konto ist geschützt ...* (403) beim Offboarding oder Löschen | Das Konto ist Mitglied einer privilegierten Gruppe (z. B. Domänen-Admins). Beabsichtigter Schutz. Soll es wirklich bearbeitet werden, zuerst die Mitgliedschaft im AD entfernen |
| Onboarding-Warnung *Postfach konnte nicht angelegt werden* | Meldung lesen: *Anmeldung abgelehnt* → Anmeldeart ändern (NTLM) oder Rolle *Mail Recipients* prüfen. *Nicht erreichbar* → Servername, Port 443 und Firewall vom Container zum Exchange-Server. *Zertifikat* → Zertifikat vertrauen oder die Prüfung bewusst abschalten. Konto ist angelegt, Postfach in Exchange nachholen |
| Wiederherstellen: *Die OU … gibt es nicht mehr* | Im Wiederherstellen-Dialog eine andere OU wählen |
| Zeiten in den Berichten stehen in UTC | `TZ` fehlt in der `.env` oder das Image ist alt. `TZ=Europe/Berlin` setzen und neu bauen (`docker compose up -d --build`) |
| Löschen: *Seit der Simulation hat sich etwas geändert* | Zwischen Simulation und Löschen hat sich der Zustand verändert (z. B. ein Benutzer hat sich angemeldet und ein Profil angelegt). Nichts wurde gelöscht. Simulation wiederholen |
| Löschen: *Nicht alle Ordner konnten gelöscht werden* | Meist gesperrte Dateien (Benutzer noch angemeldet, Virenscanner) oder fehlende Löschrechte. Das AD-Konto bleibt bestehen. Fehlerdetails in der Ergebnisliste, danach Simulation wiederholen |
| Löschen-Simulation: *Dateiserver nicht erreichbar* | Port 445 vom Container zum Dateiserver gesperrt oder Servername im Pfad falsch. Prüfen mit dem Verbindungstest auf der Seite |
| Löschen-Simulation: *Anmeldung am Dateiserver fehlgeschlagen* | Der Server lehnt NTLM mit den Zugangsdaten des Administrators ab (Konto ohne Zugriff auf die Freigabe, SMB-Signing/NTLM-Richtlinie) |
| Löschen-Simulation: *Kein Zugriff* auf einen Profilordner | Der Administrator hat auf dem Ordner keine Rechte, typisch bei servergespeicherten Profilen. GPO zum Hinzufügen der Administratorgruppe oder Freigabe-/NTFS-Rechte prüfen |
| Löschen: Datei oder Ordner *ist in Benutzung (gesperrt)* | Eine Datei ist noch geöffnet (Benutzer angemeldet, Virenscanner, Indexdienst). Sitzung auf dem Server beenden (`Get-SmbOpenFile | Close-SmbOpenFile`) oder warten, danach Simulation wiederholen. Eine Besitzübernahme hilft hier nicht |
| Löschen: *Besitzübernahme fehlgeschlagen* | Dem Administrator fehlt auf dem Server das Recht *Eigentum an Dateien oder Objekten übernehmen*, oder der Ordner liegt auf einem Laufwerk, das keine NTFS-Rechte kennt |
| Löschen-Simulation: Profilordner wird nicht gefunden | Die Endung stimmt nicht (z. B. `.V6` statt `.V2`) oder der Ordner liegt nicht unter einem eingetragenen Basispfad |
| Build bricht mit `"/samonboarding/web": not found` ab | Der Ordner `samonboarding/` liegt nicht neben dem `Dockerfile` |

---

## 11. Entwicklung

### Struktur

```
app.py                      Einstiegspunkt für uvicorn (app:app), importiert nur samonboarding.main
samonboarding/
  main.py                   baut die FastAPI-App: Router einhängen, Fehlerbehandlung, Sicherheits-Header
  config.py                 Umgebungsvariablen, Pfade, Standardwerte, VERSION
  storage.py                JSON-Dateien lesen/schreiben (atomar, mit Sperre)
  audit.py                  audit(...) und audited(...): Änderungen in die Berichte schreiben
  reports.py                Berichte in SQLite (data/reports.db): Änderungen, Protokoll, Suche, Löschen, Übernahme audit.log
  tls.py                    HTTPS-Zertifikat: prüfen (PFX/PEM/DER), speichern, im laufenden Betrieb tauschen, selbstsigniert erzeugen
  routers/certificate.py    Seite "Zertifikat": anzeigen, hochladen, selbstsigniert erzeugen (nur Admins)
  serve.py                  Start nur über HTTPS (python -m samonboarding.serve)
  errors.py                 AdError, DcUnreachable
  dn.py                     DN-/Filter-Hilfen (Escaping, Zerlegen, Vergleichen)
  ldap_client.py            Verbindung, Suche, Fehlerprüfung, Row-Objekte, Sortierung
  sessions.py               Sitzungen, Login-Sperre
  permissions.py            Rollenprüfung, Prüfung der freigegebenen OUs
  naming.py                 Passwörter, Namensmakros, Ländercodes
  models.py                 Pydantic-Modelle der Anfragen
  mailer.py                 E-Mail-Vorlage und SMTP-Versand
  fileshare.py              UNC-Pfadprüfung, Zielordner bestimmen, Ordner-Scan, Löschen, SMB-Zugriff (smbprotocol)
  offboard_store.py         gespeicherter Zustand vor dem Offboarding (SQLite, data/offboarding.db)
  adguid.py                 objectGUID lesen und suchen (Konten/Gruppen nach Umbenennen wiederfinden)
  listcache.py              Kontolisten je Sitzung kurz im Arbeitsspeicher (60 s, bei jeder Änderung geleert)
  references.py             Verweise auf OUs/Gruppen in den Einstellungen prüfen und nach Umbenennen anpassen
  routers/references.py     /api/references (Prüfung) und /api/references/repair (nur Admins)
  acl.py                    Windows-Sicherheitsdeskriptoren lesen/ändern (Besitz, Zugriffseintrag)
  routers/                  je Funktionsbereich ein Modul (auth, settings, usermgmt, offboarding, restore,
                            pwdreset, deletion, infrastructure, templates, onboarding, ui)
  web/index.html            komplette Oberfläche (HTML + JavaScript)
  web/theme.json            Farben und Schriften der Oberfläche (für den Docker-Build)
  web/i18n.json             englische Texte (Oberfläche, Meldungen, Mails)
  web/manual/               Handbuch (HANDBUCH.md, MANUAL.en.md) - erscheint in der Oberfläche unter Hilfe → Handbuch
  i18n.py                   Übersetzer auf dem Server (Mails) und Sprache je Anfrage (Header X-UI-Lang)
  routers/privacy_info.py   Datenschutz-Fenster: Fristen (/api/privacy-info) und Auskunft für Admins (/api/privacy/report)
  privacy.py                Datenschutz: Aufbewahrungsfristen (täglich), Auskunft (python -m samonboarding.privacy)
DATENSCHUTZ.md              Datenschutz-Dokumentation (DSGVO), englisch: DATA-PROTECTION.en.md
Dockerfile                  Stufe 1 baut Tailwind-CSS, Schriften (Manrope, JetBrains Mono) und Font Awesome, Stufe 2 ist die App
tailwind.config.js          Tailwind scannt samonboarding/web/*.html, Farben und Schriften aus web/theme.json
tests/                      Unit-Tests und Szenarien (siehe Tests)
pyproject.toml              Konfiguration von ruff und pytest
requirements-dev.txt        Pakete zum Testen (exakte Versionen)
requirements.in             direkte Python-Pakete; requirements.txt ist die exakte Sperrliste
package.json                npm-Pakete für den CSS-Build (exakt), package-lock.json entsteht mit sh update.sh
images.lock                 Basis-Images (Python, Node) mit fester Version bzw. Digest
update.sh                   Sichern, bauen, neu starten, Status prüfen; --lock schreibt die Versionen neu fest
```

### Neue Funktion hinzufügen

1. Neue Datei `samonboarding/routers/<name>.py` mit `router = APIRouter()` und den Endpunkten anlegen
2. In `samonboarding/main.py` importieren und in die Liste der Router aufnehmen
3. Gemeinsame Helfer (LDAP, DN, Berechtigungen) aus den vorhandenen Modulen importieren
4. Neue Aktionen mit `audited(...)` in die Berichte schreiben und Rechte serverseitig prüfen (`require_admin`, `require_user_in_ous`)
5. Neue Texte auf Deutsch schreiben und die englische Fassung in `web/i18n.json` ergänzen (`exact` für feste Texte, `patterns` mit `{0}` für Texte mit Werten). AD-Daten in der Oberfläche mit `nt(...)` bzw. `translate="no"` ausgeben, damit sie nie übersetzt werden

### Hinweise

- Neue **Tailwind-Klassen** in `web/index.html` brauchen einen neuen Image-Build (`docker compose up -d --build`), weil das CSS beim Build aus der HTML-Datei erzeugt wird
- Änderungen an **Python-Code** brauchen einen neuen Image-Build (`sudo sh update.sh`). Der Code steckt im Image und wird nicht vom Host eingebunden – so bringt ein zurückgeholtes Image beim Zurückrollen auch seinen eigenen Code mit
- Die Python-Pakete sind bewusst minimal: `fastapi`, `uvicorn`, `ldap3`, `pydantic`, für die Dateiserver-Funktionen `smbprotocol` und für das Exchange-Postfach `pypsrp`

### Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # alle Tests
ruff check . && ruff format --check .
```

| Datei | Prüft |
|---|---|
| `tests/test_acl.py` | Windows-Sicherheitsdeskriptoren (SID, ACE, Einfügen vor geerbten Einträgen, defekte Daten) |
| `tests/test_protection.py` | Schutz privilegierter Konten (SIDs aus Rohdaten, verschachtelte Gruppen, RID 500/502), Erkennung Samba/Windows und Exchange/Entra-Hinweis |
| `tests/test_exchange.py` | Exchange-Einstellungen prüfen, Aufrufe an die Exchange-Verwaltungsshell (mit Ersatzmodulen für `pypsrp`), Fehlermeldungen |
| `tests/test_fileshare.py` | UNC-Pfadprüfung, Zielordner, Scan, Löschen mit Verknüpfungen und Besitzübernahme, Fehlerabbildung, Basisordner anlegen |
| `tests/test_smb_requests.py` | Baut Berechtigungs-Anfragen mit den echten `smbprotocol`-Klassen (ohne Server). Wird ohne `smbprotocol` übersprungen |
| `tests/test_ui.py` | Oberflächenlogik (JavaScript in `index.html`) unter Node.js mit Fake-DOM: Auswahl, Sammel-Simulation, Passwort-/Anzahl-Bestätigung, Fortschritt, Navigation, mobiles Menü, Meldungen, Wiederherstellen-Dialog, Sprachumschaltung, Laden nur des geöffneten Bereichs. Wird ohne Node.js übersprungen |
| `tests/test_adguid.py` | `objectGUID` lesen (Rohbytes) und als LDAP-Filter schreiben |
| `tests/test_i18n.py` | Englisch: Wörterbuch, jede feste Fehlermeldung der API übersetzt, Mails in der gewählten Sprache |
| `tests/test_hardening.py` | Sicherheitsprüfung: Ordnername passt zum Konto, Mail-Werte (Passwort) werden nie übersetzt, Absendername, Dateirechte 0600, Exchange basic nur mit HTTPS, Eingaben, DN-Sonderformen, Rollen-SIDs |
| `tests/test_certificate.py` | Eigenes Zertifikat: PFX mit Kette, PEM/DER, verschlüsselter Schlüssel, falsche Paare, abgelaufen, kurze Schlüssel, Speichern mit `.prev`, Austausch im laufenden Betrieb, Ablaufwarnung, API nur für Admins |
| `tests/test_https_reports.py` | Zertifikat erzeugen/wiederverwenden, Start nur mit TLS, HTTP abgewiesen, HSTS nur mit eigenem Zertifikat, 30 Minuten Inaktivität, Berichte-API (nur Admins, Löschen mit Passwort und Nachweis) |
| `tests/test_privacy.py` | Berichte in SQLite (Fristen 365/90 Tage, Suche, Seiten, `secure_delete`, Übernahme des alten audit.log), Wiederherstellungs-Einträge, Auskunft |
| `tests/test_manual.py`, `tests/ui/manual.test.js` | Handbuch: nur mit Anmeldung, beide Sprachen, sichere Darstellung (kein HTML, nur interne oder https-Links), alle Einträge im Inhaltsverzeichnis führen zu einer Überschrift |
| `tests/test_assets.py` | Farben/Schriften (`theme.json`), Einbindung nur lokal, keine Internet-Adressen, CSP, Schriften im Dockerfile |
| `tests/test_scenarios.py` | Startet die Szenarien in `tests/scenarios/`: Anmeldung und Rollen, Onboarding, Offboarding, Gruppen, Einstellungen, Löschen (Simulation, Ausführung, Besitzübernahme, Mail), Wiederherstellen nach dem Offboarding, Templates, Sortierung, umbenannte/verschobene OUs und Gruppen |

Die Szenarien laufen gegen ein **simuliertes AD und einen simulierten Dateiserver** und brauchen dafür keine installierten Pakete (kleine Ersatzmodule in `tests/scenarios/stubs`). Einzeln starten: `python tests/scenarios/scenario_deletion.py`. Echte SMB-Verbindungen und echte Dateirechte testen sie **nicht**; das ist nur auf einem Testserver möglich (siehe Abschnitt Konten löschen, erst mit einem unwichtigen Konto ausprobieren). Bei jedem Push laufen dieselben Prüfungen in GitHub Actions (`.github/workflows/image.yml`); nur wenn alles besteht, wird das Image gebaut.

## Lizenz

SAMONBOARDING ist freie Software unter der **GNU Affero General Public License, Version 3 oder neuer** (AGPL-3.0-or-later), siehe [LICENSE](LICENSE). Du darfst das Programm nutzen, weitergeben und verändern. Wer eine **veränderte** Version anderen anbietet – auch nur über das Netzwerk als Webanwendung –, muss diesen Nutzern den Quellcode der veränderten Version zugänglich machen (Abschnitt 13 der Lizenz). Die Anmeldeseite verlinkt deshalb auf den Quellcode; wer eine eigene Version betreibt, passt den Link in `samonboarding/web/index.html` auf sein eigenes Repository an. Es gibt keine Gewährleistung (Abschnitte 15 und 16).

Die eingebundenen Pakete (FastAPI, ldap3, Tailwind CSS, Font Awesome, Schriften usw.) haben ihre eigenen Lizenzen.
