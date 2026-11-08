# SAMONBOARDING – Datenschutz (DSGVO)

[English version](DATA-PROTECTION.md)

Dieses Dokument beschreibt, welche personenbezogenen Daten SAMONBOARDING verarbeitet, wo sie liegen, wie lange sie aufbewahrt werden und welche technischen Maßnahmen eingebaut sind. Es ist als Grundlage für euren Eintrag im **Verzeichnis von Verarbeitungstätigkeiten** (Art. 30 DSGVO) gedacht.

> **Wichtig:** Eine Software allein ist nie „DSGVO-konform“. Konform ist die *Verarbeitung* beim Verantwortlichen, also bei euch. SAMONBOARDING liefert die technischen Voraussetzungen: Datensparsamkeit, Speicherbegrenzung, keine Weitergabe an Dritte, Zugriffsschutz und Auskunft. Die organisatorischen Punkte in [Abschnitt 6](#6-was-ihr-als-verantwortliche-noch-tun-müsst) bleiben eure Aufgabe. Das ist keine Rechtsberatung. Stimmt den Einsatz mit eurem Datenschutzbeauftragten ab.

---

## 1. Kurzfassung

| Frage | Antwort |
|---|---|
| Zweck | Anlegen, Ändern, Deaktivieren, Wiederherstellen und Löschen von Benutzerkonten im eigenen Active Directory |
| Rechtsgrundlage (typisch) | Art. 6 Abs. 1 lit. b DSGVO / § 26 BDSG (Durchführung des Beschäftigungsverhältnisses), für die Berichte Art. 6 Abs. 1 lit. f bzw. Art. 32 DSGVO (Nachweis und Sicherheit) |
| Wo laufen die Daten? | Im eigenen Netz: Container, Domänencontroller, Dateiserver, Exchange. Dazu euer SMTP-Server, ggf. bei einem externen Mail-Anbieter |
| Dritte / Drittland | **Keine.** Keine Cloud, keine CDNs, kein Google Fonts, keine Telemetrie, keine Update-Prüfung |
| Internetzugang | Nicht nötig. Die Anwendung baut von sich aus keine Verbindungen ins Internet auf, sie verbindet sich nur mit DC, Dateiserver, eurem SMTP- und Exchange-Server. Wer den Container zusätzlich abschotten will, beschränkt den ausgehenden Verkehr in der Firewall des Hosts, Routers oder der Synology |
| Speicherdauer | Berichte (Änderungen) 365 Tage, Protokoll 90 Tage, Wiederherstellungs-Einträge 180 Tage (einstellbar), danach automatische Löschung. Manuell löschen unter *Berichte* |
| Verbindung | Nur HTTPS (TLS 1.2/1.3). Sitzungen enden bei Abmeldung, nach 30 Minuten Inaktivität, spätestens nach 12 Stunden oder beim Neustart |
| Cookies | Nur ein technisch notwendiges Sitzungs-Cookie, kein Tracking, kein Einwilligungsbanner nötig |

---

## 2. Welche Daten verarbeitet werden

**Betroffene Personen:** Beschäftigte, deren Konten verwaltet werden, und die Administratoren bzw. Operatoren, die die Anwendung bedienen.

| Daten | Wo | Zweck |
|---|---|---|
| Kontodaten im AD (Name, Benutzername, E-Mail, Abteilung, Firma, Telefon, Manager, OU, Gruppen; in der Offboarding-Liste zusätzlich die ungefähre letzte Anmeldung `lastLogonTimestamp` – nur angezeigt, nie gespeichert oder protokolliert; die Startseite bekommt davon nur Anzahlen, keine Namen) | **Im Active Directory**, nicht in der Anwendung. SAMONBOARDING liest und schreibt sie nur dort | Kontoverwaltung |
| Berichte – Änderungen: Zeitpunkt, ausführender Benutzer, Aktion, Zielkonto (DN), Ergebnis, ggf. Fehlermeldung. **Keine Passwörter** | `data/reports.db` (SQLite, Tabelle `audit`) | Nachvollziehbarkeit, Sicherheit |
| Berichte – Protokoll: Meldungen des Programms ab Stufe *Info* (z. B. Verbindungsfehler); kann Kontonamen oder Pfade enthalten. **Keine Passwörter, keine IP-Adressen je Zugriff** | `data/reports.db` (Tabelle `applog`) | Betrieb, Fehlersuche |
| Wiederherstellungs-Einträge: Benutzername, Name, frühere OU, Gruppen, ob aktiv, wann und von wem offgeboardet. **Keine Passwörter** | `data/offboarding.db` (SQLite) | Rückgängig machen eines versehentlichen Offboardings |
| Anmeldesitzung inkl. Passwort des angemeldeten Admins (für die Anmeldung am DC mit seinen eigenen Rechten) | **Nur im Arbeitsspeicher**, nie auf der Festplatte. Weg nach Abmelden, 30 Minuten ohne Aktivität oder Neustart | Zugriff mit den Rechten des Benutzers |
| Konfiguration (SMTP-Zugang, Templates, OUs) | `data/*.json` | Betrieb |
| Merkliste der Verweise: Pfad (DN) und objectGUID der OUs und Gruppen, die in den Einstellungen und Templates gewählt sind. **Keine Konten, keine Personendaten** | `data/verweise.json` | Hinweis, wenn eine OU/Gruppe im AD umbenannt, verschoben oder gelöscht wurde |
| Kontolisten der Module und AD-Struktur (Namen/DNs für die Auswahllisten) (Zwischenspeicher, damit der Wechsel zwischen den Bereichen schnell geht) | **Nur im Arbeitsspeicher**, je Sitzung; nach 60 Sekunden ungültig und beim nächsten Zugriff entfernt, sofort geleert bei jeder Änderung, beim Abmelden und beim Neustart. **Keine Kopie in einer Datenbank** | Bedienung |
| Benachrichtigungs-Mails (bei Onboarding und Passwort-Reset mit neuem Passwort) | Eigener Mailserver, Postfach des ausführenden Mitarbeiters | Übergabe der Zugangsdaten |
| Spracheinstellung DE/EN, zuletzt gelesene Version der Neuigkeiten und Zeitpunkt der letzten Aktivität (für die Abmeldung bei Leerlauf) | `localStorage` im Browser | Bedienung |
| Container-Protokoll (Fehler, Hinweise) | Docker-Log, rotiert (3 × 10 MB) | Betrieb / Fehlersuche |

---

## 3. Speicherdauer und automatische Löschung

| Daten | Standard | Einstellung (`.env`) |
|---|---|---|
| Berichte – Änderungen | 365 Tage | `AUDIT_RETENTION_DAYS=365` |
| Berichte – Protokoll | 90 Tage | `LOG_RETENTION_DAYS=90` |
| Wiederherstellungs-Einträge | 180 Tage nach dem Offboarding | `OFFBOARD_RETENTION_DAYS=180` |
| Sitzungen | Abmeldung, 30 Minuten ohne Aktivität, spätestens 12 Stunden oder Neustart | `SESSION_IDLE_MINUTES=30`, `SESSION_MAX_HOURS=12` |
| Container-Protokoll | max. 30 MB, älteres wird überschrieben | `logging:` in docker-compose.yml |

- Die Bereinigung läuft **beim Start und danach einmal täglich**. Ältere Einträge werden endgültig entfernt; die Datenbank überschreibt gelöschte Einträge (`secure_delete`), sie lassen sich nicht wiederherstellen.
- **Manuell löschen:** Administratoren können in der Oberfläche unter **Berichte** Änderungen oder Protokoll vorzeitig löschen (älter als 30/90/180 Tage oder alles), bestätigt mit dem eigenen Passwort. Das Löschen selbst wird vermerkt.
- Ein `audit.log` aus älteren Versionen wird beim ersten Start in die Datenbank übernommen und danach gelöscht.
- `0` bedeutet *unbegrenzt*. Das ist für die Speicherbegrenzung nach Art. 5 Abs. 1 lit. e DSGVO nicht zu empfehlen.
- Ein Wiederherstellungs-Eintrag verschwindet außerdem sofort, wenn das Konto wiederhergestellt oder gelöscht wird oder ein Administrator ihn verwirft. Die Frist steht auch in der Oberfläche über der Liste.
- Sofort bereinigen (z. B. nach dem Verkürzen einer Frist):
  ```bash
  docker compose exec samonboarding python -m samonboarding.privacy bereinigen
  ```
- **Backups:** Wenn `data/` gesichert wird, gelten die Fristen auch für die Sicherungen. Plant die Aufbewahrung der Backups passend. Das Programm legt vor jedem Versionswechsel selbst eine Sicherung in `data/backups/` an (nur für den Programmbenutzer lesbar) und behält nur die letzten 10. Diese Sicherungen enthalten auch Berichte und Protokoll: Die tägliche Bereinigung löscht sie, sobald sie älter als die längste Frist sind (dann ist alles darin abgelaufen); ist eine Frist `0`, bleiben sie. Ältere Sicherungen in `backups/` neben der `docker-compose.yml` stammen von `update.sh` bis Version 1.48 und können nach Prüfung gelöscht werden.

---

## 4. Technische und organisatorische Maßnahmen (Art. 32 DSGVO) – was eingebaut ist

**Zugriffskontrolle**
- Die Anwendung läuft im Container nicht als root, sondern als eigener Benutzer ohne Sonderrechte; nur er kann `data/` lesen.
- Anmeldung nur mit AD-Konto. Jede Aktion läuft mit den Rechten des angemeldeten Benutzers am DC, nicht mit einem Dienstkonto.
- Rollen: Operator oder Administrator. Löschen und Verwerfen ist nur Administratoren erlaubt, und der Server prüft das.
- Domänen-Admin-Konten sind vor Offboarding und Löschung geschützt.
- Sperre nach wiederholten Fehlanmeldungen (Standard 5 Versuche / 5 Minuten).
- Sitzungs-Cookie mit `HttpOnly`, `SameSite=Strict` und `Secure`; es endet mit dem Browser. Sitzungen liegen nur im Arbeitsspeicher und enden nach 30 Minuten ohne Aktivität (Server und Oberfläche).

**Übertragung**
- LDAPS zum DC; mit `LDAP_CA_FILE` wird das Zertifikat geprüft. Unverschlüsseltes LDAP ist standardmäßig verboten (`LDAP_ALLOW_PLAIN=false`).
- SMB zum Dateiserver mit Signierung. Verschlüsselt wird, wenn der Dateiserver es verlangt; das lässt sich auf der Freigabe einschalten (`Set-SmbShare -EncryptData $true` bzw. `smb encrypt = required`).
- SMTP mit STARTTLS oder TLS. Im Modus *Auto* wird STARTTLS genutzt; bietet der Server es nicht an, wird **nichts** gesendet (auch nicht, wenn ein Angreifer STARTTLS unterdrückt). Unverschlüsselt geht es nur mit dem ausdrücklich gewählten Modus *Ohne Verschlüsselung* für ein internes Relay – und dann nie mit SMTP-Passwort.
- **Nur HTTPS** (TLS 1.2/1.3, moderne Verfahren). Es gibt keinen HTTP-Port. Eigenes Zertifikat (Upload in der Oberfläche unter *Zertifikat* oder Dateien in `data/tls/`), sonst selbstsigniert; mit eigenem Zertifikat zusätzlich HSTS.

**Datensparsamkeit**
- Keine Passwörter in Berichten, Datenbanken oder Container-Protokoll. Einzelne Zugriffe (IP-Adressen) werden nicht protokolliert.
- Keine Kopie der AD-Daten. Die Anwendung speichert nur das Nötigste für Nachweis und Wiederherstellung.

**Trennung vom Internet**
- Keine externen Ressourcen. Ein Content-Security-Policy-Header verbietet dem Browser fremde Server.
- Die Anwendung baut von sich aus keine Verbindungen ins Internet auf (keine CDNs, keine Telemetrie, keine Update-Prüfung). IPv6 ist für das Container-Netz abgeschaltet.
- Security-Header: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` und `Referrer-Policy: same-origin`.

**Speicherbegrenzung**
- Automatische Löschung nach Fristen ([Abschnitt 3](#3-speicherdauer-und-automatische-löschung)).

**Nachvollziehbarkeit**
- Berichte (Änderungen) mit Zeitpunkt (Ortszeit mit Zeitzone), Benutzer, Aktion und Ergebnis; nur für Administratoren einsehbar.

**Vorsicht beim Löschen**
- Löschen erst nach Simulation und Bestätigung mit dem eigenen Passwort.
- Offboarding lässt sich rückgängig machen.

---

## 5. Rechte der betroffenen Personen

**Auskunft (Art. 15):** Alles, was SAMONBOARDING selbst über ein Konto gespeichert hat, also Änderungen, Protokoll-Treffer und Wiederherstellungs-Einträge, laden Administratoren in der Oberfläche unter *Datenschutz* als JSON-Datei herunter. Das wird in den Berichten vermerkt. Alternativ gibt es diesen Befehl:

```bash
docker compose exec samonboarding python -m samonboarding.privacy auskunft mustermann > auskunft-mustermann.json
```

Die Suche läuft als Textsuche nach dem Benutzernamen. Bitte prüft das Ergebnis vor der Herausgabe und schwärzt Einträge zu anderen Personen. Die Kontodaten im AD selbst sind nicht enthalten. Diese holt ihr wie gewohnt aus dem AD.

**Berichtigung (Art. 16):** Die Daten werden direkt im AD korrigiert, etwa über die Benutzerverwaltung von SAMONBOARDING.

**Löschung (Art. 17):** Die Löschfunktion entfernt das AD-Konto, die Profil- und Basisordner sowie den Wiederherstellungs-Eintrag. Einträge in den Berichten bleiben bis zum Ende ihrer Frist bestehen (oder bis sie unter *Berichte* manuell gelöscht werden), weil sie dem Nachweis dienen (vgl. Art. 17 Abs. 3). Ob diese Abwägung für euch passt, entscheidet ihr mit eurem DSB. Die Frist lässt sich verkürzen.

---

## 6. Was ihr als Verantwortliche noch tun müsst

- [ ] **Verzeichnis von Verarbeitungstätigkeiten** (Art. 30): Eintrag anlegen. Die Vorlage unten hilft dabei.
- [ ] **Fristen festlegen und dokumentieren** (Löschkonzept). Die Standardwerte ggf. anpassen, auch für Backups von `data/`.
- [ ] **Betriebsrat beteiligen**, falls vorhanden: Die Berichte zeichnen auf, was Administratoren tun. Das kann als technische Einrichtung zur Leistungs- und Verhaltenskontrolle gelten (§ 87 Abs. 1 Nr. 6 BetrVG).
- [ ] **Eigenes Zertifikat** unter *Zertifikat* hochladen (statt des selbstsignierten) und `LDAP_ALLOW_PLAIN` auf `false` lassen.
- [ ] **Rechte auf `data/` einschränken** (`chmod 700 data`). Dort liegt u. a. das SMTP-Passwort im Klartext.
- [ ] **Passwörter in Mails abwägen:** Onboarding- und Passwort-Reset-Mails enthalten das neue Passwort. Gehen sie nur intern an den ausführenden Mitarbeiter, ist das meist vertretbar. Alternativ SMTP nicht aktivieren und das PDF bzw. die Kopierfunktion nutzen.
- [ ] **Berechtigungen** für Operatoren nur auf die nötigen OUs delegieren.
- [ ] **Externer Mail-Anbieter** für die Benachrichtigungen? Dann einen Vertrag zur Auftragsverarbeitung (Art. 28) mit dem Anbieter abschließen bzw. prüfen und ihn im Verzeichnis der Verarbeitungstätigkeiten als Empfänger eintragen.
- [ ] Den Einsatz mit eurem **Datenschutzbeauftragten** abstimmen.

### Vorlage: Eintrag im Verzeichnis von Verarbeitungstätigkeiten

| Feld | Inhalt |
|---|---|
| Bezeichnung | Verwaltung von Benutzerkonten im Active Directory (SAMONBOARDING) |
| Zweck | Ein- und Austritt von Beschäftigten, Pflege von Konten, Wiederherstellung, Löschung |
| Rechtsgrundlage | Art. 6 Abs. 1 lit. b DSGVO i. V. m. § 26 BDSG; Berichte: Art. 6 Abs. 1 lit. f, Art. 32 DSGVO |
| Betroffene | Beschäftigte, externe Mitarbeitende mit Konto, IT-Administratoren |
| Datenkategorien | Stammdaten (Name, Benutzername, E-Mail, Abteilung, Firma, Telefon, Vorgesetzter), Gruppen und OU, Protokolldaten |
| Empfänger | Interne IT. Benachrichtigungen an den ausführenden Mitarbeiter (über euren Mailserver bzw. Mail-Anbieter). Sonst keine Dritten |
| Drittland | Keins |
| Löschfristen | Änderungen __ Tage, Protokoll __ Tage, Wiederherstellungs-Einträge __ Tage, Sitzungen 30 Minuten Inaktivität (siehe Abschnitt 3) |
| TOM | Siehe Abschnitt 4 |
