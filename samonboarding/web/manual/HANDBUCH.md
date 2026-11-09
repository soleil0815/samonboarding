# SAMONBOARDING – Handbuch

Dieses Handbuch erklärt die Bedienung der Oberfläche: für **Operatoren**, die täglich Konten anlegen und pflegen, und für **Administratoren**, die die Anwendung einrichten. Installation und technische Details stehen in der README.

## Inhalt

1. [Überblick](#1-überblick)
2. [Anmelden und Sitzung](#2-anmelden-und-sitzung)
3. [Rollen: Was darf wer?](#3-rollen-was-darf-wer)
4. [Onboarding: neuen Benutzer anlegen](#4-onboarding-neuen-benutzer-anlegen)
5. [Benutzerverwaltung](#5-benutzerverwaltung)
6. [Passwort zurücksetzen](#6-passwort-zurücksetzen)
7. [Offboarding](#7-offboarding)
8. [Offboarding rückgängig machen](#8-offboarding-rückgängig-machen)
9. [Konten löschen (nur Administratoren)](#9-konten-löschen-nur-administratoren)
10. [Ersteinrichtung (Administratoren)](#10-ersteinrichtung-administratoren)
11. [Templates](#11-templates)
12. [E-Mail-Benachrichtigung](#12-e-mail-benachrichtigung)
13. [Berichte](#13-berichte)
14. [Zertifikat](#14-zertifikat)
15. [Datenschutz](#15-datenschutz)
16. [Betrieb auf dem Server](#16-betrieb-auf-dem-server)
17. [Häufige Fragen und Fehler](#17-häufige-fragen-und-fehler)

---

## 1. Überblick

SAMONBOARDING ist eine Weboberfläche für den Lebenszyklus von Benutzerkonten im Active Directory (Samba AD oder Windows Server AD):

| Menüpunkt | Wofür |
|---|---|
| **Start** | Was steht an? Konten ohne Anmeldung seit 90 Tagen, gesperrte Konten und (für Administratoren) Konten, die bereit zum Löschen sind – ein Klick öffnet die passende Liste. Die Zahlen kommen live vom DC und frischen sich jede Minute selbst auf, solange die Startseite offen ist. Während des Lesens laufen auf den Karten die Sekunden mit; ist das Ergebnis da, zählen die Zahlen hoch |
| **Neuer Mitarbeiter** (Onboarding) | Neues Konto nach einem Template anlegen |
| **Benutzerverwaltung** | Konto in eine andere OU verschieben, Gruppen pflegen |
| **Passwort zurücksetzen** | Neues Passwort setzen, Kontosperre aufheben |
| **Austritt** (Offboarding) | Konto deaktivieren, aus allen Gruppen nehmen, in die Ziel-OU verschieben; rückgängig machen |
| **Konten löschen** | Deaktivierte Konten samt Profil- und Basisordnern endgültig löschen (nur Administratoren) |
| **Templates** | Vorlagen für das Onboarding |
| **E-Mail-Benachrichtigung** | SMTP-Server und welche Mails verschickt werden |
| **AD-Struktur** | Übersicht über OUs und Gruppen |
| **Berichte** | Wer hat wann was getan, Programm-Meldungen (nur Administratoren) |
| **Zertifikat** | HTTPS-Zertifikat hochladen (nur Administratoren) |
| **Neuigkeiten** | Was sich in den installierten Versionen geändert hat. Ein kleiner Punkt zeigt eine neue Version an, ein oranger Punkt ein Sicherheitsupdate |

Die Menüpunkte sind in **Aufgaben** (Start bis Konten löschen) und **Einstellungen** (Templates bis Zertifikat) gruppiert. Zahlen neben einem Menüpunkt zeigen, wie viele Konten dort warten.

**Schnellsuche (Strg + K, am Mac ⌘ + K):** Öffnet ein Suchfeld für Personen und Seiten. Nach Name, Anmeldename oder E-Mail suchen, mit den Pfeiltasten wählen und mit Enter öffnen. Eine Person öffnet sich in der Benutzerverwaltung, schon nach ihr gefiltert. Ist sie dort nicht freigegeben, öffnet sich Austritt oder Passwort zurücksetzen. Ab zwei Zeichen sucht der DC direkt im AD (höchstens 10 Treffer), und zwar nur in den OUs, die für Benutzerverwaltung, Austritt und Passwort zurücksetzen freigegeben sind, mit deinem eigenen AD-Konto. Der Suchtext wird nirgends gespeichert oder protokolliert. Esc schließt die Suche.

Wichtig zu wissen:

- **Jede Aktion läuft mit deinem eigenen AD-Konto.** Die Anwendung hat kein eigenes Dienstkonto. Was du im AD nicht darfst, darfst du auch hier nicht.
- **Nur freigegebene OUs.** Jedes Modul zeigt nur Konten aus den OUs, die ein Administrator für dieses Modul freigegeben hat.
- **Alles wird protokolliert**, ohne Passwörter (siehe [Berichte](#13-berichte)).
- **Sprache:** Unten in der Seitenleiste zwischen Deutsch (DE) und Englisch (EN) umschalten. Die Wahl merkt sich der Browser.
- **Listen und „Aktualisieren“:** Geladen wird nur der Bereich, den du gerade öffnest. Die Kontolisten merkt sich die Anwendung bis zu 60 Sekunden, damit der Wechsel zwischen den Bereichen schnell geht. Nach jeder Änderung über SAMONBOARDING sind die Listen sofort aktuell. Was jemand direkt im AD ändert (z. B. mit RSAT), erscheint beim nächsten Öffnen des Bereichs, spätestens nach 60 Sekunden – oder sofort mit **Konten aktualisieren** bzw. **Neu einlesen**. Vor jeder Aktion prüft die Anwendung ohnehin live am DC.

---

## 2. Anmelden und Sitzung

1. Die Adresse im Browser öffnen, z. B. `https://server:9500`. Bei einem selbstsignierten Zertifikat warnt der Browser beim ersten Mal; ein Administrator kann ein eigenes Zertifikat hinterlegen (siehe [Zertifikat](#14-zertifikat)).
2. Mit dem **AD-Benutzernamen** (z. B. `mmustermann`, ohne Domäne) und dem AD-Passwort anmelden.

Die Sitzung endet

- beim Klick auf **Abmelden**,
- nach **30 Minuten ohne Aktivität** (die Oberfläche meldet das),
- beim Neustart der Anwendung, z. B. nach einem Update,
- spätestens nach **12 Stunden**, auch wenn du durchgehend arbeitest.

Nach mehreren falschen Passwörtern sperrt die Anwendung weitere Versuche für einige Minuten (Standard: 5 Versuche, 5 Minuten). Unabhängig davon gilt die Kontosperr-Richtlinie des AD.

---

## 3. Rollen: Was darf wer?

Die Rolle ergibt sich aus der Gruppenmitgliedschaft im AD. Erkannt wird sie an der festen Kennung (SID) der Gruppe, nicht am Namen.

| | Operator | Administrator |
|---|---|---|
| Wer | Mitglied von *Konten-Operatoren* (Account Operators) oder der eigenen Operator-Gruppe | Mitglied von *Domänen-Admins*, *Organisations-Admins* oder *Administratoren* |
| Onboarding, Benutzerverwaltung, Passwort, Offboarding, Wiederherstellen | ja, in den freigegebenen OUs | ja |
| Einstellungen der Module, Templates | nur ansehen | ja |
| SMTP- und Exchange-Einstellungen | nein | ja |
| Konten löschen, Berichte, Zertifikat | nein | ja |
| Geschützte Konten (z. B. Domänen-Admins) bearbeiten | nein | ja (Offboarding und Löschen: für niemanden) |
| In privilegierte Gruppen aufnehmen | nein | ja |

Neue Gruppenmitgliedschaften gelten nach der nächsten Anmeldung.

**Geschützte Konten** sind Mitglieder (auch verschachtelt) von Domänen-, Schema- und Organisations-Admins, Administratoren und den Operator-Gruppen sowie das integrierte Administratorkonto und `krbtgt`. Sie erscheinen in den Listen mit einem **Schloss**.

---

## 4. Onboarding: neuen Benutzer anlegen

1. Menü **Onboarding** öffnen.
2. **Template** wählen. Rechts siehst du, was das Template tut: Ziel-OU, Aufbau des Benutzernamens, Gruppen.
3. **Vorname** und **Nachname** eingeben. Je nach Template auch die **E-Mail-Adresse** (Pflicht, optional oder gar nicht abgefragt).
4. Auf **Mitarbeiter im Active Directory anlegen** klicken.

Was dabei passiert:

- Der Benutzername wird nach dem Makro des Templates gebildet, z. B. `MUSTERMANNMAX`. Umlaute werden umgesetzt (Ö → OE). Ist der Name vergeben, wird eine Zahl angehängt.
- Das Konto wird zunächst deaktiviert angelegt, das Passwort gesetzt und dann aktiviert. Klappt das Passwort nicht, wird das halbfertige Konto wieder entfernt.
- Gruppen des Templates werden zugewiesen. Klappt das für eine Gruppe nicht, erscheint eine Warnung; das Konto bleibt bestehen.
- Je nach Template wird ein **Exchange-Postfach** angelegt oder ein **Basisordner** auf dem Dateiserver erstellt. Fehler dabei verhindern nie das Konto, sie erscheinen als Hinweis.

Am Ende zeigt ein **Ergebnisfenster** Benutzername, Anmeldename und Passwort. Mit **Kopieren** übernimmst du die Daten, mit **PDF-Zugangsdaten** erzeugst du ein Blatt zum Aushändigen. Das Passwort wird danach nicht mehr angezeigt. Ist die E-Mail-Benachrichtigung aktiv, bekommst du die Zugangsdaten zusätzlich per Mail.

---

## 5. Benutzerverwaltung

Die Tabelle zeigt alle Konten aus den freigegebenen OUs mit ihren Gruppen, alphabetisch sortiert. Über das Suchfeld filtern.

- **Verschieben:** Beim Konto auf **Verschieben** klicken, Ziel-OU wählen, **Verschieben**. Zur Auswahl stehen nur die freigegebenen Ziel-OUs.
- **Gruppen:** Auf **Gruppen** klicken, Haken setzen oder entfernen, **Änderungen speichern**. Zur Auswahl stehen die Gruppen aus den freigegebenen Gruppen-OUs.

---

## 6. Passwort zurücksetzen

1. Menü **Passwort zurücksetzen**, Konto in der Liste suchen, auf **Kennwort zurücksetzen** klicken.
2. Modus wählen:
   - **Automatisches starkes Zufallspasswort** (12 Zeichen, ohne leicht verwechselbare Zeichen wie 0/O oder 1/l/I) oder
   - **manuell eingeben** (zweimal; die Passwortrichtlinie des AD gilt).
3. Optionen:
   - **Benutzer muss Kennwort bei der nächsten Anmeldung ändern** (empfohlen, standardmäßig an)
   - **Sperre des Benutzerkontos aufheben**, wenn das Konto nach Fehlversuchen gesperrt ist
4. **Zurücksetzen** klicken. Das neue Passwort erscheint **einmalig** im Ergebnisfenster.

---

## 7. Offboarding

Beim Offboarding wird ein Konto **deaktiviert**, aus **allen Gruppen entfernt** und in die **Ziel-OU** für ausgeschiedene Mitarbeiter verschoben. Das Passwort bleibt unverändert.

1. Menü **Offboarding**, Konto suchen, beim Konto auf **Offboarding** klicken und bestätigen.
2. **Mehrere auf einmal:** Haken bei bis zu 25 Konten setzen (das Kästchen oben wählt alle sichtbaren) und **Auswahl offboarden** klicken. Vor dem Start erscheint eine Bestätigung mit Anzahl und Namen. Ein Fehler bei einem Konto stoppt die anderen nicht; am Ende steht, was geklappt hat.

Nicht möglich: das eigene Konto und geschützte Konten (mit Schloss).

**Letzte Anmeldung:** Die Spalte zeigt, wann sich das Konto zuletzt angemeldet hat (Datum und „vor … Tagen“, ab 90 Tagen gelb hervorgehoben), oder **nie**. Ein Klick auf die Überschrift sortiert: älteste zuerst, noch ein Klick neueste zuerst, ein dritter Klick wieder nach Namen. Der Wert ist **ungefähr**: Active Directory gleicht ihn nur alle 9–14 Tage zwischen den Domänencontrollern ab. Für die Frage „noch aktiv oder schon lange weg?“ reicht das; „vor 3 Tagen“ kann auch „gestern“ bedeuten.

---

## 8. Offboarding rückgängig machen

Vor jedem Offboarding merkt sich die Anwendung OU, Gruppen und ob das Konto aktiv war. Unten auf der Offboarding-Seite unter **Offgeboardete Konten wiederherstellen**:

1. Beim Konto auf **Wiederherstellen** klicken. Eine **Vorschau** zeigt, was passieren wird. Noch wird nichts verändert.
2. Gibt es die alte OU nicht mehr, wählst du eine andere.
3. **Wiederherstellen** bestätigen: Das Konto kommt in die OU zurück, in seine Gruppen und wird wieder aktiv (war es vorher schon deaktiviert, bleibt es das). Das alte Passwort gilt weiter.

Eine inzwischen gelöschte Gruppe wird übersprungen und gemeldet. Administratoren können einen Eintrag auch **verwerfen**. Die Einträge werden nach einer Frist automatisch gelöscht (Standard 180 Tage, die Seite zeigt die Frist an).

---

## 9. Konten löschen (nur Administratoren)

Hier werden **deaktivierte** Konten **endgültig** gelöscht: das AD-Konto und, wenn eingerichtet, Roamingprofil, Ordnerumleitung und Basisordner auf den Dateiservern. **Es gibt keinen Papierkorb.** Das AD-Konto lässt sich nur über den AD-Papierkorb zurückholen (falls aktiviert), Dateien nur aus der Sicherung.

### Ein Konto löschen

1. In der Liste (Konten aus der OU der deaktivierten Konten) auf **Simulation** klicken. Die Simulation **verändert nichts**. Sie zeigt das AD-Konto und je Ordner Status, Anzahl Dateien und Größe.
2. Sieht alles richtig aus: darunter den **Benutzernamen** eintippen, **dein eigenes Passwort** eingeben und **Endgültig löschen** klicken.
3. Vor dem Löschen wird alles erneut geprüft. Hat sich seit der Simulation etwas geändert, passiert nichts und du simulierst neu. Der Plan gilt 10 Minuten und nur einmal.
4. Zuerst werden die Ordner gelöscht, danach das AD-Konto. Scheitert ein Ordner (z. B. eine noch geöffnete Datei), **bleibt das AD-Konto bestehen**. Ursache beheben und neu simulieren.

### Mehrere Konten löschen

1. Haken setzen (höchstens 25) und **Auswahl simulieren**.
2. Jedes Konto erscheint als **Bereit** oder **Blockiert** (mit Grund). Blockierte werden nie mitgelöscht.
3. Zur Bestätigung die **Anzahl** der bereiten Konten und dein **Passwort** eingeben, dann **Endgültig löschen**.
4. Gelöscht wird im Hintergrund mit Fortschrittsanzeige. Am Ende zeigt eine Tabelle das Ergebnis je Konto.

### Schutzmechanismen

- Nur deaktivierte Konten, nie das eigene, nie geschützte.
- Nur Ordner **unterhalb** der eingetragenen Basispfade, und nur, wenn der Ordnername zum Benutzernamen passt.
- Ordner, die auch bei anderen Konten eingetragen sind, werden ausgeschlossen.
- Verknüpfungen (Junctions, Symlinks) werden nie verfolgt.
- Nach 5 falschen Passwörtern ist das Löschen für etwa 5 Minuten gesperrt.

---

## 10. Ersteinrichtung (Administratoren)

Die Einstellungen stehen in den jeweiligen Menüpunkten in einem Kasten **(Nur Admin)**. OUs und Gruppen wählst du in einem **Baum mit Haken**; mit den Pfeilen auf- und zuklappen, mit dem Suchfeld filtern.

1. **AD-Struktur** öffnen und prüfen, ob OUs und Gruppen erscheinen. Ist die Liste leer, stimmt die Verbindung zum DC nicht.
2. **Offboarding:** Quell-OUs (aus diesen darf offgeboardet werden) und die Ziel-OU für deaktivierte Konten festlegen.
3. **Passwort zurücksetzen:** Quell-OUs festlegen.
4. **Benutzerverwaltung:** Quell-OUs (welche Konten erscheinen), erlaubte Ziel-OUs (wohin verschoben werden darf) und Gruppen-OUs (welche Gruppen zur Auswahl stehen).
5. **Templates:** mindestens ein Template anlegen (siehe [Templates](#11-templates)).
6. **E-Mail-Benachrichtigung** (optional) einrichten und testen.
7. **Konten löschen** (optional): OU der deaktivierten Konten und die Speicherorte mit ihren Basispfaden eintragen, speichern und mit **Verbindung zu den Basispfaden testen** prüfen.
8. Mit einem **Operator-Konto** anmelden und alles einmal mit einem Testbenutzer durchspielen.

Regel: Bei **Quell-OUs** und **Gruppen-OUs** gilt eine gewählte OU **mit allen Unter-OUs**, bei **Ziel-OUs** genau die gewählte OU. Solange für ein Modul keine Quell-OU gewählt ist, bleibt seine Liste leer.

### Wenn OUs oder Gruppen im AD umbenannt oder verschoben werden

Die Einstellungen (Quell- und Ziel-OUs der Module, OU der deaktivierten Konten, Ziel-OU und Gruppen der Templates) speichern den **Pfad (DN)** der OU bzw. Gruppe. Wird sie im AD umbenannt oder verschoben, zeigt der gespeicherte Pfad ins Leere. Das ist nicht gefährlich – eine fehlende OU liefert keine Konten, eine fehlende Gruppe wird nicht zugewiesen –, aber das Modul arbeitet nicht mehr wie gedacht.

Darum merkt sich die Anwendung zu jedem Verweis die feste Kennung des Objekts (**objectGUID**), die beim Umbenennen und Verschieben gleich bleibt. Administratoren sehen oben auf der Seite einen gelben Hinweis, sobald etwas nicht mehr passt:

| Hinweis | Bedeutung | Was tun |
|---|---|---|
| *umbenannt oder verschoben* | Das Objekt gibt es noch, unter neuem Namen bzw. an anderem Ort. Der neue Pfad wird angezeigt | **Neue Namen übernehmen** klicken – alle betroffenen Einstellungen und Templates werden angepasst |
| *gelöscht und neu angelegt* | Unter dem alten Namen steht ein **anderes** Objekt (z. B. Gruppe gelöscht und gleichnamig neu angelegt) | Prüfen, ob das so gewollt ist; dann **Neue Namen übernehmen** (bestätigt das neue Objekt) |
| *nicht mehr vorhanden* | Das Objekt wurde gelöscht | In der Einstellung bzw. im Template eine andere OU/Gruppe wählen |

Gut zu wissen:

- Die Kennungen merkt sich die Anwendung, sobald ein Administrator die Seite öffnet. Wird eine OU umbenannt, **bevor** das je passiert ist (z. B. nach dem Update auf diese Version, noch bevor sich ein Administrator angemeldet hat), meldet der Hinweis *nicht mehr vorhanden* – dann die OU einfach neu auswählen.
- **Rollen** hängen nicht an Gruppennamen, sondern an festen SIDs (Domänen-Admins, Kontenoperatoren …). Umbenennen dieser Gruppen ändert nichts.
- **Offboarding rückgängig machen** findet Konto und Gruppen über die objectGUID, auch nach einer Umbenennung.
- Ein **umbenanntes Konto** (anderer Anmeldename) ist für die Anwendung dasselbe Konto. Gespeicherte Basis- und Profilpfade im Konto ändern sich dabei nicht automatisch – beim Löschen zählt der Pfad im AD-Konto.
- Eine Gruppe nach der Umbenennung im Template neu auszuwählen, statt *Neue Namen übernehmen* zu klicken, führt zum selben Ergebnis.

---

## 11. Templates

Ein Template legt fest, wie ein neues Konto aussieht. Menü **Templates**: **+ Neues Template**, oder bei einem bestehenden **Bearbeiten** bzw. **Duplizieren**.

| Feld | Bedeutung |
|---|---|
| Template Name | Name in der Auswahl beim Onboarding |
| Username Makro | Aufbau des Benutzernamens, z. B. `%LASTNAME%%FIRSTNAME%[3]` |
| Ziel OU | OU, in der das Konto entsteht |
| E-Mail-Adresse / Postfach | Pflicht, optional, Exchange im eigenen Haus oder Microsoft 365 |
| Passwort-Modus | Zufallspasswort oder festes Standardpasswort |
| Passwort ändern / läuft nie ab | Konto-Optionen |
| AD Gruppen | Gruppen für das neue Konto |
| Weitere Felder | Abteilung, Firma, Stellenbezeichnung, Vorgesetzter, Büro, Telefon, Adresse … |
| Profil | Profilpfad, Anmeldeskript, Basisordner (wie im RSAT-Reiter „Profil“) |

**Namens-Makros:**

| Makro | Beispiel Max Mustermann |
|---|---|
| `%LASTNAME%%FIRSTNAME%[3]` | `MUSTERMANNMAX` |
| `%FIRSTNAME[1]%.%LASTNAME%` | `M.MUSTERMANN` |
| `%LASTNAME[5]%%FIRSTNAME[2]%` | `MUSTEMA` |

`[n]` nimmt die ersten *n* Zeichen. Erlaubt sind `A–Z`, `0–9`, `.`, `_`, `-`, höchstens 20 Zeichen. In Textfeldern wird `%username%` durch den neuen Benutzernamen ersetzt, z. B. `\\server\home$\%username%`.

**E-Mail und Postfach:**

| Einstellung | Verhalten |
|---|---|
| Eigener Mailserver ohne Exchange | Adresse ist Pflicht und wird ins AD geschrieben |
| E-Mail-Adresse optional | Feld darf leer bleiben |
| Exchange im eigenen Haus | Feld ausgeblendet, Postfach wird auf dem Exchange-Server angelegt (Verbindung im Kasten *Exchange im eigenen Haus* einrichten und testen) |
| Microsoft 365 | Feld ausgeblendet, Postfach entsteht über die Lizenz |

**Basisordner automatisch anlegen:** Mit Netzwerkpfad und der Option *Ordner automatisch erstellen* legt die Anwendung den Ordner an und gibt dem neuen Konto Vollzugriff. Ein vorhandener Ordner wird nicht angefasst.

---

## 12. E-Mail-Benachrichtigung

Menü **E-Mail-Benachrichtigung** (nur Administratoren; Operatoren sehen die Einstellungen nicht). Mails gehen an die Adresse aus dem AD-Attribut `mail` des Angemeldeten; ohne dieses Attribut wird keine Mail verschickt.

1. **E-Mail-Versand global aktivieren**, Server, Port, TLS-Modus, Benutzer und Passwort sowie Absender eintragen. Zum Beispiel `mail.firma.local`, Port `587`, *STARTTLS*.
2. **Speichern**, dann mit **Test-Mail senden** eine Mail an dich schicken.
3. Festlegen, wofür Mails verschickt werden: Offboarding, Passwort-Reset, Benutzerverwaltung, Löschen. Die Onboarding-Mail geht immer, sobald SMTP aktiv ist.

Die Mails gehen an die **angemeldete Person**, optional zusätzlich an CC-Empfänger. Onboarding- und Passwort-Mails enthalten das neue Passwort.

Hinweise:

- *Auto* nutzt STARTTLS. Bietet der Server keine Verschlüsselung an, wird nichts gesendet. *Ohne Verschlüsselung* nur für ein internes Relay wählen; ein SMTP-Passwort wird dann nie gesendet.
- Ändert sich Server oder Benutzername, muss das Passwort neu eingegeben werden.
- Schlägt der Test fehl, Servername und Port prüfen und ob Netzwerk bzw. Firewall die Verbindung zum Mailserver erlauben.

---

## 13. Berichte

Menü **Berichte** (nur Administratoren), zwei Bereiche:

| Bereich | Inhalt | Gelöscht nach |
|---|---|---|
| **Änderungen** | Wer hat wann was getan, mit Ergebnis und Details | 365 Tagen |
| **Protokoll** | Meldungen des Programms (Warnungen, Fehler, Verbindungsprobleme) | 90 Tagen |

- **Suchen** und **filtern** (Erfolgreich/Fehlgeschlagen bzw. Warnungen/Fehler), mit **Mehr laden** ältere Einträge anzeigen.
- **Manuell löschen:** unten „älter als 30/90/180 Tage“ oder „alle“ wählen und mit dem eigenen Passwort bestätigen. Das Löschen selbst wird vermerkt.
- Passwörter stehen nie in den Berichten.

---

## 14. Zertifikat

Menü **Zertifikat** (nur Administratoren). Die Seite zeigt das aktuelle Zertifikat mit Namen, Aussteller und Ablaufdatum.

- **PFX / P12** hochladen (mit Passwort, z. B. aus der Windows-Zertifikatsverwaltung exportiert, mit privatem Schlüssel) oder
- **Zertifikat + Schlüssel** als PEM/DER-Dateien, optional mit Zwischenzertifikaten, oder
- ein neues **selbstsigniertes** Zertifikat mit den richtigen Servernamen erzeugen.

Mit **Prüfen und übernehmen** wird geprüft, ob Zertifikat und Schlüssel zusammenpassen und gültig sind. Das neue Zertifikat gilt **sofort**; danach die Seite neu laden. Das alte bleibt als Sicherung erhalten. 30 Tage vor Ablauf erscheint eine Warnung im Protokoll.

---

## 15. Datenschutz

Der Link **Datenschutz** (Anmeldeseite unten und Seitenleiste unter *Hilfe*) zeigt kurz, was gespeichert wird und die aktuellen Löschfristen.

- Keine Verbindungen ins Internet: Oberfläche, Schriften und Icons kommen vom eigenen Server.
- Nur ein notwendiges Cookie für die Anmeldung, kein Tracking.
- Dein Passwort liegt nur während der Sitzung im Arbeitsspeicher.
- **Auskunft (Art. 15 DSGVO):** Administratoren geben dort einen Benutzernamen ein und laden alles herunter, was die Anwendung über dieses Konto gespeichert hat (JSON). Vor der Herausgabe prüfen und Angaben über andere Personen schwärzen.

Details für das Verzeichnis der Verarbeitungstätigkeiten stehen in `DATENSCHUTZ.de.md`.

---

## 16. Betrieb auf dem Server

Für Administratoren mit Zugriff auf den Docker-Host.

Auf dem Server liegen nur die `docker-compose.yml`, die `.env` mit den Einstellungen und der Ordner `data/` mit allen Daten. Das Programm steckt komplett im Image.

**Update mit einer Container-Verwaltung** (Dockhand, Watchtower, Tugtainer, Portainer …): automatische Aktualisierung einschalten, am besten nachts.

**Update von Hand** im Ordner der `docker-compose.yml`:

```bash
sudo docker compose pull && sudo docker compose up -d
```

Oder mit dem Hilfsskript `sudo sh update.sh`: Es merkt sich die laufende Version, holt die neue, startet sie und wartet auf den Gesundheitscheck. Startet die neue Version nicht, startet es nach Rückfrage wieder die vorherige (mit `-y` ohne Rückfrage). Ist das Image privat, vorher einmal `sudo docker login ghcr.io` (Passwort: Token mit *read:packages*).

**Sicherung vor einem Versionswechsel:** Startet eine neue Programmversion, sichert das Programm zuerst selbst den Datenordner nach `data/backups/vor-<Version>-<Datum>.tar.gz` (die letzten 10 bleiben). Startet eine ältere Version auf Daten einer neueren, bricht sie mit einer Meldung ab, die die passende Sicherung nennt.

**Version festlegen und zurückgehen:** In der `.env` steht `SAMONBOARDING_VERSION`. Leer = immer die neueste Version, `2.0` = die neueste 2.0.x samt Sicherheitsupdates, `2.0.1` = genau diese Version. Zurück auf eine ältere Version, deren Datenstand älter ist: `sudo sh update.sh --restore data/backups/vor-<neuere Version>-<Datum>.tar.gz --version <ältere Version>`.

**Ohne Internet:** Die Image-Datei aus dem Release (`samonboarding-<Version>-amd64.tar.gz` bzw. `-arm64`) auf den Server kopieren und `sudo sh update.sh --offline <Datei>` ausführen.

**Hinweis auf eine veraltete docker-compose.yml:** Erscheint er in der Oberfläche, `sudo sh update.sh` ausführen (ersetzt die Datei und behält die alte als `docker-compose.yml.alt`) oder die Datei aus dem aktuellen Release holen und `sudo docker compose up -d`.

**Umstieg von Version 1.x:** einmal `sudo sh update.sh --pull`, prüfen, dann `sudo sh update.sh --cleanup`. Das entfernt nach Rückfrage die alten Programmdateien und nie Daten, Sicherungen, `.env` oder `docker-compose.yml`. Schritt für Schritt in der README.

**Sicherheitsupdates:** GitHub prüft einmal im Monat am Patchday (zweiter Dienstag), ob es für die Pakete im Image neuere Versionen gibt, aber nur innerhalb des Unterbaus: gleiche Debian-, Python- und Node-Reihe, jedes Paket innerhalb seiner Hauptversion. Erst wenn Bau, Tests im Image und die Schwachstellen-Prüfung (Trivy) bestanden sind, erscheint eine neue Nummer wie `2.0.0-s1`. Sie bedeutet: gleiches Programm, nur neuere Pakete. Unter *Neuigkeiten* steht dazu die Liste der geänderten Pakete. Zusätzlich wird das veröffentlichte Image jeden Tag geprüft, und ein Jahr bevor Debian, Python oder Node keine Sicherheitsupdates mehr bekommen, erscheint ein Hinweis; ein halbes Jahr vorher ein roter Lauf. Der Unterbau wird nie automatisch gewechselt.

**Wenn auf GitHub ein Lauf rot ist:** Es wird nichts veröffentlicht, das bisherige Image bleibt unverändert, und GitHub schickt eine Mail. Die Ursache steht kurz am Lauf unter *Actions*. Meist ist eine gemeldete Korrektur noch nicht in den Paketquellen angekommen; dann den Lauf in ein bis zwei Tagen wiederholen (*Actions → Image → Run workflow*). Die README beschreibt jede Meldung im Abschnitt *Automatische Sicherheitsupdates*.

**Einstellungen** wie Domäne, DC, Port und Fristen stehen in der Datei `.env`. Nach einer Änderung `sudo docker compose up -d` ausführen. Alle Benutzer sind danach abgemeldet.

**Sichern:** den Ordner `data/` und die Datei `.env`. Dort liegt alles, was die Anwendung dauerhaft speichert, auch die Sicherungen vor Versionswechseln.

**Container-Ausgabe ansehen:**

```bash
docker compose logs -f
```

---
**Wenn etwas langsam ist:** Jede Anfrage, die länger als eine Sekunde dauert, steht im Protokoll mit ihrer Dauer je Schritt, zum Beispiel `Langsam: GET /api/offboarding/users 2.9 s (Verbindung 0.1 s, Suche 0.4 s, Schutzpruefung 2.4 s)` – nur Zeiten, nie Namen oder Suchbegriffe. Anzeigen mit `sudo docker compose logs samonboarding | grep Langsam`. Dieselben Zeiten zeigt der Browser in den Entwicklertools (Netzwerk → Timing, „Server-Timing“).

## 17. Häufige Fragen und Fehler

| Meldung / Frage | Was tun |
|---|---|
| Liste ist leer | Für das Modul sind noch keine Quell-OUs freigegeben, oder das Konto liegt außerhalb. Administrator fragen |
| Ein gerade im AD angelegtes Konto fehlt in der Liste | Die Listen werden bis zu 60 Sekunden zwischengespeichert. **Konten aktualisieren** klicken |
| Gelber Hinweis *Einstellungen verweisen auf geänderte OUs oder Gruppen* | Eine OU oder Gruppe wurde im AD umbenannt, verschoben oder gelöscht. Siehe [Ersteinrichtung](#10-ersteinrichtung-administratoren) |
| *Zugriff verweigert: Sie müssen Mitglied …* | Du bist weder Operator noch Administrator. Gruppenmitgliedschaft prüfen lassen, dann neu anmelden |
| *LDAP-Anmeldung fehlgeschlagen* | Benutzername oder Passwort falsch, Konto gesperrt oder deaktiviert |
| *Zu viele fehlgeschlagene Anmeldungen* | Einige Minuten warten |
| *Domain Controller … nicht erreichbar* | DC aus, Netzwerk oder Firewall. Administrator informieren |
| *Passwort setzen fehlgeschlagen* | Passwort entspricht nicht der Richtlinie, oder dir fehlen Rechte auf der OU |
| *insufficientAccessRights* | Dir fehlen im AD Rechte auf dieser OU (Delegierung) |
| *Dieses Konto ist geschützt* | Mitglied einer privilegierten Gruppe. Gewollter Schutz |
| *Sie wurden abgemeldet, weil 30 Minuten lang nichts passiert ist* | Gewollt. Neu anmelden. Nach einem Neustart der Anwendung (z. B. Update) ist ebenfalls eine neue Anmeldung nötig |
| Mail kommt nicht an | SMTP aktiviert? In der E-Mail-Benachrichtigung **Test-Mail senden** und die Meldung lesen |
| *Postfach konnte nicht angelegt werden* | Konto ist angelegt. Meldung lesen (Anmeldung, Erreichbarkeit, Zertifikat) und das Postfach in Exchange nachholen |
| Löschen: *Seit der Simulation hat sich etwas geändert* | Nichts wurde gelöscht. Simulation wiederholen |
| Löschen: *Datei ist in Benutzung* | Benutzer noch angemeldet oder Virenscanner. Später neu simulieren |
| Löschen: *Kein Zugriff* | Dir fehlen auf dem Dateiserver Rechte auf dem Ordner. Rechte prüfen oder *Besitz übernehmen* aktivieren |
| Uhrzeiten in den Berichten stimmen nicht | `TZ` in der `.env` ist leer oder ungültig: richtig setzen (z. B. `Europe/Berlin`) und `sudo docker compose up -d` |
