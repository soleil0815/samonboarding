# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""E-Mail-Benachrichtigungen: HTML-/Text-Vorlage und SMTP-Versand."""

import contextlib
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate

from .config import SMTP_CONFIG_FILE, VERSION, default_smtp_config
from .config import SMTP_UNENCRYPTED as UNENCRYPTED
from .i18n import current_lang
from .i18n import tr as translate
from .storage import load_json

log = logging.getLogger(__name__)


# Nur diese festen Woerter werden in Werten uebersetzt. Alles andere sind Daten (Namen, Gruppen, Passwoerter) und
# bleibt unveraendert - ein Passwort darf nie durch das Woerterbuch laufen.
TRANSLATABLE_VALUES = {"Ja", "Nein", "Keine", "offgeboardet"}
TRANSLATABLE_PREFIXES = ("NICHT offgeboardet - ",)


def _translate_value(value, kind):
    if not isinstance(value, str) or kind == "pwd":
        return value
    if value in TRANSLATABLE_VALUES:
        return translate(value)
    if value.startswith(TRANSLATABLE_PREFIXES):
        return translate(value)  # Muster "NICHT offgeboardet - {0}" (Fehlermeldung, keine Daten)
    return value


MAIL_VALUE_STYLES = {
    "": "color: #0f172a;",
    "bold": "color: #0f172a; font-weight: bold;",
    "mono": "font-family: monospace; color: #0f172a;",
    "pwd": "font-family: monospace; font-weight: bold; color: #b45309; background: #fef3c7;",
    "good": "font-family: monospace; color: #059669;",
    "bad": "font-family: monospace; color: #e11d48;",
}


def render_mail(operator, title, accent, intro, rows):
    """Baut Text- und HTML-Variante einer Benachrichtigung. rows = [(Label, Wert, Stil), ...]

    Texte werden in die Sprache der Oberflaeche uebersetzt (i18n.tr; Deutsch bleibt unveraendert)."""
    title, intro = translate(title), translate(intro)
    rows = [(translate(label), _translate_value(value, kind), kind) for label, value, kind in rows]
    greeting = translate(f"Hallo {operator},") if operator else translate("Hallo,")
    closing = translate("Mit freundlichen Grüßen")
    text_lines = [greeting, "", intro, ""]
    text_lines += [f"{label} {value}" for label, value, _ in rows]
    text_lines += ["", closing, f"SAMONBOARDING Suite v{VERSION}", ""]
    body_text = "\n".join(text_lines)

    tr = []
    for i, (label, value, kind) in enumerate(rows):
        border = "" if i == len(rows) - 1 else " border-bottom: 1px solid #e2e8f0;"
        value_style = MAIL_VALUE_STYLES.get(kind, "")
        tr.append(
            '<tr><td style="padding: 10px; font-weight: bold; color: #475569; width: 160px;'
            + border
            + '">'
            + html.escape(str(label))
            + '</td><td style="padding: 10px; '
            + value_style
            + border
            + '">'
            + html.escape(str(value))
            + "</td></tr>"
        )
    rows_html = "".join(tr)
    safe_title = html.escape(str(title))
    safe_intro = html.escape(str(intro))
    body_html = f"""<!DOCTYPE html>
<html lang="{current_lang()}">
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif; color: #1e293b; line-height: 1.6; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 25px;">
        <h2 style="color: {accent}; margin-top: 0;">{safe_title}</h2>
        <p>{safe_intro}</p>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px;">
            {rows_html}
        </table>
        <p style="font-size: 13px; color: #475569;">{html.escape(str(closing))}<br><strong>SAMONBOARDING Suite v{VERSION}</strong></p>
    </div>
</body>
</html>"""
    return body_text, body_html


def smtp_send(cfg, recipient_email, subject, body_text, body_html=None):
    """Versendet eine Mail und wirft bei Fehlern. Beachtet 'enabled' bewusst nicht."""
    cc_list = [e.strip() for e in (cfg.get("ccRecipients") or "").replace(";", ",").split(",") if e.strip()]

    msg = EmailMessage()
    msg["Subject"] = translate(subject)
    display_name = cfg.get("displayName")
    msg["From"] = formataddr((display_name, cfg["fromEmail"])) if display_name else cfg["fromEmail"]
    msg["To"] = recipient_email
    msg["Date"] = formatdate(localtime=True)  # Ortszeit des Containers (TZ)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    mode = cfg.get("tlsMode") or "Auto"
    host, port = cfg["host"], int(cfg["port"])
    try:
        if mode == "SSL/TLS":
            server = smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=10)
    except (ConnectionRefusedError, ConnectionResetError, TimeoutError) as e:
        raise OSError(f"SMTP-Server {host}:{port} nicht erreichbar ({e}). Servername, Port und Firewall prüfen.") from e
    try:
        server.ehlo()
        if mode == "STARTTLS" or (mode == "Auto" and server.has_extn("starttls")):
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        elif mode == "Auto":
            # Kein STARTTLS (oder von einem Angreifer im Netz unterdrueckt): nichts im Klartext senden - die Mails
            # enthalten z. B. Startpasswoerter, dazu kaeme das SMTP-Passwort
            raise smtplib.SMTPException(
                f"Der SMTP-Server {host} bietet keine Verschlüsselung (STARTTLS) an - es wird nichts unverschlüsselt "
                "gesendet. TLS-Modus 'SSL/TLS' wählen, den Server prüfen oder (nur für ein internes Relay) "
                "bewusst 'Ohne Verschlüsselung' einstellen."
            )
        elif mode == UNENCRYPTED:
            if cfg.get("username") and cfg.get("password"):
                raise smtplib.SMTPException(
                    "Ohne Verschlüsselung wird kein SMTP-Passwort gesendet. Benutzer und Passwort leer lassen "
                    "(internes Relay) oder einen TLS-Modus wählen."
                )
            log.warning("E-Mail an %s geht UNVERSCHLUESSELT ueber %s (TLS-Modus 'Ohne Verschluesselung')", host, host)
        if cfg.get("username") and cfg.get("password"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg, to_addrs=[recipient_email] + cc_list)
        log.info('E-Mail gesendet: "%s" an %s Empfaenger ueber %s', msg["Subject"], 1 + len(cc_list), host)
    finally:
        with contextlib.suppress(Exception):
            server.quit()


def send_notification_email(recipient_email, subject, body_text, body_html=None):
    cfg = load_json(SMTP_CONFIG_FILE, default_smtp_config)
    if not cfg.get("enabled", False) or not recipient_email:
        return
    try:
        smtp_send(cfg, recipient_email, subject, body_text, body_html)
    except Exception as e:
        log.error("SMTP Notification Error: %s", e)


def send_onboarding_mail(recipient_email, created_user_data):
    fullname = created_user_data.get("fullname", created_user_data["sam"])
    subject = f"Neuer Mitarbeiter angelegt: {fullname} ({created_user_data['sam']})"
    body_text, body_html = render_mail(
        "",
        "Neuer Mitarbeiter angelegt",
        "#0284c7",
        f"Im Active Directory wurde erfolgreich ein neuer Benutzer für {fullname} eingerichtet.",
        [
            ("Mitarbeiter:", fullname, "bold"),
            ("Benutzername:", created_user_data["sam"], "mono"),
            ("UPN:", created_user_data["upn"], "mono"),
            *([("E-Mail:", created_user_data["mail"], "mono")] if created_user_data.get("mail") else []),
            ("Passwort:", created_user_data["pwd"], "pwd"),
        ],
    )
    send_notification_email(recipient_email, subject, body_text, body_html)
