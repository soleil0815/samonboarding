"""HTTPS-Zertifikat: eigenes Zertifikat verwenden oder beim ersten Start ein selbstsigniertes erzeugen.

Reihenfolge:
  1. TLS_CERT_FILE / TLS_KEY_FILE (Standard data/tls/cert.pem und data/tls/key.pem), falls beide vorhanden
  2. sonst wird ein selbstsigniertes Zertifikat nach data/tls/ geschrieben (10 Jahre gueltig, Namen aus TLS_HOSTNAMES)

Eigenes Zertifikat (z. B. von der internen CA): in der Oberflaeche unter "Zertifikat" hochladen (PFX/P12 oder
Zertifikat + Schluessel) - es gilt sofort, ohne Neustart. Alternativ cert.pem (inkl. Zwischenzertifikate) und key.pem
nach data/tls/ legen und den Container neu starten. `cryptography` ist ueber smbprotocol/pypsrp bereits installiert.

Austausch im laufenden Betrieb: Der Server fragt bei jeder neuen TLS-Verbindung (SNI-Callback) das aktuelle Zertifikat
ab. Bestehende Verbindungen behalten das alte, neue bekommen sofort das neue.
"""

import datetime
import hashlib
import ipaddress
import logging
import os
import re
import socket
import ssl
import threading

from . import config

log = logging.getLogger(__name__)

# Moderne Verschluesselung (TLS 1.2/1.3 mit Forward Secrecy); TLS 1.3 nutzt immer sichere Verfahren
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM"
MAX_UPLOAD_BYTES = 1024 * 1024
WARN_DAYS = 30

_lock = threading.Lock()
_active = {"ctx": None}  # aktueller SSLContext fuer neue Verbindungen (None = der des Servers)


class CertError(ValueError):
    """Verstaendliche Meldung fuer die Oberflaeche."""


def _names():
    names = list(config.TLS_HOSTNAMES)
    for extra in ("localhost", socket.gethostname()):
        if extra and extra not in names:
            names.append(extra)
    return names


def generate_self_signed(cert_file, key_file, names=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    names = names or _names()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAMONBOARDING"),
        ]
    )
    alt = []
    for name in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt.append(x509.DNSName(name))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    os.makedirs(os.path.dirname(cert_file) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(key_file) or ".", exist_ok=True)
    # Schluessel nur fuer den Eigentuemer lesbar anlegen
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return names


def is_self_signed(cert_file):
    """True, wenn Aussteller = Inhaber. Dann kein HSTS, sonst liesse sich die Zertifikatswarnung nicht wegklicken."""
    try:
        from cryptography import x509

        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert.issuer == cert.subject
    except Exception:
        return True


def ensure_certificate():
    """Liefert (cert_file, key_file, self_signed); erzeugt bei Bedarf ein selbstsigniertes Zertifikat."""
    cert_file, key_file = config.TLS_CERT_FILE, config.TLS_KEY_FILE
    if os.path.isfile(cert_file) and os.path.isfile(key_file):
        self_signed = is_self_signed(cert_file)
        log.info("HTTPS-Zertifikat: %s (%s)", cert_file, "selbstsigniert" if self_signed else "eigenes Zertifikat")
        return cert_file, key_file, self_signed
    if os.path.exists(cert_file) != os.path.exists(key_file):
        raise SystemExit(f"Zertifikat und Schluessel muessen beide vorhanden sein: {cert_file}, {key_file}")
    names = generate_self_signed(cert_file, key_file)
    log.warning(
        "Selbstsigniertes HTTPS-Zertifikat erzeugt fuer %s (%s). Eigenes Zertifikat: in der Oberflaeche unter "
        '"Zertifikat" hochladen oder cert.pem und key.pem '
        "nach %s legen.",
        ", ".join(names),
        cert_file,
        os.path.dirname(cert_file),
    )
    return cert_file, key_file, True


# ---------------------------------------------------------------------------
# Austausch im laufenden Betrieb
# ---------------------------------------------------------------------------
def make_context(cert_file, key_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def _sni_callback(ssl_obj, server_name, base_ctx):
    current = _active["ctx"]
    if current is not None and current is not base_ctx:
        ssl_obj.context = current
    return None


def activate(base_ctx):
    """Haengt den Austausch an den SSLContext des Servers (einmal beim Start)."""
    base_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    base_ctx.sni_callback = _sni_callback
    _active["ctx"] = base_ctx
    _set_hsts_flag(config.TLS_CERT_FILE)


def _set_hsts_flag(cert_file):
    # main.py sendet HSTS nur bei einem eigenen (vertrauenswuerdigen) Zertifikat
    os.environ["SAMONBOARDING_TLS_SELF_SIGNED"] = "1" if is_self_signed(cert_file) else "0"


def reload_active():
    """Laedt die Dateien neu; neue Verbindungen bekommen sofort das neue Zertifikat. False = Neustart noetig."""
    ctx = make_context(config.TLS_CERT_FILE, config.TLS_KEY_FILE)
    _set_hsts_flag(config.TLS_CERT_FILE)
    if _active["ctx"] is None:
        return False
    _active["ctx"] = ctx
    return True


# ---------------------------------------------------------------------------
# Anzeige
# ---------------------------------------------------------------------------
def _load_pem_chain(data):
    from cryptography import x509

    return x509.load_pem_x509_certificates(data)


def _cn(name):
    from cryptography.x509.oid import NameOID

    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def _sans(cert):
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(v) for v in ext.get_values_for_type(x509.DNSName)] + [
        str(v) for v in ext.get_values_for_type(x509.IPAddress)
    ]


def describe(leaf, chain=()):
    from cryptography.hazmat.primitives import serialization

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = leaf.not_valid_after_utc
    der = leaf.public_bytes(serialization.Encoding.DER)
    return {
        "subject": _cn(leaf.subject),
        "names": _sans(leaf),
        "issuer": _cn(leaf.issuer),
        "selfSigned": leaf.issuer == leaf.subject,
        "notBefore": leaf.not_valid_before_utc.isoformat(timespec="seconds"),
        "notAfter": not_after.isoformat(timespec="seconds"),
        "daysLeft": (not_after - now).days,
        "keyType": _key_type(leaf.public_key()),
        "chainLength": len(chain),
        "fingerprint": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()),
    }


def _key_type(pub):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}"
    return type(pub).__name__


def current_info():
    with open(config.TLS_CERT_FILE, "rb") as f:
        certs = _load_pem_chain(f.read())
    return describe(certs[0], certs[1:])


def check_expiry():
    """Warnung ins Protokoll, wenn das Zertifikat bald ablaeuft (taeglich aufgerufen)."""
    try:
        info = current_info()
    except Exception as e:
        log.warning("HTTPS-Zertifikat nicht lesbar: %s", e)
        return None
    if info["daysLeft"] < 0:
        log.error("HTTPS-Zertifikat ist abgelaufen (seit %s Tagen) - bitte erneuern", -info["daysLeft"])
    elif info["daysLeft"] <= WARN_DAYS:
        log.warning("HTTPS-Zertifikat laeuft in %s Tagen ab (%s) - bitte erneuern", info["daysLeft"], info["notAfter"])
    return info


# ---------------------------------------------------------------------------
# Hochladen und pruefen
# ---------------------------------------------------------------------------
def _certs_from(data, what):
    """PEM (auch mehrere) oder DER."""
    from cryptography import x509

    if not data:
        return []
    if b"-----BEGIN" in data:
        try:
            return _load_pem_chain(data)
        except ValueError:
            if b"CERTIFICATE-----" in data:
                raise CertError(f"{what}: Die Datei enthält kein lesbares Zertifikat.") from None
            return []  # z. B. nur ein Schluessel in der Datei
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        raise CertError(f"{what}: Die Datei ist kein Zertifikat (PEM oder DER/CER erwartet).") from None


def _key_from(data, password):
    from cryptography.hazmat.primitives import serialization

    pw = password.encode("utf-8") if password else None
    loaders = (serialization.load_pem_private_key,) if b"-----BEGIN" in data else (serialization.load_der_private_key,)
    for loader in loaders:
        try:
            return loader(data, password=pw)
        except TypeError:
            if pw is None:
                raise CertError(
                    "Der Schlüssel ist mit einem Passwort geschützt - bitte das Passwort angeben."
                ) from None
            raise CertError("Der Schlüssel ist nicht verschlüsselt - bitte das Passwortfeld leer lassen.") from None
        except ValueError:
            if pw is not None:
                raise CertError("Der Schlüssel lässt sich nicht öffnen - ist das Passwort richtig?") from None
    raise CertError("Der private Schlüssel ist nicht lesbar (PEM oder DER erwartet).")


def _same_key(cert, key):
    from cryptography.hazmat.primitives import serialization

    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_key().public_bytes(*fmt) == key.public_key().public_bytes(*fmt)


def _order_chain(leaf, others):
    """Zwischenzertifikate in der Reihenfolge vom Server-Zertifikat Richtung Wurzel; Doppelte entfernen."""
    chain, current, pool = [], leaf, [c for c in others if c != leaf]
    while pool:
        nxt = next((c for c in pool if c.subject == current.issuer), None)
        if nxt is None or nxt.subject == nxt.issuer:  # Wurzel braucht der Browser nicht
            break
        chain.append(nxt)
        pool.remove(nxt)
        current = nxt
    return chain


def parse_upload(pfx=None, cert=None, key=None, chain=None, password=""):
    """Liest PFX/P12 oder Zertifikat + Schluessel (+ Kette). Liefert (key, leaf, chain, warnings)."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    for blob in (pfx, cert, key, chain):
        if blob and len(blob) > MAX_UPLOAD_BYTES:
            raise CertError("Die Datei ist zu groß (höchstens 1 MB).")
    certs, priv = [], None
    if pfx:
        try:
            priv, leaf_pfx, extra = pkcs12.load_key_and_certificates(
                pfx, password.encode("utf-8") if password else None
            )
        except ValueError:
            raise CertError("Die PFX/P12-Datei lässt sich nicht öffnen - ist das Passwort richtig?") from None
        if priv is None:
            raise CertError(
                "Die PFX/P12-Datei enthält keinen privaten Schlüssel. "
                "Beim Export „Privaten Schlüssel exportieren“ wählen."
            )
        certs = ([leaf_pfx] if leaf_pfx else []) + list(extra or [])
    else:
        if not cert:
            raise CertError("Bitte eine PFX/P12-Datei oder ein Zertifikat mit Schlüssel auswählen.")
        certs = _certs_from(cert, "Zertifikat")
        key_data = key or (cert if b"PRIVATE KEY-----" in cert else None)
        if not key_data:
            raise CertError("Der private Schlüssel fehlt.")
        priv = _key_from(key_data, password)
    certs += _certs_from(chain, "Zwischenzertifikate")
    if not certs:
        raise CertError("Es wurde kein Zertifikat gefunden.")
    if not isinstance(priv, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CertError("Nur RSA- oder ECDSA-Schlüssel werden unterstützt.")
    if isinstance(priv, rsa.RSAPrivateKey) and priv.key_size < 2048:
        raise CertError("Der RSA-Schlüssel ist zu kurz (mindestens 2048 Bit).")
    leaf = next((c for c in certs if _same_key(c, priv)), None)
    if leaf is None:
        raise CertError("Zertifikat und Schlüssel gehören nicht zusammen.")
    now = datetime.datetime.now(datetime.timezone.utc)
    if leaf.not_valid_after_utc < now:
        raise CertError(f"Das Zertifikat ist abgelaufen (am {leaf.not_valid_after_utc:%d.%m.%Y}).")
    warnings = []
    if leaf.not_valid_before_utc > now:
        warnings.append(f"Das Zertifikat gilt erst ab {leaf.not_valid_before_utc:%d.%m.%Y %H:%M} UTC.")
    if (leaf.not_valid_after_utc - now).days <= WARN_DAYS:
        warnings.append(f"Das Zertifikat läuft bald ab (am {leaf.not_valid_after_utc:%d.%m.%Y}).")
    if not _sans(leaf):
        warnings.append(
            "Das Zertifikat enthält keine alternativen Namen (SAN) - aktuelle Browser zeigen dann eine Warnung."
        )
    chain_certs = _order_chain(leaf, certs)
    if leaf.issuer != leaf.subject and not chain_certs:
        warnings.append(
            "Keine Zwischenzertifikate enthalten. Das ist in Ordnung, wenn die Clients die ausstellende CA direkt "
            "kennen (z. B. Firmen-CA per Gruppenrichtlinie)."
        )
    return priv, leaf, chain_certs, warnings


def _write(path, data, private=False):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return tmp


def _backup_current():
    for path in (config.TLS_CERT_FILE, config.TLS_KEY_FILE):
        if os.path.isfile(path):
            os.replace(path, path + ".prev")


def install(priv, leaf, chain):
    """Schreibt Zertifikat und Schluessel (vorher Probe mit OpenSSL), sichert die alten als *.prev, aktiviert sofort."""
    from cryptography.hazmat.primitives import serialization

    cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [leaf, *chain])
    key_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with _lock:
        cert_tmp = _write(config.TLS_CERT_FILE, cert_pem)
        key_tmp = _write(config.TLS_KEY_FILE, key_pem, private=True)
        try:
            make_context(cert_tmp, key_tmp)  # nimmt OpenSSL es an?
        except (ssl.SSLError, OSError) as e:
            for t in (cert_tmp, key_tmp):
                os.remove(t)
            raise CertError(f"Das Zertifikat wird vom Server nicht angenommen: {e}") from None
        _backup_current()
        os.replace(cert_tmp, config.TLS_CERT_FILE)
        os.replace(key_tmp, config.TLS_KEY_FILE)
        live = reload_active()
    return live


_DNS_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _valid_name(name):
    """IP-Adresse oder DNS-Name (ASCII, Teile bis 63 Zeichen, optional '*.' am Anfang)."""
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    host = name[2:] if name.startswith("*.") else name
    return 0 < len(name) <= 253 and all(_DNS_LABEL.match(label) for label in host.split("."))


def install_self_signed(names):
    """Neues selbstsigniertes Zertifikat (z. B. zurueck vom eigenen), alte Dateien als *.prev.

    Erst in temporaere Dateien schreiben und pruefen, dann tauschen - bei einem Fehler bleibt das bisherige
    Zertifikat unveraendert in Betrieb."""
    clean = []
    for n in names or []:
        n = str(n).strip()
        if n and n not in clean:
            if not _valid_name(n):
                raise CertError(f"Ungültiger Name: {n}")
            clean.append(n)
    with _lock:
        cert_tmp, key_tmp = config.TLS_CERT_FILE + ".tmp", config.TLS_KEY_FILE + ".tmp"
        try:
            used = generate_self_signed(cert_tmp, key_tmp, clean or None)
            make_context(cert_tmp, key_tmp)
        except (ValueError, ssl.SSLError, OSError) as e:
            for t in (cert_tmp, key_tmp):
                if os.path.exists(t):
                    os.remove(t)
            raise CertError(f"Das Zertifikat wird vom Server nicht angenommen: {e}") from None
        _backup_current()
        os.replace(cert_tmp, config.TLS_CERT_FILE)
        os.replace(key_tmp, config.TLS_KEY_FILE)
        live = reload_active()
    return used, live
