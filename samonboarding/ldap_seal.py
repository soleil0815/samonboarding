# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Encrypted LDAP on port 389 without a certificate: SASL GSS-SPNEGO bind with NTLM (or Kerberos) and
"sign and seal" of every following message - as Windows tools (RSAT) do it.

Many Windows domains have no certificate on their domain controllers, so LDAPS (636) is not available there. A simple
bind on 389 would send the password in clear text, the DC refuses it anyway if LDAP signing is required, and Active
Directory never accepts a new password (unicodePwd) over an unencrypted connection. With SASL sealing the connection
is encrypted after the bind; the DC then also accepts password changes.

ldap3 can bind with NTLM but never seals the traffic, so the security layer sits below ldap3: after the bind, the
connection's socket is replaced by SealedSocket, which wraps (encrypts) every outgoing LDAP message and unwraps every
incoming one. The SASL framing is a 4-byte big-endian length followed by the wrapped token (RFC 4422 / 4752).
pyspnego (a dependency of pypsrp) provides NTLM and, with the MIT Kerberos libraries and the packages gssapi and krb5
(in the image since 2.10.0), Kerberos - see kerberos.py. Kerberos is tried first; its target name comes from the
configuration (AD_DC_IP as DNS name), never from the unauthenticated RootDSE.
"""

import logging
import struct
import time

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError

log = logging.getLogger(__name__)

SASL_MECHANISM = "GSS-SPNEGO"
MAX_FRAME = 16 * 1024 * 1024  # a broken or hostile server must not make us allocate unlimited memory
SASL_BIND_IN_PROGRESS = 14
INVALID_CREDENTIALS = 49


class SealError(LDAPCommunicationError):
    """The encrypted connection could not be set up or a message could not be decrypted."""


class SealedSocket:
    """Socket replacement for ldap3's sync strategy: only sendall, recv, settimeout, shutdown and close are used."""

    def __init__(self, sock, ctx):
        self._sock = sock
        self._ctx = ctx
        self._raw = bytearray()  # bytearray: appending chunks does not copy the whole buffer each time
        self._plain = b""

    def sendall(self, data):
        try:
            wrapped = self._ctx.wrap(bytes(data), encrypt=True).data
        except Exception as e:
            raise OSError(f"LDAP-Verschlüsselung fehlgeschlagen: {type(e).__name__}") from None
        self._sock.sendall(struct.pack(">I", len(wrapped)) + wrapped)

    def _read(self, n):
        while len(self._raw) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise OSError("LDAP-Verbindung vom Server geschlossen")
            self._raw += chunk
        out = bytes(self._raw[:n])
        del self._raw[:n]
        return out

    def recv(self, size):
        if not self._plain:
            length = struct.unpack(">I", self._read(4))[0]
            if not 0 < length <= MAX_FRAME:
                raise OSError(f"Ungültige Länge einer verschlüsselten LDAP-Nachricht: {length}")
            frame = self._read(length)
            try:
                self._plain = self._ctx.unwrap(frame).data
            except Exception as e:
                # a message that cannot be decrypted (or whose signature is wrong) is never passed on
                raise OSError(f"LDAP-Nachricht nicht entschlüsselbar: {type(e).__name__}") from None
            if not self._plain:
                raise OSError("Leere verschlüsselte LDAP-Nachricht")
        out, self._plain = self._plain[:size], self._plain[size:]
        return out

    def settimeout(self, value):
        self._sock.settimeout(value)

    def shutdown(self, how):
        self._sock.shutdown(how)

    def close(self):
        self._sock.close()

    def __getattr__(self, name):  # anything else (fileno, getpeername ...) from the real socket
        return getattr(self._sock, name)


_SPNEGO_CLASSES = {}


def _spnego_class(protocol):
    """SPNEGO that offers exactly ONE mechanism. pyspnego's "negotiate" would try Kerberos and then NTLM on its own -
    with a wrong password that would count twice towards the account lockout, and after a refused Kerberos it would
    silently use NTLM. The order (Kerberos first, NTLM only if Kerberos is not possible) is decided in sealed_bind."""
    if protocol not in _SPNEGO_CLASSES:
        from spnego._negotiate import NegotiateProxy

        class OneMechanism(NegotiateProxy):
            @classmethod
            def available_protocols(cls, options=None):
                return [protocol, "negotiate"]

        _SPNEGO_CLASSES[protocol] = OneMechanism
    return _SPNEGO_CLASSES[protocol]


def _client_context(user, password, hostname, protocol):
    """protocol: 'kerberos' or 'ntlm', always wrapped in SPNEGO (the SASL mechanism is GSS-SPNEGO)."""
    import spnego  # imported here: only needed for this kind of connection

    req = spnego.ContextReq.default | spnego.ContextReq.integrity | spnego.ContextReq.confidentiality
    return _spnego_class(protocol)(user, password, hostname=hostname, service="ldap", context_req=req)


# Kerberos per DC target: worked once in this process (then never NTLM again - someone blocking port 88 must not be
# able to force the weaker NTLM), or failed a moment ago (then NTLM for a while, without waiting and logging each time)
KERBEROS_RETRY_SECONDS = 600
_kerberos_seen: set = set()
_kerberos_missing: dict = {}


def _start(conn, user, password, host, kerberos):
    """Create the context and its first token: Kerberos first (if possible), else NTLM.
    Returns (ctx, token, kind, ticket) - the ticket (Kerberos) must be destroyed after the bind."""
    from . import kerberos as krb

    target = (kerberos or {}).get("target", "")
    if kerberos and _kerberos_missing.get(target, 0) <= time.monotonic():
        ticket = None
        try:
            import spnego

            ticket = krb.new_ticket(kerberos["principal"], password)
            ctx = _client_context(spnego.KerberosCCache(ccache=ticket.name), None, target, "kerberos")
            token = ctx.step()
            _kerberos_seen.add(target)
            _kerberos_missing.pop(target, None)
            return ctx, token, "kerberos", ticket
        except Exception as e:
            krb.destroy_ticket(ticket)
            reason = krb.credential_error(e)
            if reason:
                # the KDC refused the password or the account: do NOT try NTLM with the same password as well
                raise LDAPBindError(f"automatic bind not successful - invalidCredentials ({reason})") from None
            if target in _kerberos_seen:
                raise SealError(
                    f"Kerberos zu {target} nicht moeglich (vorher ging es) - kein Rueckfall auf NTLM"
                ) from None
            if target not in _kerberos_missing:
                log.info("Kerberos zu %s nicht moeglich, NTLM wird verwendet: %s", target, _short(e))
            _kerberos_missing[target] = time.monotonic() + KERBEROS_RETRY_SECONDS
    try:
        ctx = _client_context(user, password, _dns_host_name(conn) or host, "ntlm")
        return ctx, ctx.step(), "ntlm", None
    except Exception as e:
        raise SealError(f"Anmeldung mit Verschlüsselung nicht möglich: {type(e).__name__}") from None


def _short(error, limit=200):
    text = " ".join(str(error).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _dns_host_name(conn):
    """Name of the DC from the RootDSE (readable without signing in); used as target name of the authentication."""
    try:
        if conn.search("", "(objectClass=*)", ldap3.BASE, attributes=["dnsHostName"]):
            for entry in conn.response or []:
                if entry.get("type") == "searchResEntry":
                    value = (entry.get("attributes") or {}).get("dnsHostName")
                    if isinstance(value, (list, tuple)):
                        value = value[0] if value else ""
                    return str(value or "")
    except Exception as e:
        log.debug("RootDSE nicht lesbar: %s", e)
    return ""


def _negotiate(conn, token):
    """One SASL bind round (replaceable in tests)."""
    from ldap3.protocol.sasl.sasl import send_sasl_negotiation

    return send_sasl_negotiation(conn, None, token)


def sealed_bind(conn, user, password, host, kerberos=None):
    """SASL GSS-SPNEGO bind on an opened (not yet bound) ldap3 connection; afterwards all traffic is encrypted.

    kerberos: {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"} to try Kerberos first (the target from
    the configuration, never from the network), or None for NTLM only.

    Raises LDAPBindError for a wrong password or a locked account (like a simple bind, so the caller treats it the
    same way) and SealError if the DC does not support it or the security layer could not be negotiated."""
    ctx, token, kind, ticket = _start(conn, user, password, host, kerberos)
    try:
        return _bind_rounds(conn, ctx, token, kind)
    finally:
        # the user's Kerberos tickets are not kept: the established context has its own session key
        from . import kerberos as krb

        krb.destroy_ticket(ticket)


def _bind_rounds(conn, ctx, token, kind):
    conn.sasl_mechanism = SASL_MECHANISM
    conn.sasl_in_progress = True
    try:
        for _round in range(10):  # NTLM needs 2, Kerberos 1-2 rounds
            result = _negotiate(conn, token)
            code = (result or {}).get("result")
            creds = (result or {}).get("saslCreds") or b""
            if code == INVALID_CREDENTIALS:
                raise LDAPBindError("automatic bind not successful - invalidCredentials")
            if code == 0:
                if creds and not ctx.complete:
                    ctx.step(creds)
                break
            if code != SASL_BIND_IN_PROGRESS:
                raise SealError(f"Der DC lehnt die verschlüsselte Anmeldung ab: {(result or {}).get('description')}")
            token = ctx.step(creds)
        else:
            raise SealError("Verschlüsselte Anmeldung: zu viele Runden")
        if not ctx.complete:
            raise SealError("Verschlüsselte Anmeldung nicht abgeschlossen")
        import spnego

        if spnego.ContextReq.confidentiality not in ctx.context_attr:
            # the DC agreed to the bind but not to encryption - never continue unencrypted
            raise SealError("Der DC hat die Verschlüsselung nicht zugesagt")
    except (LDAPBindError, SealError):
        raise
    except Exception as e:
        raise SealError(f"Verschlüsselte Anmeldung fehlgeschlagen: {type(e).__name__}") from None
    finally:
        conn.sasl_in_progress = False
    conn.socket = SealedSocket(conn.socket, ctx)
    conn.bound = True
    conn.sob_transport = "ldap-sealed-" + kind
    return conn
