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
pyspnego (a dependency of pypsrp, already in the image) provides NTLM and - when the Kerberos libraries are present -
Kerberos via "negotiate".
"""

import logging
import struct

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
        self._raw = b""
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
        out, self._raw = self._raw[:n], self._raw[n:]
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


def _client_context(user, password, hostname, protocol):
    import spnego  # imported here: only needed for this kind of connection

    req = spnego.ContextReq.default | spnego.ContextReq.integrity | spnego.ContextReq.confidentiality
    return spnego.client(user, password, hostname=hostname, service="ldap", protocol=protocol, context_req=req)


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


def sealed_bind(conn, user, password, host, protocol="negotiate"):
    """SASL GSS-SPNEGO bind on an opened (not yet bound) ldap3 connection; afterwards all traffic is encrypted.

    Raises LDAPBindError for a wrong password or a locked account (like a simple bind, so the caller treats it the
    same way) and SealError if the DC does not support it or the security layer could not be negotiated."""
    hostname = _dns_host_name(conn) or host
    try:
        ctx = _client_context(user, password, hostname, protocol)
        token = ctx.step()
    except Exception as e:
        raise SealError(f"Anmeldung mit Verschlüsselung nicht möglich: {type(e).__name__}") from None
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
    conn.sob_transport = "ldap-sealed-" + (
        "kerberos" if getattr(ctx, "negotiated_protocol", "") == "kerberos" else "ntlm"
    )
    return conn
