# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""File shares (SMB): strict path validation and a read-only folder scan for the deletion simulation.

Everything that concerns a path goes through the same rules here:
  * UNC paths only (\\\\server\\share\\folder), no '..', no wildcards, no streams (':')
  * a target must lie STRICTLY BELOW a base path approved by the administrator
  * the base path itself (and the share) is never a valid target
The actual SMB access sits behind SmbBackend; the checks and the scan work against a
small interface (stat/listdir) and can therefore be tested without a file server.
"""

import errno
import logging
import re
import stat as statmod
import time
from dataclasses import dataclass, field
from types import SimpleNamespace

from . import acl

log = logging.getLogger(__name__)

ATTR_REPARSE_POINT = 0x400
ATTR_DIRECTORY = 0x10

_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_BAD_CHARS_RE = re.compile(r'[\x00-\x1f<>"|?*:%/]')
_SUFFIX_RE = re.compile(r"^[A-Za-z0-9]{1,10}$")


class FsError(Exception):
    """File system error with a coarse kind: notfound, exists, denied, locked, auth, unreachable, other."""

    def __init__(self, kind, message=""):
        super().__init__(message or kind)
        self.kind = kind
        self.message = message or kind


@dataclass
class FsStat:
    is_dir: bool
    size: int = 0
    reparse: bool = False


@dataclass
class FsEntry:
    name: str
    is_dir: bool
    size: int = 0
    reparse: bool = False


@dataclass
class ScanResult:
    files: int = 0
    dirs: int = 0
    size: int = 0
    reparse: int = 0
    truncated: bool = False
    denied: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def _check_component(comp, what):
    if comp in (".", ".."):
        raise ValueError(f"{what} enthält '{comp}'.")
    if _BAD_CHARS_RE.search(comp):
        raise ValueError(f"{what} enthält unzulässige Zeichen (z. B. * ? : % < > |).")
    if comp != comp.rstrip(" ."):
        raise ValueError(f"{what} endet mit Punkt oder Leerzeichen.")


def parse_unc(path):
    """'\\\\server\\share\\a\\b' -> ('server', 'share', ['a', 'b']). Raises ValueError on any doubt."""
    raw = str(path or "").strip().replace("/", "\\")
    if not raw.startswith("\\\\"):
        raise ValueError("Der Pfad muss ein UNC-Pfad sein (\\\\server\\freigabe\\ordner).")
    comps = raw[2:].split("\\")
    while comps and comps[-1] == "":
        comps.pop()
    if len(comps) < 2:
        raise ValueError("Der Pfad braucht mindestens Server und Freigabe (\\\\server\\freigabe).")
    if any(c == "" for c in comps):
        raise ValueError("Der Pfad enthält leere Teile (doppelte Trennzeichen).")
    server, share, parts = comps[0], comps[1], comps[2:]
    if not _SERVER_RE.match(server):
        raise ValueError("Ungültiger Servername.")
    for comp in [share, *parts]:
        _check_component(comp, "Der Pfad")
    return server, share, parts


def canonical(server, share, parts):
    return "\\\\" + "\\".join([server, share, *parts])


def normalize_unc(path):
    return canonical(*parse_unc(path))


def _key(server, share, parts):
    return (server.lower(), share.lower(), tuple(p.lower() for p in parts))


def is_strictly_below(path, root):
    """True if path lies below root (same server/share, not root itself)."""
    ps, psh, pp = _key(*parse_unc(path))
    rs, rsh, rp = _key(*parse_unc(root))
    return ps == rs and psh == rsh and len(pp) > len(rp) and pp[: len(rp)] == rp


def below_any_root(path, roots):
    return any(is_strictly_below(path, r) for r in roots)


def expand_username(value, sam):
    """Replace %username% (case-insensitive). Other variables cannot be resolved."""
    out = re.sub(r"%username%", sam, str(value or ""), flags=re.IGNORECASE)
    if "%" in out:
        raise ValueError("Der Pfad enthält eine nicht auflösbare Variable (nur %username% wird ersetzt).")
    return out


def valid_sam(sam):
    sam = str(sam or "")
    if not sam or "\\" in sam:
        return False
    try:
        _check_component(sam, "Der Benutzername")
    except ValueError:
        return False
    return True


def valid_suffix(suffix):
    return bool(_SUFFIX_RE.match(str(suffix or "")))


def join_path(root, *names):
    server, share, parts = parse_unc(root)
    return canonical(server, share, [*parts, *names])


def last_name(path):
    return parse_unc(path)[2][-1]


# ---------------------------------------------------------------------------
# Determine an account's target paths
# ---------------------------------------------------------------------------
LOCATION_LABELS = {
    "profile": "Roamingprofil",
    "folderRedirection": "Ordnerumleitung",
    "home": "Basisordner",
}


def _target(kind, path, source, skip=""):
    return {"kind": kind, "label": LOCATION_LABELS[kind], "path": path, "source": source, "skip": skip}


def _from_attribute(kind, raw, sam, roots, suffixes=()):
    """Path from an AD attribute -> target (with a skip reason if applicable)."""
    try:
        path = normalize_unc(expand_username(raw, sam))
    except ValueError as e:
        return _target(kind, str(raw), "AD-Attribut", f"Nicht verwendbar: {e}")
    if not below_any_root(path, roots):
        return _target(kind, path, "AD-Attribut", "Liegt nicht unterhalb eines freigegebenen Basispfads.")
    if "~" in path:
        # Windows short names (CHEF~1) could point to someone else's folder; the comparison with other accounts
        # does not see them
        return _target(kind, path, "AD-Attribut", "Der Pfad enthält '~' (Kurzname) - wird nicht automatisch gelöscht.")
    if not name_matches_sam(last_name(path), sam, suffixes):
        # Safeguard: if the attribute holds someone else's folder (e.g. \\fs\home$\chef), it must not be deleted
        return _target(
            kind, path, "AD-Attribut", f"Der Ordnername passt nicht zum Benutzernamen '{sam}' - wird nicht gelöscht."
        )
    return _target(kind, path, "AD-Attribut")


def name_matches_sam(name, sam, suffixes=()):
    """Folder name belongs to the account: exactly the user name, for profiles also with one of the configured suffixes
    (e.g. 'mueller.V6'). 'mueller.alt' or 'max.mustermann' (for the account 'max') do NOT belong to it."""
    name, sam = str(name).lower(), str(sam).lower()
    if not sam:
        return False
    return name == sam or any(name == f"{sam}.{str(s).lower()}" for s in suffixes if valid_suffix(s))


def build_targets(kind, loc_cfg, sam, attr_value=""):
    """All possible folders of this account for one storage location (existing ones are checked later).

    Roaming profile: the folder must end in one of the configured suffixes (e.g. .V2) - without a suffix
    nothing is suggested. Other locations: <base path>\\<user name> and (optionally) the path from AD.
    """
    if not loc_cfg.get("enabled"):
        return []
    roots = [normalize_unc(r) for r in loc_cfg.get("roots", [])]
    suffixes = [s for s in loc_cfg.get("suffixes", []) if valid_suffix(s)] if kind == "profile" else []
    if not valid_sam(sam):
        return [_target(kind, "", "Konto", f"Benutzername '{sam}' ist als Ordnername nicht zulässig.")]
    if "~" in str(sam):
        # Windows short names (e.g. ADMINI~1 for Administrator) could point to someone else's folder
        return [
            _target(kind, "", "Konto", f"Benutzername '{sam}' enthält '~' - Ordner werden nicht automatisch gelöscht.")
        ]

    bases = []
    if loc_cfg.get("useAdAttr") and attr_value:
        bases.append(_from_attribute(kind, attr_value, sam, roots, suffixes))
    bases.extend(_target(kind, join_path(r, sam), "Basispfad") for r in roots)

    targets, seen = [], set()
    for base in bases:
        candidates = [base]
        if kind == "profile" and not base["skip"]:
            name = last_name(base["path"]).lower()
            if not any(name.endswith("." + s.lower()) for s in suffixes):
                candidates = [dict(base, path=f"{base['path']}.{s}") for s in suffixes]
        for cand in candidates:
            dedupe = cand["path"].lower() if cand["path"] else id(cand)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            targets.append(cand)
    return targets


# ---------------------------------------------------------------------------
# Scan (read-only)
# ---------------------------------------------------------------------------
def scan_tree(backend, path, max_entries=100000, max_seconds=20.0):
    """Count files/folders/size below path. Links (reparse points) are NOT followed."""
    result = ScanResult()
    deadline = time.monotonic() + max_seconds
    stack = [path]
    seen = 0
    while stack:
        current = stack.pop()
        try:
            entries = backend.listdir(current)
        except FsError as e:
            if e.kind == "denied":
                result.denied.append(current)
            else:
                result.errors.append(f"{current}: {e.message}")
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries or time.monotonic() > deadline:
                result.truncated = True
                return result
            if entry.reparse:
                result.reparse += 1
                continue
            child = current.rstrip("\\") + "\\" + entry.name
            if entry.is_dir:
                result.dirs += 1
                stack.append(child)
            else:
                result.files += 1
                result.size += entry.size
    return result


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------
MAX_REPORTED_ERRORS = 20


@dataclass
class DeleteResult:
    files: int = 0
    dirs: int = 0
    links: int = 0
    error_count: int = 0
    errors: list = field(default_factory=list)
    takeover_count: int = 0
    takeovers: list = field(default_factory=list)

    def fail(self, message):
        self.error_count += 1
        if len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append(message)

    def took_over(self, path):
        self.takeover_count += 1
        if len(self.takeovers) < MAX_REPORTED_ERRORS:
            self.takeovers.append(path)


def _plain_name(name):
    return bool(name) and name not in (".", "..") and "\\" not in name and "/" not in name


def delete_tree(backend, root, takeover=False):
    """Delete root including its contents (files first, then folders from the inside out).

    Links (junctions/symlinks) are never followed: only the link itself is removed, the target stays
    untouched. Errors do not abort: as much as possible is deleted and everything left over is listed in the
    result. With takeover=True, ownership is taken over on "access denied" and the operation is retried once.
    The caller must have checked root against the base paths beforehand.
    """
    result = DeleteResult()

    def run(operation, path, is_dir):
        try:
            return operation(path)
        except FsError as e:
            if e.kind != "denied" or not takeover:
                raise
        backend.take_ownership(path, is_dir)
        result.took_over(path)
        return operation(path)

    stack = [(root, False)]
    while stack:
        path, children_done = stack.pop()
        if children_done:
            try:
                run(backend.rmdir, path, True)
                result.dirs += 1
            except FsError as e:
                result.fail(f"{path}: {e.message}")
            continue
        if path != root and hasattr(backend, "stat"):
            # Check again right before descending: if the folder has meanwhile been replaced by a link
            # (junction), remove only the link - never follow its target
            try:
                now = run(backend.stat, path, True)
            except FsError as e:
                result.fail(f"{path}: {e.message}")
                continue
            if now.reparse:
                try:
                    run(backend.rmdir if now.is_dir else backend.remove, path, now.is_dir)
                    result.links += 1
                except FsError as e:
                    result.fail(f"{path}: {e.message}")
                continue
        try:
            entries = run(backend.listdir, path, True)
        except FsError as e:
            result.fail(f"{path}: {e.message}")
            continue
        stack.append((path, True))
        for entry in entries:
            child = path.rstrip("\\") + "\\" + entry.name
            if not _plain_name(entry.name):
                result.fail(f"{child}: ungültiger Name, übersprungen")
                continue
            try:
                if entry.reparse:
                    run(backend.rmdir if entry.is_dir else backend.remove, child, entry.is_dir)
                    result.links += 1
                elif entry.is_dir:
                    stack.append((child, False))
                else:
                    run(backend.remove, child, False)
                    result.files += 1
            except FsError as e:
                result.fail(f"{child}: {e.message}")
    return result


# ---------------------------------------------------------------------------
# SMB access (smbprotocol, imported only when needed)
# ---------------------------------------------------------------------------
_NT_STATUS = {
    0xC0000022: ("denied", "Zugriff verweigert."),
    0xC0000061: ("denied", "Erforderliches Recht fehlt (Zugriff verweigert)."),
    0xC0000043: ("locked", "Datei oder Ordner ist in Benutzung (gesperrt)."),
    0xC0000121: ("other", "Löschen nicht möglich (STATUS_CANNOT_DELETE)."),
    0xC0000101: ("other", "Ordner ist nicht leer."),
    0xC0000034: ("notfound", "Nicht gefunden."),
    0xC000003A: ("notfound", "Pfad nicht gefunden."),
    0xC0000225: ("notfound", "Nicht gefunden."),
    0xC00000CC: ("notfound", "Freigabe nicht gefunden."),
    0xC0000035: ("exists", "Existiert bereits."),
    0xC000006D: ("auth", "Anmeldung am Dateiserver fehlgeschlagen (Benutzername/Passwort oder Berechtigung)."),
}


def _translate(exc):
    """smbprotocol/OS error -> FsError with an understandable message."""
    if isinstance(exc, FsError):
        return exc
    code = getattr(exc, "errno", None)
    text = str(exc)
    name = type(exc).__name__
    ntstatus = getattr(exc, "ntstatus", None)
    if ntstatus in _NT_STATUS:
        return FsError(*_NT_STATUS[ntstatus])
    if "Authentication" in name or "LOGON_FAILURE" in text.upper():
        return FsError(*_NT_STATUS[0xC000006D])
    if code in (errno.EACCES, errno.EPERM) or "ACCESS_DENIED" in text.upper():
        return FsError("denied", "Zugriff verweigert.")
    if code == errno.EEXIST:
        return FsError("exists", "Existiert bereits.")
    if code == errno.ENOENT or "NOT_FOUND" in text.upper() or "BAD_NETWORK_NAME" in text.upper():
        return FsError("notfound", text)
    if (
        isinstance(exc, (ConnectionError, TimeoutError))
        or "gaierror" in name
        or code
        in (
            errno.ECONNREFUSED,
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
        )
    ):
        return FsError("unreachable", f"Dateiserver nicht erreichbar ({text}).")
    return FsError("other", text or name)


def _lib():
    """The required parts of smbprotocol (imported only when needed)."""
    from smbclient._io import SMBDirectoryIO, SMBFileIO, SMBFileTransaction
    from smbprotocol import MAX_PAYLOAD_SIZE
    from smbprotocol.file_info import InfoType
    from smbprotocol.open import (
        CreateOptions,
        FilePipePrinterAccessMask,
        SMB2QueryInfoRequest,
        SMB2QueryInfoResponse,
        SMB2SetInfoRequest,
        SMB2SetInfoResponse,
    )

    return SimpleNamespace(
        dir_io=SMBDirectoryIO,
        file_io=SMBFileIO,
        transaction=SMBFileTransaction,
        max_payload=MAX_PAYLOAD_SIZE,
        info_type=InfoType,
        create_options=CreateOptions,
        access=FilePipePrinterAccessMask,
        query_request=SMB2QueryInfoRequest,
        query_response=SMB2QueryInfoResponse,
        set_request=SMB2SetInfoRequest,
        set_response=SMB2SetInfoResponse,
    )


class SmbBackend:
    """SMB access on behalf of the logged-on administrator.

    Each instance has its own connection cache so that sessions of different users are never mixed.
    """

    def __init__(self, username, password, timeout=10):
        try:
            import smbclient
        except ImportError as e:
            raise FsError("other", "Das Paket 'smbprotocol' ist nicht installiert (Image neu bauen).") from e
        self._smb = smbclient
        self._kw = {"username": username, "password": password, "connection_timeout": timeout, "connection_cache": {}}

    def close(self):
        try:
            self._smb.reset_connection_cache(connection_cache=self._kw["connection_cache"])
        except Exception as e:  # cleanup must never fail
            log.debug("SMB-Verbindungen schliessen: %s", e)

    # -- read -----------------------------------------------------------------
    def stat(self, path):
        try:
            st = self._smb.lstat(path, **self._kw)
        except Exception as e:
            raise _translate(e) from e
        return FsStat(
            is_dir=statmod.S_ISDIR(st.st_mode),
            size=int(getattr(st, "st_size", 0) or 0),
            reparse=bool(int(getattr(st, "st_file_attributes", 0) or 0) & ATTR_REPARSE_POINT),
        )

    def listdir(self, path):
        """Entries of a folder. Kind and size come straight from the directory query (no per-entry queries)."""
        entries = []
        try:
            with self._smb.scandir(path, **self._kw) as iterator:
                for entry in iterator:
                    info = entry.smb_info
                    attrs = int(info.file_attributes)
                    entries.append(
                        FsEntry(
                            name=entry.name,
                            is_dir=bool(attrs & ATTR_DIRECTORY),
                            size=int(info.end_of_file),
                            reparse=bool(attrs & ATTR_REPARSE_POINT),
                        )
                    )
        except Exception as e:
            raise _translate(e) from e
        return entries

    # -- modify ---------------------------------------------------------------
    def remove(self, path):
        """Delete a file or file link (the library clears the read-only flag first)."""
        try:
            self._smb.remove(path, **self._kw)
        except Exception as e:
            raise _translate(e) from e

    def rmdir(self, path):
        """Delete an empty folder or a folder link (without following it)."""
        try:
            self._smb.rmdir(path, **self._kw)
        except Exception as e:
            raise _translate(e) from e

    def mkdir(self, path):
        try:
            self._smb.mkdir(path, **self._kw)
        except Exception as e:
            raise _translate(e) from e

    # -- permissions ----------------------------------------------------------
    def _open_for_security(self, lib, path, is_dir, access):
        cls = lib.dir_io if is_dir else lib.file_io
        return cls(
            path,
            mode="r",
            share_access="rwd",
            desired_access=access,
            create_options=lib.create_options.FILE_OPEN_REPARSE_POINT,
            **self._kw,
        )

    def get_security(self, path, is_dir, info=acl.SECINFO_OWNER | acl.SECINFO_GROUP | acl.SECINFO_DACL):
        """Read the security descriptor (binary format) of an entry."""
        try:
            lib = _lib()
            raw = self._open_for_security(lib, path, is_dir, lib.access.READ_CONTROL)
            with lib.transaction(raw) as transaction:
                request = lib.query_request()
                request["info_type"] = lib.info_type.SMB2_0_INFO_SECURITY
                request["additional_information"] = info
                request["output_buffer_length"] = lib.max_payload
                request["file_id"] = transaction.raw.fd.file_id

                def receive(sent, transaction=transaction):
                    response = transaction.raw.fd.connection.receive(sent)
                    answer = lib.query_response()
                    answer.unpack(response["data"].get_value())
                    return answer["buffer"].get_value()

                transaction += (request, receive)
            return transaction.results[0]
        except Exception as e:
            raise _translate(e) from e

    def set_security(self, path, is_dir, descriptor, info, access):
        """Write parts of a security descriptor (info = what, access = access right required for it)."""
        try:
            lib = _lib()
            raw = self._open_for_security(lib, path, is_dir, access(lib.access))
            with lib.transaction(raw) as transaction:
                request = lib.set_request()
                request["info_type"] = lib.info_type.SMB2_0_INFO_SECURITY
                request["additional_information"] = info
                request["file_id"] = transaction.raw.fd.file_id
                request["buffer"] = descriptor

                def receive(sent, transaction=transaction):
                    response = transaction.raw.fd.connection.receive(sent)
                    answer = lib.set_response()
                    answer.unpack(response["data"].get_value())
                    return answer

                transaction += (request, receive)
        except Exception as e:
            raise _translate(e) from e

    def can_take_ownership(self, path, is_dir):
        """Only check whether ownership could be taken over (open a handle with WRITE_OWNER, change nothing)."""
        try:
            lib = _lib()
            raw = self._open_for_security(lib, path, is_dir, lib.access.WRITE_OWNER)
            raw.open()
            raw.close()
            return True
        except Exception as e:
            log.debug("Besitzuebernahme nicht moeglich bei %s: %s", path, e)
            return False

    def grant_access(self, path, is_dir, sid, mask=acl.FILE_ALL_ACCESS):
        """Add an access control entry for sid to the ACL and verify the result."""
        try:
            sd = acl.parse_sd(self.get_security(path, is_dir))
            aces, changed = acl.with_allow_ace(sd, acl.allow_ace(sid, mask, is_dir))
            if changed:
                descriptor = acl.build_sd(dacl=aces, dacl_control=sd.control, dacl_revision=sd.dacl_revision)
                self.set_security(path, is_dir, descriptor, acl.SECINFO_DACL, lambda a: a.WRITE_DAC)
            if not acl.has_allow_ace(acl.parse_sd(self.get_security(path, is_dir)), sid, mask):
                raise FsError("other", "Die Berechtigung konnte nicht bestätigt werden.")
        except acl.AclError as e:
            raise FsError("other", f"Berechtigung nicht setzbar: {e}") from e

    def take_ownership(self, path, is_dir):
        """Take ownership for BUILTIN\\Administrators and grant this group full control."""
        try:
            descriptor = acl.build_sd(owner=acl.SID_ADMINISTRATORS)
            self.set_security(path, is_dir, descriptor, acl.SECINFO_OWNER, lambda a: a.WRITE_OWNER)
        except FsError as e:
            raise FsError(e.kind, f"Besitzübernahme fehlgeschlagen: {e.message}") from e
        self.grant_access(path, is_dir, acl.SID_ADMINISTRATORS)


def create_home_folder(backend, path, sid):
    """Create a home folder and grant the account (sid) full control. Returns 'created' or 'exists'.

    Only the last folder is created (the parent folder must exist). An existing folder
    is NOT touched, because it could belong to someone else.
    """
    try:
        _server, _share, parts = parse_unc(path)
    except ValueError as e:
        raise FsError("other", f"Ungültiger Pfad: {e}") from e
    if not parts:
        raise FsError("other", "Der Pfad zeigt auf die Freigabe selbst, nicht auf einen Ordner darin.")
    try:
        backend.mkdir(path)
    except FsError as e:
        if e.kind == "exists":
            return "exists"
        if e.kind == "notfound":
            raise FsError("notfound", "Der übergeordnete Ordner oder die Freigabe existiert nicht.") from e
        raise
    backend.grant_access(path, True, sid)
    return "created"


def open_backend(user):
    """SMB access with the credentials of the logged-on user (replaceable in tests)."""
    return SmbBackend(user["bind_user"], user["password"])
