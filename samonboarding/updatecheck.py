# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Is a newer version available? For installations that do not update their container automatically.

Once a day the server (never the browser) fetches the public list of releases from GitHub - the same place the
images come from. Nothing is sent along: no version, no identifier, no data from the AD; the request carries only
a fixed User-Agent. The comparison happens here. Administrators then see a note with the update commands.

Switched off with UPDATE_CHECK=false in .env. Without internet access the check simply fails quietly; the reason
is shown in the diagnostic package. A proxy only for this check: UPDATE_CHECK_PROXY in .env.

A fixed version in .env (SAMONBOARDING_VERSION) is respected:
  empty / latest   the newest version
  2.6              the newest 2.6.x including its security updates; a newer line (2.7 ...) is mentioned separately
  2.6.2 / 2.6.2-s1 exactly this version - "docker compose pull" never changes it, so the note names the
                   command to switch to the newest 2.6.x
"""

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request

from .config import BASE_DIR, VERSION
from .routers import news

log = logging.getLogger(__name__)

REPOSITORY = "soleil0815/samonboarding"
RELEASES_URL = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=100"
RELEASE_PAGE = f"https://github.com/{REPOSITORY}/releases/tag/v"
USER_AGENT = "SAMONBOARDING-update-check"  # fixed: no version, no identifier
TIMEOUT_SECONDS = 15
MAX_BYTES = 8 * 1024 * 1024
FIRST_DELAY_SECONDS = 60  # after the start: the program is up before anything goes out
INTERVAL_SECONDS = 24 * 3600
RETRY_SECONDS = 6 * 3600  # after a failure: not more often than this

_TAG_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-s\d+)?)$")
_PIN_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+)(?:-s\d+)?)?$")

_lock = threading.Lock()
_state = {"checkedAt": None, "ok": None, "problem": None, "versions": []}


def enabled(env=None):
    """UPDATE_CHECK in .env: empty or missing = on (like every other setting, empty means the default)."""
    env = os.environ if env is None else env
    value = str(env.get("UPDATE_CHECK", "") or "").strip().lower()
    return not value or value in ("1", "true", "yes", "on")


def pin(env=None):
    """SAMONBOARDING_VERSION from .env -> ("", "") | ("line", "2.6") | ("exact", "2.6.2"). Unknown = no pin."""
    env = os.environ if env is None else env
    raw = str(env.get("SAMONBOARDING_VERSION", "") or "").strip().lower()
    match = _PIN_RE.match(raw)
    if not match:
        return ("", "")
    line = f"{match.group(1)}.{match.group(2)}"
    return ("exact", raw) if match.group(3) is not None else ("line", line)


def installed():
    """Installed release including the security-update counter, from the changelog shipped in the image."""
    try:
        text = (BASE_DIR / news.FILES["en"]).read_text(encoding="utf-8")
    except OSError:
        return VERSION
    return news.installed(news.parse(text, limit=10_000))


def parse_releases(payload):
    """GitHub's answer -> sorted list of published version numbers (no drafts, no pre-releases, nothing odd)."""
    if not isinstance(payload, list):
        raise ValueError("unexpected answer")
    found = set()
    for release in payload:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        match = _TAG_RE.match(str(release.get("tag_name") or ""))
        if match:
            found.add(match.group(1))
    return sorted(found, key=news.version_key)


def _line(version):
    return ".".join(version.split("-s")[0].split(".")[:2])


def evaluate(current, versions, pinned=("", "")):
    """None if nothing is newer; otherwise what to show. Pure function - no network, no state."""
    kind, value = pinned
    key = news.version_key(current)
    newer = [v for v in versions if news.version_key(v) > key]
    if not newer:
        return None
    newest = max(newer, key=news.version_key)
    own_line = value if kind == "line" else _line(value) if kind == "exact" else ""
    within = [v for v in newer if not own_line or _line(v) == own_line]
    latest = max(within, key=news.version_key) if within else None
    outside = newest if own_line and newest != latest else None
    if latest is None and outside is None:
        return None
    note = {"installed": current, "pin": value, "latest": latest, "outside": outside}
    if latest:
        note["level"] = "security" if latest.split("-s")[0] == current.split("-s")[0] else "version"
        note["url"] = RELEASE_PAGE + latest
        # a line pin or no pin: "pull" fetches it; an exact pin never changes by itself
        note["switch"] = kind == "exact"
    if outside:
        note["outsideLine"] = _line(outside)
        note["outsideUrl"] = RELEASE_PAGE + outside
    return note


def _fetch():
    request = urllib.request.Request(
        RELEASES_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    # Own setting instead of HTTPS_PROXY: that would also send the connections to Exchange through the proxy
    proxy = os.environ.get("UPDATE_CHECK_PROXY", "").strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy})) if proxy else None
    open_url = opener.open if opener else urllib.request.urlopen
    with open_url(request, timeout=TIMEOUT_SECONDS) as answer:  # noqa: S310 - fixed https URL
        body = answer.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("answer too large")
    return json.loads(body.decode("utf-8"))


def _problem(error):
    """A short class of the error - never the message itself (it may name a proxy or an internal host)."""
    if isinstance(error, urllib.error.HTTPError):
        return f"http-{error.code}"
    if isinstance(error, TimeoutError) or "timed out" in str(getattr(error, "reason", "")):
        return "timeout"
    if isinstance(error, urllib.error.URLError):
        return "network"
    if isinstance(error, (ValueError, UnicodeDecodeError)):
        return "answer"
    return "other"


def check(fetch=None, now=None):
    """Ask GitHub once and remember the result. Returns True if the list could be read."""
    fetch = fetch or _fetch
    now = time.time() if now is None else now
    try:
        versions = parse_releases(fetch())
    except Exception as e:
        problem = _problem(e)
        with _lock:
            _state.update(checkedAt=now, ok=False, problem=problem)
        log.info("Versionspruefung nicht moeglich (%s) - naechster Versuch spaeter", problem)
        return False
    with _lock:
        _state.update(checkedAt=now, ok=True, problem=None, versions=versions)
    return True


def status():
    """For the diagnostic package: switched on, last check, result - no addresses, no messages."""
    with _lock:
        state = dict(_state)
    checked = state["checkedAt"]
    return {
        "eingeschaltet": enabled(),
        "festeVersion": pin()[1] or None,
        "installiert": installed(),
        "zuletztGeprueft": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(checked)) if checked else None,
        "ergebnis": None if state["ok"] is None else ("ok" if state["ok"] else state["problem"]),
        "neuesteVeroeffentlicht": state["versions"][-1] if state["versions"] else None,
    }


def notice():
    """The note for administrators, or None (switched off, not checked yet, failed, or up to date)."""
    if not enabled():
        return None
    with _lock:
        versions = list(_state["versions"])
    if not versions:
        return None
    return evaluate(installed(), versions, pin())


def start_thread():
    """Check shortly after the start and then daily in the background. Returns the stop event."""
    stop = threading.Event()
    if not enabled():
        log.info("Versionspruefung ausgeschaltet (UPDATE_CHECK=false)")
        return stop

    def loop():
        wait = FIRST_DELAY_SECONDS
        while not stop.wait(wait):
            wait = INTERVAL_SECONDS if check() else RETRY_SECONDS

    threading.Thread(target=loop, name="update-check", daemon=True).start()
    return stop
