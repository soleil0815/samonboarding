# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Session management (in memory) and protection against repeated failed logins.

A session ends on logout, after SESSION_IDLE_SECONDS without a request (sliding: every request extends it)
or on restart, because it is kept in memory only. Independently of that, it ends at the latest after
SESSION_MAX_SECONDS (default 12 hours) - the role is then determined again at the next login.
"""

import secrets
import threading
import time

from fastapi import Cookie, HTTPException, status

from .config import LOGIN_LOCK_SECONDS, LOGIN_MAX_ATTEMPTS, SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS

active_sessions = {}

_session_lock = threading.Lock()

_login_failures = {}

_login_lock = threading.Lock()


def create_session(data):
    token = secrets.token_hex(32)
    now = time.time()
    with _session_lock:
        for sid in [k for k, v in active_sessions.items() if v["expires"] <= now]:
            del active_sessions[sid]
        active_sessions[token] = dict(data, sid=token, expires=now + SESSION_IDLE_SECONDS, created=now)
    return token


def drop_session(token):
    if token:
        with _session_lock:
            active_sessions.pop(token, None)
        from . import listcache

        listcache.forget_session(token)


def get_current_user(session_id: str = Cookie(None)):
    if session_id:
        with _session_lock:
            session = active_sessions.get(session_id)
        now = time.time()
        if session and session["expires"] > now and now - session.get("created", now) < SESSION_MAX_SECONDS:
            session["expires"] = now + SESSION_IDLE_SECONDS  # activity extends the session
            return session
        drop_session(session_id)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not logged in.")


def throttle_key(request, username):
    ip = request.client.host if request.client else "?"
    return f"{ip}|{username.lower()}"


def throttle_check(key):
    now = time.time()
    with _login_lock:
        if len(_login_failures) > 1000:
            for k in [k for k, v in _login_failures.items() if not v or now - v[-1] >= LOGIN_LOCK_SECONDS]:
                del _login_failures[k]
        recent = [t for t in _login_failures.get(key, []) if now - t < LOGIN_LOCK_SECONDS]
        if recent:
            _login_failures[key] = recent
        else:
            _login_failures.pop(key, None)
        if len(recent) >= LOGIN_MAX_ATTEMPTS:
            wait = int(LOGIN_LOCK_SECONDS - (now - recent[0])) + 1
            minutes = max(1, (wait + 59) // 60)
            raise HTTPException(
                status_code=429,
                detail=f"Zu viele fehlgeschlagene Anmeldungen. Bitte in {minutes} Minute(n) erneut versuchen.",
            )
        # The attempt counts immediately (under the lock) - otherwise many concurrent requests would all get through
        # before the first failure is recorded. On success, or if no password check took place, it is released.
        _login_failures.setdefault(key, []).append(now)
        return now


def throttle_fail(key):
    """Failure: the attempt recorded by throttle_check simply remains."""


def throttle_release(key, stamp):
    """Withdraws the attempt (e.g. DC unreachable - the password was never checked)."""
    with _login_lock:
        attempts = _login_failures.get(key, [])
        if stamp in attempts:
            attempts.remove(stamp)


def throttle_clear(key):
    with _login_lock:
        _login_failures.pop(key, None)


def peek_session(token):
    """Returns the session for the token (or None) without checking expiry or cookie."""
    with _session_lock:
        return active_sessions.get(token)
