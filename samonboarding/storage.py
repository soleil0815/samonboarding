# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""JSON storage: atomic writing and safe reading of the configuration files."""

import contextlib
import copy
import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)


file_lock = threading.RLock()


def load_json(filename, default):
    with file_lock:
        if not os.path.exists(filename):
            return copy.deepcopy(default)
        try:
            with open(filename, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            # Do not overwrite a corrupt file, back it up instead.
            backup = f"{filename}.corrupt-{int(time.time())}"
            try:
                os.replace(filename, backup)
                log.error("%s ist kein gueltiges JSON - gesichert als %s", filename, backup)
            except OSError as e:
                log.error("%s ist kein gueltiges JSON und konnte nicht gesichert werden: %s", filename, e)
            return copy.deepcopy(default)
        except OSError as e:
            log.error("%s konnte nicht gelesen werden: %s", filename, e)
            return copy.deepcopy(default)


def save_json(filename, data, invalidate=True):
    with file_lock:
        tmp = f"{filename}.tmp"
        # Readable only by the owner: the files contain e.g. the SMTP password
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, filename)
        restrict(filename)
    if invalidate:
        from . import listcache

        listcache.invalidate()  # changed settings (e.g. source OUs) take effect on the lists immediately


def restrict(path):
    """Set permissions to 0600 (best effort, e.g. for existing files from older versions)."""
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
