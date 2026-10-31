# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Einstiegspunkt fuer uvicorn: `uvicorn app:app`. Die Anwendung liegt im Paket samonboarding/."""

from samonboarding.main import app  # noqa: F401
