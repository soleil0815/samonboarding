"""Fehlerklassen fuer AD-Operationen."""

from fastapi import HTTPException


class AdError(HTTPException):
    def __init__(self, message, status_code=500):
        super().__init__(status_code=status_code, detail=message)


class DcUnreachable(AdError):
    def __init__(self, message):
        super().__init__(message, status_code=503)
