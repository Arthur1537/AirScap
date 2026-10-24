"""Redaction of scanner secrets in log output (mirrors internal/vens/redact.go).

The default password is the last four characters of the serial
(Scanner.password_from_serial), the pairing identity is derived from the
password, and every control and data packet carries the session token.
None of them may appear in logs or error messages, also not at DEBUG level.
Packets are logged by length only; serials via redact_serial().
RedactingFilter replaces registered secrets in every record as a second
line of defence.
"""

from __future__ import annotations

import logging
import threading

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 3

_lock = threading.Lock()
_secrets: list[str] = []


def redact_serial(serial: str) -> str:
    """Keep the model prefix (up to the last '-') and mask the rest."""
    s = serial.rstrip(" \x00")
    if not s:
        return ""
    i = s.rfind("-")
    if 0 < i < len(s) - 1:
        return s[: i + 1] + "****"
    return "****"


def register_secret(secret: str | bytes | None) -> None:
    """Add a value that must never appear in log output."""
    if secret is None:
        return
    if isinstance(secret, bytes):
        register_secret(secret.hex())
        register_secret(secret.hex().upper())
        return
    secret = secret.rstrip(" \x00")
    if len(secret) < MIN_SECRET_LENGTH:
        return
    with _lock:
        if secret not in _secrets:
            _secrets.append(secret)


def scrub(text: str) -> str:
    """Replace every registered secret in text."""
    with _lock:
        secrets = list(_secrets)
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


class RedactingFilter(logging.Filter):
    """Formats the message, then removes registered secrets from it."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = scrub(record.getMessage())
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = scrub(
                logging.Formatter().formatException(record.exc_info)
            )
            record.exc_info = None
        return True


def install(handler: logging.Handler) -> None:
    """Attach the filter to a handler (filters on loggers miss children)."""
    handler.addFilter(RedactingFilter())
