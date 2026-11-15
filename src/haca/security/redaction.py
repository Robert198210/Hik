"""Log secret redaction.

``install_redaction()`` attaches a :class:`SecretRedactor` filter to the root logger and to the
``haca`` logger so every record is masked before handlers format it. The same filter is also added
to each handler on the root logger (existing and later-added); calling ``install_redaction()``
again only attaches the redactor to handlers that do not already have it.
"""

from __future__ import annotations

import logging
import re
import traceback

_REDACTION_INSTALLED = False

_REGISTERED_SECRETS: set[str] = set()

_AUTHORIZATION_HEADER = re.compile(r"(?im)(Authorization:\s*).+")
_DIGEST_QUOTED = re.compile(r'(?i)\b(response|cnonce|nonce)="[^"]*"')
_DIGEST_FIELD = re.compile(r'(?i)\b(response|cnonce)=([^,\s"]+)')
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*(\S+)"
)
_KV_SECRET_DQUOTED = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*"[^"]*"'
)
_KV_SECRET_SQUOTED = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*'[^']*'"
)
_JSON_PASSWORD = re.compile(r'(?i)"password"\s*:\s*"[^"]*"')
_GEMINI_KEY = re.compile(r"AIza[0-9A-Za-z_-]{35}")
_MAC_COLON = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_SERIAL_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,}\b")


def register_secret(value: str) -> None:
    """Register a value that must never appear in logs."""
    if value:
        _REGISTERED_SECRETS.add(value)


def mask_device_identifiers(text: str) -> str:
    """Mask MAC addresses and serial-like tokens for safe display."""

    def _mask_mac(match: re.Match[str]) -> str:
        parts = match.group(0).split(":")
        if len(parts) == 6:
            return f"**:**:**:**:{parts[4]}:{parts[5]}"
        return "**:**:**:**:**:**"

    def _mask_serial(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) < 4:
            return "****"
        return f"****{token[-4:]}"

    text = _MAC_COLON.sub(_mask_mac, text)
    return _SERIAL_TOKEN.sub(_mask_serial, text)


def redact_text(text: str) -> str:
    """Mask known secret patterns and registered values in *text*."""
    for secret in sorted(_REGISTERED_SECRETS, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, "***")
    text = _AUTHORIZATION_HEADER.sub(r"\1***", text)
    text = _JSON_PASSWORD.sub('"password": "***"', text)
    text = _DIGEST_QUOTED.sub(lambda m: f'{m.group(1)}="***"', text)
    text = _DIGEST_FIELD.sub(lambda m: f"{m.group(1)}=***", text)
    text = _KV_SECRET_DQUOTED.sub(lambda m: f"{m.group(1)}=***", text)
    text = _KV_SECRET_SQUOTED.sub(lambda m: f"{m.group(1)}=***", text)
    text = _KV_SECRET.sub(lambda m: f"{m.group(1)}=***", text)
    text = _GEMINI_KEY.sub("***", text)
    return mask_device_identifiers(text)


class SecretRedactor(logging.Filter):
    """Logging filter applying :func:`redact_text` to rendered messages and tracebacks."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg = redact_text(message)
        record.args = None
        if record.exc_info:
            formatted = "".join(traceback.format_exception(*record.exc_info))
            record.exc_text = redact_text(formatted)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        return True


def install_redaction() -> None:
    """Attach :class:`SecretRedactor` to root/haca loggers and all root handlers."""
    global _REDACTION_INSTALLED
    redactor = SecretRedactor()
    root = logging.getLogger()
    haca = logging.getLogger("haca")
    if not _REDACTION_INSTALLED:
        root.addFilter(redactor)
        haca.addFilter(redactor)
        _REDACTION_INSTALLED = True
    for handler in root.handlers:
        if not any(isinstance(f, SecretRedactor) for f in handler.filters):
            handler.addFilter(redactor)