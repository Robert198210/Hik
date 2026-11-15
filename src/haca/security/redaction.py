"""Log secret redaction."""

from __future__ import annotations

import logging
import re

_REDACTION_INSTALLED = False

_REGISTERED_SECRETS: set[str] = set()

_AUTHORIZATION_HEADER = re.compile(r"(?im)(Authorization:\s*).+")
_DIGEST_FIELD = re.compile(r'(?i)\b(response|cnonce)=([^,\s"]+)')
_DIGEST_QUOTED = re.compile(r'(?i)\b(nonce)="[^"]*"')
_KV_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*(\S+)"
)
_GEMINI_KEY = re.compile(r"AIza[0-9A-Za-z_-]{35}")


def register_secret(value: str) -> None:
    """Register a value that must never appear in logs."""
    if value:
        _REGISTERED_SECRETS.add(value)


def redact_text(text: str) -> str:
    """Mask known secret patterns and registered values in *text*."""
    for secret in sorted(_REGISTERED_SECRETS, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, "***")
    text = _AUTHORIZATION_HEADER.sub(r"\1***", text)
    text = _DIGEST_QUOTED.sub(r'\1="***"', text)
    text = _DIGEST_FIELD.sub(lambda m: f"{m.group(1)}=***", text)
    text = _KV_SECRET.sub(lambda m: f"{m.group(1)}=***", text)
    return _GEMINI_KEY.sub("***", text)


class SecretRedactor(logging.Filter):
    """Logging filter applying :func:`redact_text` to messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            record.args = tuple(
                redact_text(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        return True


def install_redaction() -> None:
    """Attach :class:`SecretRedactor` to every handler on the root logger (idempotent)."""
    global _REDACTION_INSTALLED
    if _REDACTION_INSTALLED:
        return
    redactor = SecretRedactor()
    root = logging.getLogger()
    for handler in root.handlers:
        handler.addFilter(redactor)
    root.addFilter(redactor)
    _REDACTION_INSTALLED = True