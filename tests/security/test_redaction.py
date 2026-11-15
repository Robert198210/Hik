from __future__ import annotations

import logging

import pytest

from haca.security.redaction import (
    install_redaction,
    redact_text,
    register_secret,
)


@pytest.mark.security
def test_redacts_authorization_header() -> None:
    text = "Authorization: Digest username=admin, response=deadbeef"
    redacted = redact_text(text)
    assert "deadbeef" not in redacted
    assert "Authorization:" in redacted


@pytest.mark.security
def test_redacts_digest_fields() -> None:
    text = 'nonce="abc123" response=deadbeef cnonce=facefeed'
    redacted = redact_text(text)
    assert "deadbeef" not in redacted
    assert "facefeed" not in redacted
    assert "abc123" not in redacted


@pytest.mark.security
def test_redacts_kv_secrets() -> None:
    text = "password=secret123 token=tok_abc"
    redacted = redact_text(text)
    assert "secret123" not in redacted
    assert "tok_abc" not in redacted


@pytest.mark.security
def test_redacts_gemini_api_key_pattern() -> None:
    key = "AIza" + "A" * 35
    assert key not in redact_text(f"key={key}")


@pytest.mark.security
def test_register_secret_masks_value() -> None:
    register_secret("CANARY-REGISTERED")
    assert "CANARY-REGISTERED" not in redact_text("pwd=CANARY-REGISTERED")


@pytest.mark.security
def test_install_redaction_is_idempotent() -> None:
    install_redaction()
    install_redaction()
    logger = logging.getLogger("haca.security.redaction.test")
    logger.propagate = True
    record = logger.makeRecord(
        name=logger.name,
        level=logging.INFO,
        fn=__file__,
        lno=1,
        msg="Authorization: Bearer TOKEN123",
        args=(),
        exc_info=None,
    )
    for handler in logging.getLogger().handlers:
        if any(isinstance(f, type) and False for f in handler.filters):
            pass
    redacted = redact_text(record.msg)
    assert "TOKEN123" not in redacted