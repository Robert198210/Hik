"""Load Gemini API key from keyring or environment."""

from __future__ import annotations

import os

import keyring
from pydantic import SecretStr

from haca.security.redaction import register_secret

_SERVICE = "haca"
_GEMINI_KEY_NAME = "gemini_api_key"
_ENV_NAME = "GEMINI_API_KEY"


def load_gemini_api_key() -> SecretStr | None:
    env = os.environ.get(_ENV_NAME)
    if env:
        register_secret(env)
        return SecretStr(env)
    try:
        stored = keyring.get_password(_SERVICE, _GEMINI_KEY_NAME)
    except Exception:  # noqa: BLE001
        stored = None
    if stored:
        register_secret(stored)
        return SecretStr(stored)
    return None