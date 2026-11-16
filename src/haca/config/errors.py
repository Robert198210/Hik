"""Configuration loading errors."""

from __future__ import annotations

from pathlib import Path

_SECRET_KEY_PATTERN = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "username",
        "user",
        "credential",
        "private_key",
    }
)


class ConfigError(Exception):
    """Raised when configuration validation fails."""

    def __init__(self, path: Path, field: str, message: str) -> None:
        self.path = path
        self.field = field
        self.message = message
        super().__init__(f"{path}: {field}: {message}")

    _TOKEN_ALLOWLIST = frozenset(
        {
            "max_output_tokens",
            "max_input_tokens",
        }
    )

    @staticmethod
    def secret_field_name(key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        if normalized in ConfigError._TOKEN_ALLOWLIST:
            return False
        if normalized in _SECRET_KEY_PATTERN:
            return True
        return any(part in normalized for part in ("password", "secret", "token"))