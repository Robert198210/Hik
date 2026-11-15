"""Security policy exceptions."""

from __future__ import annotations


class PolicyViolation(Exception):
    """Raised when a request violates read-only security policy."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(reason_code)