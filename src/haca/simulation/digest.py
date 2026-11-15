"""Minimal RFC 7616 Digest authentication verification for the device simulator."""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass, field

from httpx import Request

SIMULATED_REALM = "HACA-SIMULATED"
SIMULATED_QOP = "auth"
SIMULATED_ALGORITHM = "MD5"

_AUTH_PAIR = re.compile(r'(\w+)=("([^"]*)"|([^\s,]+))')


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _parse_digest_params(header_value: str) -> dict[str, str]:
    if header_value.lower().startswith("digest "):
        header_value = header_value[7:]
    params: dict[str, str] = {}
    for match in _AUTH_PAIR.finditer(header_value):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4)
        params[key] = value
    return params


@dataclass
class DigestAuthState:
    """Per-device Digest nonce state."""

    current_nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    valid_nonces: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.valid_nonces.add(self.current_nonce)

    def challenge_header(self) -> str:
        return (
            f'Digest realm="{SIMULATED_REALM}", qop="{SIMULATED_QOP}", '
            f'nonce="{self.current_nonce}", algorithm={SIMULATED_ALGORITHM}'
        )

    def rotate_nonce(self) -> None:
        self.valid_nonces.add(self.current_nonce)
        self.current_nonce = uuid.uuid4().hex
        self.valid_nonces.add(self.current_nonce)
        if len(self.valid_nonces) > 8:
            self.valid_nonces = {self.current_nonce}

    def verify(
        self,
        request: Request,
        username: str,
        password: str,
        authorization: str,
    ) -> bool:
        params = _parse_digest_params(authorization)
        if params.get("username") != username:
            return False
        if params.get("realm") != SIMULATED_REALM:
            return False
        nonce = params.get("nonce", "")
        if nonce not in self.valid_nonces:
            return False
        response = params.get("response", "")
        if not response:
            return False

        uri = params.get("uri") or request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        method = request.method
        qop = params.get("qop", "")
        nc = params.get("nc", "")
        cnonce = params.get("cnonce", "")

        ha1 = _md5_hex(f"{username}:{SIMULATED_REALM}:{password}")
        ha2 = _md5_hex(f"{method}:{uri}")
        if qop == SIMULATED_QOP:
            expected = _md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            expected = _md5_hex(f"{ha1}:{nonce}:{ha2}")
        return secrets.compare_digest(expected, response)