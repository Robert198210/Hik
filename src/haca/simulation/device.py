"""Single simulated Hikvision device."""

from __future__ import annotations

from importlib.resources.abc import Traversable
from pathlib import Path

import httpx

from haca.simulation.digest import DigestAuthState
from haca.simulation.faults import FaultProfile
from haca.simulation.profile_loader import (
    load_path_responses,
    shared_malformed_body,
    shared_not_support_body,
    shared_url_not_found_body,
)

_CONTENT_XML = 'application/xml; charset="UTF-8"'
_TIMEOUT_MSG = "simulated read timeout"


class SimulatedDevice:
    def __init__(
        self,
        device_id: str,
        profile_dir: Path | Traversable,
        username: str,
        password: str,
        faults: FaultProfile | None = None,
    ) -> None:
        self.device_id = device_id
        self._username = username
        self._password = password
        self._faults = faults or FaultProfile()
        self._paths = load_path_responses(profile_dir)
        self._digest = DigestAuthState()
        self._timeout_count = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        raw_path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")

        if method != "GET":
            return httpx.Response(
                405,
                headers={"Allow": "GET"},
                content=b"",
            )

        if self._faults.connect_error:
            raise httpx.ConnectError(f"simulated device {self.device_id} unreachable")

        if self._timeout_count < self._faults.read_timeout_times:
            self._timeout_count += 1
            raise httpx.ReadTimeout(_TIMEOUT_MSG)

        auth = request.headers.get("Authorization")
        if auth is None or self._faults.auth_always_fail:
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": self._digest.challenge_header()},
                content=b"",
            )

        if not self._digest.verify(request, self._username, self._password, auth):
            self._digest.rotate_nonce()
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": self._digest.challenge_header()},
                content=b"",
            )

        if raw_path in self._faults.not_support_paths:
            return httpx.Response(
                200,
                headers={"Content-Type": _CONTENT_XML},
                content=shared_not_support_body(),
            )

        if raw_path in self._faults.malformed_paths:
            return httpx.Response(
                200,
                headers={"Content-Type": _CONTENT_XML},
                content=shared_malformed_body(),
            )

        if raw_path in self._faults.http_status_override:
            status = self._faults.http_status_override[raw_path]
            body = b""
            if raw_path in self._paths:
                body = self._paths[raw_path].body
            return httpx.Response(status, headers={"Content-Type": _CONTENT_XML}, content=body)

        entry = self._paths.get(raw_path)
        if entry is None:
            return httpx.Response(
                404,
                headers={"Content-Type": _CONTENT_XML},
                content=shared_url_not_found_body(),
            )

        return httpx.Response(
            entry.status,
            headers={"Content-Type": _CONTENT_XML},
            content=entry.body,
        )