"""httpx transport wrapper enforcing read-only policy."""

from __future__ import annotations

import logging

import httpx

from haca.devices.registry import DeviceRegistry
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy
from haca.security.errors import PolicyViolation

_LOGGER = logging.getLogger("haca.security")


class ReadOnlyTransport(httpx.BaseTransport):
    def __init__(
        self,
        inner: httpx.BaseTransport,
        registry: DeviceRegistry,
        policy: EndpointPolicy,
        egress: EgressPolicy,
    ) -> None:
        self._inner = inner
        self._registry = registry
        self._policy = policy
        self._egress = egress

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("Upgrade") is not None:
            violation = PolicyViolation("upgrade_denied", "Upgrade header not permitted")
            _LOGGER.warning(
                "%s %s blocked: %s",
                request.method,
                request.url.raw_path.decode("ascii", errors="replace"),
                violation.reason_code,
            )
            raise violation

        url = request.url
        try:
            self._egress.check(url)
        except PolicyViolation as exc:
            _LOGGER.warning(
                "%s %s blocked: %s",
                request.method,
                url.raw_path.decode("ascii", errors="replace"),
                exc.reason_code,
            )
            raise

        port = url.port
        if port is None:
            port = 443 if url.scheme == "https" else 80

        host = url.host or ""
        if self._registry.match(host, port, url.scheme) is None:
            violation = PolicyViolation(
                "unknown_device",
                "request target is not a registered device",
            )
            _LOGGER.warning(
                "%s %s blocked: %s",
                request.method,
                url.raw_path.decode("ascii", errors="replace"),
                violation.reason_code,
            )
            raise violation

        query = url.query.decode("ascii") if url.query else ""
        # httpx URL.raw_path includes the query string; the policy needs them separately.
        raw_path = url.raw_path.split(b"?", 1)[0].decode("ascii")

        try:
            self._policy.authorize(request.method, raw_path, query, request.content)
        except PolicyViolation as exc:
            _LOGGER.warning(
                "%s %s blocked: %s",
                request.method,
                raw_path,
                exc.reason_code,
            )
            raise

        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()