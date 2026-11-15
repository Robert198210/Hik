"""Read-only ISAPI HTTP client."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.registry import DeviceRegistry
from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    DeviceReportedError,
    DeviceTimeout,
    EndpointNotFound,
    IsapiError,
    NotSupportedError,
    UnexpectedStatus,
    XmlParseError,
)
from haca.isapi.response_status import parse_response_status
from haca.isapi.xml import XmlDocument, parse_xml
from haca.security.credentials import Credential
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy
from haca.security.errors import PolicyViolation
from haca.security.transport_guard import ReadOnlyTransport

_RETRYABLE_HTTP = frozenset({502, 503, 504})
_BACKOFF_SECONDS = (0.5, 1.0)
_XML_CONTENT_TYPES = (
    "application/xml",
    "text/xml",
    "application/iso-19136-1+xml",
)


@dataclass(frozen=True)
class IsapiResponse:
    device_id: str
    endpoint_id: str
    path: str
    http_status: int
    content_type: str | None
    body: bytes
    sha256: str
    elapsed_ms: float
    document: XmlDocument | None
    response_status: object | None


class IsapiClient:
    def __init__(
        self,
        device: ResolvedDevice,
        credential: Credential,
        registry: DeviceRegistry,
        policy: EndpointPolicy,
        egress: EgressPolicy,
        timeouts: TimeoutConfig,
        inner_transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._device = device
        self._credential = credential
        self._policy = policy
        self._sleep = sleep
        inner = inner_transport or httpx.HTTPTransport(retries=0)
        transport = ReadOnlyTransport(inner, registry, policy, egress)
        password = credential.password.get_secret_value()
        self._client = httpx.Client(
            transport=transport,
            auth=httpx.DigestAuth(credential.username, password),
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=timeouts.connect,
                read=timeouts.read,
                write=5.0,
                pool=5.0,
            ),
            headers={"Accept": "application/xml"},
            trust_env=False,
        )

    def __enter__(self) -> IsapiClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def read(self, endpoint_id: str, **params: int) -> IsapiResponse:
        rule = self._policy.rule_for(endpoint_id)
        if rule.sensitivity == "denied":
            raise PolicyViolation("denied_endpoint", f"endpoint {endpoint_id!r} is denied")

        path = self._policy.render(endpoint_id, **params)
        url = f"{self._device.scheme}://{self._device.host}:{self._device.port}{path}"
        method = rule.method.upper()

        last_error: Exception | None = None
        attempts = 1 + len(_BACKOFF_SECONDS)
        for attempt in range(attempts):
            try:
                response = self._client.request(method, url)
            except PolicyViolation:
                raise
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                last_error = exc
                if attempt < attempts - 1:
                    self._sleep(_BACKOFF_SECONDS[attempt])
                    continue
                if isinstance(exc, httpx.ReadTimeout):
                    raise DeviceTimeout(
                        self._device.id,
                        endpoint_id,
                        "read timeout after retries",
                    ) from exc
                raise DeviceConnectionError(
                    self._device.id,
                    endpoint_id,
                    "connection failed after retries",
                ) from exc
            except httpx.TimeoutException as exc:
                raise DeviceTimeout(self._device.id, endpoint_id, "request timed out") from exc

            if response.status_code in _RETRYABLE_HTTP and attempt < attempts - 1:
                self._sleep(_BACKOFF_SECONDS[attempt])
                continue

            try:
                return self._build_response(endpoint_id, path, response)
            except IsapiError:
                raise
            except PolicyViolation:
                raise

        if last_error is not None:
            if isinstance(last_error, httpx.ReadTimeout):
                raise DeviceTimeout(
                    self._device.id,
                    endpoint_id,
                    "read timeout",
                ) from last_error
            raise DeviceConnectionError(
                self._device.id,
                endpoint_id,
                "connection failed",
            ) from last_error
        msg = "unreachable"
        raise DeviceConnectionError(self._device.id, endpoint_id, msg)

    def _build_response(
        self,
        endpoint_id: str,
        path: str,
        response: httpx.Response,
    ) -> IsapiResponse:
        body = response.content
        content_type = response.headers.get("Content-Type")
        document: XmlDocument | None = None
        response_status = None

        # 401 is unambiguous; 403 may carry a ResponseStatus such as notSupport.
        if response.status_code == 401:
            raise AuthError(self._device.id, endpoint_id)

        if body:
            try:
                doc = parse_xml(body)
                status = parse_response_status(doc)
                if status is not None:
                    response_status = status
                    if status.sub_status_code == "notSupport":
                        raise NotSupportedError(self._device.id, endpoint_id)
                    if status.sub_status_code == "RequestUrlNotFound":
                        raise EndpointNotFound(self._device.id, endpoint_id)
                    if not status.is_success:
                        raise DeviceReportedError(
                            self._device.id,
                            endpoint_id,
                            status.status_code,
                            status.sub_status_code,
                        )
            except XmlParseError:
                if self._looks_like_xml(body, content_type):
                    raise
                document = None
            else:
                if response_status is None:
                    document = doc

        if response.status_code in (401, 403):
            raise AuthError(self._device.id, endpoint_id)
        if response.status_code == 404:
            raise EndpointNotFound(self._device.id, endpoint_id)
        if response.status_code < 200 or response.status_code >= 300:
            raise UnexpectedStatus(self._device.id, endpoint_id, response.status_code)

        if document is None and body and self._looks_like_xml(body, content_type):
            try:
                document = parse_xml(body)
            except XmlParseError as exc:
                raise XmlParseError(
                    self._device.id,
                    endpoint_id,
                    exc.message,
                ) from exc

        try:
            elapsed_ms = response.elapsed.total_seconds() * 1000.0
        except RuntimeError:
            elapsed_ms = 0.0
        return IsapiResponse(
            device_id=self._device.id,
            endpoint_id=endpoint_id,
            path=path,
            http_status=response.status_code,
            content_type=content_type,
            body=body,
            sha256=hashlib.sha256(body).hexdigest(),
            elapsed_ms=elapsed_ms,
            document=document,
            response_status=response_status,
        )

    @staticmethod
    def _looks_like_xml(body: bytes, content_type: str | None) -> bool:
        if content_type:
            media = content_type.split(";", 1)[0].strip().lower()
            if media in _XML_CONTENT_TYPES:
                return True
        stripped = body.lstrip()
        return stripped.startswith(b"<")