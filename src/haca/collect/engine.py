"""Sequential ISAPI collection engine."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Network

import httpx

from haca.collect.capabilities import parse_smart_capabilities
from haca.collect.extract import DeviceViews, extract_views, merge_views
from haca.collect.identify import IdentificationResult, IdentificationStatus, identify
from haca.collect.models import (
    CollectionResult,
    DeviceCollection,
    EndpointOutcome,
    PlannedRequest,
    RawEvidence,
)
from haca.collect.normalizer import flatten
from haca.collect.planner import plan
from haca.config.models import TimeoutConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.devices.registry import DeviceRegistry
from haca.isapi.client import IsapiClient, IsapiResponse
from haca.isapi.errors import (
    AuthError,
    DeviceConnectionError,
    DeviceReportedError,
    DeviceTimeout,
    EndpointNotFound,
    IsapiError,
    NotSupportedError,
    XmlParseError,
)
from haca.isapi.registry.loader import (
    RegistryEntry,
    variant_endpoint_id,
)
from haca.isapi.xml import parse_xml
from haca.security.credentials import CredentialStore
from haca.security.egress import EgressPolicy
from haca.security.endpoint_policy import EndpointPolicy
from haca.security.errors import PolicyViolation

_LOGGER = logging.getLogger("haca.collect")

ProgressCallback = Callable[[str, str, EndpointOutcome], None]

_SIM_SUBNET = IPv4Network("192.168.250.0/24")


class CollectionEngine:
    def __init__(
        self,
        registry: tuple[RegistryEntry, ...],
        policy: EndpointPolicy,
        egress: EgressPolicy,
        credential_store: CredentialStore,
        timeouts: TimeoutConfig,
        transport_factory: Callable[[ResolvedDevice], httpx.BaseTransport],
    ) -> None:
        self._registry = registry
        self._registry_by_id = {e.id: e for e in registry}
        self._policy = policy
        self._egress = egress
        self._credential_store = credential_store
        self._timeouts = timeouts
        self._transport_factory = transport_factory

    def collect(
        self,
        devices: list[ResolvedDevice],
        *,
        simulated: bool = False,
        on_progress: ProgressCallback | None = None,
    ) -> CollectionResult:
        started = datetime.now(tz=UTC)
        collections = [
            self._collect_device(device, simulated=simulated, on_progress=on_progress)
            for device in devices
        ]
        return CollectionResult(
            run_started=started,
            run_finished=datetime.now(tz=UTC),
            simulated=simulated,
            devices=collections,
        )

    def _collect_device(
        self,
        device: ResolvedDevice,
        *,
        simulated: bool,
        on_progress: ProgressCallback | None,
    ) -> DeviceCollection:
        cred = self._credential_store.get(device.credential_ref)
        transport = self._transport_factory(device)
        registry = DeviceRegistry([device], NetworkPolicy(_SIM_SUBNET, simulation=True))
        evidence: dict[str, RawEvidence] = {}
        flattened: dict[str, str] = {}
        views = DeviceViews()
        missing_fields: list[str] = []
        capabilities: dict[str, bool] = {}
        identity = None
        offline = False

        with IsapiClient(
            device,
            cred,
            registry,
            self._policy,
            self._egress,
            self._timeouts,
            inner_transport=transport,
            sleep=lambda _s: None,
        ) as client:
            id_result = identify(client, device, simulated=simulated)
            identity = id_result.identity

            for request in plan(device, self._registry):
                if offline:
                    ev = self._offline_evidence(device, request)
                    evidence[request.endpoint_id] = ev
                    self._notify(on_progress, device.id, request.endpoint_id, ev.outcome)
                    continue

                entry = self._registry_by_id.get(request.endpoint_id)

                if request.endpoint_id == "system.device_info":
                    ev = self._device_info_evidence(device, request, id_result, client)
                    evidence[request.endpoint_id] = ev
                    self._notify(on_progress, device.id, request.endpoint_id, ev.outcome)
                    if ev.outcome in (EndpointOutcome.CONNECTION_ERROR, EndpointOutcome.TIMEOUT):
                        offline = True
                    elif ev.outcome == EndpointOutcome.AUTH_DENIED:
                        offline = False
                    elif ev.outcome == EndpointOutcome.COLLECTED and ev.body:
                        views = self._ingest(
                            request.endpoint_id, ev, views, missing_fields, flattened
                        )
                    continue

                gate = self._capability_skip(device, request, entry, capabilities)
                if gate is not None:
                    evidence[request.endpoint_id] = gate
                    self._notify(on_progress, device.id, request.endpoint_id, gate.outcome)
                    continue

                ev = self._read_planned(client, device, request, entry)
                evidence[request.endpoint_id] = ev
                self._notify(on_progress, device.id, request.endpoint_id, ev.outcome)

                if ev.outcome == EndpointOutcome.COLLECTED and ev.body:
                    if request.endpoint_id == "smart.capabilities":
                        with contextlib.suppress(XmlParseError):
                            capabilities = parse_smart_capabilities(parse_xml(ev.body))
                    views = self._ingest(request.endpoint_id, ev, views, missing_fields, flattened)

        return DeviceCollection(
            device_id=device.id,
            role=device.role,
            identity=identity,
            evidence=evidence,
            views=views,
            missing_fields=tuple(missing_fields),
            flattened=flattened,
        )

    @staticmethod
    def _notify(
        cb: ProgressCallback | None,
        device_id: str,
        endpoint_id: str,
        outcome: EndpointOutcome,
    ) -> None:
        if cb is not None:
            cb(device_id, endpoint_id, outcome)

    def _capability_skip(
        self,
        device: ResolvedDevice,
        request: PlannedRequest,
        entry: RegistryEntry | None,
        capabilities: dict[str, bool],
    ) -> RawEvidence | None:
        if entry is None or not entry.capability_gate:
            return None
        gate = entry.capability_gate
        if gate in capabilities and capabilities[gate] is False:
            return RawEvidence(
                device_id=device.id,
                endpoint_id=request.endpoint_id,
                path=self._policy.render(request.endpoint_id, **request.params),
                outcome=EndpointOutcome.SKIPPED_CAPABILITY,
                http_status=None,
                sub_status_code="capability_false",
                sha256=None,
                body=None,
                collected_at=datetime.now(tz=UTC),
                elapsed_ms=0.0,
            )
        return None

    def _device_info_evidence(
        self,
        device: ResolvedDevice,
        request: PlannedRequest,
        id_result: IdentificationResult,
        client: IsapiClient,
    ) -> RawEvidence:
        status = id_result.status
        if status == IdentificationStatus.POLICY_BLOCKED:
            return self._error_evidence(
                device, request, EndpointOutcome.BLOCKED_BY_POLICY, None, None
            )
        if status == IdentificationStatus.AUTH_FAILED:
            return self._error_evidence(device, request, EndpointOutcome.AUTH_DENIED, 401, None)
        if status == IdentificationStatus.UNREACHABLE:
            return self._error_evidence(
                device, request, EndpointOutcome.CONNECTION_ERROR, None, None
            )
        if status == IdentificationStatus.NOT_SUPPORTED:
            return self._error_evidence(
                device, request, EndpointOutcome.NOT_SUPPORTED, 200, "notSupport"
            )
        if status == IdentificationStatus.ENDPOINT_NOT_FOUND:
            return self._error_evidence(
                device, request, EndpointOutcome.ENDPOINT_NOT_FOUND, 404, "RequestUrlNotFound"
            )
        if status not in (IdentificationStatus.IDENTIFIED, IdentificationStatus.MODEL_MISMATCH):
            return self._error_evidence(device, request, EndpointOutcome.PARSE_ERROR, None, None)
        try:
            response = client.read(request.endpoint_id, **request.params)
        except Exception:  # noqa: BLE001
            return self._error_evidence(device, request, EndpointOutcome.PARSE_ERROR, None, None)
        return self._from_response(device, request.endpoint_id, response)

    def _read_planned(
        self,
        client: IsapiClient,
        device: ResolvedDevice,
        request: PlannedRequest,
        entry: RegistryEntry | None,
    ) -> RawEvidence:
        try:
            response = client.read(request.endpoint_id, **request.params)
            return self._from_response(device, request.endpoint_id, response)
        except PolicyViolation as exc:
            _LOGGER.warning(
                "collection policy blocked %s %s: %s",
                device.id,
                request.endpoint_id,
                exc.reason_code,
            )
            return self._error_evidence(
                device, request, EndpointOutcome.BLOCKED_BY_POLICY, None, str(exc.reason_code)
            )
        except AuthError:
            return self._error_evidence(device, request, EndpointOutcome.AUTH_DENIED, 401, None)
        except DeviceTimeout:
            return self._error_evidence(device, request, EndpointOutcome.TIMEOUT, None, None)
        except DeviceConnectionError:
            return self._error_evidence(
                device, request, EndpointOutcome.CONNECTION_ERROR, None, None
            )
        except NotSupportedError:
            return self._error_evidence(
                device, request, EndpointOutcome.NOT_SUPPORTED, 200, "notSupport"
            )
        except EndpointNotFound:
            if entry and entry.variants:
                for index in range(len(entry.variants)):
                    variant_id = variant_endpoint_id(request.endpoint_id, index)
                    try:
                        response = client.read(variant_id, **request.params)
                        return self._from_response(device, request.endpoint_id, response)
                    except EndpointNotFound:
                        continue
                    except PolicyViolation as exc:
                        _LOGGER.warning(
                            "collection policy blocked variant %s %s",
                            device.id,
                            variant_id,
                        )
                        return self._error_evidence(
                            device,
                            request,
                            EndpointOutcome.BLOCKED_BY_POLICY,
                            None,
                            str(exc.reason_code),
                        )
                    except AuthError:
                        return self._error_evidence(
                            device, request, EndpointOutcome.AUTH_DENIED, 401, None
                        )
                    except NotSupportedError:
                        return self._error_evidence(
                            device, request, EndpointOutcome.NOT_SUPPORTED, 200, "notSupport"
                        )
                    except (
                        DeviceConnectionError,
                        DeviceTimeout,
                        XmlParseError,
                        DeviceReportedError,
                    ) as exc:
                        return self._exception_evidence(device, request, exc)
            return self._error_evidence(
                device, request, EndpointOutcome.ENDPOINT_NOT_FOUND, 404, "RequestUrlNotFound"
            )
        except XmlParseError:
            return self._error_evidence(device, request, EndpointOutcome.PARSE_ERROR, None, None)
        except (DeviceReportedError, IsapiError) as exc:
            return self._exception_evidence(device, request, exc)

    def _exception_evidence(
        self,
        device: ResolvedDevice,
        request: PlannedRequest,
        exc: Exception,
    ) -> RawEvidence:
        if isinstance(exc, DeviceTimeout):
            outcome = EndpointOutcome.TIMEOUT
        elif isinstance(exc, DeviceConnectionError):
            outcome = EndpointOutcome.CONNECTION_ERROR
        else:
            outcome = EndpointOutcome.PARSE_ERROR
        path = self._render_path(request)
        return RawEvidence(
            device_id=device.id,
            endpoint_id=request.endpoint_id,
            path=path,
            outcome=outcome,
            http_status=None,
            sub_status_code=None,
            sha256=None,
            body=None,
            collected_at=datetime.now(tz=UTC),
            elapsed_ms=0.0,
        )

    def _from_response(
        self,
        device: ResolvedDevice,
        endpoint_id: str,
        response: IsapiResponse,
    ) -> RawEvidence:
        sub = None
        status_obj = response.response_status
        if status_obj is not None:
            sub = getattr(status_obj, "sub_status_code", None)
        return RawEvidence(
            device_id=device.id,
            endpoint_id=endpoint_id,
            path=response.path,
            outcome=EndpointOutcome.COLLECTED,
            http_status=response.http_status,
            sub_status_code=sub,
            sha256=response.sha256,
            body=response.body,
            collected_at=datetime.now(tz=UTC),
            elapsed_ms=response.elapsed_ms,
        )

    def _error_evidence(
        self,
        device: ResolvedDevice,
        request: PlannedRequest,
        outcome: EndpointOutcome,
        http_status: int | None,
        sub_status: str | None,
    ) -> RawEvidence:
        return RawEvidence(
            device_id=device.id,
            endpoint_id=request.endpoint_id,
            path=self._render_path(request),
            outcome=outcome,
            http_status=http_status,
            sub_status_code=sub_status,
            sha256=None,
            body=None,
            collected_at=datetime.now(tz=UTC),
            elapsed_ms=0.0,
        )

    def _offline_evidence(self, device: ResolvedDevice, request: PlannedRequest) -> RawEvidence:
        return RawEvidence(
            device_id=device.id,
            endpoint_id=request.endpoint_id,
            path=self._render_path(request),
            outcome=EndpointOutcome.SKIPPED_DEVICE_OFFLINE,
            http_status=None,
            sub_status_code=None,
            sha256=None,
            body=None,
            collected_at=datetime.now(tz=UTC),
            elapsed_ms=0.0,
        )

    def _render_path(self, request: PlannedRequest) -> str:
        return self._policy.render(request.endpoint_id, **request.params)

    @staticmethod
    def _ingest(
        endpoint_id: str,
        ev: RawEvidence,
        views: DeviceViews,
        missing_fields: list[str],
        flattened: dict[str, str],
    ) -> DeviceViews:
        if not ev.body:
            return views
        try:
            doc = parse_xml(ev.body)
        except XmlParseError:
            return views
        for key, value in flatten(doc).items():
            flattened[f"{endpoint_id}:{key}"] = value
        patch = extract_views(endpoint_id, doc, missing_fields)
        return merge_views(views, patch)