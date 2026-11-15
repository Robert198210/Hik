"""ISAPI client errors."""

from __future__ import annotations


class IsapiError(Exception):
    def __init__(self, device_id: str, endpoint_id: str, message: str = "") -> None:
        self.device_id = device_id
        self.endpoint_id = endpoint_id
        self.message = message
        super().__init__(message or f"{device_id}/{endpoint_id}")


class AuthError(IsapiError):
    pass


class EndpointNotFound(IsapiError):
    pass


class NotSupportedError(IsapiError):
    pass


class DeviceReportedError(IsapiError):
    def __init__(
        self,
        device_id: str,
        endpoint_id: str,
        status_code: int | None,
        sub_status_code: str | None,
    ) -> None:
        self.status_code = status_code
        self.sub_status_code = sub_status_code
        super().__init__(
            device_id,
            endpoint_id,
            f"device status_code={status_code!r} sub_status_code={sub_status_code!r}",
        )


class DeviceTimeout(IsapiError):
    pass


class DeviceConnectionError(IsapiError):
    pass


class XmlParseError(IsapiError):
    def __init__(self, device_id: str, endpoint_id: str, message: str) -> None:
        super().__init__(device_id, endpoint_id, message)


class UnexpectedStatus(IsapiError):
    def __init__(self, device_id: str, endpoint_id: str, http_status: int) -> None:
        self.http_status = http_status
        super().__init__(device_id, endpoint_id, f"unexpected HTTP status {http_status}")