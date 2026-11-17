"""Short progress lines for a live audit. Each line is printed once."""

from __future__ import annotations

from collections.abc import Callable

_READY = {
    "nvr": "NVR odpowiada",
    "ptz": "Kamera obrotowa odpowiada",
    "camera": "Kamera stała odpowiada",
}

_PHASES: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "Czytam czas i sieć",
        frozenset(
            {
                "system.time",
                "system.time.ntp_servers",
                "system.network.interfaces",
            }
        ),
    ),
    ("Czytam harmonogram nagrywania", frozenset({"record.tracks"})),
    (
        "Czytam detekcję linii i strefy",
        frozenset(
            {
                "smart.line_detection",
                "smart.field_detection",
                "smart.region_entrance",
            }
        ),
    ),
    ("Szukam dziennika z ostatnich 24 godzin", frozenset({"content.log_search"})),
    ("Szukam nagrań na torach 101 i 201", frozenset({"content.record_search"})),
)

BEGIN = "Kod aktualny, zaczynam audyt"
COMPARE = "Porównuję odczyt z profilem"
AI_SEND = "Wysyłam skrót do Gemini"
AI_DONE = "Gemini odpowiedziało"
SAVING = "Zapisuję raport"
PUSHING = "Wysyłam raport na GitHub"


class AuditAnnouncer:
    def __init__(
        self,
        roles: dict[str, str],
        write: Callable[[str], None] | None = None,
    ) -> None:
        self._roles = roles
        self._write = write or _print
        self._said: set[str] = set()

    def begin(self) -> None:
        self._say(BEGIN)

    def device_ready(self, device_id: str) -> None:
        text = _READY.get(self._roles.get(device_id, ""))
        if text:
            self._say(text)

    def before_endpoint(self, _device_id: str, endpoint_id: str) -> None:
        for text, endpoints in _PHASES:
            if endpoint_id in endpoints:
                self._say(text)
                return

    def compare(self) -> None:
        self._say(COMPARE)

    def sending_summary(self) -> None:
        self._say(AI_SEND)

    def gemini_replied(self) -> None:
        self._say(AI_DONE)

    def saving_report(self) -> None:
        self._say(SAVING)

    def _say(self, text: str) -> None:
        if text in self._said:
            return
        self._said.add(text)
        self._write(text)


def _print(text: str) -> None:
    print(text, flush=True)
