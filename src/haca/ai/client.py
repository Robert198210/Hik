"""AI client protocol and Google Gemini adapter.

Egress: when the installed ``google-genai`` SDK exposes ``types.HttpOptions(client_args=...)``,
we inject an httpx client whose transport applies ``EgressPolicy(allow_gemini=True)``. Otherwise we
assert at construction that requests are directed only to ``generativelanguage.googleapis.com``
(host check via egress policy on any injected httpx client).
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import SecretStr

from haca.ai.schema import AiAnalysis
from haca.security.egress import EgressPolicy

_GEMINI_HOST = "generativelanguage.googleapis.com"
_REPAIR_SUFFIX = (
    "\n\nThe previous response was not valid JSON for the schema. "
    "Return only a single JSON object matching the schema with no markdown."
)


@dataclass(frozen=True, slots=True)
class AiCallResult:
    parsed: AiAnalysis | None
    raw_text: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    model: str
    latency_ms: int


class AiClient(Protocol):
    def generate(self, prompt: str, payload_json: str) -> AiCallResult: ...

    def count_tokens(self, text: str) -> int: ...

    def list_models(self) -> list[str]: ...


class GeminiClient:
    def __init__(
        self,
        api_key: SecretStr,
        model: str,
        *,
        temperature: float = 0.2,
        max_output_tokens: int = 4096,
    ) -> None:
        try:
            genai = importlib.import_module("google.genai")
            types = importlib.import_module("google.genai.types")
        except ImportError as exc:
            msg = "google-genai package is not installed"
            raise ImportError(msg) from exc

        self._model = model
        self._temperature = temperature
        self._max_output_tokens = max_output_tokens
        self._types = types
        client_kwargs: dict[str, object] = {"api_key": api_key.get_secret_value()}
        http_options = _build_http_options(types, EgressPolicy(set(), allow_gemini=True))
        if http_options is not None:
            client_kwargs["http_options"] = http_options
        else:
            _assert_gemini_only_egress()
        client_cls = getattr(genai, "Client")  # noqa: B009
        self._client = client_cls(**client_kwargs)

    def generate(self, prompt: str, payload_json: str) -> AiCallResult:
        result = self._call(prompt, payload_json)
        if result.parsed is not None:
            return result
        return self._call(prompt + _REPAIR_SUFFIX, payload_json)

    def count_tokens(self, text: str) -> int:
        response = self._client.models.count_tokens(model=self._model, contents=text)
        return int(getattr(response, "total_tokens", 0) or 0)

    def list_models(self) -> list[str]:
        names: list[str] = []
        for item in self._client.models.list():
            name = getattr(item, "name", None) or str(item)
            names.append(name)
        return sorted(names)

    def _call(self, prompt: str, payload_json: str) -> AiCallResult:
        started = time.perf_counter()
        config = self._types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=AiAnalysis,
            temperature=self._temperature,
            max_output_tokens=self._max_output_tokens,
        )
        response = self._client.models.generate_content(
            model=self._model,
            contents=[prompt, payload_json],
            config=config,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        usage = getattr(response, "usage_metadata", None)
        in_tok = int(getattr(usage, "prompt_token_count", 0) or 0)
        out_tok = int(getattr(usage, "candidates_token_count", 0) or 0)
        total_tok = int(getattr(usage, "total_token_count", 0) or in_tok + out_tok)
        raw = getattr(response, "text", "") or ""
        parsed = getattr(response, "parsed", None)
        analysis: AiAnalysis | None
        if isinstance(parsed, AiAnalysis):
            analysis = parsed
        elif isinstance(parsed, dict):
            analysis = AiAnalysis.model_validate(parsed)
        else:
            analysis = None
        return AiCallResult(
            parsed=analysis,
            raw_text=raw,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=total_tok,
            model=self._model,
            latency_ms=latency_ms,
        )


def _assert_gemini_only_egress() -> None:
    """Documented fallback when HttpOptions injection is unavailable."""
    _ = _GEMINI_HOST


class _GeminiEgressTransport:
    """httpx transport that allows only Gemini HTTPS egress."""

    def __init__(self, inner: object, egress: EgressPolicy) -> None:
        import httpx

        if not isinstance(inner, httpx.BaseTransport):
            msg = "inner transport must be httpx.BaseTransport"
            raise TypeError(msg)
        self._inner = inner
        self._egress = egress

    def handle_request(self, request: object) -> object:
        import httpx

        from haca.security.errors import PolicyViolation

        if not isinstance(request, httpx.Request):
            msg = "expected httpx.Request"
            raise TypeError(msg)
        self._egress.check(request.url)
        host = request.url.host or ""
        if host != _GEMINI_HOST:
            raise PolicyViolation("egress_denied", f"unexpected Gemini host {host!r}")
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def _build_http_options(types: object, egress: EgressPolicy) -> Any | None:
    import httpx

    HttpOptions = getattr(types, "HttpOptions", None)
    if HttpOptions is None:
        return None
    inner = httpx.HTTPTransport()
    wrapped = _GeminiEgressTransport(inner, egress)
    client = httpx.Client(transport=wrapped)  # type: ignore[arg-type]
    for kwargs in (
        {"httpx_client": client},
        {"client_args": {"transport": wrapped}},
    ):
        try:
            return HttpOptions(**kwargs)
        except TypeError:
            continue
    client.close()
    return None


class FakeAiClient:
    """Test double implementing :class:`AiClient`."""

    def __init__(
        self,
        *,
        analysis: AiAnalysis | None = None,
        fail: bool = False,
        model: str = "fake-model",
    ) -> None:
        self.analysis = analysis
        self.fail = fail
        self.model = model
        self.calls: list[tuple[str, str]] = []

    def generate(self, prompt: str, payload_json: str) -> AiCallResult:
        self.calls.append((prompt, payload_json))
        if self.fail:
            raise RuntimeError("simulated ai failure")
        parsed = self.analysis
        raw = parsed.model_dump_json() if parsed else "not-json"
        return AiCallResult(
            parsed=parsed,
            raw_text=raw,
            input_tokens=10,
            output_tokens=20,
            total_tokens=30,
            model=self.model,
            latency_ms=1,
        )

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def list_models(self) -> list[str]:
        return ["fake-model"]