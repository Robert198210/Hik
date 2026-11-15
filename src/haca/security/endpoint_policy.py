"""ISAPI endpoint allowlist and authorization."""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import parse_qsl, unquote_to_bytes

from defusedxml.ElementTree import ParseError, fromstring  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field

from haca.security.denylist import is_denied_path
from haca.security.errors import PolicyViolation

_PLACEHOLDER_RE = re.compile(r"\{(channel|id|track)\}")
_PATH_PARAM_RE = re.compile(r"^[0-9]{1,5}$")
_PERCENT_BYTE_RE = re.compile(rb"%(?P<hex>[0-9a-fA-F]{2})")
_ALLOWED_METHODS = frozenset({"GET", "POST"})


class EndpointRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    path_template: str
    method: Literal["GET", "POST"]
    read_post: bool = False
    allowed_query: frozenset[str] = Field(default_factory=frozenset)
    sensitivity: Literal["normal", "sensitive", "denied"]
    post_root_elements: frozenset[str] = Field(default_factory=frozenset)


class EndpointPolicy:
    def __init__(self, rules: list[EndpointRule]) -> None:
        self._rules = tuple(rules)
        self._by_id = {rule.id: rule for rule in rules}
        self._compiled: list[tuple[re.Pattern[str], EndpointRule]] = []
        for rule in rules:
            pattern = self._compile_template(rule.path_template)
            self._compiled.append((pattern, rule))

    @staticmethod
    def _compile_template(template: str) -> re.Pattern[str]:
        parts: list[str] = []
        last = 0
        for match in _PLACEHOLDER_RE.finditer(template):
            parts.append(re.escape(template[last : match.start()]))
            parts.append(r"[0-9]{1,5}")
            last = match.end()
        parts.append(re.escape(template[last:]))
        return re.compile("^" + "".join(parts) + "$")

    def rule_for(self, endpoint_id: str) -> EndpointRule:
        try:
            return self._by_id[endpoint_id]
        except KeyError as exc:
            msg = f"unknown endpoint id {endpoint_id!r}"
            raise PolicyViolation("not_allowlisted", msg) from exc

    def render(self, endpoint_id: str, **params: int) -> str:
        rule = self.rule_for(endpoint_id)
        path = rule.path_template
        seen: set[str] = set()
        for match in _PLACEHOLDER_RE.finditer(rule.path_template):
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            if name not in params:
                raise PolicyViolation("invalid_params", f"missing path parameter {name!r}")
            value = params[name]
            if not isinstance(value, int) or value < 0 or value > 99999:
                raise PolicyViolation("invalid_params", f"invalid value for {name!r}")
            text = str(value)
            if not _PATH_PARAM_RE.fullmatch(text):
                raise PolicyViolation("invalid_params", f"out of range value for {name!r}")
            path = path.replace(f"{{{name}}}", text, 1)
        if _PLACEHOLDER_RE.search(path):
            raise PolicyViolation("invalid_params", "unsubstituted path placeholders")
        extra = set(params) - seen
        if extra:
            raise PolicyViolation("invalid_params", f"unknown parameters: {sorted(extra)!r}")
        return path

    @staticmethod
    def _check_path_hygiene(raw_path: str) -> None:
        if not raw_path.isascii():
            raise PolicyViolation("path_hygiene", "non-ASCII characters in path")
        if "\x00" in raw_path or "\\" in raw_path:
            raise PolicyViolation("path_hygiene", "illegal character in path")
        if "//" in raw_path:
            raise PolicyViolation("path_hygiene", "double slash in path")
        if (
            "/./" in raw_path
            or raw_path.endswith("/.")
            or "/../" in raw_path
            or raw_path.endswith("/..")
        ):
            raise PolicyViolation("path_hygiene", "path traversal in path")
        lower = raw_path.lower()
        if "%25" in lower:
            raise PolicyViolation("path_hygiene", "double percent-encoding in path")
        for match in _PERCENT_BYTE_RE.finditer(raw_path.encode("ascii", errors="strict")):
            byte_val = int(match.group("hex"), 16)
            if byte_val in (0x2E, 0x2F, 0x5C, 0x00):
                raise PolicyViolation("path_hygiene", "encoded reserved character in path")

    @staticmethod
    def _decode_path(raw_path: str) -> str:
        try:
            decoded_bytes = unquote_to_bytes(raw_path.encode("ascii"))
        except UnicodeError as exc:
            raise PolicyViolation("path_hygiene", "invalid path encoding") from exc
        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyViolation("path_hygiene", "non-UTF-8 decoded path") from exc

    def _match_rule(self, raw_path: str) -> EndpointRule | None:
        for pattern, rule in self._compiled:
            if pattern.fullmatch(raw_path):
                return rule
        return None

    @staticmethod
    def _query_keys(query: str) -> frozenset[str]:
        if not query:
            return frozenset()
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
        return frozenset(key for key, _ in pairs)

    @staticmethod
    def _validate_post_body(rule: EndpointRule, body: bytes | None) -> None:
        if body is None or not body.strip():
            raise PolicyViolation("invalid_post_body", "POST requires a non-empty body")
        try:
            root = fromstring(
                body,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (ParseError, ValueError, TypeError) as exc:
            raise PolicyViolation("invalid_post_body", "POST body is not valid XML") from exc
        local = root.tag.split("}", 1)[-1] if "}" in root.tag else root.tag
        if local not in rule.post_root_elements:
            raise PolicyViolation("invalid_post_body", f"disallowed POST root element {local!r}")

    def authorize(
        self,
        method: str,
        raw_path: str,
        query: str,
        body: bytes | None,
    ) -> EndpointRule:
        self._check_path_hygiene(raw_path)
        decoded = self._decode_path(raw_path)
        if is_denied_path(decoded):
            raise PolicyViolation("denylist_match", "path matches denylist")

        rule = self._match_rule(raw_path)
        if rule is None:
            raise PolicyViolation("not_allowlisted", "no matching endpoint rule")
        if rule.sensitivity == "denied":
            raise PolicyViolation("denied_endpoint", f"endpoint {rule.id!r} is denied")

        method_upper = method.upper()
        if method_upper not in _ALLOWED_METHODS:
            raise PolicyViolation("method_not_allowed", f"method {method_upper!r} not allowed")
        if method_upper == "GET":
            if rule.method != "GET":
                raise PolicyViolation("method_not_allowed", "GET not allowed for this rule")
        elif method_upper == "POST":
            if not rule.read_post:
                raise PolicyViolation("method_not_allowed", "POST not allowed for this rule")
            self._validate_post_body(rule, body)

        query_keys = self._query_keys(query)
        if not query_keys.issubset(rule.allowed_query):
            unknown = query_keys - rule.allowed_query
            raise PolicyViolation("query_not_allowed", f"unknown query keys: {sorted(unknown)!r}")

        return rule