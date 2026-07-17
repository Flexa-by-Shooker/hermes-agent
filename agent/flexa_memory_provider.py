"""Read-only adapter for Engine-governed Flexa Memory v2 recall.

The adapter deliberately owns no business storage, candidate extraction,
approval, or lifecycle writes.  It sends a principal-scoped recall request to
the employee's signed local enforcement route and returns approved context to
Hermes.  Every failure propagates in governed mode; native MEMORY/USER files
are never consulted as a fallback.
"""

from __future__ import annotations

import http.client
import json
import math
from typing import Any
from urllib.parse import urlsplit

from agent.memory_provider import MemoryProvider, MemoryProviderCapabilities
from hermes_cli.flexa_governed import (
    GOVERNED_MEMORY_PROVIDER,
    GOVERNED_MEMORY_SCOPE_VERSION,
    GovernedProfileError,
    binding_for_current_home,
    governed_mode,
    governed_principal_assertion_ready,
    require_governed_principal_binding,
)

_RECALL_PATH = "/v1/memory/recall"
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_HITS = 12
_MAX_QUERY_BYTES = 8_192
_MAX_CONTEXT_SIZE = 32_768
_MAX_HIT_CONTENT_SIZE = 32_768
_MAX_MEMORY_ID_CHARS = 128
_MAX_CITATION_CHARS = 256
_SCOPE_PARTITION_KINDS = {
    "organization_shared": frozenset({"organization"}),
    "employee_private": frozenset({"employee"}),
    "employee_episodic": frozenset({"employee"}),
    "user_private": frozenset({"user_global", "user_employee"}),
    "policy": frozenset({"employee"}),
}
_READ_ONLY_CAPABILITIES = MemoryProviderCapabilities.read_only_recall()


class FlexaMemoryProviderError(RuntimeError):
    """Opaque fail-closed recall error with no user or memory content."""


class FlexaMemoryProvider(MemoryProvider):
    """Bundled governed-scope v1 recall adapter."""

    def __init__(self) -> None:
        self._scope: dict[str, str] | None = None
        self._principal_binding: Any = None
        self._recall_binding: Any = None
        self._endpoint = ""
        self._initial_session_id = ""

    @property
    def name(self) -> str:
        return GOVERNED_MEMORY_PROVIDER

    @property
    def governed_scope_version(self) -> str:
        return GOVERNED_MEMORY_SCOPE_VERSION

    @property
    def capabilities(self) -> MemoryProviderCapabilities:
        return _READ_ONLY_CAPABILITIES

    def is_available(self) -> bool:
        """Check immutable trust material only; never make a network call."""

        return governed_mode() and governed_principal_assertion_ready()

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        """Bind recall to one verified tenant/employee/principal scope."""

        if not governed_mode():
            raise GovernedProfileError("managed memory provider requires governed mode")
        raw_scope = kwargs.get("flexa_scope")
        required_scope_fields = {
            "schema_version",
            "tenant_id",
            "employee_id",
            "profile_slug",
            "principal_namespace",
            "principal_id",
            "release_id",
            "bundle_signing_payload_sha256",
        }
        if not isinstance(raw_scope, dict) or set(raw_scope) != required_scope_fields:
            raise GovernedProfileError("managed memory scope is invalid")
        if any(not isinstance(value, str) or not value for value in raw_scope.values()):
            raise GovernedProfileError("managed memory scope is invalid")
        profile, _binding = binding_for_current_home()
        expected = {
            "schema_version": GOVERNED_MEMORY_SCOPE_VERSION,
            "tenant_id": profile.tenant_id,
            "employee_id": profile.employee_id,
            "profile_slug": profile.slug,
            "release_id": profile.release_id,
            "bundle_signing_payload_sha256": profile.bundle_signing_payload_sha256,
        }
        if any(raw_scope.get(key) != value for key, value in expected.items()):
            raise GovernedProfileError("managed memory scope is invalid")
        principal_binding = require_governed_principal_binding(
            kwargs.get("flexa_principal_binding")
        )
        if (
            principal_binding.tenant_id != raw_scope["tenant_id"]
            or principal_binding.employee_id != raw_scope["employee_id"]
            or principal_binding.profile_id != raw_scope["profile_slug"]
            or principal_binding.release_id != raw_scope["release_id"]
            or principal_binding.principal_namespace
            != raw_scope["principal_namespace"]
            or principal_binding.principal_id != raw_scope["principal_id"]
        ):
            raise GovernedProfileError("managed memory scope is invalid")
        parsed = urlsplit(profile.enforcement_api)
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise GovernedProfileError("managed memory route is invalid")
        self._scope = dict(raw_scope)
        self._principal_binding = principal_binding
        self._endpoint = profile.enforcement_api
        self._initial_session_id = self._validated_session_id(session_id)

    def bind_governed_principal(self, binding: Any) -> None:
        """Refresh proof without permitting the canonical scope to change."""

        scope = self._scope
        if scope is None:
            raise GovernedProfileError("managed memory scope is invalid")
        verified = require_governed_principal_binding(binding)
        if (
            verified.tenant_id != scope["tenant_id"]
            or verified.employee_id != scope["employee_id"]
            or verified.profile_id != scope["profile_slug"]
            or verified.release_id != scope["release_id"]
            or verified.principal_namespace != scope["principal_namespace"]
            or verified.principal_id != scope["principal_id"]
        ):
            raise GovernedProfileError("authenticated memory principal changed")
        self._principal_binding = verified
        # A fresh wire assertion starts a new inbound event.  Never carry an
        # unconsumed active-turn token across that boundary.
        self._recall_binding = None

    def bind_governed_recall(self, binding: Any) -> None:
        """Bind the next synchronous recall to one active Engine turn."""

        from agent.flexa_enforcement import require_governed_recall_binding

        scope = self._scope
        if scope is None:
            raise GovernedProfileError("managed memory scope is invalid")
        verified = require_governed_recall_binding(binding)
        if (
            verified.tenant_id != scope["tenant_id"]
            or verified.employee_id != scope["employee_id"]
            or verified.principal_id != scope["principal_id"]
        ):
            raise GovernedProfileError("governed recall binding is invalid")
        self._validated_session_id(verified.session_id)
        self._validated_turn_id(verified.turn_id)
        self._recall_binding = verified

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """Never expose memory operations to the model."""

        return []

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        """Recall approved context for one query or fail closed."""

        scope = self._scope
        principal_binding = self._principal_binding
        recall_binding = self._recall_binding
        # The active-turn proof is locally single-use even when input or HTTP
        # validation fails.  Engine independently enforces token/turn state.
        self._recall_binding = None
        if (
            scope is None
            or principal_binding is None
            or recall_binding is None
            or not self._endpoint
        ):
            raise FlexaMemoryProviderError("managed memory recall is unavailable")
        if not isinstance(query, str) or not query.strip():
            return ""
        if len(query.encode("utf-8")) > _MAX_QUERY_BYTES:
            raise FlexaMemoryProviderError("managed memory recall request is invalid")
        bound_session_id = self._validated_session_id(
            session_id or self._initial_session_id
        )
        if recall_binding.session_id != bound_session_id:
            raise FlexaMemoryProviderError("managed memory recall is unavailable")
        payload = {
            "query": query,
            "task_id": None,
            "session_id": None,
            "limit": _MAX_HITS,
            "principal_assertion": json.loads(
                principal_binding.assertion_json.decode("utf-8")
            ),
            "turn": {
                "tenant_id": recall_binding.tenant_id,
                "employee_id": recall_binding.employee_id,
                "principal_id": recall_binding.principal_id,
                "session_id": recall_binding.session_id,
                "turn_id": recall_binding.turn_id,
            },
            "turn_context_token": recall_binding.turn_context_token,
        }
        try:
            status, raw = self._post_recall(payload)
            if status != 200 or len(raw) > _MAX_RESPONSE_BYTES:
                raise ValueError("unexpected recall response")
            response = self._strict_json(raw)
            hits = response.get("hits")
            if set(response) != {"hits"} or not isinstance(hits, list):
                raise ValueError("invalid recall response shape")
            if len(hits) > _MAX_HITS:
                raise ValueError("too many recall hits")
            return self._format_hits(hits, scope)
        except FlexaMemoryProviderError:
            raise
        except Exception as exc:
            raise FlexaMemoryProviderError(
                "managed memory recall is unavailable"
            ) from exc

    def _post_recall(self, payload: dict[str, Any]) -> tuple[int, bytes]:
        parsed = urlsplit(self._endpoint)
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
        try:
            connection.request(
                "POST",
                _RECALL_PATH,
                body=encoded,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(encoded)),
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            return response.status, raw
        finally:
            connection.close()

    @staticmethod
    def _validated_session_id(value: Any) -> str:
        session_id = str(value or "").strip()
        if (
            not session_id
            or len(session_id) > 512
            or "\x00" in session_id
            or not session_id.isprintable()
        ):
            raise GovernedProfileError("managed memory session binding is invalid")
        return session_id

    @staticmethod
    def _validated_turn_id(value: Any) -> str:
        identifier = str(value or "").strip()
        if (
            not identifier
            or len(identifier) > 512
            or "\x00" in identifier
            or not identifier.isprintable()
        ):
            raise GovernedProfileError("managed memory turn binding is invalid")
        return identifier

    @staticmethod
    def _strict_json(raw: bytes) -> dict[str, Any]:
        def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"invalid JSON constant: {value}")

        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
        if not isinstance(parsed, dict):
            raise ValueError("recall response must be an object")
        return parsed

    @staticmethod
    def _format_hits(hits: list[Any], scope: dict[str, str]) -> str:
        rendered: list[str] = []
        total_chars = 0
        total_bytes = 0
        for index, hit in enumerate(hits, start=1):
            if not isinstance(hit, dict) or set(hit) != {
                "memory_id",
                "scope",
                "version",
                "content",
                "partition",
                "provenance",
                "score",
            }:
                raise ValueError("recall hit must be an object")
            memory_id = hit.get("memory_id")
            memory_scope = hit.get("scope")
            partition = hit.get("partition")
            content = hit.get("content")
            version = hit.get("version")
            score = hit.get("score")
            provenance = hit.get("provenance")
            if (
                not isinstance(memory_id, str)
                or not memory_id
                or len(memory_id) > _MAX_MEMORY_ID_CHARS
                or "\x00" in memory_id
                or not memory_id.isprintable()
                or not isinstance(memory_scope, str)
                or memory_scope not in _SCOPE_PARTITION_KINDS
                or not isinstance(partition, dict)
                or set(partition)
                != {
                    "kind",
                    "employee_id",
                    "principal_id",
                    "task_id",
                    "session_id",
                }
                or not isinstance(content, str)
                or not content.strip()
                or len(content) > _MAX_HIT_CONTENT_SIZE
                or len(content.encode("utf-8")) > _MAX_HIT_CONTENT_SIZE
                or not isinstance(version, int)
                or isinstance(version, bool)
                or version < 1
                or not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(float(score))
                or not isinstance(provenance, dict)
                or set(provenance) != {"evidence_hash", "citation"}
            ):
                raise ValueError("recall hit is invalid")
            partition_kind = partition.get("kind")
            partition_employee = partition.get("employee_id")
            partition_principal = partition.get("principal_id")
            partition_task = partition.get("task_id")
            partition_session = partition.get("session_id")
            evidence_hash = provenance.get("evidence_hash")
            citation = provenance.get("citation")
            expected_partition = {
                "organization": (None, None, None, None),
                "employee": (scope["employee_id"], None, None, None),
                "user_global": (None, scope["principal_id"], None, None),
                "user_employee": (
                    scope["employee_id"],
                    scope["principal_id"],
                    None,
                    None,
                ),
            }.get(partition_kind)
            if (
                not isinstance(partition_kind, str)
                or partition_kind not in _SCOPE_PARTITION_KINDS[memory_scope]
                or any(
                    value is not None
                    and (
                        not isinstance(value, str)
                        or not value
                        or len(value) > 512
                        or "\x00" in value
                        or not value.isprintable()
                    )
                    for value in (
                        partition_employee,
                        partition_principal,
                        partition_task,
                        partition_session,
                    )
                )
                or expected_partition is None
                or (
                    partition_employee,
                    partition_principal,
                    partition_task,
                    partition_session,
                )
                != expected_partition
                or not isinstance(evidence_hash, str)
                or len(evidence_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in evidence_hash)
                or not isinstance(citation, str)
                or not citation
                or len(citation) > _MAX_CITATION_CHARS
                or "\x00" in citation
                or not citation.isprintable()
            ):
                raise ValueError("recall hit escaped its partition")
            entry = (
                f"[{index}] scope={memory_scope}; id={memory_id}; version={version}; "
                f"evidence_sha256={evidence_hash}; citation={citation}\n"
                f"{content.strip()}"
            )
            total_chars += len(entry)
            total_bytes += len(entry.encode("utf-8"))
            if (
                total_chars > _MAX_CONTEXT_SIZE
                or total_bytes > _MAX_CONTEXT_SIZE
            ):
                raise ValueError("recall context exceeds the governed limit")
            rendered.append(entry)
        return "\n\n".join(rendered)

    def shutdown(self) -> None:
        self._scope = None
        self._principal_binding = None
        self._recall_binding = None
        self._endpoint = ""
        self._initial_session_id = ""
