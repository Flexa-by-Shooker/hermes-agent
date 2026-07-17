"""Fail-closed live-turn enforcement for Flexa-governed Hermes runtimes.

The enforcement sidecar owns the policy decision and the opaque turn token.
Hermes keeps only short-lived in-process routing state, keyed by the immutable
tenant/profile/session/turn identity.  Tokens are never placed in prompts,
tool arguments, RPC payloads, logs, or durable Hermes state.
"""

from __future__ import annotations

import contextvars
import copy
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from hermes_cli.flexa_governed import (
    GovernedProfileError,
    ManagedProfile,
    binding_for_current_home,
    ensure_governed_content_free_logging,
    governed_mode,
)

_MAX_BOUNDARY_BYTES = 10_000_000
_REQUEST_LIMITS = {
    "channel.ingress": 262_144,
    "hermes.input": 262_144,
    "memory.retrieval": 1_048_576,
    "hermes.tool-proposal": 1_048_576,
    "hermes.tool-result": 2_097_152,
    "memory.candidate": 1_048_576,
    "hermes.output": 1_048_576,
    "revoke": 65_536,
}
_TURN_TTL_SECONDS = 3600.0
_ATTACHMENT_INBOX_PARTS = (".flexa", "inbox")
_ATTACHMENT_MAX_COUNT = 8
_ATTACHMENT_MAX_BYTES = 25 * 1024 * 1024
_ATTACHMENT_MAX_TOTAL_BYTES = 50 * 1024 * 1024
_ATTACHMENT_INBOX_MAX_FILES = 64
_ATTACHMENT_INBOX_MAX_BYTES = 200 * 1024 * 1024
_ATTACHMENT_CIPHERTEXT_OVERHEAD = 16
_ATTACHMENT_STAGING_LIFETIME_SECONDS = _TURN_TTL_SECONDS
_ATTACHMENT_RETENTION_SECONDS = 2 * _ATTACHMENT_STAGING_LIFETIME_SECONDS
_ATTACHMENT_TEXT_MAX_BYTES = 2 * 1024 * 1024
_ATTACHMENT_TEXT_MAX_LINES = 20_000
_ATTACHMENT_READ_MAX_LINES = 500
_ATTACHMENT_READ_MAX_CHARS = 100_000
_ATTACHMENT_BROKER_MAX_SERIALIZED_CHARS = 96_000
_ATTACHMENT_VIRTUAL_LINE_MAX_CHARS = 1_000
_OPAQUE_ATTACHMENT_NAME = re.compile(r"^[a-f0-9]{32}\.[a-z0-9]{1,8}$")
_ATTACHMENT_SUFFIXES = frozenset({
    ".bmp", ".csv", ".doc", ".docx", ".gif", ".jpeg", ".jpg",
    ".json", ".m4a", ".md", ".mov", ".mp3", ".mp4", ".ogg",
    ".opus", ".pdf", ".png", ".ppt", ".pptx", ".txt", ".wav",
    ".webm", ".webp", ".xls", ".xlsx",
})
_AGENT_TURN_KEY = "_flexa_governed_turn_key"
_AGENT_PERSISTENCE_LOCK = "_flexa_governed_persistence_lock"
_AGENT_PERSISTENCE_QUARANTINE = "_flexa_persistence_quarantined"
_AGENT_PERSISTENCE_SAFE_SNAPSHOT = "_flexa_persistence_safe_snapshot"
_RECALL_BINDING_PROOF = object()
_BOUND_TURN: contextvars.ContextVar[TurnKey | None] = contextvars.ContextVar(
    "flexa_governed_turn_binding", default=None
)


class FlexaEnforcementError(RuntimeError):
    """Opaque fail-closed boundary failure; never contains request content."""


@dataclass(frozen=True, repr=False)
class TurnKey:
    tenant_id: str
    employee_id: str
    principal_id: str
    profile_slug: str
    session_id: str
    turn_id: str


@dataclass(frozen=True)
class GovernedTurnInput:
    """Trusted in-process handoff; never serialized to RPC/model/tool data."""

    key: TurnKey
    model_message: Any
    persistence_message: Any


@dataclass(frozen=True, repr=False)
class GovernedRecallBinding:
    """Opaque, content-free proof binding one recall to an active turn."""

    tenant_id: str
    employee_id: str
    principal_id: str
    session_id: str
    turn_id: str
    turn_context_token: str = field(repr=False, compare=False)
    _proof: object = field(repr=False, compare=False)


class GovernedAttachmentPrompt(str):
    """String prompt carrying non-serializable cleanup ownership."""

    attachment_ids: tuple[str, ...]

    def __new__(cls, value: str, attachment_ids: tuple[str, ...]):
        instance = super().__new__(cls, value)
        instance.attachment_ids = attachment_ids
        return instance


class GovernedNativeAttachmentContent(list):
    """Trusted native image parts whose bytes never cross policy HTTP."""

    attachment_ids: tuple[str, ...]
    boundary_text: str

    def __init__(
        self,
        value: list[Any],
        attachment_ids: tuple[str, ...],
        boundary_text: str,
    ):
        super().__init__(value)
        self.attachment_ids = attachment_ids
        self.boundary_text = boundary_text


@dataclass
class _TurnState:
    key: TurnKey
    endpoint: str
    token: str = field(repr=False)
    phase: str
    expires_at: float
    attachment_ids: tuple[str, ...] = ()
    pending_tools: dict[str, tuple[str, str]] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)


@dataclass
class _AttachmentRecord:
    """Process-local key material for one ciphertext-only spool object."""

    attachment_id: str
    workspace: Path
    tenant_id: str
    employee_id: str
    profile_slug: str
    suffix: str
    plaintext_size: int
    key: bytearray = field(repr=False)
    nonce: bytes = field(repr=False)
    aad: bytes = field(repr=False)
    created_at: float
    turn_key: TurnKey | None = None


_REGISTRY_LOCK = threading.RLock()
_ATTACHMENT_LOCK = threading.RLock()
_TURN_STATES: dict[TurnKey, _TurnState] = {}
_ATTACHMENT_RECORDS: dict[str, _AttachmentRecord] = {}
_CLOCK: Callable[[], float] = time.monotonic


def _arguments_digest(arguments: dict[str, Any]) -> str:
    encoded = json.dumps(
        arguments,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_owned_attachment_tool(
    name: str,
    arguments: dict[str, Any],
    attachment_ids: tuple[str, ...],
) -> None:
    """Bind the broker tool to one exact attachment in the current turn."""

    if name != "read_attachment":
        return
    if set(arguments) - {"attachment_id", "offset", "limit"}:
        raise FlexaEnforcementError("managed attachment request is invalid")
    arguments.setdefault("offset", 1)
    arguments.setdefault("limit", _ATTACHMENT_READ_MAX_LINES)
    attachment_id = arguments.get("attachment_id")
    if (
        not isinstance(attachment_id, str)
        or not _OPAQUE_ATTACHMENT_NAME.fullmatch(attachment_id)
        or attachment_id not in attachment_ids
    ):
        raise FlexaEnforcementError("managed attachment is unavailable")
    for field_name in ("offset", "limit"):
        value = arguments.get(field_name)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool)
        ):
            raise FlexaEnforcementError("managed attachment pagination is invalid")


def _require_boolean(name: str, expected: str) -> None:
    if os.environ.get(name, "").strip().lower() != expected:
        raise FlexaEnforcementError("governed semantic policy evidence is incomplete")


def require_governed_runtime(agent: Any) -> None:
    if not governed_mode():
        return
    ensure_governed_content_free_logging()
    profile, _config = binding_for_current_home()
    if not profile.buffered_output:
        raise FlexaEnforcementError("governed profile binding is invalid")
    _require_boolean("FLEXA_GUARDRAILS_RAISE_ERRORS", "true")
    _require_boolean("FLEXA_GUARDRAILS_INCLUDE_REASONING", "false")
    # Codex app-server owns its own tool execution and persistence surfaces.
    # Until it exposes every Flexa boundary, governed deployments deny it at
    # the transport seam instead of pretending the Hermes hooks cover it.
    if getattr(agent, "api_mode", None) == "codex_app_server":
        raise FlexaEnforcementError("runtime transport is unavailable in governed mode")


def _session_id(agent: Any, explicit: str | None = None) -> str:
    value = str(explicit or getattr(agent, "session_id", None) or "").strip()
    if not value or len(value) > 512 or "\x00" in value:
        raise FlexaEnforcementError("governed turn session binding is invalid")
    return value


def _profile_and_endpoint() -> tuple[ManagedProfile, str]:
    profile, _binding = binding_for_current_home()
    parsed = urlsplit(profile.enforcement_api)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.port is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise FlexaEnforcementError("profile enforcement route is invalid")
    return profile, profile.enforcement_api


def _typed_content(value: Any) -> str:
    return json.dumps(
        {"kind": "text" if isinstance(value, str) else "json", "value": value},
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_typed_content(value: str, original: Any) -> Any:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise FlexaEnforcementError("sanitized boundary content is invalid") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"kind", "value"}:
        raise FlexaEnforcementError("sanitized boundary content shape is invalid")
    if isinstance(original, str):
        if parsed["kind"] != "text" or not isinstance(parsed["value"], str):
            raise FlexaEnforcementError("sanitized boundary content type changed")
    elif parsed["kind"] != "json" or not isinstance(
        parsed["value"], (dict, list, int, float, bool, type(None))
    ):
        raise FlexaEnforcementError("sanitized boundary content type changed")
    return parsed["value"]


def _post_json(endpoint: str, path: str, body: dict[str, Any]) -> tuple[int, bytes]:
    parsed = urlsplit(endpoint)
    stage = path.rsplit("/", 1)[-1]
    limit = _REQUEST_LIMITS.get(stage, 262_144)

    def _bounded_size(value: Any, *, depth: int = 0) -> int:
        if depth > 32:
            raise FlexaEnforcementError("enforcement request is too complex")
        if value is None or isinstance(value, (bool, int, float)):
            return 16
        if isinstance(value, str):
            size = len(value.encode("utf-8"))
            if size > limit:
                raise FlexaEnforcementError("enforcement request is too large")
            return size
        if isinstance(value, list):
            total = 2
            for item in value:
                total += _bounded_size(item, depth=depth + 1) + 1
                if total > limit:
                    raise FlexaEnforcementError("enforcement request is too large")
            return total
        if isinstance(value, dict):
            total = 2
            for key, item in value.items():
                if not isinstance(key, str):
                    raise FlexaEnforcementError("enforcement request shape is invalid")
                total += _bounded_size(key, depth=depth + 1)
                total += _bounded_size(item, depth=depth + 1) + 2
                if total > limit:
                    raise FlexaEnforcementError("enforcement request is too large")
            return total
        raise FlexaEnforcementError("enforcement request contains binary content")

    _bounded_size(body)
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > limit:
        raise FlexaEnforcementError("enforcement request is too large")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
    try:
        connection.request(
            "POST",
            path,
            body=encoded,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(_MAX_BOUNDARY_BYTES + 1)
        return response.status, raw
    finally:
        connection.close()


def _boundary_request(
    state: _TurnState | None,
    key: TurnKey,
    endpoint: str,
    path: str,
    content: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> tuple[str, str | None]:
    try:
        request_id = str(uuid.uuid4())
        safe_metadata = dict(metadata or {})
        if {"content", "token", "turn_context_token"}.intersection(safe_metadata):
            raise FlexaEnforcementError("reserved enforcement metadata")
        body: dict[str, Any] = {
            "schema_version": "1",
            "request_id": request_id,
            "content": content,
            "turn": {
                "tenant_id": key.tenant_id,
                "employee_id": key.employee_id,
                "principal_id": key.principal_id,
                "session_id": key.session_id,
                "turn_id": key.turn_id,
            },
        }
        if state is not None:
            body["turn_context_token"] = state.token
        if safe_metadata:
            body["metadata"] = safe_metadata
        status, raw = _post_json(endpoint, f"/v1/boundaries/{path}", body)
        if status != 200 or len(raw) > _MAX_BOUNDARY_BYTES:
            raise FlexaEnforcementError("enforcement service rejected the boundary")
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "request_id",
            "path",
            "decision",
            "committed",
            "sanitized_content",
            "finding_ids",
            "turn_context_token",
        }:
            raise FlexaEnforcementError("enforcement response shape is invalid")
        if (
            value["schema_version"] != "1"
            or value["request_id"] != request_id
            or value["path"] != path
            or value["decision"] != "allow"
            or value["committed"] is not True
            or not isinstance(value["sanitized_content"], str)
            or not isinstance(value["finding_ids"], list)
            or any(not isinstance(item, str) for item in value["finding_ids"])
        ):
            raise FlexaEnforcementError("enforcement boundary failed closed")
        return value["sanitized_content"], value["turn_context_token"]
    except (FlexaEnforcementError, GovernedProfileError):
        raise
    except Exception as exc:
        raise FlexaEnforcementError("enforcement service unavailable") from exc


def _agent_key(agent: Any) -> TurnKey:
    key = getattr(agent, _AGENT_TURN_KEY, None)
    if not isinstance(key, TurnKey):
        key = _BOUND_TURN.get()
    if not isinstance(key, TurnKey):
        raise FlexaEnforcementError("governed turn handoff is missing")
    return key


def _state_for(agent: Any) -> _TurnState:
    key = _agent_key(agent)
    with _REGISTRY_LOCK:
        state = _TURN_STATES.get(key)
    if state is None:
        raise FlexaEnforcementError("governed turn is unavailable")
    if _CLOCK() >= state.expires_at:
        _drop_local_state(agent, state)
        raise FlexaEnforcementError("governed turn expired")
    profile, endpoint = _profile_and_endpoint()
    from hermes_cli.flexa_governed import require_governed_principal_binding

    principal = require_governed_principal_binding(
        getattr(agent, "_governed_principal_binding", None)
    )
    if (
        profile.tenant_id != key.tenant_id
        or profile.employee_id != key.employee_id
        or profile.slug != key.profile_slug
        or endpoint != state.endpoint
        or _session_id(agent) != key.session_id
        or principal.tenant_id != key.tenant_id
        or principal.employee_id != key.employee_id
        or principal.profile_id != key.profile_slug
        or principal.principal_id != key.principal_id
    ):
        raise FlexaEnforcementError("governed turn binding mismatch")
    return state


def _drop_local_state(agent: Any, state: _TurnState) -> None:
    with _REGISTRY_LOCK:
        if _TURN_STATES.get(state.key) is state:
            _TURN_STATES.pop(state.key, None)
    if getattr(agent, _AGENT_TURN_KEY, None) == state.key:
        try:
            delattr(agent, _AGENT_TURN_KEY)
        except (AttributeError, TypeError):
            setattr(agent, _AGENT_TURN_KEY, None)
    if getattr(agent, "_flexa_turn_id", None) == state.key.turn_id:
        setattr(agent, "_flexa_turn_id", None)
    if _BOUND_TURN.get() == state.key:
        _BOUND_TURN.set(None)
    for attachment_id in state.attachment_ids:
        try:
            delete_governed_upload(attachment_id)
        except FlexaEnforcementError:
            pass


def channel_ingress(
    agent: Any,
    content: Any,
    *,
    platform: str,
    session_id: str | None = None,
    persistence_content: Any | None = None,
) -> Any:
    """Create the trusted channel-to-agent handoff for one new turn."""

    if not governed_mode():
        return content
    require_governed_runtime(agent)
    attachment_ids = tuple(getattr(content, "attachment_ids", ()))
    existing = getattr(agent, _AGENT_TURN_KEY, None)
    if isinstance(existing, TurnKey):
        for attachment_id in attachment_ids:
            try:
                delete_governed_upload(attachment_id)
            except FlexaEnforcementError:
                pass
        raise FlexaEnforcementError("agent already owns a governed turn")
    profile, endpoint = _profile_and_endpoint()
    from hermes_cli.flexa_governed import require_governed_principal_binding

    principal = require_governed_principal_binding(
        getattr(agent, "_governed_principal_binding", None)
    )
    if (
        principal.tenant_id != profile.tenant_id
        or principal.employee_id != profile.employee_id
        or principal.profile_id != profile.slug
        or not principal.principal_id
    ):
        raise FlexaEnforcementError("governed principal binding mismatch")
    key = TurnKey(
        tenant_id=profile.tenant_id,
        employee_id=profile.employee_id,
        principal_id=principal.principal_id,
        profile_slug=profile.slug,
        session_id=_session_id(agent, session_id),
        turn_id=str(uuid.uuid4()),
    )
    _bind_attachment_records_to_turn(attachment_ids, key)
    envelope = {
        "model_message": content,
        "persistence_message": content if persistence_content is None else persistence_content,
    }
    try:
        sanitized, token = _boundary_request(
            None,
            key,
            endpoint,
            "channel.ingress",
            _typed_content(envelope),
            metadata={"platform": str(platform or "unknown")[:128]},
        )
    except Exception:
        for attachment_id in attachment_ids:
            try:
                delete_governed_upload(attachment_id)
            except FlexaEnforcementError:
                pass
        raise
    if not isinstance(token, str) or not token or len(token) > 4096:
        for attachment_id in attachment_ids:
            try:
                delete_governed_upload(attachment_id)
            except FlexaEnforcementError:
                pass
        raise FlexaEnforcementError("turn context token is missing")
    state = _TurnState(
        key=key,
        endpoint=endpoint,
        token=token,
        phase="channel.ingress",
        expires_at=_CLOCK() + _TURN_TTL_SECONDS,
        attachment_ids=attachment_ids,
    )
    with _REGISTRY_LOCK:
        if key in _TURN_STATES:
            for attachment_id in attachment_ids:
                try:
                    delete_governed_upload(attachment_id)
                except FlexaEnforcementError:
                    pass
            raise FlexaEnforcementError("governed turn identity collision")
        _TURN_STATES[key] = state
    setattr(agent, _AGENT_TURN_KEY, key)
    setattr(agent, "_flexa_turn_id", key.turn_id)
    _BOUND_TURN.set(key)
    try:
        sanitized_envelope = _decode_typed_content(sanitized, envelope)
        if not isinstance(sanitized_envelope, dict) or set(sanitized_envelope) != {
            "model_message", "persistence_message"
        }:
            raise FlexaEnforcementError("sanitized ingress envelope is invalid")
    except Exception:
        revoke_turn(agent)
        raise
    return GovernedTurnInput(
        key=key,
        model_message=sanitized_envelope["model_message"],
        persistence_message=sanitized_envelope["persistence_message"],
    )


def has_channel_handoff(agent: Any) -> bool:
    if not governed_mode():
        return False
    try:
        return _state_for(agent).phase == "channel.ingress"
    except FlexaEnforcementError:
        return False


def governed_native_attachment_input(
    content: GovernedTurnInput,
    parts: list[dict[str, Any]],
    image_attachment_ids: tuple[str, ...],
) -> GovernedTurnInput:
    """Attach verified in-memory native image parts after text-only ingress."""

    if not isinstance(content, GovernedTurnInput):
        raise FlexaEnforcementError("governed input handoff is invalid")
    state = _bound_turn_state()
    if content.key != state.key or state.phase != "channel.ingress":
        raise FlexaEnforcementError("governed native attachment phase is invalid")
    if not isinstance(content.model_message, str):
        raise FlexaEnforcementError("governed native attachment text is invalid")
    if (
        not image_attachment_ids
        or len(set(image_attachment_ids)) != len(image_attachment_ids)
        or not set(image_attachment_ids).issubset(state.attachment_ids)
        or len(parts) != len(image_attachment_ids) + 1
        or not isinstance(parts[0], dict)
        or parts[0].get("type") != "text"
        or not isinstance(parts[0].get("text"), str)
    ):
        raise FlexaEnforcementError("governed native attachment input is invalid")
    profile, workspace, _inbox = _attachment_profile_identity()
    image_suffixes = {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"}
    expected_urls: list[str] = []
    with _ATTACHMENT_LOCK:
        for attachment_id in image_attachment_ids:
            record = _ATTACHMENT_RECORDS.get(attachment_id)
            if (
                record is None
                or not _record_is_live(record)
                or record.turn_key != state.key
                or record.suffix not in image_suffixes
                or not _record_matches_profile(record, profile, workspace)
            ):
                raise FlexaEnforcementError("managed image attachment is unavailable")
            from agent.image_routing import image_bytes_to_data_url

            expected_url = image_bytes_to_data_url(
                _decrypt_attachment_record(record), record.suffix
            )
            if expected_url is None:
                raise FlexaEnforcementError("managed image attachment is unavailable")
            expected_urls.append(expected_url)
    for part, expected_url in zip(parts[1:], expected_urls, strict=True):
        if not isinstance(part, dict) or set(part) != {"type", "image_url"}:
            raise FlexaEnforcementError("governed native image part is invalid")
        image_url = part.get("image_url")
        url = image_url.get("url") if isinstance(image_url, dict) else None
        if (
            part.get("type") != "image_url"
            or not isinstance(url, str)
            or not url.startswith("data:image/")
            or ";base64," not in url[:128]
            or len(url) > ((_ATTACHMENT_MAX_BYTES + 2) // 3) * 4 + 4096
            or url != expected_url
        ):
            raise FlexaEnforcementError("governed native image part is invalid")
    native = GovernedNativeAttachmentContent(
        [dict(part) for part in parts],
        image_attachment_ids,
        content.model_message,
    )
    return GovernedTurnInput(
        key=content.key,
        model_message=native,
        persistence_message=content.persistence_message,
    )


def turn_active(agent: Any) -> bool:
    """Return whether ``agent`` owns an unrevoked in-process turn state."""

    key = getattr(agent, _AGENT_TURN_KEY, None)
    if not isinstance(key, TurnKey):
        return False
    with _REGISTRY_LOCK:
        return key in _TURN_STATES


def governed_recall_binding(agent: Any) -> GovernedRecallBinding:
    """Return an opaque recall proof for the current sanitized active turn."""

    if not governed_mode():
        raise FlexaEnforcementError("governed recall binding is unavailable")
    state = _state_for(agent)
    with state.lock:
        if state.phase != "memory.retrieval" or state.pending_tools:
            raise FlexaEnforcementError("governed recall boundary is unavailable")
        from hermes_cli.flexa_governed import require_governed_principal_binding

        principal = require_governed_principal_binding(
            getattr(agent, "_governed_principal_binding", None)
        )
        if (
            principal.tenant_id != state.key.tenant_id
            or principal.employee_id != state.key.employee_id
            or principal.profile_id != state.key.profile_slug
            or principal.principal_id != state.key.principal_id
        ):
            raise FlexaEnforcementError("governed recall principal is invalid")
        return GovernedRecallBinding(
            tenant_id=state.key.tenant_id,
            employee_id=state.key.employee_id,
            principal_id=state.key.principal_id,
            session_id=state.key.session_id,
            turn_id=state.key.turn_id,
            turn_context_token=state.token,
            _proof=_RECALL_BINDING_PROOF,
        )


def require_governed_recall_binding(value: Any) -> GovernedRecallBinding:
    """Validate an opaque recall proof passed between reviewed components."""

    if (
        not isinstance(value, GovernedRecallBinding)
        or value._proof is not _RECALL_BINDING_PROOF
        or not value.turn_context_token
    ):
        raise FlexaEnforcementError("governed recall binding is unavailable")
    return value


def governed_persistence_lock(agent: Any) -> threading.RLock:
    """Return the per-agent lock serializing governed persistence lifecycle."""

    lock = getattr(agent, _AGENT_PERSISTENCE_LOCK, None)
    if lock is not None:
        return lock
    with _REGISTRY_LOCK:
        lock = getattr(agent, _AGENT_PERSISTENCE_LOCK, None)
        if lock is None:
            lock = threading.RLock()
            setattr(agent, _AGENT_PERSISTENCE_LOCK, lock)
    return lock


def governed_persistence_quarantined(agent: Any) -> bool:
    """Return whether teardown permanently disabled this agent's persistence."""

    return getattr(agent, _AGENT_PERSISTENCE_QUARANTINE, False) is True


def quarantine_governed_persistence(
    agent: Any,
    safe_messages: list[dict[str, Any]],
) -> None:
    """Atomically quarantine persistence and install a committed safe snapshot."""

    snapshot = copy.deepcopy(safe_messages)
    lock = governed_persistence_lock(agent)
    with lock:
        setattr(agent, _AGENT_PERSISTENCE_QUARANTINE, True)
        setattr(agent, _AGENT_PERSISTENCE_SAFE_SNAPSHOT, snapshot)
        agent._session_messages = copy.deepcopy(snapshot)


def restore_governed_quarantine_snapshot(agent: Any) -> bool:
    """Restore the safe snapshot when quarantined; return whether it applied."""

    lock = governed_persistence_lock(agent)
    with lock:
        if not governed_persistence_quarantined(agent):
            return False
        snapshot = getattr(agent, _AGENT_PERSISTENCE_SAFE_SNAPSHOT, [])
        agent._session_messages = copy.deepcopy(
            [message for message in snapshot if isinstance(message, dict)]
        )
        return True


def _advance(
    agent: Any,
    path: str,
    content: str,
    *,
    allowed_phases: set[str],
    next_phase: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    state = _state_for(agent)
    with state.lock:
        if state.phase not in allowed_phases:
            raise FlexaEnforcementError("governed boundary phase is invalid")
        sanitized, token = _boundary_request(
            state, state.key, state.endpoint, path, content, metadata=metadata
        )
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise FlexaEnforcementError("turn context token is missing")
        if token != state.token:
            raise FlexaEnforcementError("turn context token changed unexpectedly")
        state.phase = next_phase
        return sanitized


def user_input(agent: Any, content: Any) -> Any:
    require_governed_runtime(agent)
    if not governed_mode():
        return content
    if not isinstance(content, GovernedTurnInput) or content.key != _agent_key(agent):
        raise FlexaEnforcementError("governed input handoff is invalid")
    native_content = (
        content.model_message
        if isinstance(content.model_message, GovernedNativeAttachmentContent)
        else None
    )
    envelope = {
        "model_message": (
            native_content.boundary_text
            if native_content is not None
            else content.model_message
        ),
        "persistence_message": content.persistence_message,
    }
    sanitized = _advance(
        agent,
        "hermes.input",
        _typed_content(envelope),
        allowed_phases={"channel.ingress"},
        next_phase="hermes.input",
    )
    sanitized_envelope = _decode_typed_content(sanitized, envelope)
    if not isinstance(sanitized_envelope, dict) or set(sanitized_envelope) != {
        "model_message", "persistence_message"
    }:
        raise FlexaEnforcementError("sanitized input envelope is invalid")
    model_message = sanitized_envelope["model_message"]
    if native_content is not None:
        if not isinstance(model_message, str):
            raise FlexaEnforcementError("sanitized native attachment text is invalid")
        model_parts = [dict(part) for part in native_content]
        model_parts[0] = {"type": "text", "text": model_message}
        model_message = model_parts
    return GovernedTurnInput(
        key=content.key,
        model_message=model_message,
        persistence_message=sanitized_envelope["persistence_message"],
    )


def memory_retrieval(agent: Any, content: str, *, target: str) -> str:
    if not governed_mode():
        return content
    return _advance(
        agent,
        "memory.retrieval",
        content,
        allowed_phases={"hermes.input", "memory.retrieval"},
        next_phase="memory.retrieval",
        metadata={"target": str(target)[:256]},
    )


def tool_proposal(
    agent: Any,
    name: str,
    arguments: dict[str, Any],
    *,
    operation_id: str | None = None,
) -> tuple[str, dict[str, Any], str]:
    require_governed_runtime(agent)
    if not governed_mode():
        return name, arguments, operation_id or str(uuid.uuid4())
    op_id = str(operation_id or uuid.uuid4())
    if not op_id or len(op_id) > 512 or "\x00" in op_id:
        raise FlexaEnforcementError("tool operation binding is invalid")
    state = _state_for(agent)
    with state.lock:
        if state.phase not in {
            "hermes.input", "memory.retrieval", "tools", "memory.candidate"
        }:
            raise FlexaEnforcementError("governed boundary phase is invalid")
        if state.pending_tools:
            raise FlexaEnforcementError("concurrent tool proposals are unavailable")
        if op_id in state.pending_tools:
            raise FlexaEnforcementError("tool proposal replayed")
        _require_owned_attachment_tool(name, arguments, state.attachment_ids)
        payload = json.dumps(
            {"arguments": arguments, "name": name},
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        sanitized, token = _boundary_request(
            state,
            state.key,
            state.endpoint,
            "hermes.tool-proposal",
            payload,
            metadata={"operation_id": op_id, "tool_name": name},
        )
        if token != state.token:
            raise FlexaEnforcementError("turn context token changed unexpectedly")
        try:
            value = json.loads(sanitized)
        except json.JSONDecodeError as exc:
            raise FlexaEnforcementError("sanitized tool proposal is invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"arguments", "name"}
            or value.get("name") != name
            or not isinstance(value.get("arguments"), dict)
        ):
            raise FlexaEnforcementError("sanitized tool proposal shape is invalid")
        _require_owned_attachment_tool(
            name, value["arguments"], state.attachment_ids
        )
        state.pending_tools[op_id] = (name, _arguments_digest(value["arguments"]))
        state.phase = "tools"
        return name, value["arguments"], op_id


def tool_result(
    agent: Any,
    name: str,
    result: Any,
    *,
    operation_id: str,
) -> Any:
    require_governed_runtime(agent)
    if not governed_mode():
        return result
    state = _state_for(agent)
    with state.lock:
        if (
            state.phase not in {"tools", "memory.candidate"}
            or state.pending_tools.get(operation_id, (None, None))[0] != name
        ):
            raise FlexaEnforcementError("tool result does not match a live proposal")
        sanitized, token = _boundary_request(
            state,
            state.key,
            state.endpoint,
            "hermes.tool-result",
            _typed_content(result),
            metadata={"operation_id": operation_id, "tool_name": name},
        )
        if token != state.token:
            raise FlexaEnforcementError("turn context token changed unexpectedly")
        value = _decode_typed_content(sanitized, result)
        state.pending_tools.pop(operation_id, None)
        return value


def require_tool_dispatch(
    name: str,
    *,
    arguments: dict[str, Any],
    operation_id: str | None,
    session_id: str | None,
    turn_id: str | None,
) -> None:
    """Prove a registry dispatch belongs to an allowed live proposal.

    This closes direct ``model_tools.handle_function_call`` and MCP-server
    bypasses without advancing the sidecar phase a second time.
    """

    if not governed_mode():
        return
    key = _BOUND_TURN.get()
    if not isinstance(key, TurnKey):
        raise FlexaEnforcementError("tool dispatch is missing a governed turn")
    with _REGISTRY_LOCK:
        state = _TURN_STATES.get(key)
    if state is None or _CLOCK() >= state.expires_at:
        raise FlexaEnforcementError("tool dispatch turn is unavailable")
    op_id = str(operation_id or "")
    with state.lock:
        if (
            not op_id
            or state.pending_tools.get(op_id)
            != (name, _arguments_digest(arguments))
            or str(session_id or "") != key.session_id
            or str(turn_id or "") != key.turn_id
        ):
            raise FlexaEnforcementError("tool dispatch binding mismatch")


def governed_tool_denial(name: str) -> str | None:
    """Return an explicit synthetic denial for ungovernable nested dispatch."""

    if not governed_mode():
        return None
    if name == "tool_call":
        return "Tool Search bridge dispatch is unavailable in governed mode"
    if name == "execute_code":
        return "Nested execute_code dispatch is unavailable in governed mode"
    return None


def _path_is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise FlexaEnforcementError("managed attachment path is unavailable") from exc
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(info, "st_file_attributes", 0) & reparse_flag:
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(callable(is_junction) and is_junction())


def _assert_no_reparse_chain(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    chain = list(reversed(absolute.parents)) + [absolute]
    for component in chain:
        if component.exists() and _path_is_reparse_or_symlink(component):
            raise FlexaEnforcementError("managed attachment path is unsafe")


def _attachment_workspace() -> tuple[Path, Path]:
    _profile, binding = binding_for_current_home()
    raw_workspace = str(binding.get("working_directory") or "").strip()
    workspace = Path(raw_workspace)
    if not workspace.is_absolute() or not workspace.is_dir():
        raise FlexaEnforcementError("managed attachment workspace is invalid")
    _assert_no_reparse_chain(workspace)
    workspace = workspace.resolve(strict=True)
    flexa_dir = workspace / _ATTACHMENT_INBOX_PARTS[0]
    inbox = flexa_dir / _ATTACHMENT_INBOX_PARTS[1]
    try:
        flexa_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
        inbox.mkdir(mode=0o700, parents=False, exist_ok=True)
    except OSError as exc:
        raise FlexaEnforcementError("managed attachment inbox is unavailable") from exc
    _assert_no_reparse_chain(inbox)
    if not inbox.is_dir():
        raise FlexaEnforcementError("managed attachment inbox is invalid")
    return workspace, inbox


def _attachment_profile_identity() -> tuple[ManagedProfile, Path, Path]:
    profile, _binding = binding_for_current_home()
    workspace, inbox = _attachment_workspace()
    return profile, workspace, inbox


def _attachment_aad(
    profile: ManagedProfile,
    attachment_id: str,
    suffix: str,
) -> bytes:
    return json.dumps(
        {
            "employee_id": profile.employee_id,
            "format": "flexa-attachment-aes256gcm-v1",
            "profile": profile.slug,
            "suffix": suffix,
            "tenant_id": profile.tenant_id,
            "upload_id": attachment_id,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _record_matches_profile(
    record: _AttachmentRecord,
    profile: ManagedProfile,
    workspace: Path,
) -> bool:
    return (
        record.workspace == workspace
        and record.tenant_id == profile.tenant_id
        and record.employee_id == profile.employee_id
        and record.profile_slug == profile.slug
    )


def _record_is_live(record: _AttachmentRecord) -> bool:
    age = _CLOCK() - record.created_at
    return 0 <= age < _ATTACHMENT_STAGING_LIFETIME_SECONDS


def _wipe_attachment_key(record: _AttachmentRecord) -> None:
    for index in range(len(record.key)):
        record.key[index] = 0


def _read_owned_ciphertext(record: _AttachmentRecord) -> bytes:
    """Read one registry-owned ciphertext through a no-follow descriptor."""

    expected_size = record.plaintext_size + _ATTACHMENT_CIPHERTEXT_OVERHEAD
    workspace = record.workspace
    inbox = workspace / _ATTACHMENT_INBOX_PARTS[0] / _ATTACHMENT_INBOX_PARTS[1]
    if os.name == "posix":
        inbox_fd = _open_posix_inbox(workspace)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(record.attachment_id, flags, dir_fd=inbox_fd)
            try:
                opened = os.fstat(fd)
                linked = os.stat(
                    record.attachment_id,
                    dir_fd=inbox_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_size != expected_size
                    or (opened.st_dev, opened.st_ino)
                    != (linked.st_dev, linked.st_ino)
                ):
                    raise FlexaEnforcementError(
                        "managed attachment ciphertext changed during open"
                    )
                chunks: list[bytes] = []
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(fd, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise FlexaEnforcementError(
                            "managed attachment ciphertext read was incomplete"
                        )
                    chunks.append(chunk)
                    remaining -= len(chunk)
                return b"".join(chunks)
            finally:
                os.close(fd)
        except FlexaEnforcementError:
            raise
        except OSError as exc:
            raise FlexaEnforcementError(
                "managed attachment ciphertext could not be opened"
            ) from exc
        finally:
            os.close(inbox_fd)

    target = inbox / record.attachment_id
    _assert_no_reparse_chain(target)
    before = os.lstat(target)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
        raise FlexaEnforcementError("managed attachment ciphertext is invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise FlexaEnforcementError(
            "managed attachment ciphertext could not be opened"
        ) from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != expected_size
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise FlexaEnforcementError(
                "managed attachment ciphertext changed during open"
            )
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise FlexaEnforcementError(
                    "managed attachment ciphertext read was incomplete"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        ciphertext = b"".join(chunks)
    finally:
        os.close(fd)
    after = os.lstat(target)
    if (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        raise FlexaEnforcementError(
            "managed attachment ciphertext changed during read"
        )
    return ciphertext


def _decrypt_attachment_record(record: _AttachmentRecord) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ciphertext = _read_owned_ciphertext(record)
    try:
        plaintext = AESGCM(bytes(record.key)).decrypt(
            record.nonce,
            ciphertext,
            record.aad,
        )
    except InvalidTag as exc:
        raise FlexaEnforcementError(
            "managed attachment ciphertext authentication failed"
        ) from exc
    if len(plaintext) != record.plaintext_size:
        raise FlexaEnforcementError("managed attachment plaintext size changed")
    _validate_attachment_bytes(plaintext, record.suffix)
    return plaintext


def trusted_gateway_attachment_bytes(attachment_id: str) -> tuple[bytes, str]:
    """Decrypt staging bytes for trusted gateway routing, never model tools.

    The model-facing broker is :func:`read_governed_attachment`; this helper
    intentionally has no turn lookup because the gateway must build native
    image content immediately before ``channel_ingress`` creates the turn.
    A subprocess cannot reach this process-local registry/key material.
    """

    if not governed_mode():
        raise FlexaEnforcementError("managed attachment broker is unavailable")
    name = str(attachment_id or "")
    if not _OPAQUE_ATTACHMENT_NAME.fullmatch(name):
        raise FlexaEnforcementError("managed attachment identifier is invalid")
    profile, workspace, _inbox = _attachment_profile_identity()
    with _ATTACHMENT_LOCK:
        record = _ATTACHMENT_RECORDS.get(name)
        if (
            record is None
            or not _record_is_live(record)
            or not _record_matches_profile(record, profile, workspace)
        ):
            raise FlexaEnforcementError("managed attachment is unavailable")
        return _decrypt_attachment_record(record), record.suffix


def _bind_attachment_records_to_turn(
    attachment_ids: tuple[str, ...],
    key: TurnKey,
) -> None:
    if not attachment_ids:
        return
    if len(attachment_ids) > _ATTACHMENT_MAX_COUNT or len(set(attachment_ids)) != len(
        attachment_ids
    ):
        raise FlexaEnforcementError("managed attachment turn binding is invalid")
    profile, workspace, _inbox = _attachment_profile_identity()
    if (
        profile.tenant_id != key.tenant_id
        or profile.employee_id != key.employee_id
        or profile.slug != key.profile_slug
    ):
        raise FlexaEnforcementError("managed attachment profile binding is invalid")
    with _ATTACHMENT_LOCK:
        records: list[_AttachmentRecord] = []
        for attachment_id in attachment_ids:
            if not _OPAQUE_ATTACHMENT_NAME.fullmatch(attachment_id):
                raise FlexaEnforcementError("managed attachment identifier is invalid")
            record = _ATTACHMENT_RECORDS.get(attachment_id)
            if (
                record is None
                or not _record_is_live(record)
                or not _record_matches_profile(record, profile, workspace)
                or record.turn_key is not None
            ):
                raise FlexaEnforcementError("managed attachment is unavailable")
            records.append(record)
        for record in records:
            record.turn_key = key


def _bound_turn_state() -> _TurnState:
    key = _BOUND_TURN.get()
    if not isinstance(key, TurnKey):
        raise FlexaEnforcementError("governed turn handoff is missing")
    with _REGISTRY_LOCK:
        state = _TURN_STATES.get(key)
    if state is None or _CLOCK() >= state.expires_at:
        raise FlexaEnforcementError("governed turn is unavailable")
    profile, endpoint = _profile_and_endpoint()
    if (
        profile.tenant_id != key.tenant_id
        or profile.employee_id != key.employee_id
        or profile.slug != key.profile_slug
        or endpoint != state.endpoint
    ):
        raise FlexaEnforcementError("governed turn binding mismatch")
    return state


def _extract_pdf_text(data: bytes) -> str:
    """Run Poppler with stdin/stdout only and an enforced output ceiling."""

    executable = shutil.which("pdftotext")
    if executable is None:
        raise FlexaEnforcementError("managed PDF extraction is unavailable")
    from hermes_cli._subprocess_compat import windows_hide_flags

    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = windows_hide_flags()
    try:
        process = subprocess.Popen(
            [executable, "-layout", "-", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_kwargs,
        )
    except OSError as exc:
        raise FlexaEnforcementError("managed PDF extraction is unavailable") from exc

    stderr_chunks: list[bytes] = []
    writer_error: list[BaseException] = []
    timed_out = threading.Event()

    def _write_stdin() -> None:
        try:
            assert process.stdin is not None
            process.stdin.write(data)
            process.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            writer_error.append(exc)

    def _drain_stderr() -> None:
        assert process.stderr is not None
        while True:
            chunk = process.stderr.read(8192)
            if not chunk:
                return
            if sum(len(item) for item in stderr_chunks) < 8192:
                stderr_chunks.append(chunk[:8192])

    def _kill_timeout() -> None:
        timed_out.set()
        try:
            process.kill()
        except OSError:
            pass

    writer = threading.Thread(target=_write_stdin, daemon=True)
    stderr_reader = threading.Thread(target=_drain_stderr, daemon=True)
    timer = threading.Timer(30.0, _kill_timeout)
    writer.start()
    stderr_reader.start()
    timer.start()
    output = bytearray()
    too_large = False
    try:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _ATTACHMENT_TEXT_MAX_BYTES:
                too_large = True
                try:
                    process.kill()
                except OSError:
                    pass
                break
        return_code = process.wait(timeout=5.0)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
        except OSError:
            pass
        process.wait(timeout=5.0)
        raise FlexaEnforcementError("managed PDF extraction timed out") from exc
    finally:
        timer.cancel()
        writer.join(timeout=1.0)
        stderr_reader.join(timeout=1.0)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    if timed_out.is_set():
        raise FlexaEnforcementError("managed PDF extraction timed out")
    if too_large:
        raise FlexaEnforcementError("managed PDF text exceeds the safe limit")
    if return_code != 0 or writer_error:
        raise FlexaEnforcementError("managed PDF extraction failed")
    try:
        return bytes(output).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FlexaEnforcementError("managed PDF text is not valid UTF-8") from exc


def _extract_attachment_text(data: bytes, suffix: str) -> tuple[str, bool]:
    if suffix in {".txt", ".md", ".csv", ".json"}:
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FlexaEnforcementError(
                "managed attachment text is not valid UTF-8"
            ) from exc
        extracted_document = False
    elif suffix in {".docx", ".xlsx"}:
        from tools.read_extract import ExtractionError, extract_document_bytes

        try:
            text = extract_document_bytes(data, suffix)
        except ExtractionError as exc:
            raise FlexaEnforcementError(
                "managed document extraction failed"
            ) from exc
        extracted_document = True
    elif suffix == ".pdf":
        text = _extract_pdf_text(data)
        extracted_document = True
    else:
        raise FlexaEnforcementError(
            "managed attachment type cannot be rendered as text"
        )
    encoded_size = len(text.encode("utf-8"))
    if encoded_size > _ATTACHMENT_TEXT_MAX_BYTES:
        raise FlexaEnforcementError("managed attachment text exceeds the safe limit")
    if len(text.splitlines()) > _ATTACHMENT_TEXT_MAX_LINES:
        raise FlexaEnforcementError("managed attachment has too many text lines")
    return text, extracted_document


def read_governed_attachment(
    attachment_id: str,
    *,
    offset: int = 1,
    limit: int = _ATTACHMENT_READ_MAX_LINES,
) -> str:
    """Bound broker used by the model-facing ``read_attachment`` tool."""

    if not governed_mode():
        raise FlexaEnforcementError("managed attachment broker is unavailable")
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or offset < 1
        or limit < 1
        or limit > _ATTACHMENT_READ_MAX_LINES
    ):
        raise FlexaEnforcementError("managed attachment pagination is invalid")
    state = _bound_turn_state()
    name = str(attachment_id or "")
    if name not in state.attachment_ids or not _OPAQUE_ATTACHMENT_NAME.fullmatch(name):
        raise FlexaEnforcementError("managed attachment is unavailable")
    approved_arguments = {
        "attachment_id": name,
        "limit": limit,
        "offset": offset,
    }
    approved_digest = _arguments_digest(approved_arguments)
    with state.lock:
        if state.phase != "tools" or not any(
            tool_name == "read_attachment" and digest == approved_digest
            for tool_name, digest in state.pending_tools.values()
        ):
            raise FlexaEnforcementError(
                "managed attachment broker proposal is unavailable"
            )
    profile, workspace, _inbox = _attachment_profile_identity()
    with _ATTACHMENT_LOCK:
        record = _ATTACHMENT_RECORDS.get(name)
        if (
            record is None
            or not _record_is_live(record)
            or record.turn_key != state.key
            or not _record_matches_profile(record, profile, workspace)
        ):
            raise FlexaEnforcementError("managed attachment is unavailable")
        data = _decrypt_attachment_record(record)
        suffix = record.suffix
    text, extracted_document = _extract_attachment_text(data, suffix)
    logical_lines = text.splitlines()
    lines: list[str] = []
    split_long_lines = False
    # Keep a single virtual line small enough to fit even the minimum 8K
    # runtime result budget when every character requires six-byte JSON
    # escaping (for example control characters).
    max_virtual_line = _ATTACHMENT_VIRTUAL_LINE_MAX_CHARS
    for line in logical_lines:
        if len(line) <= max_virtual_line:
            lines.append(line)
            continue
        split_long_lines = True
        lines.extend(
            line[index : index + max_virtual_line]
            for index in range(0, len(line), max_virtual_line)
        )
    total_lines = len(lines)
    start_index = offset - 1
    page_lines: list[str] = []
    content_chars = 0
    for line in lines[start_index : start_index + limit]:
        separator_chars = 1 if page_lines else 0
        if content_chars + separator_chars + len(line) > _ATTACHMENT_READ_MAX_CHARS:
            break
        page_lines.append(line)
        content_chars += separator_chars + len(line)
    def render_page(line_count: int) -> str:
        content = "\n".join(page_lines[:line_count])
        next_offset = offset + line_count
        truncated = next_offset <= total_lines
        result: dict[str, Any] = {
            "attachment_id": name,
            "content": content,
            "extracted_document": extracted_document,
            "file_size": len(data),
            "offset": offset,
            "returned_lines": line_count,
            "suffix": suffix,
            "total_lines": total_lines,
            "truncated": truncated,
        }
        if split_long_lines:
            result["logical_lines"] = len(logical_lines)
            result["long_lines_split"] = True
        if truncated:
            result["next_offset"] = next_offset
            result["hint"] = f"Use offset={next_offset} to continue reading."
        return json.dumps(result, ensure_ascii=False, sort_keys=True)

    # Bound the final serialized broker result, not only its raw content.
    # Quotes, backslashes, and control characters expand during JSON encoding.
    low = 0
    high = len(page_lines)
    rendered = render_page(0)
    while low <= high:
        middle = (low + high) // 2
        candidate = render_page(middle)
        if len(candidate) <= _ATTACHMENT_BROKER_MAX_SERIALIZED_CHARS:
            rendered = candidate
            low = middle + 1
        else:
            high = middle - 1
    if len(rendered) > _ATTACHMENT_BROKER_MAX_SERIALIZED_CHARS:
        raise FlexaEnforcementError("managed attachment page metadata is too large")
    return rendered


def _safe_attachment_display_name(value: str, fallback: str) -> str:
    # A Linux backend must also strip a Windows client's drive/directories.
    name = Path(str(value or "").replace("\\", "/")).name.strip()
    name = "".join(ch for ch in name if ch.isprintable() and ch not in "\r\n\x00")
    return (name or fallback)[:128]


def _validate_attachment_bytes(data: bytes, suffix: str) -> None:
    if not data or len(data) > _ATTACHMENT_MAX_BYTES:
        raise FlexaEnforcementError("managed attachment size is invalid")
    if suffix not in _ATTACHMENT_SUFFIXES:
        raise FlexaEnforcementError("managed attachment type is unavailable")
    head = data[:32]
    valid = True
    if suffix == ".png":
        valid = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif suffix in {".jpg", ".jpeg"}:
        valid = head.startswith(b"\xff\xd8\xff")
    elif suffix == ".gif":
        valid = head.startswith((b"GIF87a", b"GIF89a"))
    elif suffix == ".bmp":
        valid = head.startswith(b"BM")
    elif suffix == ".webp":
        valid = head.startswith(b"RIFF") and head[8:12] == b"WEBP"
    elif suffix == ".pdf":
        valid = head.startswith(b"%PDF-")
    elif suffix in {".docx", ".xlsx", ".pptx"}:
        valid = head.startswith(b"PK\x03\x04")
    elif suffix in {".doc", ".xls", ".ppt"}:
        valid = head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    elif suffix in {".txt", ".csv", ".json", ".md"}:
        valid = b"\x00" not in data[:4096]
        if valid:
            try:
                data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                valid = False
    elif suffix == ".wav":
        valid = head.startswith(b"RIFF") and head[8:12] == b"WAVE"
    elif suffix in {".ogg", ".opus"}:
        valid = head.startswith(b"OggS")
    elif suffix == ".mp3":
        valid = head.startswith(b"ID3") or head.startswith(b"\xff")
    elif suffix in {".mp4", ".mov", ".m4a"}:
        valid = len(head) >= 12 and head[4:8] == b"ftyp"
    elif suffix == ".webm":
        valid = head.startswith(b"\x1a\x45\xdf\xa3")
    if not valid:
        raise FlexaEnforcementError("managed attachment content does not match its type")


def _open_posix_inbox(workspace: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    workspace_fd = os.open(workspace, flags)
    flexa_fd: int | None = None
    try:
        flexa_fd = os.open(_ATTACHMENT_INBOX_PARTS[0], flags, dir_fd=workspace_fd)
        inbox_fd = os.open(_ATTACHMENT_INBOX_PARTS[1], flags, dir_fd=flexa_fd)
        if not stat.S_ISDIR(os.fstat(inbox_fd).st_mode):
            os.close(inbox_fd)
            raise FlexaEnforcementError("managed attachment inbox is invalid")
        return inbox_fd
    except OSError as exc:
        raise FlexaEnforcementError("managed attachment inbox is unsafe") from exc
    finally:
        if flexa_fd is not None:
            os.close(flexa_fd)
        os.close(workspace_fd)


def _prune_and_measure_inbox(workspace: Path, inbox: Path) -> tuple[int, int]:
    # Every in-process key/record becomes unusable after the one-hour staging /
    # turn lifetime. The two-hour ciphertext retention is therefore strictly
    # longer than every valid owner lifetime: deleting an older object cannot
    # race a usable attachment in another process, while crash orphans cannot
    # exhaust the shared flat inbox forever.
    count = 0
    total = 0
    expired_before = time.time() - _ATTACHMENT_RETENTION_SECONDS
    if os.name == "posix":
        inbox_fd = _open_posix_inbox(workspace)
        try:
            for name in os.listdir(inbox_fd):
                if not _OPAQUE_ATTACHMENT_NAME.fullmatch(name):
                    raise FlexaEnforcementError(
                        "managed attachment inbox contains an unsafe entry"
                    )
                try:
                    info = os.stat(name, dir_fd=inbox_fd, follow_symlinks=False)
                except OSError as exc:
                    raise FlexaEnforcementError(
                        "managed attachment inbox cannot be inspected"
                    ) from exc
                if not stat.S_ISREG(info.st_mode):
                    raise FlexaEnforcementError(
                        "managed attachment inbox contains an unsafe entry"
                    )
                if info.st_mtime <= expired_before:
                    try:
                        os.unlink(name, dir_fd=inbox_fd)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        raise FlexaEnforcementError(
                            "expired managed attachment could not be pruned"
                        ) from exc
                    continue
                count += 1
                total += info.st_size
        finally:
            os.close(inbox_fd)
        return count, total
    _assert_no_reparse_chain(inbox)
    for candidate in inbox.iterdir():
        if not _OPAQUE_ATTACHMENT_NAME.fullmatch(candidate.name):
            raise FlexaEnforcementError(
                "managed attachment inbox contains an unsafe entry"
            )
        _assert_no_reparse_chain(candidate)
        info = os.lstat(candidate)
        if not stat.S_ISREG(info.st_mode):
            raise FlexaEnforcementError(
                "managed attachment inbox contains an unsafe entry"
            )
        if info.st_mtime <= expired_before:
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise FlexaEnforcementError(
                    "expired managed attachment could not be pruned"
                ) from exc
            continue
        count += 1
        total += info.st_size
    return count, total


def _prune_expired_local_records(
    profile: ManagedProfile,
    workspace: Path,
) -> set[str]:
    expired: set[str] = set()
    for attachment_id, record in list(_ATTACHMENT_RECORDS.items()):
        if (
            _record_matches_profile(record, profile, workspace)
            and not _record_is_live(record)
        ):
            if _ATTACHMENT_RECORDS.get(attachment_id) is record:
                _ATTACHMENT_RECORDS.pop(attachment_id, None)
            _wipe_attachment_key(record)
            expired.add(attachment_id)
    return expired


def prune_governed_uploads(
    *,
    include_expired_ids: bool = False,
) -> tuple[int, int] | tuple[int, int, tuple[str, ...]]:
    """Validate/measure the inbox and prune only cryptographically expired data."""

    if not governed_mode():
        return (0, 0, ()) if include_expired_ids else (0, 0)
    profile, workspace, inbox = _attachment_profile_identity()
    with _ATTACHMENT_LOCK:
        expired = _prune_expired_local_records(profile, workspace)
        count, total = _prune_and_measure_inbox(workspace, inbox)
    if include_expired_ids:
        return count, total, tuple(sorted(expired))
    return count, total


def delete_governed_upload(
    attachment_id: str,
    *,
    revoke_on_failure: bool = True,
) -> bool:
    """Delete one process-owned object and revoke its in-memory key.

    Explicit detach passes ``revoke_on_failure=False`` so a transient unlink
    failure can be retried without leaving a visible but undecryptable chip.
    Turn/error/teardown cleanup uses the default and always destroys the key.
    """

    name = str(attachment_id or "")
    if not _OPAQUE_ATTACHMENT_NAME.fullmatch(name):
        raise FlexaEnforcementError("managed attachment identifier is invalid")
    profile, workspace, inbox = _attachment_profile_identity()
    with _ATTACHMENT_LOCK:
        record = _ATTACHMENT_RECORDS.get(name)
        if record is None or not _record_matches_profile(record, profile, workspace):
            # A flat inbox may be shared by several gateway processes. Absence
            # from this process's key registry proves no deletion authority.
            return False
        removed = False
        completed = False
        try:
            if os.name == "posix":
                inbox_fd = _open_posix_inbox(workspace)
                try:
                    info = os.stat(name, dir_fd=inbox_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise FlexaEnforcementError("managed attachment is unsafe")
                    os.unlink(name, dir_fd=inbox_fd)
                    removed = True
                except FileNotFoundError:
                    removed = False
                except FlexaEnforcementError:
                    raise
                except OSError as exc:
                    raise FlexaEnforcementError(
                        "managed attachment deletion failed"
                    ) from exc
                finally:
                    os.close(inbox_fd)
            else:
                target = inbox / name
                try:
                    _assert_no_reparse_chain(target)
                    info = os.lstat(target)
                    if not stat.S_ISREG(info.st_mode):
                        raise FlexaEnforcementError("managed attachment is unsafe")
                    target.unlink()
                    removed = True
                except FileNotFoundError:
                    removed = False
                except FlexaEnforcementError:
                    raise
                except OSError as exc:
                    raise FlexaEnforcementError(
                        "managed attachment deletion failed"
                    ) from exc
            completed = True
            return removed
        finally:
            # Authentication material must not outlive detach/output/error,
            # even when an attacker has replaced the ciphertext path and the
            # unlink correctly fails closed.
            if completed or revoke_on_failure:
                if _ATTACHMENT_RECORDS.get(name) is record:
                    _ATTACHMENT_RECORDS.pop(name, None)
                _wipe_attachment_key(record)


def store_governed_upload(
    data: bytes,
    *,
    suffix: str,
) -> Path:
    """Encrypt an upload into a ciphertext-only opaque spool object."""

    if not governed_mode():
        raise FlexaEnforcementError("managed upload storage requires governed mode")
    if not isinstance(data, bytes):
        raise FlexaEnforcementError("managed attachment contains binary wrapper data")
    normalized_suffix = str(suffix or "").lower()
    if normalized_suffix and not normalized_suffix.startswith("."):
        normalized_suffix = f".{normalized_suffix}"
    _validate_attachment_bytes(data, normalized_suffix)
    profile, workspace, inbox = _attachment_profile_identity()
    name = f"{uuid.uuid4().hex}{normalized_suffix}"
    destination = inbox / name
    aad = _attachment_aad(profile, name, normalized_suffix)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with _ATTACHMENT_LOCK:
        _prune_expired_local_records(profile, workspace)
        count, total = _prune_and_measure_inbox(workspace, inbox)
        if (
            count >= _ATTACHMENT_INBOX_MAX_FILES
            or total + len(data) + _ATTACHMENT_CIPHERTEXT_OVERHEAD
            > _ATTACHMENT_INBOX_MAX_BYTES
        ):
            raise FlexaEnforcementError("managed attachment inbox quota exceeded")
        key = bytearray(AESGCM.generate_key(bit_length=256))
        nonce = os.urandom(12)
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, data, aad)
        inbox_fd: int | None = None
        fd: int | None = None
        try:
            if os.name == "posix":
                inbox_fd = _open_posix_inbox(workspace)
                fd = os.open(name, flags, 0o600, dir_fd=inbox_fd)
            else:
                _assert_no_reparse_chain(inbox)
                fd = os.open(destination, flags, 0o600)
            view = memoryview(ciphertext)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short attachment write")
                view = view[written:]
            os.fsync(fd)
            if os.name == "posix":
                os.fchmod(fd, 0o600)
                created = os.fstat(fd)
                linked = os.stat(name, dir_fd=inbox_fd, follow_symlinks=False)
                if (created.st_dev, created.st_ino) != (linked.st_dev, linked.st_ino):
                    raise OSError("attachment identity changed")
            else:
                _assert_no_reparse_chain(destination)
            record = _AttachmentRecord(
                attachment_id=name,
                workspace=workspace,
                tenant_id=profile.tenant_id,
                employee_id=profile.employee_id,
                profile_slug=profile.slug,
                suffix=normalized_suffix,
                plaintext_size=len(data),
                key=key,
                nonce=nonce,
                aad=aad,
                created_at=_CLOCK(),
            )
            if name in _ATTACHMENT_RECORDS:
                raise OSError("attachment registry identity collision")
            _ATTACHMENT_RECORDS[name] = record
        except Exception as exc:
            try:
                if inbox_fd is not None:
                    os.unlink(name, dir_fd=inbox_fd)
                else:
                    destination.unlink(missing_ok=True)
            except OSError:
                pass
            stale_record = _ATTACHMENT_RECORDS.get(name)
            if stale_record is not None and stale_record.key is key:
                _ATTACHMENT_RECORDS.pop(name, None)
            for index in range(len(key)):
                key[index] = 0
            raise FlexaEnforcementError("managed attachment could not be stored") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if inbox_fd is not None:
                os.close(inbox_fd)
    return destination


def _secure_attachment_read(path: Path) -> tuple[bytes, str, Path]:
    workspace, inbox = _attachment_workspace()
    absolute = path if path.is_absolute() else workspace / path
    absolute = Path(os.path.abspath(absolute))
    try:
        inbox_relative = absolute.relative_to(inbox)
    except ValueError:
        inbox_relative = None
    if (
        inbox_relative is not None
        and inbox_relative.parent == Path(".")
        and _OPAQUE_ATTACHMENT_NAME.fullmatch(inbox_relative.name)
    ):
        data, suffix = trusted_gateway_attachment_bytes(inbox_relative.name)
        return data, suffix, absolute
    _assert_no_reparse_chain(absolute)
    before = os.lstat(absolute)
    if not stat.S_ISREG(before.st_mode) or before.st_size > _ATTACHMENT_MAX_BYTES:
        raise FlexaEnforcementError("managed attachment file is invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as exc:
        raise FlexaEnforcementError("managed attachment could not be opened") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > _ATTACHMENT_MAX_BYTES
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise FlexaEnforcementError("managed attachment changed during open")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise FlexaEnforcementError("managed attachment read was incomplete")
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    after = os.lstat(absolute)
    if (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise FlexaEnforcementError("managed attachment changed during read")
    suffix = absolute.suffix.lower()
    _validate_attachment_bytes(data, suffix)
    return data, suffix, absolute


def governed_attachment_prompt(
    user_text: str,
    paths: list[str],
    *,
    display_names: dict[str, str] | None = None,
) -> str:
    """Materialize uploads and expose only opaque broker identifiers."""

    if not governed_mode():
        return user_text
    if len(paths) > _ATTACHMENT_MAX_COUNT:
        raise FlexaEnforcementError("too many managed attachments")
    _workspace, inbox = _attachment_workspace()
    entries: list[tuple[str, str]] = []
    attachment_ids: list[str] = []
    total_bytes = 0
    try:
        for raw in paths:
            data, suffix, source = _secure_attachment_read(Path(str(raw)))
            total_bytes += len(data)
            if total_bytes > _ATTACHMENT_MAX_TOTAL_BYTES:
                raise FlexaEnforcementError("managed attachment batch is too large")
            try:
                relative_to_inbox = Path(os.path.abspath(source)).relative_to(inbox)
            except ValueError:
                relative_to_inbox = None
            if (
                relative_to_inbox is not None
                and relative_to_inbox.parent == Path(".")
                and _OPAQUE_ATTACHMENT_NAME.fullmatch(relative_to_inbox.name)
            ):
                stored = source
            else:
                stored = store_governed_upload(data, suffix=suffix)
            attachment_ids.append(stored.name)
            supplied_name = (display_names or {}).get(str(raw), source.name)
            display = _safe_attachment_display_name(supplied_name, f"attachment{suffix}")
            entries.append((stored.name, display))
    except Exception:
        for attachment_id in attachment_ids:
            try:
                delete_governed_upload(attachment_id)
            except FlexaEnforcementError:
                pass
        raise
    if not entries:
        return user_text
    rendered = "; ".join(
        f"attachment_id={attachment_id}, display_name={json.dumps(name, ensure_ascii=False)}"
        for attachment_id, name in entries
    )
    return GovernedAttachmentPrompt(
        f"{user_text}\n\n[Managed attachments: {rendered}. Use read_attachment by exact attachment_id.]",
        tuple(attachment_ids),
    )


def memory_candidate(
    agent: Any,
    content: str,
    *,
    action: str,
    target: str,
) -> str:
    if not governed_mode():
        return content
    return _advance(
        agent,
        "memory.candidate",
        content,
        allowed_phases={"hermes.input", "memory.retrieval", "tools", "memory.candidate"},
        next_phase="memory.candidate",
        metadata={"action": str(action)[:128], "target": str(target)[:256]},
    )


def memory_candidate_arguments(
    agent: Any,
    arguments: dict[str, Any],
    *,
    action: str,
    target: str,
) -> dict[str, Any]:
    if not governed_mode():
        return arguments
    raw = json.dumps(
        arguments,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    sanitized = memory_candidate(agent, raw, action=action, target=target)
    try:
        value = json.loads(sanitized)
    except json.JSONDecodeError as exc:
        raise FlexaEnforcementError("sanitized memory candidate is invalid") from exc
    if not isinstance(value, dict):
        raise FlexaEnforcementError("sanitized memory candidate shape is invalid")
    return value


def output(agent: Any, content: str) -> str:
    require_governed_runtime(agent)
    if not governed_mode():
        return content
    state = _state_for(agent)
    with state.lock:
        if state.phase not in {"hermes.input", "memory.retrieval", "tools", "memory.candidate"}:
            raise FlexaEnforcementError("governed boundary phase is invalid")
        if state.pending_tools:
            raise FlexaEnforcementError("governed turn has unfinished tool calls")
        sanitized, token = _boundary_request(
            state,
            state.key,
            state.endpoint,
            "hermes.output",
            content,
        )
        if token is not None:
            raise FlexaEnforcementError("terminal output did not revoke turn context")
        _drop_local_state(agent, state)
        return sanitized


def revoke_turn(agent: Any) -> None:
    """Explicitly revoke and forget an interrupted or failed turn."""

    if not governed_mode():
        return
    key = getattr(agent, _AGENT_TURN_KEY, None)
    if not isinstance(key, TurnKey):
        key = _BOUND_TURN.get()
    if not isinstance(key, TurnKey):
        return
    with _REGISTRY_LOCK:
        state = _TURN_STATES.get(key)
    if state is None:
        return
    with state.lock:
        body = {
            "schema_version": "1",
            "request_id": str(uuid.uuid4()),
            "turn_context_token": state.token,
            "turn": {
                "tenant_id": state.key.tenant_id,
                "employee_id": state.key.employee_id,
                "principal_id": state.key.principal_id,
                "session_id": state.key.session_id,
                "turn_id": state.key.turn_id,
            },
        }
        try:
            _post_json(state.endpoint, "/v1/turns/revoke", body)
        except Exception:
            # Local revocation is unconditional. The opaque token expires at
            # the sidecar even if the best-effort network notification fails.
            pass
        finally:
            _drop_local_state(agent, state)


def release_buffered_output(agent: Any, content: str) -> None:
    """Release one sanitized full response after ``hermes.output`` allows it."""

    callbacks: list[Callable[[str], Any]] = []
    for callback in (
        getattr(agent, "stream_delta_callback", None),
        getattr(agent, "_stream_callback", None),
    ):
        if callable(callback) and callback not in callbacks:
            callbacks.append(callback)
    for callback in callbacks:
        try:
            callback(content)
        except Exception:
            pass
    setattr(agent, "_current_streamed_assistant_text", content)


def scrub_reasoning(messages: list[Any]) -> None:
    if not governed_mode():
        return
    for message in messages:
        if isinstance(message, dict):
            for key in ("reasoning", "reasoning_content", "thinking"):
                message.pop(key, None)


def clear_turn_context(agent: Any | None = None) -> None:
    """Test/teardown helper; live failures should use :func:`revoke_turn`."""

    if agent is not None:
        revoke_turn(agent)
    _BOUND_TURN.set(None)
