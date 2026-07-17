"""Principal isolation and read-only recall contract for Flexa Memory v2."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.flexa_memory_provider import (
    FlexaMemoryProvider,
    FlexaMemoryProviderError,
)
from agent.memory_manager import MemoryManager
from agent.memory_provider import MemoryProvider, MemoryProviderCapabilities
from gateway.config import Platform
from gateway.session import SessionSource, build_session_key
from hermes_cli.flexa_governed import (
    GovernedProfileError,
    ManagedProfile,
    bind_governed_event_principal,
    bind_governed_principal_assertion,
    governed_memory_scope,
    verify_governed_principal_assertion,
)

_NOW = 1_750_000_000
_KEY_ID = "principal-key-1"


@dataclass(frozen=True)
class _PrincipalHarness:
    profile: ManagedProfile
    private_key: Ed25519PrivateKey

    def assertion(
        self,
        *,
        principal_id: str,
        subject: str,
        nonce: str,
        namespace: str = "telegram",
    ) -> dict[str, Any]:
        unsigned = {
            "schema_version": "1",
            "issuer": "flexa-engine",
            "audience": "hermes-memory",
            "tenant_id": self.profile.tenant_id,
            "employee_id": self.profile.employee_id,
            "profile_id": self.profile.slug,
            "release_id": self.profile.release_id,
            "bundle_signing_payload_sha256": (
                self.profile.bundle_signing_payload_sha256
            ),
            "principal_namespace": namespace,
            "principal_id": principal_id,
            "transport_subject_sha256": hashlib.sha256(
                f"{namespace}\x00{subject}".encode("utf-8")
            ).hexdigest(),
            "issued_at": _NOW - 5,
            "expires_at": _NOW + 120,
            "nonce": nonce,
        }
        payload = json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return {
            **unsigned,
            "signature": {
                "algorithm": "ed25519",
                "key_id": _KEY_ID,
                "value": base64.b64encode(
                    self.private_key.sign(payload)
                ).decode("ascii"),
            },
        }


@pytest.fixture
def principal_harness(monkeypatch: pytest.MonkeyPatch) -> _PrincipalHarness:
    from agent import flexa_enforcement
    from hermes_cli import flexa_governed

    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    profile = ManagedProfile(
        tenant_id="tenant-one",
        release_id="release-one",
        bundle_signing_payload_sha256="a" * 64,
        slug="oren-cto",
        employee_id="oren-cto",
        primary=True,
        description="Governed Oren profile",
        enforcement_api="http://enforcement-oren-cto:8081",
        binding_sha256="b" * 64,
        config_sha256="c" * 64,
        metadata_sha256="d" * 64,
        buffered_output=True,
    )
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        flexa_governed,
        "binding_for_current_home",
        lambda: (profile, {"working_directory": "/workspaces/oren-cto"}),
    )
    monkeypatch.setattr(
        flexa_enforcement,
        "binding_for_current_home",
        lambda: (profile, {"working_directory": "/workspaces/oren-cto"}),
    )
    monkeypatch.setattr(
        flexa_governed,
        "_managed_principal_assertion_trust",
        lambda _profile: (_KEY_ID, private_key.public_key()),
    )
    monkeypatch.setattr(flexa_governed, "_ASSERTION_CLOCK", lambda: float(_NOW))
    flexa_governed._CONSUMED_PRINCIPAL_NONCES.clear()
    flexa_enforcement._TURN_STATES.clear()
    flexa_enforcement._BOUND_TURN.set(None)
    yield _PrincipalHarness(profile=profile, private_key=private_key)
    flexa_governed._CONSUMED_PRINCIPAL_NONCES.clear()
    flexa_enforcement._TURN_STATES.clear()
    flexa_enforcement._BOUND_TURN.set(None)


def _verify(
    assertion: dict[str, Any],
    *,
    subject: str,
):
    return verify_governed_principal_assertion(
        assertion,
        platform=Platform.TELEGRAM,
        user_id=subject,
    )


def _scope(binding: Any) -> dict[str, str]:
    return governed_memory_scope(
        platform="telegram",
        user_id="transport-user",
        principal_binding=binding,
    )


def _initialized_provider(
    harness: _PrincipalHarness,
    binding: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> FlexaMemoryProvider:
    from agent import flexa_memory_provider

    monkeypatch.setattr(
        flexa_memory_provider,
        "binding_for_current_home",
        lambda: (
            harness.profile,
            {"working_directory": "/workspaces/oren-cto"},
        ),
    )
    provider = FlexaMemoryProvider()
    provider.initialize(
        "session-one",
        flexa_scope=_scope(binding),
        flexa_principal_binding=binding,
    )
    return provider


def _active_recall_binding(
    harness: _PrincipalHarness,
    principal_binding: Any,
    *,
    token: str = "opaque-turn-context-token",
):
    from agent import flexa_enforcement

    key = flexa_enforcement.TurnKey(
        tenant_id=harness.profile.tenant_id,
        employee_id=harness.profile.employee_id,
        principal_id=principal_binding.principal_id,
        profile_slug=harness.profile.slug,
        session_id="session-one",
        turn_id="turn-one",
    )
    agent = SimpleNamespace(
        session_id="session-one",
        _governed_principal_binding=principal_binding,
    )
    setattr(agent, flexa_enforcement._AGENT_TURN_KEY, key)
    flexa_enforcement._TURN_STATES[key] = flexa_enforcement._TurnState(
        key=key,
        endpoint=harness.profile.enforcement_api,
        token=token,
        phase="memory.retrieval",
        expires_at=flexa_enforcement._CLOCK() + 60,
    )
    return flexa_enforcement.governed_recall_binding(agent)


def _valid_hit(*, principal_id: str = "alice-user") -> dict[str, Any]:
    return {
        "memory_id": "memory-1",
        "scope": "user_private",
        "version": 3,
        "content": "Approved recalled context.",
        "partition": {
            "kind": "user_employee",
            "employee_id": "oren-cto",
            "principal_id": principal_id,
            "task_id": None,
            "session_id": None,
        },
        "provenance": {
            "evidence_hash": "e" * 64,
            "citation": "source:test-record-1",
        },
        "score": 0.91,
    }


def test_missing_forged_and_wrong_subject_assertions_fail_closed(
    principal_harness: _PrincipalHarness,
) -> None:
    with pytest.raises(GovernedProfileError, match="missing or invalid"):
        verify_governed_principal_assertion(
            None,
            platform="telegram",
            user_id="transport-user",
        )

    forged = principal_harness.assertion(
        principal_id="alice-user",
        subject="transport-user",
        nonce="forged-assertion-nonce-01",
    )
    forged["signature"]["value"] = base64.b64encode(b"\x00" * 64).decode(
        "ascii"
    )
    with pytest.raises(GovernedProfileError, match="signature is invalid"):
        _verify(forged, subject="transport-user")

    wrong_subject = principal_harness.assertion(
        principal_id="alice-user",
        subject="transport-user",
        nonce="wrong-subject-assertion-01",
    )
    with pytest.raises(GovernedProfileError, match="missing or invalid"):
        _verify(wrong_subject, subject="different-transport-user")


def test_assertion_is_single_use_and_binding_repr_is_opaque(
    principal_harness: _PrincipalHarness,
) -> None:
    assertion = principal_harness.assertion(
        principal_id="alice-user",
        subject="transport-user",
        nonce="single-use-assertion-0001",
    )
    binding = _verify(assertion, subject="transport-user")

    assert binding.principal_id == "alice-user"
    assert "alice-user" not in repr(binding)
    assert assertion["signature"]["value"] not in repr(binding)
    with pytest.raises(GovernedProfileError, match="already used"):
        _verify(assertion, subject="transport-user")


def test_event_assertion_is_consumed_once_and_rebinding_is_idempotent(
    principal_harness: _PrincipalHarness,
) -> None:
    source = SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="shared-group",
        chat_type="group",
        user_id="transport-user",
    )
    assertion = principal_harness.assertion(
        principal_id="alice-user",
        subject="transport-user",
        nonce="event-binding-assertion-0001",
    )
    event = SimpleNamespace(
        source=source,
        metadata={"flexa_principal_assertion": assertion},
        internal=False,
    )

    first = bind_governed_event_principal(event)
    second = bind_governed_event_principal(event)

    assert first is second
    assert event.metadata == {}
    assert ":principal:" in build_session_key(source)

    missing = SimpleNamespace(source=source, metadata={}, internal=False)
    with pytest.raises(GovernedProfileError, match="assertion is required"):
        bind_governed_event_principal(missing)


def test_every_turn_boundary_is_principal_bound_and_missing_binding_fails(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent import flexa_enforcement

    principal = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="turn-boundary-assertion-0001",
        ),
        subject="transport-user",
    )
    agent = SimpleNamespace(
        session_id="session-one",
        _governed_principal_binding=principal,
    )
    requests: list[dict[str, Any]] = []

    def _post(_endpoint: str, path: str, body: dict[str, Any]):
        requests.append(body)
        if path == "/v1/turns/revoke":
            return 204, b""
        return 200, json.dumps(
            {
                "schema_version": "1",
                "request_id": body["request_id"],
                "path": path.rsplit("/", 1)[-1],
                "decision": "allow",
                "committed": True,
                "sanitized_content": body["content"],
                "finding_ids": [],
                "turn_context_token": "active-turn-token",
            }
        ).encode("utf-8")

    monkeypatch.setattr(flexa_enforcement, "require_governed_runtime", lambda _a: None)
    monkeypatch.setattr(flexa_enforcement, "_post_json", _post)

    handoff = flexa_enforcement.channel_ingress(
        agent,
        "hello",
        platform="telegram",
    )
    flexa_enforcement.user_input(agent, handoff)
    flexa_enforcement.memory_retrieval(
        agent,
        "sanitized query",
        target="external-recall-query",
    )
    flexa_enforcement.revoke_turn(agent)

    expected_turn = {
        "tenant_id": "tenant-one",
        "employee_id": "oren-cto",
        "principal_id": "alice-user",
        "session_id": "session-one",
        "turn_id": handoff.key.turn_id,
    }
    assert [request["turn"] for request in requests] == [
        expected_turn,
        expected_turn,
        expected_turn,
        expected_turn,
    ]

    missing = SimpleNamespace(session_id="session-two")
    with pytest.raises(GovernedProfileError, match="principal is required"):
        flexa_enforcement.channel_ingress(
            missing,
            "hello",
            platform="telegram",
        )


def test_shared_group_thread_and_agent_cache_are_principal_isolated(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    # The canonical runner intentionally starts subprocesses with a minimal
    # environment.  Keep Windows known-folder caches inside pytest's tempdir.
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "user"))
    monkeypatch.setenv("SYSTEMDRIVE", "C:")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "programdata"))
    from gateway.run import GatewayRunner

    alice = SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="shared-group",
        chat_type="group",
        user_id="same-transport-user",
        thread_id="shared-topic",
    )
    bob = SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="shared-group",
        chat_type="group",
        user_id="same-transport-user",
        thread_id="shared-topic",
    )
    bind_governed_principal_assertion(
        alice,
        principal_harness.assertion(
            principal_id="alice-user",
            subject="same-transport-user",
            nonce="alice-group-assertion-01",
        ),
    )
    bind_governed_principal_assertion(
        bob,
        principal_harness.assertion(
            principal_id="bob-user",
            subject="same-transport-user",
            nonce="bob-group-assertion-0001",
        ),
    )

    alice_key = build_session_key(
        alice,
        group_sessions_per_user=False,
        thread_sessions_per_user=False,
    )
    bob_key = build_session_key(
        bob,
        group_sessions_per_user=False,
        thread_sessions_per_user=False,
    )
    assert alice_key != bob_key
    assert ":principal:" in alice_key
    assert "alice-user" not in alice_key
    assert "bob-user" not in bob_key

    runtime = {
        "provider": "test",
        "api_key": "secret",
        "base_url": "",
        "api_mode": "chat_completions",
    }
    alice_signature = GatewayRunner._agent_config_signature(
        "test/model",
        runtime,
        [],
        "",
        user_id="same-transport-user",
        principal_id="alice-user",
    )
    bob_signature = GatewayRunner._agent_config_signature(
        "test/model",
        runtime,
        [],
        "",
        user_id="same-transport-user",
        principal_id="bob-user",
    )
    assert alice_signature != bob_signature


def test_initialized_provider_cannot_be_rebound_to_another_principal(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alice = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="alice-provider-binding-0001",
        ),
        subject="transport-user",
    )
    bob = _verify(
        principal_harness.assertion(
            principal_id="bob-user",
            subject="transport-user",
            nonce="bob-provider-binding-000001",
        ),
        subject="transport-user",
    )
    provider = _initialized_provider(principal_harness, alice, monkeypatch)

    with pytest.raises(GovernedProfileError, match="principal changed"):
        provider.bind_governed_principal(bob)


def test_recall_request_and_response_contract_are_exact(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assertion = principal_harness.assertion(
        principal_id="alice-user",
        subject="transport-user",
        nonce="recall-contract-assertion-01",
    )
    binding = _verify(assertion, subject="transport-user")
    provider = _initialized_provider(principal_harness, binding, monkeypatch)
    captured: dict[str, Any] = {}

    def post_recall(payload: dict[str, Any]) -> tuple[int, bytes]:
        captured.update(payload)
        return 200, json.dumps({"hits": [_valid_hit()]}).encode("utf-8")

    monkeypatch.setattr(provider, "_post_recall", post_recall)
    recall_binding = _active_recall_binding(
        principal_harness,
        binding,
        token="opaque-contract-token",
    )
    provider.bind_governed_recall(recall_binding)
    recalled = provider.prefetch(
        "What did we decide?",
        session_id="session-one",
    )

    assert set(captured) == {
        "query",
        "task_id",
        "session_id",
        "limit",
        "principal_assertion",
        "turn",
        "turn_context_token",
    }
    assert captured == {
        "query": "What did we decide?",
        "task_id": None,
        "session_id": None,
        "limit": 12,
        "principal_assertion": assertion,
        "turn": {
            "tenant_id": "tenant-one",
            "employee_id": "oren-cto",
            "principal_id": "alice-user",
            "session_id": "session-one",
            "turn_id": "turn-one",
        },
        "turn_context_token": "opaque-contract-token",
    }
    assert "opaque-contract-token" not in repr(recall_binding)
    assert "opaque-contract-token" not in repr(provider)
    assert "Approved recalled context." in recalled
    assert "evidence_sha256=" + ("e" * 64) in recalled
    assert "citation=source:test-record-1" in recalled


@pytest.mark.parametrize(
    "response",
    [
        {"hits": [_valid_hit()], "extra": True},
        {
            "hits": [
                {
                    **_valid_hit(),
                    "provenance": {"evidence_hash": "e" * 64},
                }
            ]
        },
        {"hits": [_valid_hit(principal_id="another-user")]},
        {
            "hits": [
                {
                    **_valid_hit(),
                    "scope": "working_task",
                    "partition": {
                        "kind": "task",
                        "employee_id": "oren-cto",
                        "principal_id": "alice-user",
                        "task_id": "task-one",
                        "session_id": None,
                    },
                }
            ]
        },
        {
            "hits": [
                {
                    **_valid_hit(),
                    "scope": "session",
                    "partition": {
                        "kind": "session",
                        "employee_id": "oren-cto",
                        "principal_id": "alice-user",
                        "task_id": None,
                        "session_id": "session-one",
                    },
                }
            ]
        },
        {"hits": [{**_valid_hit(), "memory_id": "m" * 129}]},
        {
            "hits": [
                {
                    **_valid_hit(),
                    "provenance": {
                        "evidence_hash": "e" * 64,
                        "citation": "c" * 257,
                    },
                }
            ]
        },
        {"hits": [{**_valid_hit(), "content": "x" * 32_769}]},
        {
            "hits": [
                {**_valid_hit(), "memory_id": "memory-1", "content": "x" * 17_000},
                {**_valid_hit(), "memory_id": "memory-2", "content": "y" * 17_000},
            ]
        },
    ],
)
def test_malformed_or_cross_principal_recall_response_fails_closed(
    response: dict[str, Any],
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="bad-response-assertion-0001",
        ),
        subject="transport-user",
    )
    provider = _initialized_provider(principal_harness, binding, monkeypatch)
    provider.bind_governed_recall(
        _active_recall_binding(principal_harness, binding)
    )
    monkeypatch.setattr(
        provider,
        "_post_recall",
        lambda _payload: (200, json.dumps(response).encode("utf-8")),
    )

    with pytest.raises(FlexaMemoryProviderError, match="recall is unavailable"):
        provider.prefetch("recall", session_id="session-one")


def test_provider_outage_propagates_without_native_fallback(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="provider-outage-assertion-01",
        ),
        subject="transport-user",
    )
    provider = _initialized_provider(principal_harness, binding, monkeypatch)
    monkeypatch.setattr(
        provider,
        "_post_recall",
        lambda _payload: (_ for _ in ()).throw(OSError("offline")),
    )
    manager = MemoryManager()
    manager.add_provider(provider)
    manager.bind_governed_recall(
        _active_recall_binding(principal_harness, binding)
    )

    with pytest.raises(FlexaMemoryProviderError, match="recall is unavailable"):
        manager.prefetch_all("recall", session_id="session-one")
    assert [item.name for item in manager.providers] == ["flexa-memory"]


def test_recall_without_active_turn_binding_fails_closed(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="missing-turn-binding-assertion-01",
        ),
        subject="transport-user",
    )
    provider = _initialized_provider(principal_harness, binding, monkeypatch)

    with pytest.raises(FlexaMemoryProviderError, match="recall is unavailable"):
        provider.prefetch("recall", session_id="session-one")


def test_recall_query_is_bounded_by_utf8_bytes(
    principal_harness: _PrincipalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _verify(
        principal_harness.assertion(
            principal_id="alice-user",
            subject="transport-user",
            nonce="oversized-query-assertion-0001",
        ),
        subject="transport-user",
    )
    provider = _initialized_provider(principal_harness, binding, monkeypatch)
    provider.bind_governed_recall(
        _active_recall_binding(principal_harness, binding)
    )
    post = MagicMock()
    monkeypatch.setattr(provider, "_post_recall", post)

    with pytest.raises(FlexaMemoryProviderError, match="request is invalid"):
        provider.prefetch("\u00e9" * 4_097, session_id="session-one")

    post.assert_not_called()


class _ReadOnlyTripwireProvider(MemoryProvider):
    def __init__(self) -> None:
        self.recall_calls = 0

    @property
    def name(self) -> str:
        return "flexa-memory"

    @property
    def governed_scope_version(self) -> str:
        return "1"

    @property
    def capabilities(self) -> MemoryProviderCapabilities:
        return MemoryProviderCapabilities.read_only_recall()

    def is_available(self) -> bool:
        return True

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        return None

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        self.recall_calls += 1
        return "approved"

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        raise AssertionError("model tool schema hook must not run")

    def system_prompt_block(self) -> str:
        raise AssertionError("system prompt hook must not run")

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        raise AssertionError("background prefetch hook must not run")

    def sync_turn(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("turn sync hook must not run")

    def on_turn_start(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("lifecycle hook must not run")

    def on_session_end(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("lifecycle hook must not run")

    def on_session_switch(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("lifecycle hook must not run")

    def on_pre_compress(self, *args: Any, **kwargs: Any) -> str:
        raise AssertionError("lifecycle hook must not run")

    def on_memory_write(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("write bridge must not run")

    def on_delegation(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("delegation hook must not run")


def test_read_only_capabilities_prevent_every_hidden_hook(
    principal_harness: _PrincipalHarness,
) -> None:
    provider = _ReadOnlyTripwireProvider()
    manager = MemoryManager()
    manager.add_provider(provider)

    assert manager.build_system_prompt() == ""
    assert manager.prefetch_all("recall", session_id="session-one") == "approved"
    manager.queue_prefetch_all("recall", session_id="session-one")
    manager.sync_all("user", "assistant", session_id="session-one")
    assert manager.get_all_tool_schemas() == []
    manager.on_turn_start(1, "user")
    manager.on_session_end([])
    manager.on_session_switch("session-two")
    assert manager.on_pre_compress([]) == ""
    manager.on_delegation("task", "result")

    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.handle_tool_call("memory_write", {})
    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.on_memory_write("add", "memory", "candidate")
    assert provider.recall_calls == 1
