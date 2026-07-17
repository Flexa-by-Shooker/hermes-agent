"""Fail-closed memory behavior for Flexa-managed Hermes profiles."""

from __future__ import annotations

import json
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent.memory_manager import MemoryManager
from agent.memory_provider import MemoryProvider, MemoryProviderCapabilities


class _Provider(MemoryProvider):
    def __init__(self, *, fail: str = "") -> None:
        self.fail = fail
        self.initialized: dict[str, object] = {}
        self.sync_calls: list[tuple[str, str, str]] = []
        self.tool_calls: list[tuple[str, dict[str, object]]] = []
        self.memory_writes: list[tuple[str, str, str]] = []

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

    def initialize(self, session_id: str, **kwargs) -> None:
        if self.fail == "initialize":
            raise RuntimeError("offline")
        self.initialized = {"session_id": session_id, **kwargs}

    def system_prompt_block(self) -> str:
        if self.fail == "system_prompt":
            raise RuntimeError("offline")
        return ""

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        if self.fail == "prefetch":
            raise RuntimeError("offline")
        return ""

    def sync_turn(
        self,
        user_content: str,
        assistant_content: str,
        *,
        session_id: str = "",
        messages=None,
    ) -> None:
        if self.fail == "sync":
            raise RuntimeError("offline")
        self.sync_calls.append((user_content, assistant_content, session_id))

    def get_tool_schemas(self):
        return [
            {
                "name": "flexa_memory_store",
                "description": "Store governed memory",
                "parameters": {"type": "object", "properties": {}},
            }
        ]

    def handle_tool_call(self, tool_name, args, **kwargs):
        self.tool_calls.append((tool_name, dict(args)))
        return json.dumps({"success": True})

    def on_memory_write(
        self,
        action: str,
        target: str,
        content: str,
        metadata=None,
    ) -> None:
        self.memory_writes.append((action, target, content))

    def shutdown(self) -> None:
        return None


def _manager(provider: MemoryProvider) -> MemoryManager:
    manager = MemoryManager()
    manager.add_provider(provider)
    return manager


def test_governed_scope_is_forwarded_to_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    provider = _Provider()
    scope = {
        "schema_version": "1",
        "tenant_id": "tenant-one",
        "employee_id": "oren-cto",
        "principal_namespace": "telegram",
        "principal_id": "user-one",
    }

    _manager(provider).initialize_all(
        session_id="session-one",
        platform="telegram",
        hermes_home=str(tmp_path),
        flexa_scope=scope,
    )

    assert provider.initialized["flexa_scope"] == scope
    assert provider.initialized["session_id"] == "session-one"


@pytest.mark.parametrize("failure", ["initialize", "prefetch"])
def test_provider_outage_propagates_in_governed_mode(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    manager = _manager(_Provider(fail=failure))

    with pytest.raises(RuntimeError, match="offline"):
        if failure == "initialize":
            manager.initialize_all(
                session_id="session-one",
                hermes_home=str(tmp_path),
            )
        elif failure == "prefetch":
            manager.prefetch_all("remember this", session_id="session-one")


def test_governed_external_writes_are_blocked_before_provider_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from hermes_cli.flexa_governed import GovernedProfileError

    provider = _Provider()
    manager = _manager(provider)

    # Automatic post-turn hooks are absent from the exact read-only
    # capabilities, so normal turn completion is a no-op rather than an error.
    manager.sync_all("user", "assistant", session_id="session-one")
    manager.queue_prefetch_all("user", session_id="session-one")
    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.handle_tool_call("flexa_memory_store", {"content": "candidate"})
    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.on_memory_write("add", "memory", "candidate")
    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.notify_memory_tool_write(
            {"success": True},
            {"action": "add", "target": "memory", "content": "candidate"},
        )

    fake_agent = SimpleNamespace(
        _memory_manager=manager,
        enabled_toolsets=["memory"],
        tools=[],
        valid_tool_names=set(),
    )
    from agent.memory_manager import inject_memory_provider_tools

    assert inject_memory_provider_tools(fake_agent) == 0
    assert manager.get_all_tool_schemas() == []
    assert fake_agent.tools == []
    assert provider.sync_calls == []
    assert provider.tool_calls == []
    assert provider.memory_writes == []


def test_native_memory_tool_and_pending_write_are_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    from tools.memory_tool import (
        MemoryStore,
        apply_memory_pending,
        check_memory_requirements,
        load_on_disk_store,
        memory_tool,
    )

    store = MemoryStore()
    result = json.loads(memory_tool(action="add", content="must not persist", store=store))
    pending = apply_memory_pending(
        {"action": "add", "target": "user", "content": "must not persist"},
        store,
    )

    assert result["success"] is False
    assert pending["success"] is False
    assert check_memory_requirements() is False
    with pytest.raises(RuntimeError, match="native memory is unavailable"):
        load_on_disk_store()
    assert not (tmp_path / "memories" / "MEMORY.md").exists()
    assert not (tmp_path / "memories" / "USER.md").exists()


def test_governed_turn_records_and_consumes_bound_no_write_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from run_agent import AIAgent

    provider = _Provider()
    agent = object.__new__(AIAgent)
    agent.session_id = "session-one"
    agent._memory_manager = _manager(provider)
    agent._flexa_turn_id = "turn-one"

    agent._sync_external_memory_for_turn(
        original_user_message="must never enter the marker",
        final_response="must never enter the marker either",
        interrupted=False,
    )

    assert agent._flexa_pending_memory_decision == {
        "decision": "no_write",
        "turn_id": "turn-one",
        "session_id": "session-one",
    }
    assert provider.sync_calls == []

    assert agent._commit_governed_external_memory(turn_id="turn-one") is True
    assert not hasattr(agent, "_flexa_pending_memory_decision")
    assert provider.sync_calls == []


def test_governed_commit_rejects_missing_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from run_agent import AIAgent

    agent = object.__new__(AIAgent)
    agent.session_id = "session-one"
    agent._memory_manager = _manager(_Provider())

    with pytest.raises(RuntimeError, match="no-write decision is missing"):
        agent._commit_governed_external_memory(turn_id="turn-one")


@pytest.mark.parametrize(
    "decision",
    [
        {
            "decision": "write",
            "turn_id": "turn-one",
            "session_id": "session-one",
        },
        {
            "decision": "no_write",
            "turn_id": "turn-two",
            "session_id": "session-one",
        },
        {
            "decision": "no_write",
            "turn_id": "turn-one",
            "session_id": "session-two",
        },
        {
            "decision": "no_write",
            "turn_id": "turn-one",
            "session_id": "session-one",
            "user_text": "forbidden",
        },
    ],
)
def test_governed_commit_rejects_tampered_no_write_decision(
    monkeypatch: pytest.MonkeyPatch,
    decision: dict[str, str],
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from run_agent import AIAgent

    provider = _Provider()
    agent = object.__new__(AIAgent)
    agent.session_id = "session-one"
    agent._memory_manager = _manager(provider)
    agent._flexa_pending_memory_decision = decision

    with pytest.raises(RuntimeError, match="no-write decision is invalid"):
        agent._commit_governed_external_memory(turn_id="turn-one")
    assert not hasattr(agent, "_flexa_pending_memory_decision")
    assert provider.sync_calls == []


def test_system_prompt_provider_failure_propagates_in_governed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from agent.system_prompt import build_system_prompt_parts

    manager = MagicMock()
    manager.build_system_prompt.side_effect = RuntimeError("offline")
    agent = SimpleNamespace(
        load_soul_identity=False,
        skip_context_files=True,
        valid_tool_names=[],
        _task_completion_guidance=False,
        _parallel_tool_call_guidance=False,
        _tool_use_enforcement=False,
        _environment_probe=False,
        _kanban_worker_guidance="",
        _memory_store=None,
        _memory_manager=manager,
        _platform_hint_overrides={},
        context_compressor=None,
        model="",
        provider="",
        platform="",
        pass_session_id=False,
        session_id="",
    )

    with (
        patch("run_agent.build_nous_subscription_prompt", return_value=""),
        patch("run_agent.build_environment_hints", return_value=""),
        pytest.raises(RuntimeError, match="offline"),
    ):
        build_system_prompt_parts(agent)


def test_compression_provider_failures_propagate_in_governed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from agent.conversation_compression import compress_context

    manager = MagicMock()
    manager.on_pre_compress.side_effect = RuntimeError("offline")
    compressor = MagicMock()
    agent = SimpleNamespace(
        api_mode="",
        _compression_feasibility_checked=True,
        compression_in_place=False,
        session_id="session-one",
        model="test/model",
        _emit_status=lambda *_args, **_kwargs: None,
        _session_db=None,
        _memory_manager=manager,
        context_compressor=compressor,
    )

    with (
        patch("agent.flexa_enforcement.turn_active", return_value=False),
        pytest.raises(RuntimeError, match="offline"),
    ):
        compress_context(
            agent,
            [{"role": "user", "content": "remember"}],
            "system",
            approx_tokens=100,
        )
    compressor.compress.assert_not_called()


def test_compression_session_switch_failure_propagates_in_governed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FLEXA_GOVERNED_MODE", raising=False)
    with (
        patch("run_agent.get_tool_definitions", return_value=[]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        from run_agent import AIAgent

        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            skip_context_files=True,
            skip_memory=True,
        )

    compressor = MagicMock()
    compressor.context_length = 204_800
    compressor.compress.return_value = [
        {"role": "user", "content": "compressed summary"}
    ]
    compressor.compression_count = 1
    compressor.last_prompt_tokens = 0
    compressor.last_completion_tokens = 0
    compressor._last_compress_aborted = False
    compressor._last_summary_error = None
    compressor._last_compression_made_progress = True
    agent.context_compressor = compressor
    agent._compression_feasibility_checked = True
    agent.compression_in_place = True

    manager = MagicMock()
    manager.build_system_prompt.return_value = ""
    manager.on_pre_compress.return_value = ""
    manager.on_session_switch.side_effect = RuntimeError("switch offline")
    agent._memory_manager = manager
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")

    with (
        patch("agent.flexa_enforcement.turn_active", return_value=False),
        pytest.raises(RuntimeError, match="switch offline"),
    ):
        agent._compress_context(
            [
                {"role": "user", "content": "one"},
                {"role": "assistant", "content": "two"},
            ],
            "system",
            approx_tokens=100,
        )
    manager.on_session_switch.assert_called_once()


def test_provider_tool_is_never_registered_in_governed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    provider = _Provider()
    manager = _manager(provider)

    from hermes_cli.flexa_governed import GovernedProfileError

    assert manager.has_tool("flexa_memory_store") is False
    assert manager.get_all_tool_names() == set()
    with pytest.raises(GovernedProfileError, match="write approval is unavailable"):
        manager.handle_tool_call("flexa_memory_store", {"content": "candidate"})
    assert provider.tool_calls == []


def test_unconfirmed_memory_commit_never_releases_governed_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from agent import conversation_loop
    from agent.turn_context import GOVERNED_TURN_MARKER_FIELD
    from agent.flexa_enforcement import FlexaEnforcementError

    class _Input:
        def __init__(self) -> None:
            self.key = SimpleNamespace(turn_id="turn-one")
            self.model_message = "model-visible user"
            self.persistence_message = "persisted user"

    release = MagicMock()
    persist = MagicMock()
    commit = MagicMock(return_value=False)
    revoke = MagicMock()
    agent = SimpleNamespace(
        platform="telegram",
        session_id="session-one",
        quiet_mode=False,
        verbose_logging=True,
        suppress_status_output=False,
        _session_messages=[],
        _current_streamed_assistant_text="",
        _last_content_with_tools=None,
        _discard_governed_external_memory=lambda: None,
        _commit_governed_external_memory=commit,
        _persist_session=persist,
    )
    governed_input = _Input()
    result = {
        "final_response": "approved assistant output",
        "last_reasoning": "private reasoning",
        "messages": [
            {
                "role": "user",
                "content": governed_input.model_message,
                GOVERNED_TURN_MARKER_FIELD: "turn-one",
            },
            {"role": "assistant", "content": "approved assistant output"},
        ],
    }

    with (
        patch("agent.flexa_enforcement.GovernedTurnInput", _Input),
        patch("agent.flexa_enforcement.has_channel_handoff", return_value=True),
        patch(
            "agent.flexa_enforcement.user_input",
            side_effect=lambda _agent, value: value,
        ),
        patch("agent.flexa_enforcement.output", return_value="approved assistant output"),
        patch("agent.flexa_enforcement.release_buffered_output", release),
        patch("agent.flexa_enforcement.require_governed_runtime"),
        patch("agent.flexa_enforcement.revoke_turn", revoke),
        patch("agent.flexa_enforcement.scrub_reasoning"),
        patch("hermes_cli.flexa_governed.ensure_governed_content_free_logging"),
        patch("agent.conversation_loop._run_conversation_impl", return_value=result),
        pytest.raises(FlexaEnforcementError, match="managed turn failed"),
    ):
        conversation_loop.run_conversation(agent, governed_input)

    commit.assert_called_once_with(turn_id="turn-one")
    release.assert_not_called()
    persist.assert_not_called()
    assert revoke.call_count >= 1


def test_bound_no_write_decision_allows_full_governed_output_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    from agent import conversation_loop
    from agent.turn_context import GOVERNED_TURN_MARKER_FIELD
    from run_agent import AIAgent

    class _Input:
        def __init__(self) -> None:
            self.key = SimpleNamespace(turn_id="turn-one")
            self.model_message = "model-visible user"
            self.persistence_message = "persisted user"

    provider = _Provider()
    release = MagicMock()
    persist = MagicMock()
    revoke = MagicMock()
    agent = SimpleNamespace(
        platform="telegram",
        session_id="session-one",
        quiet_mode=False,
        verbose_logging=True,
        suppress_status_output=False,
        _session_messages=[],
        _current_streamed_assistant_text="",
        _last_content_with_tools=None,
        _memory_manager=_manager(provider),
        _flexa_turn_id="turn-one",
        _persist_session=persist,
    )
    agent._sync_external_memory_for_turn = MethodType(
        AIAgent._sync_external_memory_for_turn,
        agent,
    )
    agent._discard_governed_external_memory = MethodType(
        AIAgent._discard_governed_external_memory,
        agent,
    )
    agent._commit_governed_external_memory = MethodType(
        AIAgent._commit_governed_external_memory,
        agent,
    )
    governed_input = _Input()
    result = {
        "final_response": "approved assistant output",
        "last_reasoning": "private reasoning",
        "messages": [
            {
                "role": "user",
                "content": governed_input.model_message,
                GOVERNED_TURN_MARKER_FIELD: "turn-one",
            },
            {"role": "assistant", "content": "approved assistant output"},
        ],
    }

    def _completed_turn(*_args, **_kwargs):
        agent._sync_external_memory_for_turn(
            original_user_message="raw user text",
            final_response="raw assistant text",
            interrupted=False,
        )
        return result

    with (
        patch("agent.flexa_enforcement.GovernedTurnInput", _Input),
        patch("agent.flexa_enforcement.has_channel_handoff", return_value=True),
        patch(
            "agent.flexa_enforcement.user_input",
            side_effect=lambda _agent, value: value,
        ),
        patch("agent.flexa_enforcement.output", return_value="approved assistant output"),
        patch("agent.flexa_enforcement.release_buffered_output", release),
        patch("agent.flexa_enforcement.require_governed_runtime"),
        patch("agent.flexa_enforcement.revoke_turn", revoke),
        patch("agent.flexa_enforcement.scrub_reasoning"),
        patch("hermes_cli.flexa_governed.ensure_governed_content_free_logging"),
        patch("agent.conversation_loop._run_conversation_impl", side_effect=_completed_turn),
    ):
        completed = conversation_loop.run_conversation(agent, governed_input)

    assert completed["final_response"] == "approved assistant output"
    release.assert_called_once_with(agent, "approved assistant output")
    persist.assert_called_once()
    revoke.assert_not_called()
    assert provider.sync_calls == []
    assert not hasattr(agent, "_flexa_pending_memory_decision")


def test_aiagent_uses_only_scoped_external_memory_in_governed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    provider = _Provider()
    scope = {
        "schema_version": "1",
        "tenant_id": "tenant-one",
        "employee_id": "oren-cto",
        "profile_slug": "oren-cto",
        "principal_namespace": "telegram",
        "principal_id": "user-one",
        "release_id": "release-one",
        "bundle_signing_payload_sha256": "a" * 64,
    }
    cfg = {
        "memory": {
            "mode": "governed_external",
            "memory_enabled": False,
            "user_profile_enabled": False,
            "write_approval": True,
            "provider": "flexa-memory",
            "principal_assertion": {
                "algorithm": "ed25519",
                "key_id": "unconfigured",
                "public_key_sha256": "unconfigured",
            },
        },
        "agent": {},
    }

    with (
        patch("hermes_cli.config.load_config", return_value=cfg),
        patch(
            "hermes_cli.flexa_governed.verify_governed_principal_assertion",
            return_value=object(),
        ),
        patch("hermes_cli.flexa_governed.governed_memory_scope", return_value=scope),
        patch("plugins.memory.load_memory_provider", return_value=provider),
        patch("agent.model_metadata.get_model_context_length", return_value=204_800),
        patch("run_agent.get_tool_definitions", return_value=[]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        from run_agent import AIAgent

        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            skip_context_files=True,
            session_id="session-one",
            platform="telegram",
            user_id="user-one",
        )

    assert agent._memory_store is None
    assert agent._memory_enabled is False
    assert agent._user_profile_enabled is False
    assert agent._memory_manager is not None
    assert provider.initialized["flexa_scope"] == scope


def test_aiagent_cannot_skip_governed_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLEXA_GOVERNED_MODE", "true")
    cfg = {
        "memory": {
            "mode": "governed_external",
            "memory_enabled": False,
            "user_profile_enabled": False,
            "write_approval": True,
            "provider": "flexa-memory",
            "principal_assertion": {
                "algorithm": "ed25519",
                "key_id": "unconfigured",
                "public_key_sha256": "unconfigured",
            },
        },
        "agent": {},
    }

    with (
        patch("hermes_cli.config.load_config", return_value=cfg),
        patch("agent.model_metadata.get_model_context_length", return_value=204_800),
        patch("run_agent.get_tool_definitions", return_value=[]),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
    ):
        from hermes_cli.flexa_governed import GovernedProfileError
        from run_agent import AIAgent

        with pytest.raises(GovernedProfileError, match="cannot be skipped"):
            AIAgent(
                api_key="test-key-1234567890",
                base_url="https://openrouter.ai/api/v1",
                quiet_mode=True,
                skip_context_files=True,
                skip_memory=True,
                session_id="session-one",
                platform="telegram",
                user_id="user-one",
            )
