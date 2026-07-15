"""Persistence controls for the explicit Flexa supervised runtime mode."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from typing import Any


_PLUGIN_KEY = "flexa-disclosure-boundary"
_PLUGIN_MODULE = "hermes_plugins.flexa_disclosure_boundary"
_PLUGIN_FILES = frozenset({"__init__.py", "boundary.py", "plugin.yaml"})
_BLOCKED_DISPOSITION = "flexa_disclosure_blocked"
_HOOKS = {
    "pre_llm_call": "_pre_llm_call",
    "transform_llm_output": "_transform_llm_output",
}
_OUTPUT_METHODS = (
    "_safe_print",
    "_buffer_vprint",
    "_buffer_status",
    "_emit_status",
    "_emit_warning",
)


def _regular_plugin_files(root: Path) -> set[str]:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("supervised disclosure plugin directory is unsafe")
    files: set[str] = set()
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("supervised disclosure plugin contains an unsafe entry")
        files.add(path.name)
    if files != _PLUGIN_FILES:
        raise RuntimeError("supervised disclosure plugin file allowlist differs")
    return files


def validate_supervised_plugin_manager(
    manager: Any = None,
    *,
    enabled_plugins: set[str] | None = None,
    signed_profile_root: Path | None = None,
) -> None:
    """Require the sole signed profile extension and exact callback allowlist."""

    if manager is None:
        from hermes_cli.plugins import _get_enabled_plugins, get_plugin_manager

        manager = get_plugin_manager()
        manager.discover_and_load()
        enabled_plugins = _get_enabled_plugins()
    if enabled_plugins != {_PLUGIN_KEY}:
        raise RuntimeError("supervised plugin allowlist must contain exactly one plugin")

    loaded = getattr(manager, "_plugins", {}).get(_PLUGIN_KEY)
    manifest = getattr(loaded, "manifest", None)
    if (
        loaded is None
        or not getattr(loaded, "enabled", False)
        or getattr(manifest, "name", None) != _PLUGIN_KEY
        or getattr(manifest, "kind", None) != "standalone"
        or getattr(manifest, "version", None) != "1.0.0"
        or set(getattr(loaded, "hooks_registered", ())) != set(_HOOKS)
        or getattr(loaded, "tools_registered", None)
        or getattr(loaded, "middleware_registered", None)
        or getattr(loaded, "commands_registered", None)
    ):
        raise RuntimeError("signed supervised disclosure plugin is not uniquely active")

    for key, candidate in getattr(manager, "_plugins", {}).items():
        if key != _PLUGIN_KEY and getattr(candidate, "enabled", False):
            raise RuntimeError("an unapproved plugin is active")
    if os.environ.get("HERMES_ENABLE_PROJECT_PLUGINS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        raise RuntimeError("project plugins are forbidden in supervised mode")

    hooks = {
        name: callbacks
        for name, callbacks in getattr(manager, "_hooks", {}).items()
        if callbacks
    }
    if set(hooks) != set(_HOOKS):
        raise RuntimeError("supervised hook allowlist differs")
    for hook_name, expected_name in _HOOKS.items():
        callbacks = hooks[hook_name]
        if len(callbacks) != 1:
            raise RuntimeError("supervised disclosure callback is missing or ambiguous")
        callback = callbacks[0]
        if (
            getattr(callback, "__module__", "") != _PLUGIN_MODULE
            or getattr(callback, "__name__", "") != expected_name
        ):
            raise RuntimeError("supervised disclosure callback identity differs")
    if any(getattr(manager, "_middleware", {}).values()):
        raise RuntimeError("plugin middleware is forbidden in supervised mode")

    raw_profile_root = os.environ.get("FLEXA_PROFILE_BUNDLE", "").strip()
    profile_root = signed_profile_root or Path(raw_profile_root)
    if not profile_root.is_absolute() or profile_root.is_symlink() or not profile_root.is_dir():
        raise RuntimeError("signed profile bundle is unavailable")
    signed_plugin = profile_root / "plugins" / _PLUGIN_KEY
    loaded_plugin = Path(str(getattr(manifest, "path", "")))
    _regular_plugin_files(signed_plugin)
    _regular_plugin_files(loaded_plugin)
    for name in _PLUGIN_FILES:
        signed_digest = hashlib.sha256((signed_plugin / name).read_bytes()).digest()
        loaded_digest = hashlib.sha256((loaded_plugin / name).read_bytes()).digest()
        if signed_digest != loaded_digest:
            raise RuntimeError("loaded disclosure plugin differs from signed profile bundle")


def supervised_disclosure_preflight(
    user_message: Any,
    *,
    session_id: str = "",
    platform: str = "",
) -> str | None:
    """Classify one raw turn through the sole signed hook before runtime work.

    ``None`` is the trusted benign decision. A string is the complete fixed
    response for an explicitly blocked turn. Calling the exact validated
    callbacks directly avoids the base plugin manager's fail-open exception
    handling and keeps this decision ahead of context building and providers.
    """

    from hermes_cli.plugins import get_plugin_manager

    validate_supervised_plugin_manager()
    manager = get_plugin_manager()
    pre_callback = manager._hooks["pre_llm_call"][0]
    transform_callback = manager._hooks["transform_llm_output"][0]
    pre_result = pre_callback(
        session_id=session_id,
        user_message=user_message,
        model="",
        platform=platform,
    )
    if pre_result is None:
        return None
    if (
        not isinstance(pre_result, dict)
        or set(pre_result) != {"context"}
        or not isinstance(pre_result.get("context"), str)
        or not pre_result["context"]
    ):
        raise RuntimeError("signed disclosure preflight returned an invalid decision")
    transformed = transform_callback(
        response_text="",
        session_id=session_id,
        user_message=user_message,
        model="",
        platform=platform,
    )
    if (
        not isinstance(transformed, str)
        or not transformed
        or getattr(transformed, "flexa_blocked", None) is not True
    ):
        raise RuntimeError("signed disclosure preflight omitted its blocked decision")
    return str(transformed)


def filter_supervised_disclosure_history(
    history: Any,
    *,
    session_id: str = "",
    platform: str = "",
) -> list[dict[str, Any]]:
    """Exclude every durable or deterministically recognized blocked turn.

    The durable disposition survives restart. Reclassification is the fallback
    for legacy/client-seeded rows where arbitrary message metadata was lost.
    Once a blocked user row is recognized, every derived row up to the next
    user boundary is excluded so no fixed response, tool row, or paraphrase can
    become future model, compression, title, goal, or memory input.
    """

    if history is None:
        return []
    if not isinstance(history, list):
        raise RuntimeError("supervised disclosure history is invalid")
    filtered: list[dict[str, Any]] = []
    current_turn_allowed = False
    for index, raw in enumerate(history):
        if not isinstance(raw, dict):
            raise RuntimeError("supervised disclosure history row is invalid")
        role = raw.get("role")
        if raw.get("effect_disposition") == _BLOCKED_DISPOSITION:
            if role == "user":
                current_turn_allowed = False
            continue
        content = raw.get("content")
        if role == "user":
            current_turn_allowed = False
            if not isinstance(content, str):
                continue
            fixed_response = supervised_disclosure_preflight(
                content,
                session_id=f"{session_id}:history:{index}",
                platform=platform,
            )
            if fixed_response is not None:
                current_turn_allowed = False
                continue
            filtered.append(copy.deepcopy(raw))
            current_turn_allowed = True
            continue
        if role in {"assistant", "tool"} and current_turn_allowed:
            filtered.append(copy.deepcopy(raw))
    return filtered


def _clear_supervised_output_buffers(agent: Any) -> None:
    buffer_value = getattr(agent, "_retry_status_buffer", None)
    if isinstance(buffer_value, (list, dict, set)):
        buffer_value.clear()
    elif buffer_value is not None:
        agent._retry_status_buffer = []
    if hasattr(agent, "_pending_fallback_notice"):
        agent._pending_fallback_notice = None


def install_supervised_output_guard(agent: Any) -> dict[str, tuple[bool, Any]]:
    """Suppress direct prints, status callbacks, and retry buffers for a turn."""

    snapshot: dict[str, tuple[bool, Any]] = {}
    instance_dict = getattr(agent, "__dict__", {})

    def discard_output(*_args: Any, **_kwargs: Any) -> None:
        return None

    for name in _OUTPUT_METHODS:
        original = getattr(agent, name, None)
        if callable(original):
            snapshot[name] = (name in instance_dict, original)
            setattr(agent, name, discard_output)
    _clear_supervised_output_buffers(agent)
    return snapshot


def restore_supervised_output_guard(
    agent: Any,
    snapshot: dict[str, tuple[bool, Any]],
) -> None:
    """Clear transient buffers and restore the exact pre-turn output methods."""

    _clear_supervised_output_buffers(agent)
    for name, (owned_by_instance, original) in snapshot.items():
        if owned_by_instance:
            setattr(agent, name, original)
            continue
        try:
            delattr(agent, name)
        except AttributeError:
            pass


def install_supervised_turn_guard(agent: Any) -> None:
    """Defer every session write until the final response is sanitized."""

    if getattr(agent, "_flexa_supervised_turn_guard_installed", False):
        agent._flexa_supervised_final_persist_allowed = False
        return

    original_persist = agent._persist_session

    def guarded_persist(*args: Any, **kwargs: Any) -> Any:
        if getattr(agent, "_flexa_supervised_final_persist_allowed", False):
            return original_persist(*args, **kwargs)
        return None

    original_flush = agent._flush_messages_to_session_db

    def guarded_flush(*args: Any, **kwargs: Any) -> Any:
        if getattr(agent, "_flexa_supervised_final_persist_allowed", False):
            return original_flush(*args, **kwargs)
        return None

    agent._persist_session = guarded_persist
    agent._flush_messages_to_session_db = guarded_flush
    agent._flexa_supervised_final_persist_allowed = False
    agent._flexa_supervised_turn_guard_installed = True


def persist_sanitized_turn(agent: Any, messages: Any, conversation_history: Any) -> None:
    """Open the persistence gate for one sanitized final snapshot only."""

    if not getattr(agent, "_flexa_supervised_turn_guard_installed", False):
        raise RuntimeError("supervised persistence guard was not installed")
    agent._flexa_supervised_final_persist_allowed = True
    try:
        agent._persist_session(messages, conversation_history)
    finally:
        agent._flexa_supervised_final_persist_allowed = False


def _copy_supervised_history(history: Any) -> list[dict[str, Any]]:
    if history is None:
        return []
    if not isinstance(history, list):
        raise RuntimeError("supervised conversation history is invalid")
    copied: list[dict[str, Any]] = []
    for raw in history:
        if not isinstance(raw, dict):
            raise RuntimeError("supervised conversation message is invalid")
        message = copy.deepcopy(raw)
        message.pop("_hermes_governed_current_turn", None)
        for key in ("reasoning", "reasoning_content", "thinking"):
            message.pop(key, None)
        copied.append(message)
    return copied


def build_supervised_blocked_result(
    agent: Any,
    *,
    user_message: Any,
    fixed_response: str,
    conversation_history: Any,
    persist_user_message: Any = None,
    persist_user_timestamp: Any = None,
) -> dict[str, Any]:
    """Persist and return only the blocked turn's user and fixed assistant rows."""

    if not isinstance(fixed_response, str) or not fixed_response:
        raise RuntimeError("supervised fixed response is invalid")
    persisted_user = (
        persist_user_message
        if isinstance(persist_user_message, str)
        else user_message
    )
    if not isinstance(persisted_user, str):
        raise RuntimeError("supervised blocked user message must be text")
    prior = _copy_supervised_history(conversation_history)
    current_user: dict[str, Any] = {
        "role": "user",
        "content": persisted_user,
        "effect_disposition": _BLOCKED_DISPOSITION,
    }
    if isinstance(persist_user_timestamp, (int, float)):
        current_user["timestamp"] = persist_user_timestamp
    messages = [
        *prior,
        current_user,
        {
            "role": "assistant",
            "content": fixed_response,
            "effect_disposition": _BLOCKED_DISPOSITION,
        },
    ]
    persist_sanitized_turn(agent, messages, prior)
    agent._session_messages = copy.deepcopy(messages)
    agent._current_streamed_assistant_text = ""
    agent._last_content_with_tools = None
    agent._response_was_previewed = False
    return {
        "final_response": fixed_response,
        "last_reasoning": None,
        "messages": messages,
        "api_calls": 0,
        "completed": True,
        "turn_exit_reason": "disclosure_boundary_blocked",
        "failed": False,
        "partial": False,
        "interrupted": False,
        "response_transformed": True,
        "response_previewed": False,
        "disclosure_blocked": True,
        "model": None,
        "provider": None,
        "base_url": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "session_id": getattr(agent, "session_id", None),
    }


def sanitize_current_turn(
    messages: list[Any], final_response: str, turn_id: str, *, blocked: bool
) -> None:
    """Remove current-turn model prose/reasoning before durable persistence."""

    from agent.turn_context import (
        GOVERNED_TURN_MARKER_FIELD,
        governed_current_user_index,
    )

    current_user_index = governed_current_user_index(messages, turn_id)
    messages[current_user_index].pop(GOVERNED_TURN_MARKER_FIELD, None)
    if blocked:
        del messages[current_user_index + 1 :]
        messages.append({"role": "assistant", "content": final_response})
        return

    sanitized_tail: list[Any] = []
    for message in messages[current_user_index + 1 :]:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            sanitized_tail.append(message)
            continue
        for key in ("reasoning", "reasoning_content", "thinking"):
            message.pop(key, None)
        if message.get("tool_calls"):
            sanitized_tail.append(message)
    messages[current_user_index + 1 :] = sanitized_tail
    messages.append({"role": "assistant", "content": final_response})


def fixed_failure_response(user_message: Any) -> str:
    """Return a non-configurable bilingual fail-closed response."""

    text = user_message if isinstance(user_message, str) else ""
    if any("\u0590" <= character <= "\u05ff" for character in text):
        return (
            "לא הצלחתי להשלים את התשובה בצורה בטוחה. אפשר לנסות שוב, ואם "
            "הבעיה נמשכת יש לפנות לצוות Flexa."
        )
    return (
        "I could not complete the response safely. Please try again, and "
        "contact the Flexa team if the issue continues."
    )
