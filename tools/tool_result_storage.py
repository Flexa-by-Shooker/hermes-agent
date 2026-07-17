"""Tool result persistence -- preserves large outputs instead of truncating.

Defense against context-window overflow operates at three levels:

1. **Per-tool output cap** (inside each tool): Tools like search_files
   pre-truncate their own output before returning. This is the first line
   of defense and the only one the tool author controls.

2. **Per-result persistence** (maybe_persist_tool_result): After a tool
   returns, if its output exceeds the tool's registered threshold
   (registry.get_max_result_size), the full output is written INTO THE
   SANDBOX temp dir (for example /tmp/hermes-results/{tool_use_id}.txt on
   standard Linux, or $TMPDIR/hermes-results/{tool_use_id}.txt on Termux)
   via env.execute(). The in-context content is replaced with a preview +
   file path reference. The model can read_file to access the full output
   on any backend.

3. **Per-turn aggregate budget** (enforce_turn_budget): After all tool
   results in a single assistant turn are collected, if the total exceeds
   MAX_TURN_BUDGET_CHARS (200K), the largest non-persisted results are
   spilled to disk until the aggregate is under budget. This catches cases
   where many medium-sized results combine to overflow context.
"""

import hashlib
import json
import logging
import os
import re
import shlex
import uuid
from collections.abc import Collection

from tools.budget_config import (
    DEFAULT_PREVIEW_SIZE_CHARS,
    BudgetConfig,
    DEFAULT_BUDGET,
)

logger = logging.getLogger(__name__)
PERSISTED_OUTPUT_TAG = "<persisted-output>"
PERSISTED_OUTPUT_CLOSING_TAG = "</persisted-output>"
STORAGE_DIR = "/tmp/hermes-results"
HEREDOC_MARKER = "HERMES_PERSIST_EOF"
_BUDGET_TOOL_NAME = "__budget_enforcement__"
_UNSAFE_RESULT_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")
_MAX_RESULT_FILENAME_STEM = 120
_OPAQUE_ATTACHMENT_ID = re.compile(r"^[a-f0-9]{32}\.[a-z0-9]{1,8}$")


def _resolve_storage_dir(env) -> str:
    """Return the best temp-backed storage dir for this environment."""
    if env is not None:
        get_temp_dir = getattr(env, "get_temp_dir", None)
        if callable(get_temp_dir):
            try:
                temp_dir = get_temp_dir()
            except Exception as exc:
                logger.debug("Could not resolve env temp dir: %s", exc)
            else:
                if temp_dir:
                    temp_dir = temp_dir.rstrip("/") or "/"
                    return f"{temp_dir}/hermes-results"
    return STORAGE_DIR


def _safe_result_filename(tool_use_id: str) -> str:
    """Return a single safe filename for a tool result id."""
    raw_id = str(tool_use_id or "tool_result")
    safe_stem = _UNSAFE_RESULT_FILENAME_CHARS.sub("_", raw_id).strip("._-")
    changed = safe_stem != raw_id

    if not safe_stem:
        safe_stem = "tool_result"
        changed = True

    if changed or len(safe_stem) > _MAX_RESULT_FILENAME_STEM:
        digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]
        safe_stem = safe_stem[:_MAX_RESULT_FILENAME_STEM].rstrip("._-") or "tool_result"
        safe_stem = f"{safe_stem}_{digest}"

    return f"{safe_stem}.txt"


def generate_preview(content: str, max_chars: int = DEFAULT_PREVIEW_SIZE_CHARS) -> tuple[str, bool]:
    """Truncate at last newline within max_chars. Returns (preview, has_more)."""
    if len(content) <= max_chars:
        return content, False
    truncated = content[:max_chars]
    last_nl = truncated.rfind("\n")
    if last_nl > max_chars // 2:
        truncated = truncated[:last_nl + 1]
    return truncated, True


def _heredoc_marker(content: str) -> str:
    """Return a heredoc delimiter that doesn't collide with content."""
    if HEREDOC_MARKER not in content:
        return HEREDOC_MARKER
    return f"HERMES_PERSIST_{uuid.uuid4().hex[:8]}"


def _write_to_sandbox(content: str, remote_path: str, env) -> bool:
    """Write content into the sandbox via env.execute(). Returns True on success.

    Pushes ``content`` through stdin rather than embedding it in the command
    string. Linux's ``MAX_ARG_STRLEN`` caps any single argv element at 128 KB
    (32 * PAGE_SIZE), so the previous heredoc-in-the-command-string approach
    silently failed with ``OSError: [Errno 7] Argument list too long`` for any
    tool result over ~128 KB — exactly the case persistence exists to handle.
    Routing through stdin removes that ceiling on local + ssh (``_stdin_mode
    == "pipe"``); remote backends with ``_stdin_mode == "heredoc"`` keep their
    existing API-body sized limit, which is orders of magnitude larger than
    the exec-arg ceiling.
    """
    storage_dir = os.path.dirname(remote_path)
    cmd = f"mkdir -p {shlex.quote(storage_dir)} && cat > {shlex.quote(remote_path)}"
    result = env.execute(cmd, timeout=30, stdin_data=content)
    return result.get("returncode", 1) == 0


def _build_persisted_message(
    preview: str,
    has_more: bool,
    original_size: int,
    file_path: str,
) -> str:
    """Build the <persisted-output> replacement block."""
    size_kb = original_size / 1024
    if size_kb >= 1024:
        size_str = f"{size_kb / 1024:.1f} MB"
    else:
        size_str = f"{size_kb:.1f} KB"

    msg = f"{PERSISTED_OUTPUT_TAG}\n"
    msg += f"This tool result was too large ({original_size:,} characters, {size_str}).\n"
    msg += f"Full output saved to: {file_path}\n"
    msg += "Use the read_file tool with offset and limit to access specific sections of this output.\n\n"
    msg += f"Preview (first {len(preview)} chars):\n"
    msg += preview
    if has_more:
        msg += "\n..."
    msg += f"\n{PERSISTED_OUTPUT_CLOSING_TAG}"
    return msg


def maybe_persist_tool_result(
    content: str,
    tool_name: str,
    tool_use_id: str,
    env=None,
    config: BudgetConfig = DEFAULT_BUDGET,
    threshold: int | float | None = None,
) -> str:
    """Layer 2: persist oversized result into the sandbox, return preview + path.

    Writes via env.execute() so the file is accessible from any backend
    (local, Docker, SSH, Modal, Daytona). Falls back to inline truncation
    if write fails or no env is available.

    Args:
        content: Raw tool result string.
        tool_name: Name of the tool (used for threshold lookup).
        tool_use_id: Unique ID for this tool call (used as filename).
        env: The active BaseEnvironment instance, or None.
        config: BudgetConfig controlling thresholds and preview size.
        threshold: Explicit override; takes precedence over config resolution.

    Returns:
        Original content if small, or <persisted-output> replacement.
    """
    effective_threshold = threshold if threshold is not None else config.resolve_threshold(tool_name)

    if effective_threshold == float("inf"):
        return content

    if len(content) <= effective_threshold:
        return content

    storage_dir = _resolve_storage_dir(env)
    remote_path = f"{storage_dir}/{_safe_result_filename(tool_use_id)}"
    preview, has_more = generate_preview(content, max_chars=config.preview_size)

    if env is not None:
        try:
            if _write_to_sandbox(content, remote_path, env):
                logger.info(
                    "Persisted large tool result: %s (%s, %d chars -> %s)",
                    tool_name, tool_use_id, len(content), remote_path,
                )
                return _build_persisted_message(preview, has_more, len(content), remote_path)
        except Exception as exc:
            logger.warning("Sandbox write failed for %s: %s", tool_use_id, exc)

    logger.info(
        "Inline-truncating large tool result: %s (%d chars, no sandbox write)",
        tool_name, len(content),
    )
    return (
        f"{preview}\n\n"
        f"[Truncated: tool response was {len(content):,} chars. "
        f"Full output could not be saved to sandbox.]"
    )


def _read_attachment_retry_envelope(content: str) -> str:
    """Return a small, plaintext-free retry result for the attachment broker."""

    attachment_id: str | None = None
    offset = 1
    try:
        parsed = json.loads(content)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        candidate_id = parsed.get("attachment_id")
        candidate_offset = parsed.get("offset")
        if (
            isinstance(candidate_id, str)
            and _OPAQUE_ATTACHMENT_ID.fullmatch(candidate_id)
        ):
            attachment_id = candidate_id
        if (
            isinstance(candidate_offset, int)
            and not isinstance(candidate_offset, bool)
            and candidate_offset >= 1
        ):
            offset = candidate_offset

    result = {
        "content": "",
        "deferred": True,
        "hint": "Retry this attachment page in a new tool turn.",
        "next_offset": offset,
        "offset": offset,
        "returned_lines": 0,
        "truncated": True,
    }
    if attachment_id is not None:
        result["attachment_id"] = attachment_id
    return json.dumps(result, ensure_ascii=False, sort_keys=True)


def fit_inline_only_tool_result(
    content: str,
    tool_name: str,
    max_chars: int | float,
) -> str:
    """Fit a never-persisted result inline without writing plaintext to disk.

    ``read_attachment`` returns a structured pagination document. When a
    small-context model has a lower per-result budget, preserve as many whole
    broker lines as fit and advance ``next_offset`` by exactly that count. A
    malformed result, or a page for which no line fits, becomes a content-free
    retry envelope.
    """

    if max_chars == float("inf") or len(content) <= max_chars:
        return content
    if tool_name != "read_attachment":
        return content

    retry = _read_attachment_retry_envelope(content)
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
        return retry

    try:
        parsed = json.loads(content)
    except (TypeError, ValueError):
        return retry
    if not isinstance(parsed, dict):
        return retry
    page_content = parsed.get("content")
    offset = parsed.get("offset")
    returned_lines = parsed.get("returned_lines")
    if (
        not isinstance(page_content, str)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or offset < 1
        or not isinstance(returned_lines, int)
        or isinstance(returned_lines, bool)
        or returned_lines < 0
    ):
        return retry

    if returned_lines == 0:
        lines: list[str] = []
    elif returned_lines == 1:
        lines = [page_content]
    else:
        lines = page_content.split("\n")
        if len(lines) != returned_lines:
            return retry

    def render(line_count: int) -> str:
        candidate = dict(parsed)
        candidate["content"] = "\n".join(lines[:line_count])
        candidate["offset"] = offset
        candidate["returned_lines"] = line_count
        candidate["truncated"] = True
        candidate["next_offset"] = offset + line_count
        candidate["hint"] = (
            f"Use offset={offset + line_count} to continue reading."
            if line_count
            else "Retry this attachment page in a new tool turn."
        )
        if line_count == 0:
            candidate["deferred"] = True
        else:
            candidate.pop("deferred", None)
        return json.dumps(candidate, ensure_ascii=False, sort_keys=True)

    low = 0
    high = len(lines)
    best = retry
    while low <= high:
        middle = (low + high) // 2
        rendered = render(middle)
        if len(rendered) <= max_chars:
            best = rendered
            low = middle + 1
        else:
            high = middle - 1
    return best


def enforce_turn_budget(
    tool_messages: list[dict],
    env=None,
    config: BudgetConfig = DEFAULT_BUDGET,
    never_persist_tool_names: Collection[str] | None = None,
) -> list[dict]:
    """Layer 3: enforce aggregate budget across all tool results in a turn.

    If total chars exceed budget, persist the largest non-persisted results
    first (via sandbox write) until under budget. Already-persisted results
    are skipped.

    Mutates the list in-place and returns it.
    """
    never_persist = frozenset(never_persist_tool_names or ())
    candidates = []
    inline_only_candidates = []
    total_size = 0
    for i, msg in enumerate(tool_messages):
        content = msg.get("content", "")
        size = len(content)
        total_size += size
        tool_name = msg.get("tool_name") or msg.get("name")
        if tool_name in never_persist:
            inline_only_candidates.append((i, size, str(tool_name)))
        elif PERSISTED_OUTPUT_TAG not in content:
            candidates.append((i, size))

    if total_size <= config.turn_budget:
        return tool_messages

    candidates.sort(key=lambda x: x[1], reverse=True)

    for idx, size in candidates:
        if total_size <= config.turn_budget:
            break
        msg = tool_messages[idx]
        content = msg["content"]
        tool_use_id = msg.get("tool_call_id", f"budget_{idx}")

        replacement = maybe_persist_tool_result(
            content=content,
            tool_name=_BUDGET_TOOL_NAME,
            tool_use_id=tool_use_id,
            env=env,
            config=config,
            threshold=0,
        )
        if replacement != content:
            total_size -= size
            total_size += len(replacement)
            tool_messages[idx]["content"] = replacement
            logger.info(
                "Budget enforcement: persisted tool result %s (%d chars)",
                tool_use_id, size,
            )

    # Governed broker plaintext is never eligible for sandbox persistence.
    # If several inline-only pages together exceed a small model's turn
    # budget, defer the largest pages to later tool turns with an opaque,
    # content-free pagination envelope.
    inline_only_candidates.sort(key=lambda item: item[1], reverse=True)
    for idx, size, tool_name in inline_only_candidates:
        if total_size <= config.turn_budget:
            break
        content = tool_messages[idx].get("content", "")
        if not isinstance(content, str):
            continue
        if tool_name == "read_attachment":
            replacement = _read_attachment_retry_envelope(content)
        else:
            continue
        tool_messages[idx]["content"] = replacement
        total_size -= size
        total_size += len(replacement)
        logger.info(
            "Budget enforcement: deferred inline-only tool result %s (%d chars)",
            tool_messages[idx].get("tool_call_id", f"budget_{idx}"),
            size,
        )

    return tool_messages
