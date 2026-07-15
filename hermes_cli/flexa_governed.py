"""Fail-closed helpers for Flexa-managed Hermes profiles.

This module is carried as a reviewed Flexa patch.  The roster path is supplied
by the verified runtime launcher and points at an immutable, signed JSON
artifact.  HTTP/RPC request data never selects an unlisted profile, employee,
or enforcement endpoint.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_EMPLOYEE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SIDECAR = re.compile(r"^http://enforcement-[a-z0-9][a-z0-9-]{0,62}:8081$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_LOG_FACTORY_LOCK = threading.Lock()
_LOG_FACTORY_INSTALLED = False
SUPERVISED_DISCLOSURE_LINEAGE_FIELD = "_flexa_disclosure_boundary_version"
SUPERVISED_DISCLOSURE_LINEAGE_VERSION = "1"


class GovernedProfileError(RuntimeError):
    """Raised whenever signed profile routing cannot be proven."""


@dataclass(frozen=True)
class ManagedProfile:
    tenant_id: str
    release_id: str
    bundle_signing_payload_sha256: str
    slug: str
    employee_id: str
    primary: bool
    description: str
    enforcement_api: str
    binding_sha256: str
    config_sha256: str
    metadata_sha256: str
    buffered_output: bool


def governed_mode() -> bool:
    return os.environ.get("FLEXA_GOVERNED_MODE", "").strip().lower() == "true"


def supervised_disclosure_mode() -> bool:
    return (
        os.environ.get("FLEXA_SUPERVISED_DISCLOSURE_BOUNDARY", "")
        .strip()
        .lower()
        in {"1", "true", "yes", "on"}
    )


def disclosure_boundary_mode() -> bool:
    """Return whether a signed pre-persistence disclosure boundary is required."""

    return governed_mode() or supervised_disclosure_mode()


def stamp_supervised_session_config(value: Any) -> dict[str, Any] | None:
    """Stamp new supervised lineages without upgrading pre-existing rows."""

    if not supervised_disclosure_mode():
        return value
    if value is None:
        stamped: dict[str, Any] = {}
    elif isinstance(value, dict):
        stamped = dict(value)
    else:
        raise GovernedProfileError("supervised session config is invalid")
    stamped[SUPERVISED_DISCLOSURE_LINEAGE_FIELD] = (
        SUPERVISED_DISCLOSURE_LINEAGE_VERSION
    )
    return stamped


def supervised_session_lineage_qualified(row: Any) -> bool:
    """Return exact proof that a durable session began under this boundary."""

    if not isinstance(row, dict):
        return False
    raw = row.get("model_config")
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(value, dict)
        and value.get(SUPERVISED_DISCLOSURE_LINEAGE_FIELD)
        == SUPERVISED_DISCLOSURE_LINEAGE_VERSION
    )


def ensure_governed_content_free_logging() -> None:
    """Make every in-process log record content-free in governed runtimes."""

    global _LOG_FACTORY_INSTALLED
    if not disclosure_boundary_mode() or _LOG_FACTORY_INSTALLED:
        return
    with _LOG_FACTORY_LOCK:
        if _LOG_FACTORY_INSTALLED:
            return
        previous_factory = logging.getLogRecordFactory()

        def content_free_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = previous_factory(*args, **kwargs)
            if disclosure_boundary_mode():
                record.msg = "governed runtime event"
                record.args = ()
                record.exc_info = None
                record.exc_text = None
                record.stack_info = None
            return record

        logging.setLogRecordFactory(content_free_factory)
        _LOG_FACTORY_INSTALLED = True


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _immutable_file(env_name: str, label: str) -> Path:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise GovernedProfileError(f"{label} is required")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise GovernedProfileError(f"{label} must be an immutable file")
    # Production runs on Linux.  Require a read-only bind target and a
    # non-writable containing directory so the runtime uid cannot replace the
    # checked inode after verification.  Windows lacks useful POSIX mode
    # semantics, so tests there rely on the mandatory digest/signature checks.
    if os.name == "posix":
        if path.stat().st_mode & 0o222 or path.parent.stat().st_mode & 0o222:
            raise GovernedProfileError(f"{label} mount is writable")
    return path


def _roster_path() -> Path:
    return _immutable_file("FLEXA_MANAGED_PROFILE_ROSTER", "managed profile roster")


def _required_env(name: str, pattern: re.Pattern[str], label: str) -> str:
    value = os.environ.get(name, "").strip()
    if not pattern.fullmatch(value):
        raise GovernedProfileError(f"{label} is missing or invalid")
    return value


def _strict_json(data: bytes) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    parsed = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=pairs_hook,
        parse_constant=reject_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError("top-level roster must be an object")
    return parsed


def _verify_roster_signature(raw: dict[str, Any]) -> None:
    signature = raw.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "key_id", "value"
    }:
        raise GovernedProfileError("managed profile roster signature is invalid")
    key_id = _required_env(
        "FLEXA_MANAGED_PROFILE_ROSTER_KEY_ID", _KEY_ID, "roster signing key id"
    )
    if (
        signature.get("algorithm") != "ed25519"
        or signature.get("key_id") != key_id
        or not isinstance(signature.get("value"), str)
    ):
        raise GovernedProfileError("managed profile roster signature is invalid")
    public_key_path = _immutable_file(
        "FLEXA_MANAGED_PROFILE_ROSTER_PUBLIC_KEY", "roster public key"
    )
    expected_key_sha = _required_env(
        "FLEXA_MANAGED_PROFILE_ROSTER_PUBLIC_KEY_SHA256",
        _SHA256,
        "roster public key digest",
    )
    if _sha256(public_key_path) != expected_key_sha:
        raise GovernedProfileError("roster public key digest mismatch")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("not Ed25519")
        decoded = base64.b64decode(signature["value"], validate=True)
        if len(decoded) != 64:
            raise ValueError("wrong Ed25519 signature length")
        unsigned = dict(raw)
        unsigned.pop("signature", None)
        payload = json.dumps(
            unsigned,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        public_key.verify(decoded, payload)
    except (ImportError, OSError, TypeError, ValueError, binascii.Error) as exc:
        raise GovernedProfileError("managed profile roster signature is invalid") from exc
    except Exception as exc:
        # cryptography's InvalidSignature is intentionally not imported as a
        # hard dependency at module import time.
        raise GovernedProfileError("managed profile roster signature is invalid") from exc


def managed_profiles() -> tuple[ManagedProfile, ...]:
    """Load and strictly validate the signed tenant roster on every call.

    Avoiding a process-global cache is intentional: qualification can replace
    the read-only mount only by restarting/reconciling the runtime, while tests
    and profile-scoped workers remain deterministic.
    """

    if not governed_mode():
        return ()
    roster_path = _roster_path()
    try:
        roster_bytes = roster_path.read_bytes()
        expected_roster_sha = _required_env(
            "FLEXA_MANAGED_PROFILE_ROSTER_SHA256", _SHA256, "roster digest"
        )
        if hashlib.sha256(roster_bytes).hexdigest() != expected_roster_sha:
            raise GovernedProfileError("managed profile roster digest mismatch")
        raw = _strict_json(roster_bytes)
    except GovernedProfileError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise GovernedProfileError("managed profile roster is unreadable") from exc
    if not isinstance(raw, dict) or set(raw) != {
        "kind", "schema_version", "tenant_id", "release_id",
        "bundle_signing_payload_sha256", "profiles", "signature",
    }:
        raise GovernedProfileError("managed profile roster has an invalid shape")
    if raw["kind"] != "FlexaManagedProfileRoster" or raw["schema_version"] != "1":
        raise GovernedProfileError("managed profile roster version is unsupported")
    expected_tenant = _required_env(
        "FLEXA_EXPECTED_TENANT_ID", _EMPLOYEE, "expected tenant id"
    )
    expected_release = _required_env(
        "FLEXA_EXPECTED_RELEASE_ID", _RELEASE, "expected release id"
    )
    expected_bundle_sha = _required_env(
        "FLEXA_EXPECTED_BUNDLE_SIGNING_PAYLOAD_SHA256",
        _SHA256,
        "expected bundle signing payload digest",
    )
    if raw["tenant_id"] != expected_tenant:
        raise GovernedProfileError("managed profile roster tenant is invalid")
    if raw["release_id"] != expected_release:
        raise GovernedProfileError("managed profile roster release is invalid")
    if raw["bundle_signing_payload_sha256"] != expected_bundle_sha:
        raise GovernedProfileError("managed profile roster bundle binding is invalid")
    _verify_roster_signature(raw)
    entries = raw["profiles"]
    if not isinstance(entries, list) or not entries:
        raise GovernedProfileError("managed profile roster must not be empty")
    profiles: list[ManagedProfile] = []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {
            "slug", "employee_id", "primary", "description",
            "enforcement_api", "binding_sha256", "config_sha256",
            "metadata_sha256", "buffered_output",
        }:
            raise GovernedProfileError("managed profile entry has an invalid shape")
        slug = item["slug"]
        employee_id = item["employee_id"]
        endpoint = item["enforcement_api"]
        description = item["description"]
        primary = item["primary"]
        buffered_output = item["buffered_output"]
        if not isinstance(slug, str) or not _SLUG.fullmatch(slug):
            raise GovernedProfileError("managed profile slug is invalid")
        if not isinstance(employee_id, str) or not _EMPLOYEE.fullmatch(employee_id):
            raise GovernedProfileError("managed employee id is invalid")
        if type(primary) is not bool:
            raise GovernedProfileError("managed primary marker must be boolean")
        if buffered_output is not True:
            raise GovernedProfileError("managed output must be buffered")
        if not isinstance(description, str) or not description.strip() or len(description) > 512:
            raise GovernedProfileError("managed profile description is invalid")
        if not isinstance(endpoint, str) or not _SIDECAR.fullmatch(endpoint):
            raise GovernedProfileError("managed enforcement endpoint is invalid")
        if endpoint != f"http://enforcement-{employee_id}:8081":
            raise GovernedProfileError("managed enforcement endpoint does not match employee")
        digests = (
            item["binding_sha256"],
            item["config_sha256"],
            item["metadata_sha256"],
        )
        if any(not isinstance(value, str) or not _SHA256.fullmatch(value) for value in digests):
            raise GovernedProfileError("managed profile digest is invalid")
        profiles.append(
            ManagedProfile(
                tenant_id=expected_tenant,
                release_id=expected_release,
                bundle_signing_payload_sha256=expected_bundle_sha,
                slug=slug,
                employee_id=employee_id,
                primary=primary,
                description=description.strip(),
                enforcement_api=endpoint,
                binding_sha256=digests[0],
                config_sha256=digests[1],
                metadata_sha256=digests[2],
                buffered_output=buffered_output,
            )
        )
    slugs = [item.slug for item in profiles]
    employees = [item.employee_id for item in profiles]
    if len(slugs) != len(set(slugs)) or len(employees) != len(set(employees)):
        raise GovernedProfileError("managed profile roster contains duplicates")
    if slugs != sorted(slugs) or sum(item.primary for item in profiles) != 1:
        raise GovernedProfileError("managed profile roster must be sorted with one primary")
    return tuple(profiles)


def primary_profile() -> ManagedProfile:
    profiles = managed_profiles()
    try:
        return next(item for item in profiles if item.primary)
    except StopIteration as exc:  # validated above; defensive fail-closed path
        raise GovernedProfileError("managed primary profile is missing") from exc


def require_managed_profile(name: str | None) -> ManagedProfile:
    normalized = (name or "").strip()
    if not normalized or normalized == "default":
        raise GovernedProfileError("an explicit managed profile is required")
    for item in managed_profiles():
        if item.slug == normalized:
            return item
    raise GovernedProfileError("profile is not present in the signed tenant roster")


def _profile_home(profile: ManagedProfile) -> Path:
    from hermes_cli.profiles import get_profile_dir

    home = Path(get_profile_dir(profile.slug))
    if home.is_symlink() or not home.is_dir():
        raise GovernedProfileError("managed profile home is missing or unsafe")
    return home


def verified_profile_home(name: str | None) -> Path:
    profile = require_managed_profile(name)
    home = _profile_home(profile)
    _verify_profile_assets(home, profile)
    return home


def _strict_yaml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise GovernedProfileError("managed profile asset is missing or unsafe")
    try:
        import yaml

        class UniqueKeyLoader(yaml.SafeLoader):
            pass

        def construct_mapping(loader: Any, node: Any, deep: bool = False) -> Any:
            seen: set[Any] = set()
            for key_node, _value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in seen
                    seen.add(key)
                except TypeError as exc:
                    raise yaml.constructor.ConstructorError(
                        None, None, "unhashable YAML mapping key", key_node.start_mark
                    ) from exc
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        None, None, "duplicate YAML mapping key", key_node.start_mark
                    )
            return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

        UniqueKeyLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
        )
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except Exception as exc:
        raise GovernedProfileError("managed profile asset is unreadable") from exc
    if not isinstance(value, dict):
        raise GovernedProfileError("managed profile asset must be an object")
    return value


def _verify_profile_assets(home: Path, profile: ManagedProfile) -> dict[str, Any]:
    config_path = home / "config.yaml"
    metadata_path = home / "profile.yaml"
    binding_path = home / "flexa-profile.yaml"
    if any(path.is_symlink() or not path.is_file() for path in (
        config_path, metadata_path, binding_path
    )):
        raise GovernedProfileError("managed profile asset is missing or unsafe")
    if (
        _sha256(config_path) != profile.config_sha256
        or _sha256(metadata_path) != profile.metadata_sha256
        or _sha256(binding_path) != profile.binding_sha256
    ):
        raise GovernedProfileError("managed profile asset digest mismatch")
    config = _strict_yaml(config_path)
    metadata = _strict_yaml(metadata_path)
    binding = _strict_yaml(binding_path)
    expected_workspace = f"/workspaces/{profile.employee_id}"
    if (
        set(config) != {"terminal"}
        or not isinstance(config.get("terminal"), dict)
        or set(config["terminal"]) != {"cwd"}
        or config["terminal"].get("cwd") != expected_workspace
    ):
        raise GovernedProfileError("managed profile config is not canonical")
    if "flexa" in config:
        raise GovernedProfileError("Flexa identity must not be stored in Hermes config")
    flexa_meta = metadata.get("flexa")
    if (
        metadata.get("description") != profile.description
        or metadata.get("description_auto") is not False
        or not isinstance(flexa_meta, dict)
        or flexa_meta.get("schema_version") != "1"
        or flexa_meta.get("managed") is not True
        or flexa_meta.get("employee_id") != profile.employee_id
    ):
        raise GovernedProfileError("managed profile metadata mismatch")
    if (
        binding.get("profile_id") != profile.employee_id
        or binding.get("working_directory") != expected_workspace
    ):
        raise GovernedProfileError("managed profile employee binding mismatch")
    return binding


def binding_for_current_home() -> tuple[ManagedProfile, dict[str, Any]]:
    """Resolve the current ContextVar-scoped Hermes home to one roster entry."""

    from hermes_constants import get_hermes_home

    current = Path(get_hermes_home()).resolve()
    matches: list[ManagedProfile] = []
    for item in managed_profiles():
        if _profile_home(item).resolve() == current:
            matches.append(item)
    if len(matches) != 1:
        raise GovernedProfileError("current Hermes home is not one signed managed profile")
    selected = matches[0]
    return selected, _verify_profile_assets(current, selected)


def governed_profile_metadata(name: str) -> dict[str, Any]:
    profile = require_managed_profile(name)
    _verify_profile_assets(_profile_home(profile), profile)
    return {"description": profile.description, "description_auto": False}


def deny_protected_mutation() -> None:
    if governed_mode():
        raise GovernedProfileError("managed profile assets are read-only")


_GOVERNED_RPC_ALLOWLIST = frozenset({
    # Conversation lifecycle. Destructive deletion, background agents,
    # delegation, steer, one-shot LLM, shell, slash dispatch and arbitrary
    # command surfaces are deliberately absent.
    "session.create", "session.list", "session.most_recent", "session.resume",
    "session.activate", "session.title", "session.usage", "session.status",
    "session.history", "session.undo",
    "session.close", "session.branch", "session.interrupt", "prompt.submit",
    "terminal.resize", "clarify.respond", "terminal.read.respond",
    "sudo.respond", "secret.respond", "approval.respond",
    # Remote-safe attachment uploads and removal. Host-path variants are
    # separately confined to the employee workspace below.
    "image.attach_bytes", "image.detach", "file.attach",
    # Minimal setup checks required by Desktop. Project/config/process views
    # remain unavailable because they expose internal files and host paths.
    "setup.status", "setup.runtime_check", "paste.collapse",
})


_SUPERVISED_RPC_ALLOWLIST = frozenset({
    # Minimal Desktop conversation lifecycle. Every new upstream RPC remains
    # denied until Flexa explicitly reviews and adds it here.
    "session.create",
    "session.list",
    "session.most_recent",
    "session.resume",
    "session.activate",
    "session.title",
    "session.usage",
    "session.status",
    "session.history",
    "session.close",
    "session.branch",
    "session.interrupt",
    "prompt.submit",
    "terminal.resize",
    # Clarification answers are context-dependent model input, so the entire
    # surface remains unavailable until the signed boundary can bind and
    # classify the stored question, choices, and answer together.
    # All responder RPCs remain unavailable until request kind and owning
    # session are cryptographically bound to the nonce at dispatch.
    # Safe connection readiness projections used by Desktop.
    "setup.status",
    "setup.runtime_check",
})


def _validate_supervised_metadata(value: Any, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise GovernedProfileError(f"{label} must be text")
    if len(value) > 160 or any(ord(char) < 32 for char in value):
        raise GovernedProfileError(f"{label} is invalid")


def _authorize_supervised_rpc(method: str, params: dict[str, Any]) -> None:
    if method not in _SUPERVISED_RPC_ALLOWLIST:
        raise GovernedProfileError("RPC method is unavailable in a supervised profile")

    if {"messages", "cwd"}.intersection(params):
        raise GovernedProfileError("RPC runtime overrides are unavailable")
    desktop_lifecycle = method in {"session.create", "session.resume"}
    if desktop_lifecycle:
        source = str(params.get("source") or "").strip()
        if source and source != "desktop":
            raise GovernedProfileError("supervised session source is invalid")
        if params.get("lazy"):
            raise GovernedProfileError("supervised lazy sessions are unavailable")
        for key in ("model", "provider", "reasoning_effort", "fast"):
            params.pop(key, None)
    elif method == "setup.runtime_check":
        params.pop("provider", None)
        if {"model", "reasoning_effort", "fast"}.intersection(params):
            raise GovernedProfileError("RPC runtime overrides are unavailable")
    elif {"model", "provider", "reasoning_effort", "fast"}.intersection(params):
        raise GovernedProfileError("RPC runtime overrides are unavailable")

    if method in {"session.create", "session.title"}:
        _validate_supervised_metadata(params.get("title"), "session title")
    if method == "session.create" and params.get("parent_session_id"):
        raise GovernedProfileError("supervised seeded sessions are unavailable")
    if method == "session.branch":
        _validate_supervised_metadata(params.get("name"), "branch name")
    if (
        method == "prompt.submit"
        and params.get("truncate_before_user_ordinal") is not None
    ):
        raise GovernedProfileError("supervised transcript editing is unavailable")


def _path_within_workspace(value: str, workspace: str) -> bool:
    if not value or "\x00" in value:
        return False
    try:
        root = Path(workspace).resolve()
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate.resolve().relative_to(root)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def authorize_governed_rpc(method: str, params: dict[str, Any]) -> ManagedProfile | None:
    """Fail closed at the one JSON-RPC dispatch chokepoint.

    An explicit allowlist makes newly-added upstream mutators unavailable until
    Flexa reviews them.  The selected profile comes only from the verified
    connection-scoped HERMES_HOME; request JSON may not hop profiles.
    """

    if not disclosure_boundary_mode():
        return None
    supervised = supervised_disclosure_mode()
    if supervised and method not in _SUPERVISED_RPC_ALLOWLIST:
        raise GovernedProfileError("RPC method is unavailable in a supervised profile")
    if not supervised and method not in _GOVERNED_RPC_ALLOWLIST:
        raise GovernedProfileError("RPC method is unavailable in a managed profile")
    profile, binding = binding_for_current_home()
    requested_profile = str(params.get("profile") or "").strip()
    if requested_profile and requested_profile != profile.slug:
        raise GovernedProfileError("RPC profile does not match the connection binding")
    if supervised:
        _authorize_supervised_rpc(method, params)
        return profile

    desktop_lifecycle = method in {"session.create", "session.resume"}
    source = str(params.get("source") or "").strip()
    if desktop_lifecycle:
        if source and source != "desktop":
            raise GovernedProfileError("managed session source is invalid")
        # Desktop always sends its composer choices.  The signed profile owns
        # the real runtime, so accept the stock payload but remove client-side
        # choices before the handler constructs the session/agent.
        for key in ("model", "provider", "reasoning_effort", "fast"):
            params.pop(key, None)
    if method == "setup.runtime_check":
        # The renderer scopes this probe to its selected model provider.  The
        # signed profile remains authoritative; discard the hint and probe the
        # pinned runtime instead of rejecting stock Desktop traffic.
        params.pop("provider", None)
    forbidden_overrides = {"messages"}
    if not desktop_lifecycle:
        forbidden_overrides.update(
            {"model", "provider", "reasoning_effort", "fast", "source"}
        )
    if forbidden_overrides.intersection(params):
        raise GovernedProfileError("RPC runtime overrides are unavailable")
    workspace = str(binding["working_directory"])
    raw_cwd = str(params.get("cwd") or "").strip()
    if raw_cwd and raw_cwd != workspace:
        raise GovernedProfileError("RPC working directory is outside the employee workspace")
    if method == "config.get":
        allowed_keys = {
            "project", "skin", "indicator", "personality", "reasoning",
            "fast", "busy", "details_mode", "thinking_mode", "compact",
            "statusbar", "mouse", "mtime",
        }
        if params.get("key") not in allowed_keys:
            raise GovernedProfileError("protected config data is unavailable")
    if method in {"image.attach", "pdf.attach", "file.attach"}:
        # A byte/data-url upload may carry a client-local path solely as a
        # display name. A server-side path is allowed only inside the signed
        # employee workspace.
        uploaded = bool(
            params.get("content_base64") or params.get("data") or params.get("data_url")
        )
        host_path = str(params.get("path") or "").strip()
        if host_path and not uploaded and not _path_within_workspace(host_path, workspace):
            raise GovernedProfileError("attachment path is outside the employee workspace")
    if method == "file.attach":
        # Managed Desktop file ingress is byte-only. ``name`` is the sole
        # display hint; a client host ``path`` is rejected and never opened or
        # logged. Requiring a data URL prevents this RPC from becoming an
        # arbitrary host-file reader.
        if params.get("path"):
            raise GovernedProfileError("managed file upload paths are unavailable")
        if not isinstance(params.get("data_url"), str) or not params["data_url"].strip():
            raise GovernedProfileError("managed file upload bytes are required")
    if method in {"file.attach", "image.attach_bytes"}:
        upload_nonce = str(params.get("upload_nonce") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", upload_nonce):
            raise GovernedProfileError("managed upload nonce is invalid")
    if method == "image.detach":
        if params.get("path"):
            raise GovernedProfileError("managed attachment removal requires an opaque identifier")
        attachment_id = str(params.get("attachment_id") or "")
        if not re.fullmatch(r"[a-f0-9]{32}\.[a-z0-9]{1,8}", attachment_id):
            raise GovernedProfileError("managed attachment identifier is invalid")
    return profile


_GOVERNED_SESSION_SCALAR_FIELDS = frozenset({
    "id",
    "session_id",
    "title",
    "started_at",
    "last_active",
    "ended_at",
    "created_at",
    "updated_at",
    "archived",
    "message_count",
    "is_active",
    "is_default_profile",
    "profile",
    "status",
    "running",
})


def project_governed_session_metadata(value: Any) -> dict[str, Any]:
    """Return the closed, content-free managed session metadata contract."""

    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, item in value.items()
        if key in _GOVERNED_SESSION_SCALAR_FIELDS
        and isinstance(item, (str, int, float, bool, type(None)))
    }


def project_governed_messages(value: Any) -> list[dict[str, Any]]:
    """Keep only user/assistant string messages and an optional timestamp."""

    projected: list[dict[str, Any]] = []
    for row in value if isinstance(value, list) else []:
        if not isinstance(row, dict):
            continue
        role = row.get("role")
        content = row.get("content")
        if role not in {"user", "assistant"} or not isinstance(content, str):
            continue
        safe: dict[str, Any] = {"role": role, "content": content}
        if isinstance(row.get("timestamp"), (str, int, float)):
            safe["timestamp"] = row["timestamp"]
        projected.append(safe)
    return projected


def project_governed_session_info(value: Any) -> dict[str, Any]:
    """Project every ``session.info`` event through one minimal contract.

    The event is emitted from many lifecycle branches, so applying this at the
    transport chokepoint is safer than relying on each producer to remember a
    redaction call.  Token counters remain available for the managed usage UI;
    model/provider/context internals and all prompt/tool surfaces are absent.
    """

    if not isinstance(value, dict):
        return {}
    projected: dict[str, Any] = {}
    for key in ("running", "title", "desktop_contract", "profile_name", "yolo"):
        item = value.get(key)
        if isinstance(item, (str, int, float, bool, type(None))):
            projected[key] = item
    raw_usage = value.get("usage")
    if isinstance(raw_usage, dict):
        allowed_usage = {
            "input",
            "output",
            "prompt",
            "completion",
            "total",
            "calls",
            "context_used",
            "context_max",
            "context_percent",
            "compressions",
        }
        projected["usage"] = {
            key: item
            for key, item in raw_usage.items()
            if key in allowed_usage and isinstance(item, (int, float)) and not isinstance(item, bool)
        }
    return projected


def project_governed_error_event(value: Any) -> dict[str, Any]:
    """Collapse every managed error event to a content-free envelope."""

    projected: dict[str, Any] = {"message": "managed operation failed"}
    if not isinstance(value, dict):
        return projected
    audit_id = value.get("audit_id")
    if isinstance(audit_id, str) and re.fullmatch(r"[a-f0-9]{32}", audit_id):
        projected["audit_id"] = audit_id
    failure_type = value.get("type")
    if (
        isinstance(failure_type, str)
        and len(failure_type) <= 64
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", failure_type)
    ):
        projected["type"] = failure_type
    return projected


def redact_governed_rpc_response(method: str, response: Any) -> Any:
    """Minimize operational RPC disclosures used by Desktop.

    Conversation history is intentionally outside this function.  These
    projections cover only setup/runtime/process/session telemetry surfaces,
    which must not disclose provider, model, source route, host command output,
    or backend exception text to a managed client.
    """

    if not disclosure_boundary_mode() or not isinstance(response, dict):
        return response
    if "error" in response:
        result = dict(response)
        error = result.get("error")
        code = error.get("code", 5000) if isinstance(error, dict) else 5000
        message = error.get("message") if isinstance(error, dict) else None
        safe_attachment_errors = {
            "managed attachment type is unavailable",
            "managed image type is unavailable",
        }
        result["error"] = {
            "code": code,
            "message": (
                message
                if method in {"file.attach", "image.attach_bytes"}
                and message in safe_attachment_errors
                else "managed request failed"
            ),
        }
        return result
    sensitive = {
        "setup.runtime_check",
        "setup.status",
        "session.status",
        "session.usage",
        "session.history",
        "session.create",
        "session.list",
        "session.most_recent",
        "session.resume",
        "session.activate",
        "session.branch",
        "session.undo",
        "image.attach_bytes",
        "file.attach",
    }
    if method not in sensitive:
        return response
    result = dict(response)
    payload = result.get("result")
    if method == "setup.status":
        configured = bool(
            isinstance(payload, dict) and payload.get("provider_configured") is True
        )
        result["result"] = {"provider_configured": configured}
        return result
    if method == "setup.runtime_check":
        ok = bool(isinstance(payload, dict) and payload.get("ok") is True)
        result["result"] = {"ok": ok}
        return result
    if method == "image.attach_bytes":
        if isinstance(payload, dict):
            result["result"] = {
                "attached": payload.get("attached") is True,
                "count": int(payload.get("count") or 0),
                "bytes": int(payload.get("bytes") or 0),
                "attachment_id": str(payload.get("attachment_id") or "")[:48],
            }
        else:
            result["result"] = {"attached": False, "count": 0, "bytes": 0}
        return result
    if method == "file.attach":
        if isinstance(payload, dict):
            attachment_id = str(payload.get("attachment_id") or "")
            ref_text = str(payload.get("ref_text") or "")
            if not re.fullmatch(r"[a-f0-9]{32}\.[a-z0-9]{1,8}", attachment_id):
                attachment_id = ""
            expected_ref = f"@file:.flexa/inbox/{attachment_id}" if attachment_id else ""
            result["result"] = {
                "attached": payload.get("attached") is True and bool(attachment_id),
                "count": int(payload.get("count") or 0),
                "bytes": int(payload.get("bytes") or 0),
                "attachment_id": attachment_id,
                "ref_text": expected_ref if ref_text == expected_ref else "",
            }
        else:
            result["result"] = {
                "attached": False,
                "count": 0,
                "bytes": 0,
                "attachment_id": "",
                "ref_text": "",
            }
        return result
    if method == "session.history":
        rows = payload.get("messages", []) if isinstance(payload, dict) else []
        result["result"] = {"messages": project_governed_messages(rows)}
        return result
    if method in {
        "session.create", "session.list", "session.most_recent",
        "session.resume", "session.activate", "session.branch", "session.undo",
    }:
        allowed_rpc_session = {
            "session_id",
            "id",
            "title",
            "created_at",
            "updated_at",
            "status",
            "running",
            "archived",
            "message_count",
            "profile",
        }

        def _project(value: Any) -> Any:
            if isinstance(value, list):
                return [_project(item) for item in value if isinstance(item, dict)]
            if not isinstance(value, dict):
                return None
            projected = {
                key: item
                for key, item in project_governed_session_metadata(value).items()
                if key in allowed_rpc_session
            }
            for list_key in ("sessions",):
                if isinstance(value.get(list_key), list):
                    projected[list_key] = _project(value[list_key])
            return projected

        result["result"] = _project(payload) or {}
        return result
    if method == "session.status":
        allowed = {"session_id", "status", "running", "interrupted", "completed"}
    else:
        allowed = {
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "prompt_tokens",
            "completion_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "reasoning_tokens",
        }
    if isinstance(payload, dict):
        result["result"] = {
            key: value
            for key, value in payload.items()
            if key in allowed and isinstance(value, (str, int, float, bool, type(None)))
        }
    else:
        result["result"] = {}
    return result
