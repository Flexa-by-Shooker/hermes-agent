"""Governed profile verification binds policy to managed, not user, config."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from agent.memory_provider import MemoryProviderCapabilities

from hermes_cli.flexa_governed import (
    GOVERNED_MEMORY_MODE,
    GovernedProfileError,
    ManagedProfile,
    _sha256,
    _verify_profile_assets,
    governed_memory_scope,
    require_governed_memory_provider,
    validate_governed_memory_config,
)


def _write_yaml(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")
    return path


def _profile(home: Path, managed_config: Path) -> ManagedProfile:
    description = "Governed Oren profile"
    employee_id = "oren-cto"
    metadata = _write_yaml(
        home / "profile.yaml",
        {
            "description": description,
            "description_auto": False,
            "flexa": {
                "schema_version": "1",
                "managed": True,
                "employee_id": employee_id,
            },
        },
    )
    binding = _write_yaml(
        home / "flexa-profile.yaml",
        {
            "profile_id": employee_id,
            "working_directory": f"/workspaces/{employee_id}",
        },
    )
    return ManagedProfile(
        tenant_id="tenant-one",
        release_id="release-one",
        bundle_signing_payload_sha256="a" * 64,
        slug=employee_id,
        employee_id=employee_id,
        primary=True,
        description=description,
        enforcement_api=f"http://enforcement-{employee_id}:8081",
        binding_sha256=_sha256(binding),
        config_sha256=_sha256(managed_config),
        metadata_sha256=_sha256(metadata),
        buffered_output=True,
    )


def _managed_config(employee_id: str = "oren-cto") -> dict[str, object]:
    return {
        "skills": {"external_dirs": ["/opt/hermes/skills"]},
        "terminal": {"cwd": f"/workspaces/{employee_id}"},
        "memory": {
            "mode": GOVERNED_MEMORY_MODE,
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
    }


def test_verification_uses_managed_config_and_preserves_user_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "profiles" / "oren-cto"
    home.mkdir(parents=True)
    _write_yaml(
        home / "config.yaml",
        {
            "model": {"provider": "xai-oauth", "default": "grok-4.5"},
            "agent": {"reasoning_effort": "high"},
        },
    )
    managed = tmp_path / "managed"
    config = _write_yaml(managed / "config.yaml", _managed_config())
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))

    binding = _verify_profile_assets(home, _profile(home, config))

    assert binding["profile_id"] == "oren-cto"
    assert yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")) == {
        "agent": {"reasoning_effort": "high"},
        "model": {"default": "grok-4.5", "provider": "xai-oauth"},
    }


def test_verification_rejects_noncanonical_managed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "profiles" / "oren-cto"
    home.mkdir(parents=True)
    managed = tmp_path / "managed"
    config = _write_yaml(
        managed / "config.yaml",
        {"terminal": {"cwd": "/workspaces/oren-cto"}},
    )
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))

    with pytest.raises(GovernedProfileError, match="config is not canonical"):
        _verify_profile_assets(home, _profile(home, config))


def test_verification_rejects_pre_memory_managed_config_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old signed bundles stay rejected until Engine and provider roll together."""

    home = tmp_path / "profiles" / "oren-cto"
    home.mkdir(parents=True)
    managed = tmp_path / "managed"
    legacy = _write_yaml(
        managed / "config.yaml",
        {
            "skills": {"external_dirs": ["/opt/hermes/skills"]},
            "terminal": {"cwd": "/workspaces/oren-cto"},
        },
    )
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))

    with pytest.raises(GovernedProfileError, match="config is not canonical"):
        _verify_profile_assets(home, _profile(home, legacy))


def test_verification_rejects_missing_managed_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "profiles" / "oren-cto"
    home.mkdir(parents=True)
    staged = _write_yaml(
        tmp_path / "staged-config.yaml",
        _managed_config(),
    )
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(tmp_path / "missing"))

    with pytest.raises(GovernedProfileError, match="scope is missing or unsafe"):
        _verify_profile_assets(home, _profile(home, staged))


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("memory_enabled", True),
        ("user_profile_enabled", True),
        ("write_approval", False),
        ("provider", ""),
        ("mode", "native"),
    ],
)
def test_governed_memory_config_rejects_native_or_unscoped_fallback(
    field: str,
    unsafe: object,
) -> None:
    memory = dict(_managed_config()["memory"])
    memory[field] = unsafe

    with pytest.raises(GovernedProfileError, match="memory config is not canonical"):
        validate_governed_memory_config(memory, exact=True)


def test_governed_memory_scope_requires_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    monkeypatch.setattr(
        "hermes_cli.flexa_governed.binding_for_current_home",
        lambda: (profile, {"working_directory": "/workspaces/oren-cto"}),
    )

    def verify(assertion, **_kwargs):
        if assertion is None:
            raise GovernedProfileError("principal assertion is missing or invalid")
        return SimpleNamespace(
            tenant_id="tenant-one",
            employee_id="oren-cto",
            profile_id="oren-cto",
            release_id="release-one",
            principal_namespace="telegram",
            principal_id="canonical-user",
        )

    monkeypatch.setattr(
        "hermes_cli.flexa_governed.verify_governed_principal_assertion",
        verify,
    )

    with pytest.raises(GovernedProfileError, match="principal assertion"):
        governed_memory_scope(platform="desktop", user_id=None)

    scope = governed_memory_scope(
        platform="telegram",
        user_id="user-primary",
        user_id_alt="user-stable",
        principal_assertion={"signed": True},
    )
    assert scope == {
        "schema_version": "1",
        "tenant_id": "tenant-one",
        "employee_id": "oren-cto",
        "profile_slug": "oren-cto",
        "principal_namespace": "telegram",
        "principal_id": "canonical-user",
        "release_id": "release-one",
        "bundle_signing_payload_sha256": "a" * 64,
    }


def test_governed_memory_provider_must_declare_scope_v1() -> None:
    class LegacyProvider:
        governed_scope_version = ""

    class GovernedProvider:
        governed_scope_version = "1"
        capabilities = MemoryProviderCapabilities.read_only_recall()

    class WritableProvider:
        governed_scope_version = "1"
        capabilities = MemoryProviderCapabilities()

    with pytest.raises(GovernedProfileError, match="does not support governed scope"):
        require_governed_memory_provider(LegacyProvider())
    with pytest.raises(GovernedProfileError, match="not governed read-only"):
        require_governed_memory_provider(WritableProvider())

    require_governed_memory_provider(GovernedProvider())
