"""Governed profile verification binds policy to managed, not user, config."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hermes_cli.flexa_governed import (
    GovernedProfileError,
    ManagedProfile,
    _sha256,
    _verify_profile_assets,
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
    config = _write_yaml(
        managed / "config.yaml",
        {
            "skills": {"external_dirs": ["/opt/hermes/skills"]},
            "terminal": {"cwd": "/workspaces/oren-cto"},
        },
    )
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


def test_verification_rejects_missing_managed_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "profiles" / "oren-cto"
    home.mkdir(parents=True)
    staged = _write_yaml(
        tmp_path / "staged-config.yaml",
        {
            "skills": {"external_dirs": ["/opt/hermes/skills"]},
            "terminal": {"cwd": "/workspaces/oren-cto"},
        },
    )
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(tmp_path / "missing"))

    with pytest.raises(GovernedProfileError, match="scope is missing or unsafe"):
        _verify_profile_assets(home, _profile(home, staged))
