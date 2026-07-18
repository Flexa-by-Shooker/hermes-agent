"""Flexa image contract for governed writable roots and command lookup."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = "/var/lib/hermes"


def _text(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def test_dockerfile_declares_only_governed_writable_roots() -> None:
    dockerfile = _text("Dockerfile")

    assert f"hermes:x:10000:10000::{RUNTIME_ROOT}:/bin/sh" in dockerfile
    assert "install -d -o 10000 -g 10000 -m 0755 /var/lib/hermes" in dockerfile
    assert "useradd " not in dockerfile
    assert f"ENV HERMES_HOME={RUNTIME_ROOT}" in dockerfile
    assert f"ENV HERMES_WRITE_SAFE_ROOT={RUNTIME_ROOT}:/workspaces" in dockerfile
    assert "HERMES_LAZY_INSTALL_TARGET" not in dockerfile
    assert "VOLUME" not in dockerfile
    assert "RUN mkdir -p /opt/data" not in dockerfile


def test_dockerfile_path_cannot_resolve_commands_from_writable_state() -> None:
    dockerfile = _text("Dockerfile")
    path_line = next(
        line for line in dockerfile.splitlines() if line.startswith("ENV PATH=")
    )

    assert "/opt/hermes/bin:/opt/hermes/.venv/bin:" in path_line
    assert RUNTIME_ROOT not in path_line
    assert "/workspaces" not in path_line
    assert "/opt/data" not in path_line


def test_s6_entrypoints_honor_the_governed_runtime_root() -> None:
    scripts = (
        _text("docker/main-wrapper.sh"),
        _text("docker/hermes-exec-shim.sh"),
        _text("docker/s6-rc.d/dashboard/run"),
    )

    for script in scripts:
        assert f': "${{HERMES_HOME:={RUNTIME_ROOT}}}"' in script
        assert 'export HOME="$HERMES_HOME"' in script
        assert "export HOME=/opt/data" not in script
    assert 'cd "$HERMES_HOME"' in scripts[0]
    assert 'cd "$HERMES_HOME"' in scripts[2]


def test_stage2_defaults_to_the_governed_runtime_root_and_keeps_installs_disabled() -> None:
    stage2 = _text("docker/stage2-hook.sh")

    assert f'HERMES_HOME="${{HERMES_HOME:-{RUNTIME_ROOT}}}"' in stage2
    assert '"$HERMES_HOME/lazy-packages"' not in stage2
    assert "lazy-packages" not in stage2.split("for sub in", 1)[1].split(";", 1)[0]
