"""Real socket/profile/backend tests for operator lifecycle provisioning."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time

import pytest

import hermes_cli
from hermes_cli import profile_lifecycle as lifecycle
from hermes_cli import profiles


@pytest.fixture
def profile_env(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(hermes_cli, "_CONSOLIDA_CONTROL_SOCKET", None)
    # Never register a real gateway or seed via a subprocess in lifecycle tests.
    monkeypatch.setattr(profiles, "_maybe_register_gateway_service", lambda name: None)
    monkeypatch.setattr(profiles, "seed_profile_skills", lambda *args, **kwargs: {"copied": []})
    monkeypatch.setattr(profiles, "check_alias_collision", lambda name: "fixture skips wrapper")
    return home


def response(request, status="INSTALLING"):
    return {"version": 1, "profile": request["profile"],
            "operation_id": hashlib.sha256(request["profile"].encode()).hexdigest(), "status": status}


@contextmanager
def controller(monkeypatch, handler):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX is unavailable on this platform")
    # Keep the socket below the platform sockaddr_un path limit.
    with tempfile.TemporaryDirectory(prefix="lifecycle-") as folder:
        path = str(Path(folder) / "control.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(path)
            server.listen()
        except OSError:
            server.close()
            pytest.skip("AF_UNIX binding is unavailable in this test environment")
        server.settimeout(0.1)
        stopped = threading.Event()
        requests, errors = [], []

        def serve():
            while not stopped.is_set():
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with connection:
                    connection.settimeout(3)
                    packet = bytearray()
                    try:
                        while b"\n" not in packet:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            packet.extend(chunk)
                        request = json.loads(packet)
                        requests.append(request)
                        result = handler(request, stopped)
                        if isinstance(result, dict):
                            result = json.dumps(result).encode() + b"\n"
                        if result is not None:
                            connection.sendall(result)
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # timeout/malformed fixtures intentionally close early
                    except Exception as exc:
                        errors.append(type(exc).__name__)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        monkeypatch.setattr(hermes_cli, "_CONSOLIDA_CONTROL_SOCKET", path)
        try:
            yield requests
        finally:
            stopped.set()
            server.close()
            thread.join(timeout=4)
            assert not thread.is_alive(), "fixture controller failed to stop"
            assert not errors, "fixture controller failed"


def test_create_profile_sends_canonical_name_without_host_paths(profile_env, monkeypatch):
    def handle(request, stopped):
        assert (profile_env / "profiles/qa/.env").is_file()
        assert set(request) == {"version", "event", "profile"}
        return response(request)
    with controller(monkeypatch, handle) as requests:
        created = profiles.create_profile("QA", no_alias=True, no_skills=True)
    assert created == profile_env / "profiles/qa"
    assert requests == [{"version": 1, "event": "profile_created", "profile": "qa"}]


def test_absent_controller_is_explicit_pending_and_creation_survives(profile_env):
    created = profiles.create_profile("qa", no_alias=True, no_skills=True)
    assert created.is_dir()
    status = lifecycle.notify_profile("qa")
    assert status["status"] == "WAITING_CONFIG"
    assert status["operation_id"] is None


def test_unavailable_controller_does_not_undo_creation(profile_env, monkeypatch):
    monkeypatch.setattr(hermes_cli, "_CONSOLIDA_CONTROL_SOCKET", str(profile_env / "absent.sock"))
    created = profiles.create_profile("qa", no_alias=True, no_skills=True)
    assert (created / "SOUL.md").is_file()
    assert lifecycle.notify_profile("qa")["status"] == "FAILED"


def test_profile_environment_cannot_redirect_inherited_controller(profile_env, monkeypatch):
    with controller(monkeypatch, lambda req, stopped: response(req, "WAITING_MODEL")) as requests:
        monkeypatch.setenv("CONSOLIDA_CONTROL_SOCKET", str(profile_env / "attacker.sock"))
        created = profiles.create_profile("qa", no_alias=True, no_skills=True)
        (created / ".env").write_text("CONSOLIDA_CONTROL_SOCKET=/unapproved/control.sock\n")
        (created / "config.yaml").write_text("consolida_control_socket: /unapproved/control.sock\n")
        assert lifecycle.notify_profile("qa")["status"] == "WAITING_MODEL"
    assert len(requests) == 2


@pytest.mark.parametrize("status", ["INSTALLING", "WAITING_MODEL", "SEEDING", "WAITING_AUTH",
                                    "VALIDATING", "READY", "FAILED"])
def test_known_durable_status_is_returned_with_identity(profile_env, monkeypatch, status):
    with controller(monkeypatch, lambda req, stopped: response(req, status)):
        result = lifecycle.notify_profile("qa", "profile_status")
    assert result["status"] == status
    assert result["operation_id"] == hashlib.sha256(b"qa").hexdigest()


@pytest.mark.parametrize("mutation", [
    lambda value: {**value, "status": "DONE"},
    lambda value: {**value, "status": "WAITING_CONFIG"},
    lambda value: {**value, "profile": "different"},
    lambda value: {**value, "operation_id": "not-an-identity"},
    lambda value: {**value, "version": True},
    lambda value: {**value, "command": "untrusted-command"},
    lambda value: {**value, "status": "READY", "error": "MISSING_PUBLISHER"},
    lambda value: {**value, "error": "untrusted message with a path"},
    lambda value: [value],
])
def test_malformed_schema_never_claims_ready(profile_env, monkeypatch, mutation):
    def handle(request, stopped):
        return json.dumps(mutation(response(request, "READY"))).encode() + b"\n"
    with controller(monkeypatch, handle):
        status = lifecycle.notify_profile("qa")
    assert status["status"] == "FAILED"
    assert status["error"] == "INVALID_CONTROL_RESPONSE"
    assert status["operation_id"] is None


@pytest.mark.parametrize("packet", [b"not-json\n", b"\xff\n", b"{}", b"{}\n{}\n",
    b'{"version":1,"version":1}\n', b'{"version":NaN}\n', b"x" * (lifecycle.MAX_PACKET_BYTES + 1)],
    ids=["not-json", "invalid-utf8", "no-newline", "extra-line", "duplicate-key", "nan", "oversize"])
def test_bad_packets_fail_closed(profile_env, monkeypatch, packet):
    with controller(monkeypatch, lambda req, stopped: packet):
        status = lifecycle.notify_profile("qa")
    assert status["status"] == "FAILED"
    assert status["error"] == "INVALID_CONTROL_RESPONSE"


def test_total_socket_deadline_is_bounded(profile_env, monkeypatch):
    monkeypatch.setattr(lifecycle, "REQUEST_TIMEOUT", 0.1)
    def hold(request, stopped):
        stopped.wait(3)
        return None
    with controller(monkeypatch, hold):
        start = time.monotonic()
        status = lifecycle.notify_profile("qa")
        elapsed = time.monotonic() - start
    assert status["error"] == "CONTROL_TIMEOUT"
    assert elapsed < 2, "short fixture deadline did not bound the operation"


def test_bad_configuration_and_profile_do_not_connect(profile_env, monkeypatch):
    monkeypatch.setattr(hermes_cli, "_CONSOLIDA_CONTROL_SOCKET", "relative.sock")
    assert lifecycle.notify_profile("qa")["error"] == "INVALID_CONTROL_CONFIGURATION"
    assert lifecycle.notify_profile("../../outside")["error"] == "INVALID_PROFILE_EVENT"


@pytest.mark.parametrize("mutation", [
    lambda value: {**value, "status": "UNKNOWN"},
    lambda value: {**value, "profile": "different"},
    lambda value: {**value, "operation_id": "invalid"},
    lambda value: {**value, "version": True},
    lambda value: {**value, "extra": "untrusted"},
    lambda value: {**value, "status": "READY", "error": "MISSING_PUBLISHER"},
])
def test_response_schema_validation_is_portable(mutation):
    packet = json.dumps(mutation(response({"profile": "qa"}))).encode()
    with pytest.raises(ValueError):
        lifecycle._validate_response(packet, "qa")


def test_dashboard_without_controller_keeps_creation_and_pending_separate(profile_env):
    pytest.importorskip("fastapi")
    from hermes_cli.web_models import ProfileCreate
    from hermes_cli.web_routers import profiles as routes
    result = asyncio.run(routes.create_profile_endpoint(ProfileCreate(name="qa", no_skills=True)))
    assert result["ok"] is True
    assert Path(result["path"]).is_dir()
    assert result["provisioning"]["status"] == "WAITING_CONFIG"
    status = asyncio.run(routes.get_profile_provisioning_endpoint("qa"))
    assert status["provisioning"]["status"] == "WAITING_CONFIG"
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as missing:
        asyncio.run(routes.get_profile_provisioning_endpoint("unknown"))
    assert missing.value.status_code == 404


def test_dashboard_options_precede_configured_event_and_status_query(profile_env, monkeypatch):
    pytest.importorskip("fastapi")
    import yaml
    from hermes_cli.web_models import ProfileCreate
    from hermes_cli.web_routers import profiles as routes
    observed = []

    def handle(request, stopped):
        config = profile_env / "profiles/qa/config.yaml"
        data = yaml.safe_load(config.read_text()) if config.exists() else {}
        observed.append((request["event"], data.get("model")))
        return response(request, "WAITING_AUTH" if request["event"] != "profile_created" else "INSTALLING")

    with controller(monkeypatch, handle) as requests:
        result = asyncio.run(routes.create_profile_endpoint(ProfileCreate(
            name="qa", no_skills=True, provider="openrouter", model="synthetic/model")))
        polled = asyncio.run(routes.get_profile_provisioning_endpoint("qa"))
    assert result["ok"] is True
    assert result["model_set"] is True
    assert Path(result["path"]).is_dir()
    assert result["provisioning"]["status"] == "WAITING_AUTH"
    assert polled["provisioning"]["operation_id"] == result["provisioning"]["operation_id"]
    assert [req["event"] for req in requests] == ["profile_created", "profile_configured", "profile_status"]
    assert observed[1][1]["default"] == "synthetic/model"
    assert observed[1][1]["provider"] == "openrouter"


def test_dashboard_malformed_controller_preserves_ok_and_profile(profile_env, monkeypatch):
    pytest.importorskip("fastapi")
    from hermes_cli.web_models import ProfileCreate
    from hermes_cli.web_routers import profiles as routes
    with controller(monkeypatch, lambda req, stopped: b'{"status":"READY"}\n'):
        result = asyncio.run(routes.create_profile_endpoint(ProfileCreate(name="qa", no_skills=True)))
    assert result["ok"] is True
    assert Path(result["path"]).is_dir()
    assert result["provisioning"]["status"] == "FAILED"


def test_cli_creation_reports_pending_state(profile_env, monkeypatch, capsys):
    from types import SimpleNamespace
    from hermes_cli.main import cmd_profile
    cmd_profile(SimpleNamespace(profile_action="create", profile_name="qa", no_alias=True,
                                no_skills=True, clone=False, clone_all=False, clone_from=None))
    output = capsys.readouterr().out
    assert "Provisioning: WAITING_CONFIG" in output
    assert (profile_env / "profiles/qa").is_dir()
