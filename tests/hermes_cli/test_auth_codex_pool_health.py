"""Runtime fallback uses healthy pool credentials without changing auth state."""
import base64
import json
import time
from datetime import datetime, timezone

import pytest

from hermes_cli import auth as A


def token(exp):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return "synthetic." + payload + ".signature"


@pytest.fixture
def auth_store(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(A, "_auth_file_path", lambda: home / "auth.json")
    monkeypatch.setattr(A, "_auth_lock_path", lambda: home / "auth.lock")
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: None)
    def write(entries):
        path = home / "auth.json"
        path.write_text(json.dumps({"version": 1, "providers": {},
                                   "credential_pool": {"openai-codex": entries}}))
        return path
    return write


def row(identifier, **changes):
    result = {"id": identifier, "label": "synthetic", "source": "manual:device_code",
              "auth_type": "oauth", "access_token": token(time.time() + 3600),
              "refresh_token": "synthetic-refresh", "priority": 0}
    result.update(changes)
    return result


@pytest.mark.parametrize("unhealthy", [
    {"last_status": "dead"},
    {"access_token": token(1)},
    {"last_status": "exhausted", "last_status_at": time.time(), "last_error_code": 429},
    {"last_error_reset_at": time.time() + 3600},
    {"last_error_reset_at": datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()},
])
def test_runtime_skips_unhealthy_first_entry(auth_store, unhealthy):
    healthy = row("healthy", access_token=token(time.time() + 7200))
    path = auth_store([row("unhealthy", **unhealthy), healthy])
    before = path.read_bytes()
    result = A.resolve_codex_runtime_credentials(refresh_if_expiring=False)
    assert result["api_key"] == healthy["access_token"]
    assert result["source"] == "credential_pool"
    assert path.read_bytes() == before


@pytest.mark.parametrize("unhealthy", [{"last_status": "dead"}, {"access_token": token(1)}])
def test_no_usable_pool_entry_fails_closed(auth_store, unhealthy):
    path = auth_store([row("unhealthy", **unhealthy)])
    before = path.read_bytes()
    with pytest.raises(A.AuthError):
        A.resolve_codex_runtime_credentials(refresh_if_expiring=False)
    assert path.read_bytes() == before


def test_elapsed_cooldown_does_not_hide_valid_entry(auth_store):
    healthy = row("healthy", last_status="exhausted", last_error_reset_at=time.time() - 1)
    path = auth_store([healthy])
    before = path.read_bytes()
    assert A._pool_codex_access_token() == healthy["access_token"]
    assert path.read_bytes() == before


def test_opaque_token_without_known_expiry_remains_eligible(auth_store):
    healthy = row("healthy", access_token="synthetic-opaque-token")
    path = auth_store([healthy])
    before = path.read_bytes()
    assert A.resolve_codex_runtime_credentials(refresh_if_expiring=False)["api_key"] == healthy["access_token"]
    assert path.read_bytes() == before
