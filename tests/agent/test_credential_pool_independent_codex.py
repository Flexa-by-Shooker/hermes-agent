"""Independent Codex grants cannot borrow or mutate singleton credentials."""
import json
from dataclasses import replace

import pytest

from agent import credential_pool as CP
from hermes_cli import auth as A


def entry(identifier="owned", source=CP.SOURCE_MANUAL_DEVICE_CODE):
    return CP.PooledCredential(
        provider="openai-codex", id=identifier, label="fixture", auth_type="oauth",
        priority=0, source=source, access_token="synthetic-access-" + identifier,
        refresh_token="synthetic-refresh-" + identifier,
    )


@pytest.fixture
def stores(tmp_path, monkeypatch):
    profile = tmp_path / "profile" / "auth.json"
    root = tmp_path / "root" / "auth.json"
    monkeypatch.setenv("HERMES_HOME", str(profile.parent))
    monkeypatch.setattr(A, "_auth_file_path", lambda: profile)
    monkeypatch.setattr(A, "_auth_lock_path", lambda: profile.with_suffix(".lock"))
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: root)
    owned, legacy, other = entry(), entry("legacy", "device_code"), entry("other")
    profile.parent.mkdir()
    root.parent.mkdir()
    profile.write_text(json.dumps({
        "version": 1, "active_provider": "unchanged", "providers": {},
        "credential_pool": {"openai-codex": [x.to_dict() for x in (owned, legacy, other)]},
        "unknown": {"preserve": True},
    }))
    root.write_text(json.dumps({"version": 1, "active_provider": "unchanged", "providers": {
        "openai-codex": {"tokens": {"access_token": "synthetic-global-access",
                                     "refresh_token": "synthetic-global-refresh"}}
    }}))
    return profile, root, owned, legacy, other


def read(path):
    return json.loads(path.read_text())


def rows(path):
    return read(path)["credential_pool"]["openai-codex"]


def test_manual_never_adopts_or_writes_singleton(stores, monkeypatch):
    profile, root, owned, *_ = stores
    before_profile, before_root = profile.read_bytes(), root.read_bytes()
    pool = CP.CredentialPool("openai-codex", [owned])
    assert pool._sync_codex_entry_from_auth_store(owned) is owned
    pool._sync_device_code_entry_to_auth_store(owned)
    assert profile.read_bytes() == before_profile
    assert root.read_bytes() == before_root


@pytest.mark.parametrize("terminal", [True, False])
def test_refresh_failure_only_marks_matching_entry(stores, monkeypatch, terminal):
    profile, root, owned, legacy, other = stores
    before, global_before = read(profile), root.read_bytes()
    def fail(*args, **kwargs):
        raise A.AuthError("synthetic failure", provider="openai-codex",
                          code="invalid_grant" if terminal else "transient",
                          relogin_required=terminal)
    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fail)
    pool = CP.CredentialPool("openai-codex", [owned, legacy, other])
    assert pool.try_refresh_matching(credential_id=owned.id) is None
    after = read(profile)
    assert after["active_provider"] == before["active_provider"]
    assert after["providers"] == before["providers"]
    assert after["unknown"] == before["unknown"]
    assert rows(profile)[1:] == before["credential_pool"]["openai-codex"][1:]
    assert rows(profile)[0]["last_status"] == (CP.STATUS_DEAD if terminal else CP.STATUS_EXHAUSTED)
    assert rows(profile)[0]["refresh_token"] == owned.refresh_token
    assert root.read_bytes() == global_before


def test_success_persists_only_own_pair_and_preserves_concurrent_add(stores, monkeypatch):
    profile, root, owned, legacy, other = stores
    before, global_before = read(profile), root.read_bytes()
    def refresh(access, refresh):
        assert (access, refresh) == (owned.access_token, owned.refresh_token)
        # A reentrant native writer adds a credential during the request.
        A.write_credential_pool("openai-codex", rows(profile) + [entry("added").to_dict()])
        return {"access_token": "synthetic-fresh-access", "refresh_token": "synthetic-fresh-refresh"}
    monkeypatch.setattr(A, "refresh_codex_oauth_pure", refresh)
    pool = CP.CredentialPool("openai-codex", [owned, legacy, other])
    result = pool.try_refresh_matching(credential_id=owned.id)
    assert result.access_token == "synthetic-fresh-access"
    assert rows(profile)[0]["refresh_token"] == "synthetic-fresh-refresh"
    assert rows(profile)[1:3] == before["credential_pool"]["openai-codex"][1:]
    assert rows(profile)[3]["id"] == "added"
    assert read(profile)["providers"] == {}
    assert read(profile)["active_provider"] == "unchanged"
    assert root.read_bytes() == global_before


def test_stale_pool_adopts_newer_own_disk_pair_without_refresh(stores, monkeypatch):
    profile, root, owned, legacy, other = stores
    newer = replace(owned, access_token="synthetic-newer-access", refresh_token="synthetic-newer-refresh")
    A.write_credential_pool("openai-codex", [newer.to_dict(), legacy.to_dict(), other.to_dict()])
    before = profile.read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail("stale rotating token must not be spent")
    monkeypatch.setattr(A, "refresh_codex_oauth_pure", forbidden)
    result = CP.CredentialPool("openai-codex", [owned]).try_refresh_matching(credential_id=owned.id)
    assert result.refresh_token == newer.refresh_token
    assert profile.read_bytes() == before


def test_newer_reentrant_token_write_not_overwritten(stores, monkeypatch):
    profile, root, owned, legacy, other = stores
    def refresh(*args, **kwargs):
        newer = replace(owned, access_token="synthetic-newer-access", refresh_token="synthetic-newer-refresh")
        A.write_credential_pool("openai-codex", [newer.to_dict(), legacy.to_dict(), other.to_dict()])
        return {"access_token": "synthetic-obsolete-access", "refresh_token": "synthetic-obsolete-refresh"}
    monkeypatch.setattr(A, "refresh_codex_oauth_pure", refresh)
    assert CP.CredentialPool("openai-codex", [owned]).try_refresh_matching(credential_id=owned.id) is None
    assert rows(profile)[0]["refresh_token"] == "synthetic-newer-refresh"


def test_missing_local_entry_never_refreshes_global_fallback(stores, monkeypatch):
    profile, root, owned, *_ = stores
    A.write_credential_pool("openai-codex", [], removed_ids=[r["id"] for r in rows(profile)])
    def forbidden(*args, **kwargs):
        pytest.fail("removed local credential must not be refreshed")
    monkeypatch.setattr(A, "refresh_codex_oauth_pure", forbidden)
    assert CP.CredentialPool("openai-codex", [owned]).try_refresh_matching(credential_id=owned.id) is None
