"""Guards for ``get_external_skills_dirs`` mtime-based memo.

``get_external_skills_dirs()`` is called once per skill during banner
construction and tool registration — on a typical install that's 120+
calls.  Without caching, each call re-reads + YAML-parses the full
config.yaml (~85ms each, 10+ seconds total).  This test pins the
behavior: first call parses, subsequent calls return cached result,
cache invalidates when config.yaml's mtime changes.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agent import skill_utils
from agent.skill_utils import (
    _external_dirs_cache_clear,
    get_external_skills_dirs,
)


@pytest.fixture
def hermes_home_with_config(tmp_path, monkeypatch):
    """Isolated ``~/.hermes/`` with a config.yaml referencing one external dir."""
    home = tmp_path / ".hermes"
    home.mkdir()
    external = tmp_path / "external_skills"
    external.mkdir()

    config = home / "config.yaml"
    config.write_text(
        "skills:\n"
        f"  external_dirs:\n"
        f"    - {external}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    _external_dirs_cache_clear()
    yield home, external, config
    _external_dirs_cache_clear()


def test_returns_configured_external_dir(hermes_home_with_config):
    _home, external, _cfg = hermes_home_with_config
    result = get_external_skills_dirs()
    assert result == [external.resolve()]


def test_cache_reuses_result_without_reparsing(hermes_home_with_config):
    """Subsequent calls hit the cache and skip YAML parsing entirely."""
    _home, _external, _cfg = hermes_home_with_config

    # Prime cache
    get_external_skills_dirs()

    # Patch yaml_load to raise — if cache works, it's never called again.
    with patch.object(
        skill_utils,
        "yaml_load",
        side_effect=AssertionError("yaml_load should not run on cache hit"),
    ):
        # Many calls, none should trigger the patched yaml_load.
        for _ in range(100):
            get_external_skills_dirs()


def test_cache_invalidates_on_mtime_change(hermes_home_with_config):
    """A config.yaml edit invalidates the cache on the next call."""
    _home, external, config = hermes_home_with_config
    other = external.parent / "other_skills"
    other.mkdir()

    # Prime cache with original contents.
    first = get_external_skills_dirs()
    assert first == [external.resolve()]

    # Rewrite config; bump mtime forward explicitly so filesystems with
    # coarse mtime granularity still register the change on fast test
    # systems.
    config.write_text(
        "skills:\n"
        f"  external_dirs:\n"
        f"    - {other}\n",
        encoding="utf-8",
    )
    stat = config.stat()
    future = stat.st_atime + 10
    os.utime(config, (future, future))

    second = get_external_skills_dirs()
    assert second == [other.resolve()]


def test_returns_empty_when_config_missing(tmp_path, monkeypatch):
    """No config file → empty list, cached as empty."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    _external_dirs_cache_clear()

    assert get_external_skills_dirs() == []


def test_returned_list_is_a_copy(hermes_home_with_config):
    """Callers can't poison the cache by mutating the returned list."""
    first = get_external_skills_dirs()
    first.append(Path("/tmp/should-not-persist"))

    second = get_external_skills_dirs()
    assert Path("/tmp/should-not-persist") not in second


def test_cache_key_is_per_config_path(tmp_path, monkeypatch):
    """Two different HERMES_HOMEs keep separate cache entries."""
    home_a = tmp_path / "home_a" / ".hermes"
    home_a.mkdir(parents=True)
    ext_a = tmp_path / "ext_a"
    ext_a.mkdir()
    (home_a / "config.yaml").write_text(
        f"skills:\n  external_dirs:\n    - {ext_a}\n", encoding="utf-8"
    )

    home_b = tmp_path / "home_b" / ".hermes"
    home_b.mkdir(parents=True)
    ext_b = tmp_path / "ext_b"
    ext_b.mkdir()
    (home_b / "config.yaml").write_text(
        f"skills:\n  external_dirs:\n    - {ext_b}\n", encoding="utf-8"
    )

    _external_dirs_cache_clear()

    monkeypatch.setenv("HERMES_HOME", str(home_a))
    assert get_external_skills_dirs() == [ext_a.resolve()]

    monkeypatch.setenv("HERMES_HOME", str(home_b))
    assert get_external_skills_dirs() == [ext_b.resolve()]

    # And switching back still works — both entries coexist in the cache.
    monkeypatch.setenv("HERMES_HOME", str(home_a))
    assert get_external_skills_dirs() == [ext_a.resolve()]


def test_managed_config_supplies_external_dir_without_user_config(tmp_path, monkeypatch):
    """A managed skill root works even when the profile has no config file."""
    from hermes_cli.managed_scope import invalidate_managed_cache

    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "skills").mkdir()
    external = tmp_path / "managed-skills"
    external.mkdir()
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "config.yaml").write_text(
        f"skills:\n  external_dirs:\n    - {external}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    _external_dirs_cache_clear()
    invalidate_managed_cache()

    assert get_external_skills_dirs() == [external.resolve()]


def test_managed_external_dir_wins_and_invalidates_cache(tmp_path, monkeypatch):
    """The managed leaf overrides user config and edits invalidate the memo."""
    from hermes_cli.managed_scope import invalidate_managed_cache

    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "skills").mkdir()
    user_external = tmp_path / "user-skills"
    user_external.mkdir()
    managed_external = tmp_path / "managed-skills"
    managed_external.mkdir()
    replacement = tmp_path / "replacement-skills"
    replacement.mkdir()
    (home / "config.yaml").write_text(
        f"skills:\n  external_dirs:\n    - {user_external}\n",
        encoding="utf-8",
    )
    managed = tmp_path / "managed"
    managed.mkdir()
    managed_config = managed / "config.yaml"
    managed_config.write_text(
        f"skills:\n  external_dirs:\n    - {managed_external}\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    _external_dirs_cache_clear()
    invalidate_managed_cache()
    assert get_external_skills_dirs() == [managed_external.resolve()]

    managed_config.write_text(
        f"skills:\n  external_dirs:\n    - {replacement}\n",
        encoding="utf-8",
    )
    stat = managed_config.stat()
    future = stat.st_atime + 10
    os.utime(managed_config, (future, future))
    invalidate_managed_cache()

    assert get_external_skills_dirs() == [replacement.resolve()]
