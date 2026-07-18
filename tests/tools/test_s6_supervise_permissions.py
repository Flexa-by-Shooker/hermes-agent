from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker/cont-init.d/015-supervise-perms"
RECONCILE_SCRIPT = ROOT / "docker/cont-init.d/02-reconcile-profiles"
MAIN_WRAPPER = ROOT / "docker/main-wrapper.sh"


def test_static_supervision_retains_root_owner_with_hermes_group_access() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'chown -R root:hermes "$svc/supervise"' in source
    assert 'chown root:hermes "$svc/event"' in source
    assert 'chmod 0710 "$svc/supervise"' in source
    assert 'chmod 0660 "$svc/supervise/control"' in source
    assert 'chown root:hermes "$SCAN_ROOT/.s6-svscan/control"' in source
    assert 'chmod 0770 "$SCAN_ROOT"' in source
    assert 'chmod 0660 "$SCAN_ROOT/.s6-svscan/control"' in source
    assert "hermes:hermes" not in source

    reconcile = RECONCILE_SCRIPT.read_text(encoding="utf-8")
    assert "chown root:hermes /run/service" in reconcile
    assert "chmod 0770 /run/service" in reconcile
    assert 'chown root:hermes "/run/service/.s6-svscan/$entry"' in reconcile
    assert 'chmod 0660 "/run/service/.s6-svscan/$entry"' in reconcile
    assert "chown hermes:hermes /run/service" not in reconcile

    wrapper = MAIN_WRAPPER.read_text(encoding="utf-8")
    assert 'cd "$HERMES_HOME"' not in wrapper
    assert ". /opt/hermes/.venv/bin/activate" in wrapper
