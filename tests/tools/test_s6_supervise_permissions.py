from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker/cont-init.d/015-supervise-perms"
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

    wrapper = MAIN_WRAPPER.read_text(encoding="utf-8")
    assert 'cd "$HERMES_HOME"' not in wrapper
    assert ". /opt/hermes/.venv/bin/activate" in wrapper
