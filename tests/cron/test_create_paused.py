"""Native job creation must never expose a runnable intermediate record."""
import pytest
from cron import jobs


def test_create_paused_is_atomic_and_default_stays_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(jobs, "CRON_DIR", tmp_path / "cron")
    monkeypatch.setattr(jobs, "JOBS_FILE", tmp_path / "cron" / "jobs.json")
    monkeypatch.setattr(jobs, "OUTPUT_DIR", tmp_path / "cron" / "output")
    saved = []
    original = jobs.save_jobs
    def observe(records):
        saved.extend(dict(record) for record in records)
        return original(records)
    monkeypatch.setattr(jobs, "save_jobs", observe)
    paused = jobs.create_job("Synthetic maintenance", "0 8 * * 1", name="paused-fixture", create_paused=True)
    assert paused["enabled"] is False
    assert paused["state"] == "paused"
    assert saved and all(record["enabled"] is False for record in saved)
    assert jobs.get_job(paused["id"])["enabled"] is False
    active = jobs.create_job("Synthetic ordinary job", "0 8 * * 1", name="active-fixture")
    assert active["enabled"] is True
    assert active["state"] == "scheduled"
    with pytest.raises(ValueError):
        jobs.create_job("Synthetic invalid job", "0 8 * * 1", create_paused="yes")
