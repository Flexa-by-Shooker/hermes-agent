"""Opt-in full-container boot checks against synthetic host-mounted profiles."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


IMAGE = os.environ.get("HERMES_TEST_IMAGE", "")


@unittest.skipUnless(
    sys.platform.startswith("linux") and IMAGE and shutil.which("docker")
    and hasattr(os, "geteuid") and os.geteuid() == 0,
    "Requires an explicitly selected local image and root-owned synthetic Docker fixture",
)
class ProfileGroupBootTests(unittest.TestCase):
    def command(self, *args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout

    def test_boot_and_restart_preserve_groups_while_repairing_legacy_users(self):
        self.assertRegex(IMAGE, re.compile(r"sha256:[0-9a-f]{64}\Z"))
        self.command("docker", "image", "inspect", IMAGE)
        name = "hermes-profile-group-" + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="hermes-profile-group-") as temporary:
            data = Path(temporary) / "data"
            profile = data / "profiles" / "fixture"
            wiki = profile / "home" / "wiki"
            wiki.mkdir(parents=True)
            for root in (data, profile):
                (root / "config.yaml").write_text("model: {}\n", encoding="utf-8")
                (root / "gateway_state.json").write_text('{"gateway_state":"stopped"}', encoding="utf-8")
            page = wiki / "page.md"
            page.write_bytes(b"Synthetic persistent knowledge\n")
            legacy = wiki / "legacy.md"
            legacy.write_bytes(b"Synthetic file from a root invocation\n")
            outside = data / "outside"
            outside.write_bytes(b"Synthetic outside target\n")
            link = profile / "outside-link"
            link.symlink_to("/opt/data/outside")
            for path in (data, *data.rglob("*")):
                os.chown(path, 10000, 10000, follow_symlinks=False)
            os.chown(wiki, 10000, 24001)
            os.chmod(wiki, 0o2770)
            os.chown(page, 10000, 24001)
            os.chmod(page, 0o640)
            os.chown(legacy, 0, 24001)
            os.chmod(legacy, 0o640)
            os.chown(outside, 0, 0)
            before = {p.name: p.read_bytes() for p in (page, legacy, outside)}
            ready = data / "boot-ready"
            program = "from pathlib import Path;import time;Path('/opt/data/boot-ready').touch();time.sleep(300)"
            try:
                self.command("docker", "run", "-d", "--rm", "--name", name,
                             "--network=none", "--pids-limit=256", "--memory=1g",
                             "-e", "HERMES_DASHBOARD=0",
                             "--mount", "type=bind,src=" + str(data) + ",dst=/opt/data",
                             IMAGE, "/opt/hermes/.venv/bin/python3", "-I", "-B", "-c", program)
                for boot in range(2):
                    if boot:
                        ready.unlink()
                        self.command("docker", "restart", "--time", "10", name)
                    deadline = time.monotonic() + 40
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.2)
                    self.assertTrue(ready.exists(), "The actual container entrypoint did not reach its command")
                    self.assertEqual((page.stat().st_uid, page.stat().st_gid), (10000, 24001))
                    self.assertEqual((legacy.stat().st_uid, legacy.stat().st_gid), (10000, 24001))
                    self.assertEqual((wiki.stat().st_uid, wiki.stat().st_gid), (10000, 24001))
                    self.assertEqual(stat.S_IMODE(wiki.stat().st_mode), 0o2770)
                    self.assertEqual(stat.S_IMODE(page.stat().st_mode), 0o640)
                    self.assertEqual((outside.stat().st_uid, outside.stat().st_gid), (0, 0))
                    self.assertEqual({p.name: p.read_bytes() for p in (page, legacy, outside)}, before)
                    self.assertTrue(link.is_symlink())
            finally:
                subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, timeout=60)


if __name__ == "__main__":
    unittest.main()
