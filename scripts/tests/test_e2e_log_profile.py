"""Tests for scripts/e2e-log-profile.py, the E2E wall-time breakdown."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e-log-profile.py"

# A trimmed log in the shape `nix build -L` prints: a boot nested inside
# wait_for_unit, a nails command, a poll, a multi-line command, a power-off and
# a reboot, a host-side forensic step, and one subtest frame. Each line gets
# the derivation prefix below.
BODY = """\
machine: starting vm
machine # Creating Nix store image...
machine: waiting for unit multi-user.target
machine: waiting for the VM to finish booting
machine: (finished: waiting for the VM to finish booting, in 12.00 seconds)
machine: (finished: waiting for unit multi-user.target, in 20.00 seconds)
subtest: phase one
machine: must succeed: nails --config /x.toml activate -y
machine: (finished: must succeed: nails --config /x.toml activate -y, in 3.00 seconds)
machine: waiting for success: test -e /run/done
machine: (finished: waiting for success: test -e /run/done, in 4.00 seconds)
machine: must succeed: cat > /run/a <<'EOF'
line
EOF
machine: (finished: must succeed: cat > /run/a <<'EOF'
line
EOF, in 1.00 seconds)
machine: must succeed: sleep 2
machine: (finished: must succeed: sleep 2, in 2.00 seconds)
machine: waiting for the VM to power off
machine: (finished: waiting for the VM to power off, in 1.50 seconds)
disk_forensics: qemu-img took 7.25 seconds
machine: starting vm
machine # Reusing Nix store image.
machine: waiting for the VM to finish booting
machine: (finished: waiting for the VM to finish booting, in 10.00 seconds)
(finished: subtest: phase one, in 40.00 seconds)
batch: first-scenario passed in 12.5 s
batch: second-scenario FAILED after 3.0 s: boom
(finished: run the VM test script, in 70.00 seconds)
"""
LOG = "".join(f"vm-test-run-demo> {line}\n" for line in BODY.splitlines())


class ProfileTest(unittest.TestCase):
    def test_categories_add_up_and_nesting_is_counted_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "demo.log"
            log.write_text(LOG, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--json", str(log)],
                check=True,
                capture_output=True,
                text=True,
            )
        row = json.loads(completed.stdout)
        self.assertEqual(row["test"], "demo")
        self.assertEqual(row["total"], 70.0)
        self.assertEqual(row["boots"], 2)
        self.assertEqual(row["reboots"], 1)
        # The nested 12 s connect is part of the 20 s wait, not added to it.
        self.assertEqual(row["boot"], 30.0)
        self.assertEqual(row["nails"], 3.0)
        self.assertEqual(row["poll"], 4.0)
        self.assertEqual(row["guest"], 1.0)
        self.assertEqual(row["sleep"], 2.0)
        self.assertEqual(row["poweroff"], 1.5)
        self.assertEqual(row["forensic"], 7.25)
        self.assertAlmostEqual(row["unlogged"], 70 - 30 - 3 - 4 - 1 - 2 - 1.5 - 7.25)
        self.assertEqual(row["store_image_builds"], 1)
        self.assertEqual(row["store_image_reuses"], 1)
        self.assertEqual(
            row["scenarios"], {"first-scenario": 12.5, "second-scenario": 3.0}
        )

    def test_an_unprefixed_nix_log_is_named_after_its_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "demo.log"
            log.write_text(BODY, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--json", str(log)],
                check=True,
                capture_output=True,
                text=True,
            )
        row = json.loads(completed.stdout)
        self.assertEqual((row["test"], row["total"], row["boot"]), ("demo", 70.0, 30.0))


if __name__ == "__main__":
    unittest.main()
