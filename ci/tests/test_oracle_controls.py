"""Tests for ci/oracle/merge-controls.sh, which adds the live-tree controls the
producer of the real btrfs images planted to the scan's controls."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ci" / "oracle" / "merge-controls.sh"
CONTROLS_REAL = REPO_ROOT / "ci" / "oracle" / "controls-real.json"

DIGEST = "sha256:" + "0123456789abcdef" * 4


def control(**fields: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": "live-file",
        "tool": "btrfs_restore",
        "path": "/var/lib/nails-oracle/restore-control",
        "field": DIGEST,
    }
    entry.update(fields)
    return entry


@unittest.skipUnless(shutil.which("jq"), "needs jq")
class MergeControlsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.base = json.loads(CONTROLS_REAL.read_text())

    def merge(self, extra: object) -> subprocess.CompletedProcess[str]:
        path = self.dir / "extra.json"
        path.write_text(json.dumps(extra))
        return subprocess.run(
            ["bash", str(SCRIPT), str(CONTROLS_REAL), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_exact_restore_controls_are_added_and_nothing_else_changes(self) -> None:
        extra = [
            control(note="A file the decoy wrote."),
            control(name="live-change-pacman-log", path="/var/log/pacman.log"),
        ]
        done = self.merge({"positive_controls": extra})
        self.assertEqual(done.returncode, 0, done.stderr)
        merged = json.loads(done.stdout)
        self.assertEqual(
            merged["positive_controls"], self.base["positive_controls"] + extra
        )
        self.assertEqual(merged["canary"], self.base["canary"])
        self.assertEqual(merged["_comment"], self.base["_comment"])
        self.assertEqual(set(merged), set(self.base))

    def test_anything_but_exact_restore_controls_with_new_names_fails(self) -> None:
        taken = self.base["positive_controls"][0]["name"]
        cases: dict[str, object] = {
            "no list": {},
            "an empty list": {"positive_controls": []},
            "a list of something else": {"positive_controls": ["live-file"]},
            "another key beside the list": {
                "positive_controls": [control()],
                "canary": self.base["canary"],
            },
            "another channel": {"positive_controls": [control(tool="bulk_extractor")]},
            "any channel": {"positive_controls": [control(tool=None)]},
            "no value": {"positive_controls": [control(field=None)]},
            "a value that is no digest": {"positive_controls": [control(field="dir")]},
            "a short digest": {"positive_controls": [control(field=DIGEST[:-1])]},
            "an upper-case digest": {
                "positive_controls": [control(field="sha256:" + "ABCDEF0123456789" * 4)]
            },
            "a relative path": {"positive_controls": [control(path="var/log/x")]},
            "the top": {"positive_controls": [control(path="/")]},
            "a folder": {"positive_controls": [control(path="/var/log/")]},
            "no name": {"positive_controls": [control(name="")]},
            "a name the committed controls have": {
                "positive_controls": [control(name=taken)]
            },
            "a name twice": {"positive_controls": [control(), control(path="/etc/x")]},
            "a key of its own": {"positive_controls": [control(removed=True)]},
            "a note that is no text": {"positive_controls": [control(note=1)]},
            "not an object": [control()],
        }
        for case, extra in cases.items():
            with self.subTest(case=case):
                done = self.merge(extra)
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertEqual(done.stdout, "")

    def test_a_file_that_is_no_json_fails(self) -> None:
        path = self.dir / "extra.json"
        path.write_text("{")
        done = subprocess.run(
            ["bash", str(SCRIPT), str(CONTROLS_REAL), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.stdout, "")

    def test_a_missing_file_is_a_usage_error(self) -> None:
        done = subprocess.run(
            ["bash", str(SCRIPT), str(CONTROLS_REAL), str(self.dir / "none.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 2, done.stderr)


if __name__ == "__main__":
    unittest.main()
