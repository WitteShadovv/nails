"""Tests for ci/oracle/timeline-has-file.sh, the proof that plaso read an image."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ci" / "oracle" / "timeline-has-file.sh"

# The canary's file on the real decoy images, the path run-scan.sh asks about.
CANARY = "/var/lib/nails-oracle/canary"


def event(filename: str, **fields: object) -> str:
    """One event as psort's json_line export writes it: json.dumps with sorted
    keys and the default separators."""
    return json.dumps({"filename": filename, **fields}, sort_keys=True)


def stat_event(path: str) -> str:
    """plaso's fs:stat event for a file it read from an ext file system."""
    return event(
        path,
        data_type="fs:stat",
        display_name=f"EXT:{path}",
        parser="filestat",
        pathspec={
            "location": path,
            "parent": {
                "parent": {"location": "/data/disk.img", "type_indicator": "OS"},
                "type_indicator": "RAW",
            },
            "type_indicator": "EXT",
        },
        timestamp_desc="Content Modification Time",
    )


def opaque_image_event() -> str:
    """The event plaso writes for an image whose file system it cannot open: it
    dates the image file itself, at the one path every image is read through."""
    return event(
        "/data/disk.img",
        data_type="fs:stat",
        display_name="OS:/data/disk.img",
        parser="filestat",
        pathspec={"location": "/data/disk.img", "type_indicator": "OS"},
        timestamp_desc="Content Modification Time",
    )


class TimelineHasFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        # Through bash: the flake check copies the tree without its file modes.
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def check(self, events: list[str], path: str = CANARY) -> int:
        timeline = self.dir / "after.jsonl"
        timeline.write_text("".join(f"{line}\n" for line in events), encoding="utf-8")
        return self.run_script(str(timeline), path).returncode

    def test_an_event_for_the_file_proves_plaso_read_the_image(self) -> None:
        events = [stat_event("/etc/hostname"), stat_event(CANARY)]
        self.assertEqual(self.check(events), 0)

    def test_an_image_plaso_could_not_open_proves_nothing(self) -> None:
        # Not empty, so it would pass the verdict's channel rule on its own.
        self.assertEqual(self.check([opaque_image_event()] * 4), 1)
        self.assertEqual(self.check([]), 1)

    def test_only_the_exact_path_counts(self) -> None:
        # The synthetic images carry the canary in canary.txt, so neither path
        # stands in for the other, and neither does the directory holding it.
        self.assertEqual(self.check([stat_event(f"{CANARY}.txt")]), 1)
        self.assertEqual(self.check([stat_event(CANARY)], f"{CANARY}.txt"), 1)
        self.assertEqual(self.check([stat_event("/var/lib/nails-oracle")]), 1)

    def test_the_path_counts_only_as_the_events_file(self) -> None:
        # A log line naming the canary's file, even in the form of the key, is
        # not an event for that file: json.dumps escapes its quotes.
        mention = event(
            "/var/log/app.log",
            data_type="text:entry",
            message=f'removed {CANARY} ("filename": "{CANARY}")',
        )
        self.assertEqual(self.check([mention]), 1)

    def test_the_compact_json_form_counts_too(self) -> None:
        compact = json.dumps(
            {"data_type": "fs:stat", "filename": CANARY}, separators=(",", ":")
        )
        self.assertEqual(self.check([compact]), 0)

    def test_an_unreadable_timeline_or_a_bad_path_is_an_error(self) -> None:
        timeline = self.dir / "before.jsonl"
        timeline.write_text(f"{stat_event(CANARY)}\n", encoding="utf-8")
        missing = str(self.dir / "missing.jsonl")
        self.assertEqual(self.run_script(missing, CANARY).returncode, 2)
        self.assertEqual(self.run_script(str(timeline), CANARY[1:]).returncode, 2)
        self.assertEqual(self.run_script(str(timeline), "").returncode, 2)
        self.assertEqual(self.run_script(str(timeline)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
