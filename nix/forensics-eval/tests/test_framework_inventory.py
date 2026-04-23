import re
import sys
import tempfile
import unittest
from pathlib import Path


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, Evidence, Finding, file_inventory, sha256_file


class FrameworkInventoryTests(unittest.TestCase):
    def test_file_inventory_records_files_directories_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()

            payload = nested / "payload.txt"
            payload.write_text("payload", encoding="utf-8")
            (root / "payload-link").symlink_to(payload)

            inventory = file_inventory(root)

            self.assertEqual(inventory["nested"]["type"], "dir")
            self.assertEqual(inventory["nested/payload.txt"]["type"], "file")
            self.assertEqual(inventory["nested/payload.txt"]["size"], 7)
            self.assertEqual(
                inventory["nested/payload.txt"]["sha256"], sha256_file(payload)
            )
            self.assertEqual(inventory["payload-link"]["type"], "symlink")
            self.assertEqual(inventory["payload-link"]["target"], payload.as_posix())

    def test_allowlist_profile_suppresses_global_and_analyzer_specific_matches(self):
        profile = AllowlistProfile(
            path_patterns=[re.compile(r"ignored-path")],
            content_patterns=[re.compile(r"global-secret")],
            finding_ids={"global-id"},
            analyzer_path_patterns={"path_delta": [re.compile(r"analyzer-path")]},
            analyzer_content_patterns={"path_delta": [re.compile(r"analyzer-secret")]},
            analyzer_finding_ids={"path_delta": {"analyzer-id"}},
        )

        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="global-id",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[Evidence(type="file", path="safe", detail="detail")],
                ),
            )
        )
        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="analyzer-id",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[Evidence(type="file", path="safe", detail="detail")],
                ),
            )
        )
        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="x",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[
                        Evidence(
                            type="file", path="analyzer-path/file.txt", detail="detail"
                        )
                    ],
                ),
            )
        )
        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="x",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[
                        Evidence(
                            type="file", path="ignored-path/file.txt", detail="detail"
                        )
                    ],
                ),
            )
        )
        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="x",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[
                        Evidence(
                            type="file",
                            path="safe.txt",
                            detail="contains global-secret",
                        )
                    ],
                ),
            )
        )
        self.assertTrue(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="x",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[
                        Evidence(
                            type="file",
                            path="safe.txt",
                            detail="detail",
                            snippet="analyzer-secret",
                        )
                    ],
                ),
            )
        )
        self.assertFalse(
            profile.suppresses(
                "path_delta",
                Finding(
                    id="x",
                    title="title",
                    severity="low",
                    classification="class",
                    description="desc",
                    evidence=[Evidence(type="file", path="safe.txt", detail="detail")],
                ),
            )
        )


if __name__ == "__main__":
    unittest.main()
