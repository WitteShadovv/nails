"""Tests for scripts/check-line-count.sh, the Rust file size check."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-line-count.sh"

# The script relies on plain POSIX awk. CI runners default to mawk and the dev
# shell to gawk, so every implementation found here gets a run.
AWKS = sorted(
    {
        os.path.realpath(path)
        for name in ("awk", "gawk", "mawk", "nawk")
        if (path := shutil.which(name))
    }
)


def code(lines: int) -> str:
    return "".join(f"let x{i} = {i};\n" for i in range(lines))


class CheckLineCountTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self, awk: str | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        if awk is not None:
            shim = self.root / "awk-shim"
            shim.mkdir(exist_ok=True)
            (shim / "awk").unlink(missing_ok=True)
            (shim / "awk").symlink_to(awk)
            env["PATH"] = f"{shim}{os.pathsep}{env['PATH']}"
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.root)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_small_files_pass_silently(self) -> None:
        self.write("nails-core/src/lib.rs", code(10))
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")

    def test_production_file_warns_above_500_and_fails_above_850(self) -> None:
        self.write("nails-core/src/medium.rs", code(501))
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "warning: nails-core/src/medium.rs: 501 code lines", result.stdout
        )

        self.write("nails-cli/src/large.rs", code(851))
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("error: nails-cli/src/large.rs: 851 code lines", result.stdout)

    def test_limits_are_inclusive(self) -> None:
        self.write("nails-core/src/at_warn.rs", code(500))
        self.write("nails-core/src/at_fail.rs", code(850))
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("at_warn.rs", result.stdout)
        self.assertIn("warning: nails-core/src/at_fail.rs", result.stdout)

    def test_blank_and_comment_lines_are_not_counted(self) -> None:
        padding = "\n".join(["", "// note", "    /// doc", "//! module doc"] * 300)
        self.write("nails-core/src/commented.rs", padding + "\n" + code(400))
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_test_files_only_warn_above_1500(self) -> None:
        for path in (
            "nails-core/src/manager/tests.rs",
            "nails-core/src/manager/tests/activation.rs",
            "nails-core/src/manager/tests_restore.rs",
            "nails-cli/src/cli/commands/status_tests.rs",
            "nails-cli/tests/cli_integration.rs",
            "nails-core/benches/performance.rs",
        ):
            with self.subTest(path=path):
                self.write(path, code(1500))
                self.assertEqual(self.run_check().stdout, "")
                self.write(path, code(3000))
                result = self.run_check()
                self.assertEqual(result.returncode, 0)
                self.assertIn(f"warning: {path}: 3000 code lines", result.stdout)
                (self.root / path).unlink()

    def test_names_that_only_contain_test_are_production(self) -> None:
        self.write("nails-core/src/test_gate.rs", code(851))
        self.assertEqual(self.run_check().returncode, 1)

    def test_build_output_and_other_directories_are_ignored(self) -> None:
        self.write("nails-core/target/debug/build/generated.rs", code(900))
        self.write("vendor/big.rs", code(900))
        self.write("nails-core/src/lib.rs", code(1))
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_every_awk_agrees(self) -> None:
        self.write("nails-core/src/medium.rs", code(600))
        self.write("nails-core/src/large.rs", code(900))
        self.write("nails-core/src/tests.rs", code(1600))
        expected = (
            "error: nails-core/src/large.rs: 900 code lines (limit 850)\n"
            "warning: nails-core/src/medium.rs: 600 code lines (over 500)\n"
            "warning: nails-core/src/tests.rs: 1600 code lines (over 1500)\n"
        )
        for awk in AWKS:
            with self.subTest(awk=awk):
                result = self.run_check(awk)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_repository_passes_in_under_a_second(self) -> None:
        start = time.monotonic()
        result = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, check=False
        )
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertLess(elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
