"""Tests for scripts/check-fuzz-targets.sh, the fuzz target wiring check."""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-fuzz-targets.sh"

MANIFEST = """[package]
name = "nails-fuzz"
version = "0.0.0"

[dependencies]
libfuzzer-sys = "0.4"
"""

TARGET = """#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_teardown::mountinfo::parse_mountinfo;

fuzz_target!(|data: &[u8]| {
    let _ = parse_mountinfo(&String::from_utf8_lossy(data));
});
"""


def bin_entry(name: str) -> str:
    return (
        f'\n[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\n'
        "test = false\ndoc = false\nbench = false\n"
    )


def scaffold_stub() -> str:
    """The target file `just new-fuzz-target` writes, read from the justfile."""
    lines = (REPO_ROOT / "justfile").read_text(encoding="utf-8").splitlines()
    start = lines.index("    cat > \"$target\" <<'EOF'") + 1
    end = lines.index("    EOF", start)
    return textwrap.dedent("\n".join(lines[start:end])) + "\n"


class CheckFuzzTargetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "fuzz" / "fuzz_targets").mkdir(parents=True)
        (self.root / "fuzz" / "seeds").mkdir()
        self.write("fuzz/Cargo.toml", MANIFEST)

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def add_target(self, name: str, source: str, seeds: dict[str, str]) -> None:
        self.write(f"fuzz/fuzz_targets/{name}.rs", source)
        with open(self.root / "fuzz" / "Cargo.toml", "a", encoding="utf-8") as toml:
            toml.write(bin_entry(name))
        (self.root / "fuzz" / "seeds" / name).mkdir()
        for seed, content in seeds.items():
            self.write(f"fuzz/seeds/{name}/{seed}", content)

    def run_check(self, root: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), str(root or self.root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_wired_implemented_and_seeded_target_passes(self) -> None:
        self.add_target("mountinfo", TARGET, {"empty": "", "overlay": "36 35 0:1"})
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "All 1 fuzz targets are wired, implemented and seeded.", result.stdout
        )

    def test_scaffold_output_is_rejected(self) -> None:
        # Exactly what `just new-fuzz-target foo` leaves: the stub, the empty
        # starter seed and the [[bin]] entry.
        self.add_target("foo", scaffold_stub(), {"empty": ""})
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(
            "fuzz/fuzz_targets/foo.rs is still the scaffold's stub", result.stdout
        )
        self.assertIn("fuzz target 'foo' has only empty seeds", result.stdout)

    def test_stub_body_without_its_todo_markers_is_rejected(self) -> None:
        stub = "\n".join(
            line for line in scaffold_stub().splitlines() if "TODO" not in line
        )
        self.add_target("foo", stub, {"input": "data"})
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("is still the scaffold's stub", result.stdout)

    def test_corpus_of_empty_seeds_is_rejected_until_one_has_content(self) -> None:
        self.add_target("mountinfo", TARGET, {"empty": "", "also-empty": ""})
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("fuzz target 'mountinfo' has only empty seeds", result.stdout)

        self.write("fuzz/seeds/mountinfo/overlay", "36 35 0:1")
        self.assertEqual(self.run_check().returncode, 0)

    def test_target_without_seeds_or_bin_entry_is_rejected(self) -> None:
        self.write("fuzz/fuzz_targets/utab.rs", TARGET)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("fuzz/fuzz_targets/utab.rs has no [[bin]] entry", result.stdout)
        self.assertIn("fuzz target 'utab' has no seed corpus", result.stdout)

    def test_dangling_bin_entry_and_orphaned_seeds_are_rejected(self) -> None:
        self.add_target("mountinfo", TARGET, {"overlay": "36 35 0:1"})
        (self.root / "fuzz" / "fuzz_targets" / "mountinfo.rs").unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "[[bin]] 'mountinfo' points at fuzz/fuzz_targets/mountinfo.rs",
            result.stdout,
        )
        self.assertIn("fuzz/seeds/mountinfo/ has no fuzz target", result.stdout)

    def test_repository_passes(self) -> None:
        result = self.run_check(REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
