"""Tests for scripts/check-orphan-modules.sh, the undeclared module check."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-orphan-modules.sh"

# The script checks the crate directories, every crate of the side workspaces
# and the fuzz crate, and refuses a tree that lacks a source tree in one of
# them, so every scratch tree has a crate in each.
CRATES = ("nails-core", "setup/nails-setup", "gui/nails-gui", "fuzz")


class CheckOrphanModulesTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp).resolve()
        for crate in CRATES:
            self.write(f"{crate}/src/lib.rs", "")

    def write(self, relative: str, text: str = "") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self, root: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), str(root or self.root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_declared_modules_pass(self) -> None:
        self.write("nails-core/src/lib.rs", "mod store;\npub mod disk;\n")
        self.write("nails-core/src/store.rs", "mod cache;\n")
        self.write("nails-core/src/store/cache.rs")
        self.write("nails-core/src/disk/mod.rs")
        self.write("gui/nails-gui/src/main.rs", "mod window;\n")
        self.write("gui/nails-gui/src/window.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All Rust source files are declared as modules.", result.stdout)

    def test_a_path_attribute_declares_its_file(self) -> None:
        self.write(
            "setup/nails-setup/src/lib.rs",
            '#[path = "generated/table.rs"]\nmod table;\n',
        )
        self.write("setup/nails-setup/src/generated/table.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_path_attribute_declares_its_file_through_a_linked_root(self) -> None:
        # The include resolves to a physical path, which must match the one the
        # scan reports for the same file when the tree is reached by a link.
        self.write("nails-core/src/lib.rs", '#[path = "gen/table.rs"]\nmod table;\n')
        self.write("nails-core/src/gen/table.rs")
        links = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (links / "repo").symlink_to(self.root, target_is_directory=True)
        result = self.run_check(links / "repo")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_an_undeclared_file_fails(self) -> None:
        self.write("nails-core/src/stale.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("  nails-core/src/stale.rs\n", result.stdout)

    def test_side_workspaces_are_checked_like_the_crates(self) -> None:
        self.write("setup/nails-setup/src/stale.rs")
        self.write("gui/nails-gui/src/widgets/stale.rs")
        # An integration test is a crate root of its own.
        self.write("gui/nails-gui/tests/window.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("  setup/nails-setup/src/stale.rs\n", result.stdout)
        self.assertIn("  gui/nails-gui/src/widgets/stale.rs\n", result.stdout)
        self.assertNotIn("tests/window.rs", result.stdout)

    def test_the_test_bench_and_example_trees_are_checked(self) -> None:
        # Each file directly in tests/, benches/ or examples/ is a crate root of
        # its own, which declares its modules beside itself, as lib.rs does.
        trees = (
            "nails-core/tests",
            "nails-core/benches",
            "setup/nails-setup/tests",
            "gui/nails-gui/examples",
        )
        for tree in trees:
            self.write(f"{tree}/flow.rs", "mod common;\n")
            self.write(f"{tree}/common/mod.rs")
            self.write(f"{tree}/kernel.rs", '#[path = "kernel/entry.rs"]\nmod entry;\n')
            self.write(f"{tree}/kernel/entry.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for tree in trees:
            self.write(f"{tree}/common/stale.rs")
        # A tests/ directory inside src/ holds modules, not crate roots.
        self.write("nails-core/src/config/tests/stale.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        for tree in trees:
            self.assertIn(f"  {tree}/common/stale.rs\n", result.stdout)
        self.assertIn("  nails-core/src/config/tests/stale.rs\n", result.stdout)
        self.assertNotIn("flow.rs", result.stdout)
        self.assertNotIn("kernel", result.stdout)

    def test_the_fuzz_crate_is_checked_like_the_crates(self) -> None:
        self.write("fuzz/src/lib.rs", "pub mod libmount;\n")
        self.write("fuzz/src/libmount.rs")
        # A fuzz target is a crate root of its own.
        self.write("fuzz/fuzz_targets/utab.rs", "mod common;\n")
        self.write("fuzz/fuzz_targets/common/mod.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.write("fuzz/src/stale.rs")
        self.write("fuzz/fuzz_targets/common/stale.rs")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("  fuzz/src/stale.rs\n", result.stdout)
        self.assertIn("  fuzz/fuzz_targets/common/stale.rs\n", result.stdout)
        self.assertNotIn("utab.rs", result.stdout)

    def test_a_side_workspace_without_a_crate_fails(self) -> None:
        for workspace, crate in (("setup", "nails-setup"), ("gui", "nails-gui")):
            with self.subTest(workspace=workspace):
                source = self.root / workspace / crate / "src"
                (source / "lib.rs").unlink()
                source.rmdir()
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    f"ERROR: no Rust source tree at {workspace}/*/src", result.stderr
                )
                self.write(f"{workspace}/{crate}/src/lib.rs")

    def test_a_fuzz_crate_without_a_source_tree_fails(self) -> None:
        source = self.root / "fuzz" / "src"
        (source / "lib.rs").unlink()
        source.rmdir()
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERROR: no Rust source tree at fuzz/src", result.stderr)


if __name__ == "__main__":
    unittest.main()
