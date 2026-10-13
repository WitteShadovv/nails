"""Host-side tests for the store image cache.

A stand-in start script carries the nixpkgs markers around a fake "build" that
counts its runs, so the patched script is executed for real with bash: the
image is built once, reused while untouched, and rebuilt after it changed or
when an earlier build never finished.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from nails_e2e.store_image import (
    BEGIN_MARKER,
    END_MARKER,
    REUSE_MESSAGE,
    cache_store_image,
    patch_start_script,
)

SCRIPT = f"""#!/usr/bin/env bash
set -e
echo before
    {BEGIN_MARKER}

    echo build >> "$TMPDIR"/builds
    printf 'image-%s' "$(wc -l < "$TMPDIR"/builds)" > "$TMPDIR"/store.img
    {END_MARKER}
echo after
"""


class _StartCommand:
    def __init__(self, script: str) -> None:
        self._cmd = script


class _Machine:
    def __init__(self, script: str) -> None:
        self.name = "machine"
        self.start_command = _StartCommand(script)


class PatchStartScriptTest(unittest.TestCase):
    def test_leaves_a_script_without_a_store_image_alone(self) -> None:
        self.assertIsNone(patch_start_script("#!/bin/sh\nexec qemu\n"))

    def test_refuses_ambiguous_markers(self) -> None:
        doubled = SCRIPT + f"{BEGIN_MARKER}\n{END_MARKER}\n"
        self.assertIsNone(patch_start_script(doubled))
        reversed_markers = f"{END_MARKER}\n{BEGIN_MARKER}\n"
        self.assertIsNone(patch_start_script(reversed_markers))

    def test_keeps_every_original_line(self) -> None:
        patched = patch_start_script(SCRIPT)
        assert patched is not None
        for line in SCRIPT.splitlines():
            self.assertIn(line, patched.splitlines())


class PatchedScriptRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.state = self.dir / "state"
        self.state.mkdir()
        original = self.dir / "run-machine-vm"
        original.write_text(SCRIPT, encoding="utf-8")
        original.chmod(0o755)
        self.machine = _Machine(str(original))
        scratch = self.dir / "scratch"
        scratch.mkdir()
        self.assertTrue(cache_store_image(self.machine, str(scratch)))

    def run_start(self) -> str:
        env = dict(os.environ, TMPDIR=str(self.state), USE_TMPDIR="1")
        completed = subprocess.run(
            # Through bash, not the shebang: the Nix build sandbox has no /usr/bin/env.
            ["bash", self.machine.start_command._cmd],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout

    def builds(self) -> int:
        return len((self.state / "builds").read_text().splitlines())

    def test_builds_once_then_reuses(self) -> None:
        first = self.run_start()
        self.assertNotIn(REUSE_MESSAGE, first)
        self.assertIn("after", first)
        second = self.run_start()
        self.assertIn(REUSE_MESSAGE, second)
        self.assertIn("after", second)
        self.assertEqual(self.builds(), 1)
        self.assertEqual((self.state / "store.img").read_text(), "image-1")

    def test_rebuilds_an_image_that_changed(self) -> None:
        self.run_start()
        image = self.state / "store.img"
        image.write_text("tampered, and longer")
        output = self.run_start()
        self.assertNotIn(REUSE_MESSAGE, output)
        self.assertEqual(self.builds(), 2)
        self.assertEqual(image.read_text(), "image-2")

    def test_rebuilds_when_the_last_build_left_no_stamp(self) -> None:
        self.run_start()
        (self.state / "store.img.nails-stamp").unlink()
        self.run_start()
        self.assertEqual(self.builds(), 2)

    def test_the_patched_copy_is_executable_and_separate(self) -> None:
        patched = Path(self.machine.start_command._cmd)
        self.assertTrue(os.access(patched, os.X_OK))
        self.assertEqual(patched.name, "run-machine-vm")
        self.assertNotEqual(patched.parent, self.dir)


class CacheStoreImageTest(unittest.TestCase):
    def test_a_machine_without_a_script_is_left_alone(self) -> None:
        machine = _Machine("/nonexistent/run-machine-vm")
        self.assertFalse(cache_store_image(machine))
        self.assertEqual(machine.start_command._cmd, "/nonexistent/run-machine-vm")

    def test_a_script_without_a_store_image_is_left_alone(self) -> None:
        directory = Path(tempfile.mkdtemp())
        script = directory / "run-machine-vm"
        script.write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
        machine = _Machine(str(script))
        self.assertFalse(cache_store_image(machine))
        self.assertEqual(machine.start_command._cmd, str(script))


if __name__ == "__main__":
    unittest.main()
