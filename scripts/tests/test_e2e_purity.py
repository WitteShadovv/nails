"""Keep the flake's evaluation independent of the machine that runs it.

In pure evaluation, which every flake build uses, `builtins.getEnv` quietly
returns "" instead of failing, and `currentSystem`/`currentTime` exist only
with --impure. Any of them would make a derivation depend on the host or
force --impure, so the evaluation cache and the binary cache stop working.
`nix flake check` does not run in every CI job, so this scan does it there.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IMPURE_BUILTIN = re.compile(r"\b(getEnv|currentSystem|currentTime)\b")


def flake_nix_files() -> list[Path]:
    return [REPO_ROOT / "flake.nix", *sorted((REPO_ROOT / "nix").rglob("*.nix"))]


def impure_lines(text: str) -> list[int]:
    """Numbers of the lines that use an impure builtin outside a comment."""
    return [
        number
        for number, line in enumerate(text.splitlines(), 1)
        if IMPURE_BUILTIN.search(line.split("#", 1)[0])
    ]


class PurityTest(unittest.TestCase):
    def test_no_impure_builtins_in_the_flake(self) -> None:
        found = []
        for path in flake_nix_files():
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            for number in impure_lines(text):
                location = f"{path.relative_to(REPO_ROOT)}:{number}"
                found.append(f"{location}: {lines[number - 1].strip()}")
        self.assertEqual(found, [])

    def test_scan_covers_the_vm_configuration(self) -> None:
        self.assertIn(
            REPO_ROOT / "nix" / "e2e-tests" / "lib" / "vm-config.nix", flake_nix_files()
        )

    def test_scan_finds_impure_builtins_outside_comments(self) -> None:
        text = "\n".join(
            (
                'cores = builtins.getEnv "CORES";',
                "# builtins.getEnv in a comment",
                "inherit (builtins) currentSystem;",
                "memory = 4096; # not currentTime",
                "t = currentTime;",
            )
        )
        self.assertEqual(impure_lines(text), [1, 3, 5])


if __name__ == "__main__":
    unittest.main()
