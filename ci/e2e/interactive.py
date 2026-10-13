"""Launch the interactive driver of a single leaf test.

``nix run .#e2e.<name>.driverInteractive`` opens the test's Python REPL:
``start_all()`` boots the VMs, ``test_script()`` runs the test, Ctrl-D quits.
"""

from __future__ import annotations

import os


class InteractiveError(Exception):
    """The interactive driver cannot be launched for the given name."""


def driver_attr(
    name: str, attr_prefix: str = ".#legacyPackages.x86_64-linux.e2e"
) -> str:
    return f"{attr_prefix}.{name}.driverInteractive"


def exec_interactive(
    name: str, attr_prefix: str = ".#legacyPackages.x86_64-linux.e2e"
) -> None:
    """Replace this process with the test's interactive Nix driver."""
    attr = driver_attr(name, attr_prefix)
    os.execvp("nix", ["nix", "run", attr])
