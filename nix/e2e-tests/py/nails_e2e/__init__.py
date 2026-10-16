"""Importable in-VM helpers for the NAILS NixOS end-to-end test driver.

The driver exposes this package to every test's ``testScript`` through the test
framework's ``extraPythonPackages`` option (see ``nix/e2e-tests/default.nix``),
replacing the many hand-escaped copies of these helpers that used to live inside
Nix strings. Each helper takes the machine/node as its first argument, so the
same definition serves single- and multi-node tests.
"""

from __future__ import annotations

from . import mounts, session, stall, utab
from .command import CommandResult, run_command_capture
from .rebuild import install_nixos_rebuild_wrapper

__all__ = [
    "CommandResult",
    "install_nixos_rebuild_wrapper",
    "mounts",
    "run_command_capture",
    "session",
    "stall",
    "utab",
]
