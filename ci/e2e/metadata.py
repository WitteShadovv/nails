"""The E2E metadata: the single source of targets, groups and timeouts.

The flake exposes ``.#legacyPackages.<system>.e2e-metadata`` as plain data:
``availableTargets``, ``leafTests``, ``groups`` and ``timeouts``. Evaluating it
runs the suite's own assertions without building a single VM. Nix is invoked
lazily, so a subcommand that needs no metadata (``--help``, ``interactive``
argument parsing) never shells out.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass

# The flake builds its VM tests for x86_64-linux only. The full attribute path
# also works from other hosts that have an x86_64-linux builder.
METADATA_ATTR = ".#legacyPackages.x86_64-linux.e2e-metadata"


class MetadataError(Exception):
    """The E2E metadata could not be evaluated or is malformed."""


@dataclass(frozen=True)
class Metadata:
    """The resolved E2E metadata."""

    available_targets: list[str]
    leaf_tests: list[str]
    groups: dict[str, list[str]]
    timeouts: dict[str, int]

    @property
    def leaf_set(self) -> frozenset[str]:
        return frozenset(self.leaf_tests)


def parse_metadata(payload: object) -> Metadata:
    """Build :class:`Metadata` from the parsed ``e2e-metadata`` JSON."""
    if not isinstance(payload, Mapping):
        raise MetadataError("E2E metadata must be a JSON object")
    try:
        available = list(payload["availableTargets"])
        leaf_tests = list(payload["leafTests"])
        raw_groups = payload["groups"]
        raw_timeouts = payload["timeouts"]
    except KeyError as exc:
        raise MetadataError(f"E2E metadata is missing {exc.args[0]!r}") from None
    if not isinstance(raw_groups, Mapping):
        raise MetadataError("E2E metadata groups must map a name to its tests")
    if not isinstance(raw_timeouts, Mapping):
        raise MetadataError("E2E metadata timeouts must map a test to its seconds")
    groups = {str(name): list(members) for name, members in raw_groups.items()}
    timeouts = {str(name): int(value) for name, value in raw_timeouts.items()}
    return Metadata(
        available_targets=[str(name) for name in available],
        leaf_tests=[str(name) for name in leaf_tests],
        groups=groups,
        timeouts=timeouts,
    )


def load_metadata(attr: str = METADATA_ATTR) -> Metadata:
    """Evaluate the flake's E2E metadata with ``nix eval``.

    Raises :class:`MetadataError` when Nix is missing or the evaluation fails,
    so the caller can report a clear message instead of a traceback.
    """
    try:
        completed = subprocess.run(
            ["nix", "eval", "--json", attr],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise MetadataError(
            "nix is not on PATH; enter the flake dev shell first"
        ) from None
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or f"exit {exc.returncode}"
        raise MetadataError(f"nix eval {attr} failed: {detail}") from None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise MetadataError(f"nix eval {attr} returned invalid JSON: {exc}") from None
    return parse_metadata(payload)
