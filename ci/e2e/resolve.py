"""Resolve requested targets (leaf tests or groups) to an ordered leaf set.

``--affected`` narrows a run to the ``ci`` group plus every test whose Nix
derivation differs from a base revision, so an unrelated change does not boot
the whole suite.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

from .metadata import Metadata

# The group that every pull request and every `--affected` run includes.
AFFECTED_BASE_GROUP = "ci"


class ResolveError(Exception):
    """A requested target is unknown or the metadata is inconsistent."""


def resolve_targets(metadata: Metadata, requested: Sequence[str]) -> list[str]:
    """Expand targets to leaf tests in request order, without duplicates.

    A name resolves as a leaf test before a group, matching the flake, where a
    shared name would hide one of them (the suite asserts they never clash).
    """
    leaf_set = metadata.leaf_set
    seen: set[str] = set()
    resolved: list[str] = []
    for name in requested:
        if name in leaf_set:
            members = [name]
        elif name in metadata.groups:
            members = metadata.groups[name]
        else:
            raise ResolveError(f"unknown E2E target: {name}")
        for member in members:
            if member not in leaf_set:
                raise ResolveError(
                    f"target {name} resolved to unknown leaf test {member}"
                )
            if member not in seen:
                seen.add(member)
                resolved.append(member)
    return resolved


def _drv_path(attr: str) -> str:
    completed = subprocess.run(
        ["nix", "eval", "--raw", f"{attr}.drvPath"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def changed_leaf_tests(
    metadata: Metadata,
    base_rev: str,
    attr_prefix: str = ".#legacyPackages.x86_64-linux.e2e",
) -> list[str]:
    """Return the leaf tests whose derivation differs from ``base_rev``.

    Each test's current ``drvPath`` is compared with the same attribute built
    from the base revision's flake. Nix is required; callers reach this only
    through ``resolve --affected``.
    """
    changed: list[str] = []
    for test in metadata.leaf_tests:
        current = _drv_path(f"{attr_prefix}.{test}")
        try:
            base = _drv_path(f"{base_rev}#legacyPackages.x86_64-linux.e2e.{test}")
        except subprocess.CalledProcessError:
            # The test does not exist at the base revision, so it is new.
            changed.append(test)
            continue
        if current != base:
            changed.append(test)
    return changed


def resolve_affected(metadata: Metadata, base_rev: str) -> list[str]:
    """Return the ``ci`` group plus every test changed since ``base_rev``."""
    base_targets = list(metadata.groups.get(AFFECTED_BASE_GROUP, ()))
    selected = resolve_targets(metadata, base_targets)
    selected_set = set(selected)
    for test in changed_leaf_tests(metadata, base_rev):
        if test not in selected_set:
            selected_set.add(test)
            selected.append(test)
    return selected
