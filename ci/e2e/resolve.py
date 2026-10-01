"""Resolve requested targets (leaf tests or groups) to an ordered leaf set.

``--affected`` narrows a run to the ``ci`` group plus every test whose Nix
derivation differs from a base revision, so an unrelated change does not boot
the whole suite.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .metadata import Metadata

# The group that every pull request and every `--affected` run includes.
AFFECTED_BASE_GROUP = "ci"
E2E_ATTR = "legacyPackages.x86_64-linux.e2e"
REPO_ROOT = Path(__file__).resolve().parents[2]
# Test names are pasted into a Nix expression, so only plain names pass.
_TEST_NAME = re.compile(r"[A-Za-z0-9_-]+")


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


def base_flake_ref(base_rev: str, repo: Path = REPO_ROOT) -> str:
    """Return a flake reference for ``base_rev`` of this repository.

    A git revision (a SHA, ``HEAD~1``, ``origin/main``) is pinned to its commit
    in the local clone; anything containing ``:`` is taken as a flake
    reference already.
    """
    if ":" in base_rev:
        return base_rev
    completed = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{base_rev}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ResolveError(f"{base_rev} is not a commit of {repo}")
    return f"git+file://{repo}?rev={completed.stdout.strip()}"


def drv_paths(flake_ref: str, tests: Sequence[str]) -> dict[str, str]:
    """Evaluate the drvPath of every test that exists at ``flake_ref``.

    One evaluation shares nixpkgs between all tests, which is far cheaper
    than one ``nix eval`` per test. A test missing at ``flake_ref`` is left
    out of the result.
    """
    for test in tests:
        if not _TEST_NAME.fullmatch(test):
            raise ResolveError(f"refusing to evaluate odd test name {test!r}")
    wanted = json.dumps(list(tests))
    expression = (
        "e: builtins.mapAttrs (_: t: t.drvPath) (builtins.intersectAttrs "
        "(builtins.listToAttrs (map (n: { name = n; value = null; }) "
        f"(builtins.fromJSON ''{wanted}''))) e)"
    )
    completed = subprocess.run(
        ["nix", "eval", "--json", f"{flake_ref}#{E2E_ATTR}", "--apply", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise ResolveError(f"nix eval of {flake_ref} returned no attribute set")
    return {str(name): str(drv) for name, drv in payload.items()}


def changed_leaf_tests(metadata: Metadata, base_rev: str) -> list[str]:
    """Return the leaf tests whose derivation differs from ``base_rev``.

    A test that does not exist at the base revision is new, so it counts as
    changed. When the base revision does not evaluate at all, nothing can be
    compared and every test counts as changed. Nix is required; callers reach
    this only through ``--affected``.
    """
    current = drv_paths(".", metadata.leaf_tests)
    try:
        base = drv_paths(base_flake_ref(base_rev), metadata.leaf_tests)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()
        print(
            f"note: {base_rev} does not evaluate, so every test counts as "
            f"changed ({detail[-1] if detail else f'exit {exc.returncode}'})",
            file=sys.stderr,
        )
        return list(metadata.leaf_tests)
    return [test for test in metadata.leaf_tests if current.get(test) != base.get(test)]


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
