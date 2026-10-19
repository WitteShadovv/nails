"""Resolve requested targets (leaf tests or groups) to an ordered leaf set.

``--affected`` narrows a run to the ``ci`` group plus every test whose Nix
derivation differs from a base revision, so an unrelated change does not boot
the whole suite.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import evaluate
from .metadata import Metadata

# The group that every pull request and every `--affected` run includes.
AFFECTED_BASE_GROUP = "ci"
E2E_ATTR = "legacyPackages.x86_64-linux.e2e"
REPO_ROOT = Path(__file__).resolve().parents[2]


class ResolveError(Exception):
    """A requested target is unknown or the metadata is inconsistent."""


def resolve_targets(metadata: Metadata, requested: Sequence[str]) -> list[str]:
    """Expand targets to leaf tests in request order, without duplicates.

    A name resolves as a leaf test before a group, matching the flake, where a
    shared name would hide one of them (the suite asserts they never clash).
    The old name of a test that now runs as a scenario of a merged test
    resolves to that merged test.
    """
    leaf_set = metadata.leaf_set
    seen: set[str] = set()
    resolved: list[str] = []
    for name in requested:
        if name in leaf_set:
            members = [name]
        elif name in metadata.groups:
            members = metadata.groups[name]
        elif name in metadata.aliases:
            members = [metadata.aliases[name]]
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


def drv_paths(flake_ref: str, tests: Sequence[str], workers: int) -> dict[str, str]:
    """Evaluate the drvPath of every test that exists at ``flake_ref``.

    The tests are evaluated in batches, at most ``workers`` ``nix eval``
    processes at once (see :mod:`ci.e2e.evaluate`). A test missing at
    ``flake_ref`` is left out of the result.
    """
    paths = evaluate.evaluate(
        f"{flake_ref}#{E2E_ATTR}",
        tests,
        "t: t.drvPath",
        workers=workers,
        skip_missing=True,
    )
    return {test: str(drv) for test, drv in paths.items()}


def _last_line(exc: subprocess.CalledProcessError) -> str:
    detail = (exc.stderr or "").strip().splitlines()
    return detail[-1] if detail else f"exit {exc.returncode}"


def _here_and_at_base(
    function: Callable[..., Any], base_ref: str, *args: Any
) -> tuple[Any, Any]:
    """Run ``function`` on this revision and on the base at the same time.

    Returns both results; for a base that does not evaluate, its error in
    place of its result. This revision must evaluate: when it does not, that
    is a ResolveError.
    """
    with ThreadPoolExecutor(max_workers=2) as pool:
        here = pool.submit(function, ".", *args)
        base = pool.submit(function, base_ref, *args)
        try:
            current = here.result()
        except subprocess.CalledProcessError as exc:
            raise ResolveError(
                f"this revision does not evaluate: {_last_line(exc)}"
            ) from None
        try:
            return current, base.result()
        except subprocess.CalledProcessError as exc:
            return current, exc


def _every_test(
    metadata: Metadata, base_rev: str, exc: subprocess.CalledProcessError
) -> list[str]:
    print(
        f"note: {base_rev} does not evaluate, so every test counts as "
        f"changed ({_last_line(exc)})",
        file=sys.stderr,
    )
    return list(metadata.leaf_tests)


def changed_leaf_tests(
    metadata: Metadata, base_rev: str, workers: int | None = None
) -> list[str]:
    """Return the leaf tests whose derivation differs from ``base_rev``.

    Both revisions are evaluated at once, each in parallel batches over half
    of ``workers`` processes (by default as many as the host allows, see
    :func:`ci.e2e.evaluate.auto_workers`).

    A test that does not exist at the base revision is new, so it counts as
    changed. When the base revision does not evaluate at all, nothing can be
    compared and every test counts as changed; when this revision does not,
    that is a ResolveError. Nix is required; callers reach this only through
    ``--affected``.
    """
    if workers is None:
        workers = evaluate.auto_workers()
    base_ref = base_flake_ref(base_rev)
    tests = metadata.leaf_tests
    current, base = _here_and_at_base(drv_paths, base_ref, tests, max(1, workers // 2))
    if isinstance(base, subprocess.CalledProcessError):
        return _every_test(metadata, base_rev, base)
    return [test for test in tests if current.get(test) != base.get(test)]


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
