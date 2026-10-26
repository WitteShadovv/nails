"""Plan the portable distribution VM smoke matrix.

The NixOS E2E suite (``plan.py``/``resolve.py``) shards one distribution's
tests on the NixOS test driver. The distro tier instead runs a small smoke
scenario set on several Linux distributions through ``numtide/nix-vm-test``, so
a regression on a non-NixOS host is caught instead of passing unseen.

The distro list is plain data the flake exposes as
``legacyPackages.<system>.e2e-distro-metadata``. Each distribution names its
smoke scenarios, so bringing another distribution online once its backend lands
is a single entry in ``nix/distro-tests/images.nix`` -- this module and the
workflow enumerate whatever the metadata reports. The matrix is bounded so the
total number of parallel jobs (distributions times their shards) never exceeds a
ceiling, because every job holds a dedicated KVM runner.

The metadata also names the fact probes of the families not admitted yet whose
image is pinned. A dispatch can run those instead of the smokes
(:func:`plan_probe_matrix`), one job per probe.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from . import plan

# The distro tests also build x86_64-linux guests only; the attribute path
# works from any host with an x86_64-linux builder.
DISTRO_METADATA_ATTR = ".#legacyPackages.x86_64-linux.e2e-distro-metadata"

# At most this many distro VM jobs run in parallel: distributions times the
# shards each is split into. One smoke scenario per distribution stays well
# under it; the cap only bites once several scenarios per distribution exist.
MAX_DISTRO_JOBS = 8


class DistroError(Exception):
    """The distro metadata could not be evaluated or is malformed."""


@dataclass(frozen=True)
class DistroMetadata:
    """The resolved distro-suite metadata.

    ``distros`` is every distribution name, in declaration order. ``scenarios``
    maps each distribution to its smoke scenario attribute names, and
    ``timeouts`` maps each scenario, and each probe attribute, to its effective
    timeout in seconds. ``probes`` maps each probe a run can boot to its
    attribute name.
    """

    distros: list[str]
    scenarios: dict[str, list[str]]
    timeouts: dict[str, int]
    probes: dict[str, str] = field(default_factory=dict)

    def resolve(self, requested: Sequence[str]) -> list[str]:
        """Return the requested distributions, or all of them when none given."""
        if not requested:
            return list(self.distros)
        known = set(self.distros)
        resolved: list[str] = []
        for name in requested:
            if name not in known:
                raise DistroError(f"unknown distribution: {name}")
            if name not in resolved:
                resolved.append(name)
        return resolved

    def resolve_probes(self, requested: Sequence[str]) -> list[str]:
        """Return the requested probes, or every probe when none are named."""
        if not self.probes:
            raise DistroError("no probe can run: no image of the probe table is pinned")
        if not requested:
            return list(self.probes)
        resolved: list[str] = []
        for name in requested:
            if name not in self.probes:
                known = ", ".join(self.probes)
                raise DistroError(f"unknown probe: {name} (probes: {known})")
            if name not in resolved:
                resolved.append(name)
        return resolved


def parse_distro_metadata(payload: object) -> DistroMetadata:
    """Build :class:`DistroMetadata` from the parsed JSON."""
    if not isinstance(payload, Mapping):
        raise DistroError("distro metadata must be a JSON object")
    try:
        raw_distros = payload["distros"]
        raw_scenarios = payload["scenarios"]
        raw_timeouts = payload["timeouts"]
    except KeyError as exc:
        raise DistroError(f"distro metadata is missing {exc.args[0]!r}") from None
    if not isinstance(raw_distros, Sequence) or isinstance(raw_distros, str):
        raise DistroError("distro metadata distros must be a list of names")
    if not isinstance(raw_scenarios, Mapping):
        raise DistroError("distro metadata scenarios must map a distro to its tests")
    if not isinstance(raw_timeouts, Mapping):
        raise DistroError("distro metadata timeouts must map a test to its seconds")
    distros = [str(name) for name in raw_distros]
    scenarios = {
        str(name): [str(scenario) for scenario in members]
        for name, members in raw_scenarios.items()
    }
    timeouts = {str(name): int(value) for name, value in raw_timeouts.items()}
    for distro in distros:
        if distro not in scenarios:
            raise DistroError(f"distro metadata has no scenarios for {distro}")
        for scenario in scenarios[distro]:
            if scenario not in timeouts:
                raise DistroError(f"distro metadata has no timeout for {scenario}")
    raw_probes = payload.get("probes", {})
    if not isinstance(raw_probes, Mapping):
        raise DistroError("distro metadata probes must map a probe to its attribute")
    probes = {str(name): str(attr) for name, attr in raw_probes.items()}
    for attr in probes.values():
        if attr not in timeouts:
            raise DistroError(f"distro metadata has no timeout for {attr}")
    return DistroMetadata(
        distros=distros, scenarios=scenarios, timeouts=timeouts, probes=probes
    )


def load_distro_metadata(attr: str = DISTRO_METADATA_ATTR) -> DistroMetadata:
    """Evaluate the flake's distro metadata with ``nix eval``.

    Raises :class:`DistroError` when Nix is missing or the evaluation fails, so
    the caller reports a clear message instead of a traceback.
    """
    try:
        completed = subprocess.run(
            ["nix", "eval", "--json", attr],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise DistroError(
            "nix is not on PATH; enter the flake dev shell first"
        ) from None
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or f"exit {exc.returncode}"
        raise DistroError(f"nix eval {attr} failed: {detail}") from None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DistroError(f"nix eval {attr} returned invalid JSON: {exc}") from None
    return parse_distro_metadata(payload)


def _shards_per_distro(distro_count: int, max_jobs: int) -> int:
    """How many shards each distribution may use under the job ceiling.

    Every distribution gets at least one shard; the budget left after one per
    distribution is spread evenly, so ``distros * shards`` never exceeds
    ``max_jobs``. With more distributions than the ceiling, planning still runs
    them one shard each -- the ceiling bounds parallelism, never coverage.
    """
    if distro_count < 1:
        return 1
    return max(1, max_jobs // distro_count)


def plan_distro_matrix(
    metadata: DistroMetadata,
    requested: Sequence[str] = (),
    *,
    max_jobs: int = MAX_DISTRO_JOBS,
) -> dict[str, list[dict[str, object]]]:
    """Return a GitHub matrix (``{"include": [...]}``) for the distro suite.

    One ``include`` entry is one job: a distribution, the shard index, and the
    scenario attribute names that shard builds. Scenarios are split with the
    same greedy longest-first allocator the NixOS suite uses, weighted by each
    scenario's timeout, so a distribution with several scenarios balances them.
    """
    if max_jobs < 1:
        raise ValueError("max_jobs must be at least 1")
    distros = metadata.resolve(requested)
    shard_cap = _shards_per_distro(len(distros), max_jobs)
    include: list[dict[str, object]] = []
    for distro in distros:
        scenarios = metadata.scenarios[distro]
        weights = {name: metadata.timeouts[name] for name in scenarios}
        count = max(1, min(shard_cap, len(scenarios)))
        split = plan.allocate(scenarios, weights or None, count)
        shards = [
            (shard, load)
            for shard, load in zip(split.shards, split.loads, strict=True)
            if shard
        ]
        for index, (shard, load) in enumerate(shards, start=1):
            include.append(
                {
                    "distro": distro,
                    "index": index,
                    "count": len(shards),
                    "tests": shard,
                    "timeout": plan.shard_timeout_minutes(load),
                }
            )
    return {"include": include}


def plan_probe_matrix(
    metadata: DistroMetadata, requested: Sequence[str] = ()
) -> dict[str, list[dict[str, object]]]:
    """Return a GitHub matrix (``{"include": [...]}``) for a probe run.

    A probe is a single host driver, so each is one job with one shard, in the
    same shape as a smoke job. ``seconds`` is the probe's own time limit, which
    the job puts on its driver; ``timeout`` is the job's, in minutes.
    """
    include: list[dict[str, object]] = []
    for name in metadata.resolve_probes(requested):
        attr = metadata.probes[name]
        seconds = metadata.timeouts[attr]
        include.append(
            {
                "distro": name,
                "index": 1,
                "count": 1,
                "tests": [attr],
                "timeout": plan.shard_timeout_minutes(seconds),
                "seconds": seconds,
            }
        )
    return {"include": include}
