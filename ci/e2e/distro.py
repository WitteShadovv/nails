"""Plan the portable distribution VM matrix.

The NixOS E2E suite (``plan.py``/``resolve.py``) shards one distribution's
tests on the NixOS test driver. The distro tier instead boots several Linux
distributions through ``numtide/nix-vm-test``, so a regression on a non-NixOS
host is caught instead of passing unseen. It has five suites:

- ``smoke``: the smoke scenarios of the admitted distributions, each a
  derivation that ``nix build`` runs in the Nix build sandbox;
- ``records``: the login- and boot-record scenarios, one per distribution that
  has one;
- ``refusal``: the refusal of each pinned image of a family the family table
  does not admit;
- ``probe``: the fact probes of the images not admitted yet whose image is
  pinned;
- ``staged``: the smoke and records scenarios of each image staged for its
  family's admission, run with a test-only build of NAILS that admits the
  family, before the commit that admits it.

A records scenario, a refusal and a probe are each a host driver, one job of
its own that builds the driver and runs it on the runner, outside the sandbox.
A staged scenario is a job of its own too, but a derivation that ``nix build``
runs in the sandbox, as a smoke scenario is. ``all`` plans the smoke, records
and refusal suites together, the default run; the probes boot no NAILS and the
staged scenarios are no gate of the admitted families, so both run only when
asked for. The records and refusal jobs gate (:data:`GATING_SUITES`): the
workflow fails its result on them, while a smoke, staged scenario or probe that
fails only warns.

The distro list is plain data the flake exposes as
``legacyPackages.<system>.e2e-distro-metadata``. Each distribution names its
smoke scenarios, so bringing another distribution online once its backend lands
is a single entry in ``nix/distro-tests/images.nix`` -- this module and the
workflow enumerate whatever the metadata reports. The smoke shards are bounded
so their number (distributions times their shards) never exceeds a ceiling,
because every job holds a dedicated KVM runner.
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

# At most this many smoke jobs run in parallel: distributions times the shards
# each is split into. One smoke scenario per distribution stays well under it;
# the cap only bites once several scenarios per distribution exist.
MAX_DISTRO_JOBS = 8

SMOKE = "smoke"
RECORDS = "records"
REFUSAL = "refusal"
PROBE = "probe"
STAGED = "staged"
# Every suite, in the order a plan lists their jobs.
SUITES = (SMOKE, RECORDS, REFUSAL, PROBE, STAGED)
# The name that selects ALL_SUITES.
ALL = "all"
# What ``all`` plans: every suite that runs NAILS.
ALL_SUITES = (SMOKE, RECORDS, REFUSAL)
# The suites whose failure fails the run, not only warns.
GATING_SUITES = frozenset({RECORDS, REFUSAL})

# How each driver suite names what it runs, for its error messages.
_DRIVER_NOUNS = {
    RECORDS: "records scenario",
    REFUSAL: "refusal",
    PROBE: "probe",
    STAGED: "staged scenario",
}
# Why a suite can have nothing to run.
_NOTHING_TO_RUN = {
    SMOKE: "no smoke scenario can run: the metadata lists none",
    RECORDS: "no records scenario can run: the metadata lists none",
    REFUSAL: (
        "no refusal can run: no image of a family the family table refuses is pinned"
    ),
    PROBE: "no probe can run: no image of the probe table is pinned",
    STAGED: "no staged scenario can run: no image is staged for its admission",
}


class DistroError(Exception):
    """The distro metadata could not be evaluated or is malformed."""


@dataclass(frozen=True)
class DistroMetadata:
    """The resolved distro-suite metadata.

    ``distros`` is every distribution name, in declaration order. ``scenarios``
    maps each distribution to its smoke scenario attribute names, and
    ``timeouts`` maps each scenario, and each driver attribute, to its effective
    timeout in seconds. ``probes`` maps each probe a run can boot to its
    attribute name, ``records`` each distribution with a records scenario to
    that scenario's attribute, ``refusals`` each image a refusal can boot to
    the refusal's attribute, and ``staged`` each staged scenario
    (``arch-boxes-smoke``) to its attribute.
    """

    distros: list[str]
    scenarios: dict[str, list[str]]
    timeouts: dict[str, int]
    probes: dict[str, str] = field(default_factory=dict)
    records: dict[str, str] = field(default_factory=dict)
    refusals: dict[str, str] = field(default_factory=dict)
    staged: dict[str, str] = field(default_factory=dict)

    def drivers(self, suite: str) -> dict[str, str]:
        """The jobs of a suite of one job per entry: each name to its attribute."""
        tables = {
            PROBE: self.probes,
            RECORDS: self.records,
            REFUSAL: self.refusals,
            STAGED: self.staged,
        }
        if suite not in tables:
            raise DistroError(f"{suite} is not a suite of host drivers")
        return tables[suite]

    def names(self, suite: str) -> list[str]:
        """What a suite can run: distributions, or the names of its drivers."""
        if suite == SMOKE:
            return list(self.distros)
        return list(self.drivers(suite))

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

    def resolve_drivers(self, suite: str, requested: Sequence[str]) -> list[str]:
        """Return the requested drivers of a suite, or all of them."""
        drivers = self.drivers(suite)
        if not drivers:
            raise DistroError(_NOTHING_TO_RUN[suite])
        if not requested:
            return list(drivers)
        resolved: list[str] = []
        for name in requested:
            if name not in drivers:
                known = ", ".join(drivers)
                noun = _DRIVER_NOUNS[suite]
                raise DistroError(f"unknown {noun}: {name} ({noun}s: {known})")
            if name not in resolved:
                resolved.append(name)
        return resolved

    def resolve_probes(self, requested: Sequence[str]) -> list[str]:
        """Return the requested probes, or every probe when none are named."""
        return self.resolve_drivers(PROBE, requested)


def _driver_table(payload: Mapping[str, object], key: str) -> dict[str, str]:
    """An optional table of drivers: a name to its attribute."""
    raw = payload.get(key, {})
    if not isinstance(raw, Mapping):
        raise DistroError(f"distro metadata {key} must map a name to its attribute")
    return {str(name): str(attr) for name, attr in raw.items()}


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
    tables = {
        key: _driver_table(payload, key)
        for key in ("probes", "records", "refusals", "staged")
    }
    for table in tables.values():
        for attr in table.values():
            if attr not in timeouts:
                raise DistroError(f"distro metadata has no timeout for {attr}")
    return DistroMetadata(
        distros=distros,
        scenarios=scenarios,
        timeouts=timeouts,
        probes=tables["probes"],
        records=tables["records"],
        refusals=tables["refusals"],
        staged=tables["staged"],
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


def expand_suites(names: Sequence[str]) -> list[str]:
    """The suites ``names`` select, ``all`` expanded, each once, in plan order."""
    selected: set[str] = set()
    for name in names:
        if name == ALL:
            selected.update(ALL_SUITES)
        elif name in SUITES:
            selected.add(name)
        else:
            known = ", ".join((ALL, *SUITES))
            raise DistroError(f"unknown suite: {name} (suites: {known})")
    if not selected:
        raise DistroError("no suite selected")
    return [suite for suite in SUITES if suite in selected]


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


def _smoke_jobs(
    metadata: DistroMetadata, distros: Sequence[str], max_jobs: int
) -> list[dict[str, object]]:
    """The smoke jobs of ``distros``: each distribution's scenarios in shards."""
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
                    "suite": SMOKE,
                    "gating": SMOKE in GATING_SUITES,
                    "distro": distro,
                    "index": index,
                    "count": len(shards),
                    "tests": shard,
                    "timeout": plan.shard_timeout_minutes(load),
                }
            )
    return include


def _driver_jobs(
    metadata: DistroMetadata, suite: str, names: Sequence[str]
) -> list[dict[str, object]]:
    """One job per driver of ``suite`` among ``names``, in the shape of a shard.

    ``seconds`` is the driver's own time limit, which the job puts on it;
    ``timeout`` is the job's, in minutes.
    """
    drivers = metadata.drivers(suite)
    include: list[dict[str, object]] = []
    for name in names:
        attr = drivers[name]
        seconds = metadata.timeouts[attr]
        include.append(
            {
                "suite": suite,
                "gating": suite in GATING_SUITES,
                "distro": name,
                "index": 1,
                "count": 1,
                "tests": [attr],
                "timeout": plan.shard_timeout_minutes(seconds),
                "seconds": seconds,
            }
        )
    return include


def plan_distro_matrix(
    metadata: DistroMetadata,
    requested: Sequence[str] = (),
    *,
    max_jobs: int = MAX_DISTRO_JOBS,
) -> dict[str, list[dict[str, object]]]:
    """Return a GitHub matrix (``{"include": [...]}``) for the smoke suite.

    One ``include`` entry is one job: a distribution, the shard index, and the
    scenario attribute names that shard builds. Scenarios are split with the
    same greedy longest-first allocator the NixOS suite uses, weighted by each
    scenario's timeout, so a distribution with several scenarios balances them.
    """
    if max_jobs < 1:
        raise ValueError("max_jobs must be at least 1")
    distros = metadata.resolve(requested)
    return {"include": _smoke_jobs(metadata, distros, max_jobs)}


def plan_driver_matrix(
    metadata: DistroMetadata, suite: str, requested: Sequence[str] = ()
) -> dict[str, list[dict[str, object]]]:
    """Return a GitHub matrix for one suite of host drivers, one job per driver.

    Every driver of the suite runs when none is named. A suite with no driver
    to run is an error, so a run that asked for it cannot pass on nothing.
    """
    names = metadata.resolve_drivers(suite, requested)
    return {"include": _driver_jobs(metadata, suite, names)}


def plan_probe_matrix(
    metadata: DistroMetadata, requested: Sequence[str] = ()
) -> dict[str, list[dict[str, object]]]:
    """Return a GitHub matrix (``{"include": [...]}``) for a probe run.

    A probe is a single host driver, so each is one job with one shard, in the
    same shape as a smoke job. ``seconds`` is the probe's own time limit, which
    the job puts on its driver; ``timeout`` is the job's, in minutes.
    """
    return plan_driver_matrix(metadata, PROBE, requested)


def plan_matrix(
    metadata: DistroMetadata,
    suites: Sequence[str],
    requested: Sequence[str] = (),
    *,
    max_jobs: int = MAX_DISTRO_JOBS,
) -> dict[str, list[dict[str, object]]]:
    """Return one GitHub matrix for the selected suites, in plan order.

    A suite selected alone plans as :func:`plan_distro_matrix` or
    :func:`plan_driver_matrix` do. With several, each runs what it has of the
    named entries (every one when none is named): ``debian-13`` names that
    distribution's smoke and records scenarios, ``fedora-44`` the refusal of
    that image. No suite may drop out of a run unseen, so that a gate cannot
    pass having run nothing: a name that no selected suite has is an error,
    and so are a suite with nothing to run when no name is given and a plan
    that holds no job. The change that empties a suite, such as admitting the
    last refused family, therefore takes the suite out of the run as well.
    Every entry carries its ``suite``, and in ``gating`` whether its failure
    fails the run. ``max_jobs`` bounds the smoke shards; each driver is a job
    of its own.
    """
    if max_jobs < 1:
        raise ValueError("max_jobs must be at least 1")
    selected = expand_suites(suites)
    if len(selected) == 1:
        (suite,) = selected
        if suite == SMOKE:
            matrix = plan_distro_matrix(metadata, requested, max_jobs=max_jobs)
        else:
            matrix = plan_driver_matrix(metadata, suite, requested)
        if not matrix["include"]:
            if not requested:
                raise DistroError(_NOTHING_TO_RUN[suite])
            raise DistroError(f"the plan holds no job: no {suite} entry can run")
        return matrix
    names = {suite: metadata.names(suite) for suite in selected}
    wanted: list[str] = []
    for name in requested:
        if not any(name in names[suite] for suite in selected):
            raise DistroError(
                f"unknown name: {name} (no {', '.join(selected)} entry has it)"
            )
        if name not in wanted:
            wanted.append(name)
    include: list[dict[str, object]] = []
    for suite in selected:
        chosen = (
            [name for name in wanted if name in names[suite]]
            if wanted
            else names[suite]
        )
        if suite == SMOKE:
            jobs = _smoke_jobs(metadata, chosen, max_jobs)
        else:
            jobs = _driver_jobs(metadata, suite, chosen)
        # Only the names asked for may leave a suite out.
        if not jobs and not wanted:
            raise DistroError(_NOTHING_TO_RUN[suite])
        include.extend(jobs)
    if not include:
        raise DistroError(
            f"the plan holds no job: no {', '.join(selected)} entry can run"
        )
    return {"include": include}
