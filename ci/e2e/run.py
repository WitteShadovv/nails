"""Run resolved E2E tests and record their outcomes and durations.

Two ways to run a set of tests:

* ``run_build`` builds every resolved attribute in one ``nix build
  --keep-going -L``, so VMs that do not share a dependency run in parallel,
  one failure does not abandon the rest, and a test that already passed with
  the same derivation is substituted from a binary cache instead of booting.
* ``run_drivers`` builds each test's ``.driver`` and executes it directly, so
  every test boots even when a cached result exists. The nightly run uses it
  to catch tests that only pass by being cached.

A test whose output is missing from the store after its build failed. Failed
tests can be retried; one that passes on a retry is a flaky pass, reported as
FLAKY rather than hidden. Durations are written as the same
``{"test","result","seconds"}`` JSON lines the weight tools read.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# nix activity type for a derivation build (`Logger::Fields`, actBuild).
ACT_BUILD = 105
_NIX_PREFIX = "@nix "
DEFAULT_ATTR_PREFIX = ".#legacyPackages.x86_64-linux.e2e"
# Extra time a directly executed driver gets beyond its own globalTimeout, so
# the driver reports the timeout itself before it is killed.
DRIVER_GRACE_SECONDS = 120
# Lines of a failed driver's log repeated on stderr, so the cause shows in the
# job log without downloading the artifact.
LOG_TAIL_LINES = 60
# A directly executed driver's scratch directory is this prefix plus the eight
# random characters of mkdtemp, in RUNNER_TEMP or else the temporary directory.
SCRATCH_PREFIX = "e2e-"
# A Unix socket path holds at most this many bytes (sun_path, without its
# terminating NUL).
SOCKET_PATH_MAX = 107
# The longest socket below the scratch directory is virtiofsd's, which nixpkgs'
# qemu-vm.nix puts at vm-state-<node>/tmp.XXXXXXXXXX/<share>, nix-store being
# the longest share name. The reserve fits the suite's longest node name,
# notify_send. ci/tests/test_e2e_run.py fails on a longer one, and on a test's
# own share or TPM, whose sockets this budget does not count.
NODE_NAME_RESERVE = 11
SOCKET_TAIL_BYTES = (
    len(f"/{SCRATCH_PREFIX}XXXXXXXX/vm-state-")
    + NODE_NAME_RESERVE
    + len("/tmp.XXXXXXXXXX/nix-store")
)
# virtiofsd asks for 1,000,000 open files and settles for the hard limit it
# inherits. Unprivileged, it holds a descriptor for every file the guest has
# looked up, about 150,000 in a test that copies a whole NixOS closure through
# the host store: the 65,536 of a GitHub job run out, and systemd's default
# hard limit, 524,288, leaves room.
MIN_HARD_OPEN_FILES = 524_288


class RunError(Exception):
    """This host cannot run the drivers as asked."""


@dataclass
class TestOutcome:
    result: str
    seconds: int
    flaky: bool = False


def _drv_from_fields(payload: Mapping[str, object]) -> str | None:
    fields = payload.get("fields")
    if isinstance(fields, list) and fields and isinstance(fields[0], str):
        candidate = fields[0]
        if candidate.endswith(".drv"):
            return candidate
    text = payload.get("text")
    if isinstance(text, str):
        start = text.find("/nix/store/")
        end = text.find(".drv", start)
        if start != -1 and end != -1:
            return text[start : end + len(".drv")]
    return None


def durations_from_internal_json(
    lines: Iterable[str],
    drv_to_test: Mapping[str, str],
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, TestOutcome]:
    """Derive each test's outcome from a ``--log-format internal-json`` stream.

    A test that starts and stops a build is a timed ``pass``; one that starts
    without stopping (killed or failed build) is a ``fail``; a test with no
    build activity was served from the store and is a zero-second ``pass``.
    Nix also stops the activity of a failed build, so the caller corrects the
    result from the store afterwards (see ``missing_outputs``).
    """
    started: dict[int, tuple[str, float]] = {}
    outcomes: dict[str, TestOutcome] = {}
    for line in lines:
        if not line.startswith(_NIX_PREFIX):
            continue
        try:
            payload = json.loads(line[len(_NIX_PREFIX) :])
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        action = payload.get("action")
        if action == "start" and payload.get("type") == ACT_BUILD:
            drv = _drv_from_fields(payload)
            test = drv_to_test.get(drv) if drv is not None else None
            activity_id = payload.get("id")
            if test is not None and isinstance(activity_id, int):
                started[activity_id] = (test, clock())
        elif action == "stop":
            activity_id = payload.get("id")
            if isinstance(activity_id, int) and activity_id in started:
                test, start_time = started.pop(activity_id)
                outcomes[test] = TestOutcome("pass", round(clock() - start_time))
    for test, _start in started.values():
        outcomes.setdefault(test, TestOutcome("fail", 0))
    return outcomes


def _progress_line(line: str) -> str | None:
    """Return the human-readable text of a nix error or warning message."""
    if not line.startswith(_NIX_PREFIX):
        return None
    try:
        payload = json.loads(line[len(_NIX_PREFIX) :])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or payload.get("action") != "msg":
        return None
    level = payload.get("level")
    message = payload.get("msg")
    # Levels 0 and 1 are errors and warnings; the rest is chatter that the
    # failure logs hold anyway.
    if isinstance(level, int) and level <= 1 and isinstance(message, str):
        return message
    return None


def write_durations(
    path: Path, tests: Sequence[str], outcomes: Mapping[str, TestOutcome]
) -> None:
    """Write one JSON line per resolved test, in run order.

    A test with no recorded outcome was served from the Nix store, so it counts
    as a zero-second pass rather than being dropped. A flaky pass carries
    ``"flaky": true`` next to the duration of the passing attempt.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for test in tests:
            outcome = outcomes.get(test, TestOutcome("pass", 0))
            record: dict[str, object] = {
                "test": test,
                "result": outcome.result,
                "seconds": outcome.seconds,
            }
            if outcome.flaky:
                record["flaky"] = True
            handle.write(json.dumps(record) + "\n")


def _eval_drv(attr: str) -> str:
    return subprocess.run(
        ["nix", "eval", "--raw", f"{attr}.drvPath"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _eval_batch(attr_prefix: str, tests: Sequence[str]) -> dict[str, str]:
    """Evaluate the derivation paths of ``tests`` in one ``nix eval`` process."""
    names = " ".join(json.dumps(test) for test in tests)
    apply = (
        "e: builtins.listToAttrs (map (n: { name = n; value = e.${n}.drvPath; }) "
        f"[ {names} ])"
    )
    completed = subprocess.run(
        ["nix", "eval", "--json", attr_prefix, "--apply", apply],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    return {test: str(payload[test]) for test in tests}


def eval_drvs(
    tests: Sequence[str], attr_prefix: str, batch_size: int | None
) -> dict[str, str]:
    """Map each test to its ``.drv`` path, evaluating in bounded batches.

    Every test evaluates its own NixOS system, and the Nix evaluator keeps all
    of that memory until it exits, so evaluating a whole group in the process
    that builds it is what ran a 15 GB host out of memory. Each batch runs in
    its own short-lived ``nix eval``, so peak evaluation memory is that of
    ``batch_size`` tests; ``None`` evaluates every test in a process of its
    own (the slowest and leanest setting).
    """
    if batch_size is None:
        return {test: _eval_drv(f"{attr_prefix}.{test}") for test in tests}
    drvs: dict[str, str] = {}
    for start in range(0, len(tests), batch_size):
        drvs.update(_eval_batch(attr_prefix, tests[start : start + batch_size]))
    return drvs


# Host memory one running test can take: a 2 GiB guest (4 GiB for the
# graphical profile, which the reserve absorbs), QEMU and the driver, and the
# raw disk images the forensic tests write into the build directory. Measured
# with virtiofs and the guest RAM in a shared memfd over a full run of the
# suite, a test with a 2 GiB guest peaked at 2.2 GiB.
GIB_PER_TEST = 3.5
# Host memory kept free for the Nix daemon, the desktop and the page cache.
RESERVED_GIB = 3.0


def auto_jobs(meminfo: Path = Path("/proc/meminfo"), cpus: int | None = None) -> int:
    """How many VM tests fit on this host at once, from its RAM and cores.

    Every VM gets two cores, so at most one test per two host cores, and at
    most as many tests as fit in RAM next to the reserve. A 15 GiB, 12-core
    host gets 3.
    """
    total_kib = 0
    try:
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                total_kib = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        total_kib = 0
    by_memory = int((total_kib / (1024 * 1024) - RESERVED_GIB) // GIB_PER_TEST)
    cores = cpus if cpus is not None else (os.cpu_count() or 2)
    return max(1, min(cores // 2, by_memory))


def missing_outputs(drv_to_test: Mapping[str, str]) -> list[str]:
    """Return the tests whose outputs are not valid store paths, in order.

    A VM test produces its output only when its script passed, so a missing
    output is a failed (or never started) test, whatever the log said.
    """
    outputs: dict[str, list[str]] = {}
    for drv, test in drv_to_test.items():
        listed = subprocess.run(
            ["nix-store", "--query", "--outputs", drv],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        outputs[test] = listed
    paths = [path for listed in outputs.values() for path in listed]
    if not paths:
        return list(outputs)
    invalid = set(
        subprocess.run(
            ["nix-store", "--check-validity", "--print-invalid", *paths],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
    )
    return [
        test
        for test, listed in outputs.items()
        if not listed or any(path in invalid for path in listed)
    ]


def _build_once(
    tests: Sequence[str],
    drv_to_test: Mapping[str, str],
    jobs: int | None,
    clock: Callable[[], float],
) -> tuple[int, dict[str, TestOutcome]]:
    # Build by derivation path, not by flake attribute: the paths were already
    # evaluated in bounded batches, so this nix process evaluates nothing and
    # its memory stays small however many tests it runs.
    wanted = {drv: test for drv, test in drv_to_test.items() if test in tests}
    command = ["nix", "build", "--keep-going", "-L", "--log-format", "internal-json"]
    if jobs is not None:
        command += ["--max-jobs", str(jobs)]
    command += ["--no-link", *(f"{drv}^*" for drv in wanted)]

    lines: list[str] = []
    with subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        assert process.stderr is not None
        for raw in process.stderr:
            line = raw.rstrip("\n")
            lines.append(line)
            message = _progress_line(line)
            if message is not None:
                print(message, file=sys.stderr)
        status = process.wait()
    return status, durations_from_internal_json(lines, wanted, clock)


def _write_nix_log(drv: str, path: Path) -> None:
    completed = subprocess.run(
        ["nix", "log", drv], capture_output=True, text=True, check=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(completed.stdout or completed.stderr, encoding="utf-8")


def run_build(
    tests: Sequence[str],
    attr_prefix: str = DEFAULT_ATTR_PREFIX,
    jobs: int | None = None,
    durations_out: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
    retries: int = 0,
    log_dir: Path | None = None,
    report: Callable[[Sequence[str], Mapping[str, TestOutcome]], None] | None = None,
    eval_batch: int | None = None,
) -> int:
    """Build every resolved test in one ``nix build`` and record outcomes.

    The derivations are evaluated first, ``eval_batch`` tests per ``nix eval``
    process (see :func:`eval_drvs`), and then built by path with at most
    ``jobs`` VM tests at a time.

    Failed tests are rebuilt up to ``retries`` more times (Nix does not cache a
    failure); a test that passes on a retry is a flaky pass. Returns 0 when
    every test passed, 1 when a test still fails, and the ``nix build`` status
    when the build failed without a failed test to blame (an evaluation
    error, for example), which is never retried. Nix is required; this is
    reached only through the ``run`` subcommand.
    """
    if not tests:
        return 0
    test_to_drv = eval_drvs(tests, attr_prefix, eval_batch)
    drv_to_test = {drv: test for test, drv in test_to_drv.items()}

    status, outcomes = _build_once(tests, drv_to_test, jobs, clock)
    failed: list[str] = []
    if status != 0:
        failed = missing_outputs(drv_to_test)
        for test in failed:
            seconds = outcomes.get(test, TestOutcome("fail", 0)).seconds
            outcomes[test] = TestOutcome("fail", seconds)

    for _attempt in range(retries):
        if not failed:
            break
        print(
            f"retrying {len(failed)} failed test(s): {' '.join(failed)}",
            file=sys.stderr,
        )
        retry_map = {test_to_drv[test]: test for test in failed}
        _status, retried = _build_once(failed, retry_map, jobs, clock)
        still_failed = set(missing_outputs(retry_map))
        for test in failed:
            if test not in still_failed:
                seconds = retried.get(test, TestOutcome("pass", 0)).seconds
                outcomes[test] = TestOutcome("pass", seconds, flaky=True)
        failed = [test for test in failed if test in still_failed]

    log_paths: dict[str, str] = {}
    for test in failed:
        if log_dir is not None:
            path = log_dir / f"{test}.log"
            _write_nix_log(test_to_drv[test], path)
            log_paths[test] = str(path)
        else:
            log_paths[test] = f"nix log {test_to_drv[test]}"
    if durations_out is not None:
        write_durations(durations_out, tests, outcomes)
    print(format_console_summary(tests, outcomes, log_paths), file=sys.stderr)
    if report is not None:
        report(tests, outcomes)
    if status != 0 and not failed and not any(o.flaky for o in outcomes.values()):
        # The build failed, yet every test output exists: nothing to retry and
        # nothing to blame, so pass the original status on.
        return status
    return 1 if failed else 0


def _tail(path: Path, count: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-count:])


def _build_driver(attr: str) -> Path:
    completed = subprocess.run(
        ["nix", "build", "--no-link", "--print-out-paths", f"{attr}.driver"],
        check=True,
        capture_output=True,
        text=True,
    )
    return Path(completed.stdout.split()[-1])


def scratch_base(environ: Mapping[str, str] = os.environ) -> Path:
    """The directory that holds the scratch directory of every driver.

    In a GitHub job that is RUNNER_TEMP, which a hosted runner keeps on its
    root disk; elsewhere the temporary directory (TMPDIR, or /tmp without one).
    """
    return Path(os.path.abspath(environ.get("RUNNER_TEMP") or tempfile.gettempdir()))


def check_scratch_base(base: Path) -> None:
    """Refuse a base too long for the drivers' sockets, or not a directory."""
    longest = len(os.fsencode(base)) + SOCKET_TAIL_BYTES
    if longest > SOCKET_PATH_MAX:
        raise RunError(
            f"{base} is too long for the drivers' scratch directories: the "
            f"longest Unix socket below it would take {longest} bytes, and a "
            f"socket path holds at most {SOCKET_PATH_MAX}. In a GitHub job "
            "RUNNER_TEMP follows the runner's work folder (config.sh --work); "
            "for a local run, set RUNNER_TEMP or TMPDIR to a directory whose "
            f"path has at most {SOCKET_PATH_MAX - SOCKET_TAIL_BYTES} bytes."
        )
    if not base.is_dir():
        raise RunError(
            f"{base} is not a directory, so it cannot hold the drivers' scratch "
            "directories. Create it, or point RUNNER_TEMP at one that exists."
        )


def open_file_warning(hard_limit: int) -> str | None:
    """Explain why a hard open-file limit is too low for virtiofsd, or None."""
    if hard_limit == resource.RLIM_INFINITY or hard_limit >= MIN_HARD_OPEN_FILES:
        return None
    return (
        f"the hard open-file limit is {hard_limit}, below {MIN_HARD_OPEN_FILES}. "
        "virtiofsd inherits it and can run out of descriptors in the tests that "
        "copy a whole NixOS closure through the host store; raise it in the "
        "calling shell first, for example with "
        "'sudo prlimit --pid $$ --nofile=1048576:1048576'"
    )


def _execute_driver(
    driver: Path,
    timeout: int,
    log_path: Path,
    clock: Callable[[], float],
    base: Path,
) -> TestOutcome:
    """Run one driver in a scratch directory of its own and time it.

    The driver keeps every machine's state (its disks, the Nix store image and
    the sockets of QEMU and virtiofsd) and the VLAN sockets in XDG_RUNTIME_DIR,
    falling back to TMPDIR, which is the build directory inside a Nix build.
    On a hosted runner XDG_RUNTIME_DIR is a small tmpfs in RAM, so both name
    the scratch directory on disk, and removing it after the test removes the
    VM state too. Its name is short, so that the sockets below it stay within
    SOCKET_PATH_MAX.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=base))
    env = {**os.environ, "TMPDIR": str(scratch), "XDG_RUNTIME_DIR": str(scratch)}
    start = clock()
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                [str(driver / "bin" / "nixos-test-driver")],
                cwd=scratch,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout + DRIVER_GRACE_SECONDS,
                check=False,
            )
        result = "pass" if completed.returncode == 0 else "fail"
    except subprocess.TimeoutExpired:
        result = "fail"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return TestOutcome(result, round(clock() - start))


def run_drivers(
    tests: Sequence[str],
    timeouts: Mapping[str, int],
    attr_prefix: str = DEFAULT_ATTR_PREFIX,
    durations_out: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
    retries: int = 0,
    log_dir: Path | None = None,
    report: Callable[[Sequence[str], Mapping[str, TestOutcome]], None] | None = None,
) -> int:
    """Execute every test's driver one after another, ignoring cached results.

    Logs of failed tests stay in ``log_dir`` (passing logs are removed); the
    retry and flaky rules match ``run_build``. Returns 0 when every test
    passed and 1 otherwise. Before any driver is built, a scratch base that
    is too long for the drivers' sockets, or not a directory, raises RunError,
    and a hard open-file limit too low for virtiofsd prints a warning.
    """
    if not tests:
        return 0
    base = scratch_base()
    check_scratch_base(base)
    warning = open_file_warning(resource.getrlimit(resource.RLIMIT_NOFILE)[1])
    if warning is not None:
        print(f"warning: {warning}", file=sys.stderr)
    keep_logs = log_dir is not None
    logs = log_dir if log_dir is not None else Path(tempfile.mkdtemp(prefix="e2e-"))
    drivers = {test: _build_driver(f"{attr_prefix}.{test}") for test in tests}
    outcomes: dict[str, TestOutcome] = {}
    for attempt in range(retries + 1):
        pending = [
            test
            for test in tests
            if test not in outcomes or outcomes[test].result == "fail"
        ]
        if not pending:
            break
        if attempt:
            print(
                f"retrying {len(pending)} failed test(s): {' '.join(pending)}",
                file=sys.stderr,
            )
        for test in pending:
            print(f"running {test}", file=sys.stderr)
            log_path = logs / f"{test}.log"
            outcome = _execute_driver(
                drivers[test], timeouts.get(test, 900), log_path, clock, base
            )
            if outcome.result == "pass":
                outcome.flaky = attempt > 0
                log_path.unlink(missing_ok=True)
            else:
                print(_tail(log_path, LOG_TAIL_LINES), file=sys.stderr)
            print(f"{test}: {outcome.result} in {outcome.seconds}s", file=sys.stderr)
            outcomes[test] = outcome
    if not keep_logs:
        shutil.rmtree(logs, ignore_errors=True)
    if durations_out is not None:
        write_durations(durations_out, tests, outcomes)
    if report is not None:
        report(tests, outcomes)
    return 1 if any(o.result == "fail" for o in outcomes.values()) else 0


def _label(outcome: TestOutcome) -> str:
    if outcome.result == "fail":
        return "FAIL"
    if outcome.flaky:
        return "FLAKY (passed on retry)"
    return "pass"


def format_console_summary(
    tests: Sequence[str],
    outcomes: Mapping[str, TestOutcome],
    logs: Mapping[str, str],
) -> str:
    """One line per test for the terminal, each failure with its log.

    A test with no recorded outcome was served from the store; it is listed as
    ``cached`` so a reader can tell it apart from a test that booted.
    """
    lines = []
    for test in tests:
        outcome = outcomes.get(test)
        if outcome is None:
            label, seconds = "cached", "-"
        else:
            label, seconds = _label(outcome), f"{outcome.seconds}s"
        line = f"{label:<24} {seconds:>6}  {test}"
        if test in logs:
            line += f"  log: {logs[test]}"
        lines.append(line)
    failed = sum(1 for o in outcomes.values() if o.result == "fail")
    lines.append(f"{len(tests)} test(s), {failed} failed")
    return "\n".join(lines)


def format_summary(
    heading: str, tests: Sequence[str], outcomes: Mapping[str, TestOutcome]
) -> str:
    """Markdown table of every test's result, failures and flaky passes first."""
    rows = [(test, outcomes.get(test, TestOutcome("pass", 0))) for test in tests]
    rows.sort(key=lambda row: (row[1].result != "fail", not row[1].flaky))
    failed = sum(1 for _test, outcome in rows if outcome.result == "fail")
    flaky = sum(1 for _test, outcome in rows if outcome.flaky)
    lines = [
        f"## {heading}",
        "",
        f"{len(rows)} test(s): {len(rows) - failed} passed ({flaky} FLAKY), "
        f"{failed} failed.",
        "",
        "| Test | Result | Seconds |",
        "|---|---|---:|",
    ]
    lines += [
        f"| `{test}` | {_label(outcome)} | {outcome.seconds} |"
        for test, outcome in rows
    ]
    return "\n".join(lines) + "\n\n"


def format_annotations(
    tests: Sequence[str], outcomes: Mapping[str, TestOutcome]
) -> list[str]:
    """GitHub workflow commands that flag each failed and flaky test."""
    annotations = []
    for test in tests:
        outcome = outcomes.get(test)
        if outcome is None:
            continue
        if outcome.result == "fail":
            annotations.append(f"::error title=E2E test failed::{test} failed")
        elif outcome.flaky:
            annotations.append(
                f"::warning title=FLAKY E2E test::{test} failed, then passed on retry"
            )
    return annotations
