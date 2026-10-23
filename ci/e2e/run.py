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
FLAKY rather than hidden. A run that must boot every test (``require_boot``)
fails a test that was not built in it, because the store or a binary cache
already held its output, rather than count an earlier run's pass. Durations
are written as the same ``{"test","result","seconds"}`` JSON lines the weight
tools read.

Either way can run under a :class:`TimeLimit`, as a CI shard does: one attempt
of a test runs at most a share of the run's time, so a test that hangs is
stopped by name, its driver and VMs with it, and its log kept; and the run
itself ends before the CI job would be cancelled, stopping whatever still
runs, so the job can still upload the logs instead of losing them all.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from . import evaluate

# nix activity type for a derivation build (`Logger::Fields`, actBuild).
ACT_BUILD = 105
# nix result type of one line a build logged (resBuildLogLine).
RES_BUILD_LOG_LINE = 101
_NIX_PREFIX = "@nix "
DEFAULT_ATTR_PREFIX = ".#legacyPackages.x86_64-linux.e2e"
# Extra time a directly executed driver gets beyond its own globalTimeout, so
# the driver reports the timeout itself before it is killed.
DRIVER_GRACE_SECONDS = 120
# Of a CI job's timeout, the minutes kept for the steps around the run:
# checking out and setting up Nix before it, and after it the drift report and
# the upload of the durations and of the logs of failed tests.
JOB_RESERVE_MINUTES = 5
# No test starts or is retried with less than this left before the run's time
# limit: a VM test could not boot and finish in it.
MIN_TEST_SECONDS = 60
# A failed test that ran at least its timeout less this had run out of time.
TIMEOUT_SLACK_SECONDS = 5
# How long a stopped nix build or driver gets to exit before it is killed.
STOP_GRACE_SECONDS = 30
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
    # A failure only because the test did not boot in a run that requires it:
    # the store or a binary cache already held its output.
    not_booted: bool = False
    # The test ran out of time, its own or its share of the run's, and was
    # stopped.
    timed_out: bool = False
    # The run reached its time limit before the test could start.
    not_run: bool = False


@dataclass(frozen=True)
class TimeLimit:
    """How long a run may take, and one attempt of one test in it.

    ``deadline`` is a :func:`time.monotonic` reading: there the run stops what
    still runs, starts nothing more and reports. ``test_seconds`` bounds one
    attempt of one test.
    """

    deadline: float
    test_seconds: int

    def left(self) -> float:
        """Seconds until the deadline, never below zero."""
        return max(0.0, self.deadline - time.monotonic())

    def for_test(self) -> int:
        """The most one attempt of a test started now may take."""
        return max(1, min(self.test_seconds, int(self.left())))


def job_time_limit(job_minutes: int, retries: int) -> TimeLimit:
    """The time limit of a run in a CI job whose timeout is ``job_minutes``.

    The run ends JOB_RESERVE_MINUTES before the job would be cancelled, so it
    still reports the tests it stopped and the job still uploads their logs.
    One attempt of a test gets an equal share of the rest per attempt, half of
    it with one retry, so a test that hangs is stopped well inside the job and
    its retry can follow.
    """
    seconds = (job_minutes - JOB_RESERVE_MINUTES) * 60
    if seconds < MIN_TEST_SECONDS:
        raise RunError(
            f"a {job_minutes}-minute job leaves no time to run a test: "
            f"{JOB_RESERVE_MINUTES} minutes are kept for the steps around the run"
        )
    return TimeLimit(time.monotonic() + seconds, seconds // (retries + 1))


def ran_out(seconds: int, timeout: int | None) -> bool:
    """Whether a failed test that ran ``seconds`` failed by its ``timeout``."""
    return timeout is not None and seconds + TIMEOUT_SLACK_SECONDS >= timeout


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


class BuildWatch:
    """Follow the ``--log-format internal-json`` stream of a ``nix build``.

    A test that starts and stops a build is a timed ``pass``; one that starts
    without stopping (killed or failed build) is a ``fail``; a test with no
    build activity was served from the store and gets no outcome here. Nix also
    stops the activity of a failed build, so the caller corrects the result
    from the store afterwards (see ``missing_outputs``).

    The lines carry no time of their own: ``clock`` is read as each start and
    stop line is fed. Feed the live stream of a running ``nix build``, never
    lines collected after it exited, in which every build would take the same
    instant and last zero seconds.

    With ``logs``, each line a test's build logs goes to ``<logs>/<test>.log``
    as it arrives, so a test stopped part way keeps its log so far. With
    ``progress``, a line there says when each test starts and stops, and nix's
    errors and warnings are copied there, so a job log shows what ran and what
    never ended even when the job itself is cut short.
    """

    def __init__(
        self,
        drv_to_test: Mapping[str, str],
        clock: Callable[[], float] = time.monotonic,
        logs: Path | None = None,
        progress: TextIO | None = None,
    ) -> None:
        self.outcomes: dict[str, TestOutcome] = {}
        self._drv_to_test = drv_to_test
        self._clock = clock
        self._logs = logs
        self._progress = progress
        self._started: dict[int, tuple[str, float]] = {}
        self._files: dict[int, TextIO] = {}

    def feed(self, line: str) -> None:
        if not line.startswith(_NIX_PREFIX):
            return
        try:
            payload = json.loads(line[len(_NIX_PREFIX) :])
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        action = payload.get("action")
        activity = payload.get("id")
        if action == "msg":
            self._relay(payload)
        elif not isinstance(activity, int):
            return
        elif action == "start" and payload.get("type") == ACT_BUILD:
            self._start(activity, payload)
        elif action == "result" and payload.get("type") == RES_BUILD_LOG_LINE:
            handle = self._files.get(activity)
            fields = payload.get("fields")
            if handle is not None and isinstance(fields, list) and fields:
                handle.write(f"{fields[0]}\n")
        elif action == "stop" and activity in self._started:
            test, start = self._started.pop(activity)
            seconds = round(self._clock() - start)
            self.outcomes[test] = TestOutcome("pass", seconds)
            self._close(activity)
            self._say(f"{test}: finished after {seconds}s")

    def finish(self) -> set[str]:
        """End the stream: each build that never stopped is a failure.

        Returns those tests, timed up to now.
        """
        unfinished: set[str] = set()
        now = self._clock() if self._started else 0.0
        for activity, (test, start) in self._started.items():
            self.outcomes.setdefault(test, TestOutcome("fail", round(now - start)))
            unfinished.add(test)
            self._close(activity)
        self._started.clear()
        return unfinished

    def _start(self, activity: int, payload: Mapping[str, object]) -> None:
        drv = _drv_from_fields(payload)
        test = self._drv_to_test.get(drv) if drv is not None else None
        if test is None:
            return
        self._started[activity] = (test, self._clock())
        if self._logs is not None:
            path = self._logs / f"{test}.log"
            # Line-buffered, so the log is on disk however the run ends.
            self._files[activity] = path.open("w", encoding="utf-8", buffering=1)
        self._say(f"{test}: started")

    def _close(self, activity: int) -> None:
        handle = self._files.pop(activity, None)
        if handle is not None:
            handle.close()

    def _relay(self, payload: Mapping[str, object]) -> None:
        level = payload.get("level")
        message = payload.get("msg")
        # Levels 0 and 1 are errors and warnings; the rest is chatter that the
        # failure logs hold anyway.
        if isinstance(level, int) and level <= 1 and isinstance(message, str):
            self._say(message)

    def _say(self, text: str) -> None:
        if self._progress is not None:
            print(text, file=self._progress, flush=True)


def durations_from_internal_json(
    lines: Iterable[str],
    drv_to_test: Mapping[str, str],
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, TestOutcome]:
    """Each test's outcome in a ``--log-format internal-json`` stream.

    See :class:`BuildWatch`, which this feeds every line and finishes.
    """
    watch = BuildWatch(drv_to_test, clock)
    for line in lines:
        watch.feed(line)
    watch.finish()
    return watch.outcomes


def write_durations(
    path: Path, tests: Sequence[str], outcomes: Mapping[str, TestOutcome]
) -> None:
    """Write one JSON line per resolved test, in run order.

    A test with no recorded outcome was served from the Nix store, so it counts
    as a zero-second pass rather than being dropped. A flaky pass carries
    ``"flaky": true`` next to the duration of the passing attempt, a test that
    failed only because it did not boot carries ``"not_booted": true``, one
    stopped for running out of time ``"timed_out": true``, and one the run's
    time limit kept from starting ``"not_run": true``.
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
            for flag in ("flaky", "not_booted", "timed_out", "not_run"):
                if getattr(outcome, flag):
                    record[flag] = True
            handle.write(json.dumps(record) + "\n")


def eval_drvs(
    tests: Sequence[str],
    attr_prefix: str,
    batch_size: int | None,
    workers: int | None = None,
) -> dict[str, str]:
    """Map each test to its ``.drv`` path, evaluating in parallel batches.

    ``batch_size`` tests go to one ``nix eval`` process, and at most
    ``workers`` processes run at once (by default as many as the host's cores
    and memory allow); without ``batch_size`` the tests are spread evenly
    over the processes. See :mod:`ci.e2e.evaluate`.
    """
    paths = evaluate.evaluate(
        attr_prefix,
        tests,
        "t: t.drvPath",
        workers=workers or evaluate.auto_workers(),
        batch_size=batch_size,
    )
    return {test: str(drv) for test, drv in paths.items()}


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


@dataclass
class _Attempt:
    """One ``nix build`` of a set of tests."""

    status: int
    # The tests whose build started, timed (see BuildWatch).
    outcomes: dict[str, TestOutcome]
    # Started and still building when the stream ended.
    unfinished: set[str] = field(default_factory=set)
    # The run's time limit stopped the build.
    stopped: bool = False
    # The most any one build could run (nix --timeout), if bounded.
    timeout: int | None = None


def _build_once(
    tests: Sequence[str],
    drv_to_test: Mapping[str, str],
    jobs: int | None,
    clock: Callable[[], float],
    logs: Path | None = None,
    limit: TimeLimit | None = None,
) -> _Attempt:
    # Build by derivation path, not by flake attribute: the paths were already
    # evaluated in bounded batches, so this nix process evaluates nothing and
    # its memory stays small however many tests it runs.
    wanted = {drv: test for drv, test in drv_to_test.items() if test in tests}
    command = ["nix", "build", "--keep-going", "-L", "--log-format", "internal-json"]
    if jobs is not None:
        command += ["--max-jobs", str(jobs)]
    timeout = None
    if limit is not None:
        # nix stops any build that runs longer, a test's or another, and fails
        # it: the test's share of the run, or what is left of the run.
        timeout = limit.for_test()
        command += ["--timeout", str(timeout)]
    command += ["--no-link", *(f"{drv}^*" for drv in wanted)]

    watch = BuildWatch(wanted, clock, logs, sys.stderr)
    stopped = threading.Event()
    with subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    ) as process:
        assert process.stderr is not None
        timer = None
        if limit is not None:
            timer = threading.Timer(limit.left(), _stop_build, (process, stopped))
            timer.daemon = True
            timer.start()
        try:
            # Parsed while nix runs, so each build is timed as its start and
            # stop lines arrive.
            for raw in process.stderr:
                watch.feed(raw.rstrip("\n"))
            status = process.wait()
        finally:
            if timer is not None:
                timer.cancel()
            unfinished = watch.finish()
    return _Attempt(status, watch.outcomes, unfinished, stopped.is_set(), timeout)


def _stop_build(process: subprocess.Popen[str], stopped: threading.Event) -> None:
    """Stop a nix build at the run's time limit, as Ctrl+C would.

    Interrupted, nix ends its builds and exits; one that lingers is killed,
    which the daemon also takes as the end of the builds it ran for it.
    """
    if process.poll() is not None:
        return
    stopped.set()
    print("the run reached its time limit: stopping the build", file=sys.stderr)
    process.send_signal(signal.SIGINT)
    deadline = time.monotonic() + STOP_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.5)
    if process.poll() is None:
        process.kill()


def _failure(
    test: str, attempt: _Attempt, timeouts: Mapping[str, int] | None
) -> TestOutcome:
    """The outcome of a test whose output ``attempt`` left missing.

    A test that never started failed with a dependency, or, when the time limit
    stopped the build, was not run. One still running when it was stopped timed
    out, and so did one that ran into its own timeout or nix's.
    """
    built = attempt.outcomes.get(test)
    if built is None:
        return TestOutcome("fail", 0, not_run=attempt.stopped)
    limits = [t for t in ((timeouts or {}).get(test), attempt.timeout) if t]
    timed_out = (attempt.stopped and test in attempt.unfinished) or ran_out(
        built.seconds, min(limits, default=None)
    )
    return TestOutcome("fail", built.seconds, timed_out=timed_out)


def _has_text(path: Path) -> bool:
    try:
        return path.stat().st_size > 0
    except OSError:
        return False


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
    eval_workers: int | None = None,
    require_boot: bool = False,
    timeouts: Mapping[str, int] | None = None,
    limit: TimeLimit | None = None,
) -> int:
    """Build every resolved test in one ``nix build`` and record outcomes.

    The derivations are evaluated first, ``eval_batch`` tests per ``nix eval``
    process and ``eval_workers`` processes at once (see :func:`eval_drvs`),
    and then built by path with at most ``jobs`` VM tests at a time. Each
    test's build log is kept as it runs, and a line on stderr says when each
    test starts and finishes.

    Failed tests are rebuilt up to ``retries`` more times (Nix does not cache a
    failure); a test that passes on a retry is a flaky pass. With
    ``require_boot``, a test that passed without being built, because the
    store or a binary cache already held its output, fails as not booted, so
    that a runner whose own Nix settings or store hold an earlier run's pass
    cannot pass it off as this run's.

    With a ``limit``, nix stops any build that runs longer than one test's
    share of it, and the build is stopped when the run reaches its deadline: a
    test still running then timed out, one that had not started was not run,
    and no retry starts with less than MIN_TEST_SECONDS left. ``timeouts``
    (each test's own, from the metadata) tell a test that its driver stopped
    for running out of time from one that failed. The log of every failed test
    is kept in ``log_dir``, and the tail of a timed-out test's is printed.

    Returns 0 when every test passed, 1 when a test still fails, timed out,
    was not run or did not boot, and the ``nix build`` status when the build
    failed without a failed test to blame (an evaluation error, for example),
    which is never retried. Nix is required; this is reached only through the
    ``run`` subcommand.
    """
    if not tests:
        return 0
    test_to_drv = eval_drvs(tests, attr_prefix, eval_batch, eval_workers)
    drv_to_test = {drv: test for test, drv in test_to_drv.items()}
    keep_logs = log_dir is not None
    logs = log_dir if log_dir is not None else Path(tempfile.mkdtemp(prefix="e2e-"))
    logs.mkdir(parents=True, exist_ok=True)

    attempt = _build_once(tests, drv_to_test, jobs, clock, logs, limit)
    status, outcomes, stopped = attempt.status, dict(attempt.outcomes), attempt.stopped
    failed: list[str] = []
    if status != 0:
        failed = missing_outputs(drv_to_test)
        for test in failed:
            outcomes[test] = _failure(test, attempt, timeouts)
    # A test that passed without a build in the attempt that passed it was
    # served from the store or a binary cache: its pass is an earlier run's.
    served = {test for test in tests if test not in outcomes}

    for _attempt in range(retries):
        if not failed:
            break
        if limit is not None and limit.left() < MIN_TEST_SECONDS:
            print(
                f"no time left to retry {len(failed)} failed test(s): "
                f"{' '.join(failed)}",
                file=sys.stderr,
            )
            break
        print(
            f"retrying {len(failed)} failed test(s): {' '.join(failed)}",
            file=sys.stderr,
        )
        retry_map = {test_to_drv[test]: test for test in failed}
        retried = _build_once(failed, retry_map, jobs, clock, logs, limit)
        stopped = stopped or retried.stopped
        still_failed = set(missing_outputs(retry_map))
        for test in failed:
            if test not in still_failed:
                seconds = retried.outcomes.get(test, TestOutcome("pass", 0)).seconds
                outcomes[test] = TestOutcome("pass", seconds, flaky=True)
                if test not in retried.outcomes:
                    served.add(test)
            elif test in retried.outcomes:
                outcomes[test] = _failure(test, retried, timeouts)
        failed = [test for test in failed if test in still_failed]

    not_booted: list[str] = []
    if require_boot:
        not_booted = [test for test in tests if test in served]
        for test in not_booted:
            outcomes[test] = TestOutcome("fail", 0, not_booted=True)
        if not_booted:
            print(
                f"{len(not_booted)} test(s) did not boot, because the store or a "
                "binary cache already held their results, and this run must "
                f"boot every test: {' '.join(not_booted)}",
                file=sys.stderr,
            )

    log_paths: dict[str, str] = {}
    for test in tests:
        path = logs / f"{test}.log"
        if test not in failed or outcomes[test].not_run:
            # Passing logs are removed; only failures are worth uploading.
            path.unlink(missing_ok=True)
            continue
        if not _has_text(path):
            _write_nix_log(test_to_drv[test], path)
        if outcomes[test].timed_out:
            print(
                f"{test} ran out of time after {outcomes[test].seconds}s; the end "
                f"of its log:\n{_tail(path, LOG_TAIL_LINES)}",
                file=sys.stderr,
            )
        log_paths[test] = str(path) if keep_logs else f"nix log {test_to_drv[test]}"
    if not keep_logs:
        shutil.rmtree(logs, ignore_errors=True)
    if durations_out is not None:
        write_durations(durations_out, tests, outcomes)
    print(format_console_summary(tests, outcomes, log_paths), file=sys.stderr)
    if report is not None:
        report(tests, outcomes)
    if (
        status != 0
        and not failed
        and not stopped
        and not any(o.flaky for o in outcomes.values())
    ):
        # The build failed, yet every test output exists: nothing to retry and
        # nothing to blame, so pass the original status on.
        return status
    return 1 if failed or not_booted else 0


def _tail(path: Path, count: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-count:])


def build_drivers(
    tests: Sequence[str],
    attr_prefix: str,
    batch_size: int | None = None,
    workers: int | None = None,
    limit: TimeLimit | None = None,
) -> dict[str, Path]:
    """Build the driver of every test and return each one's store path.

    The drivers are evaluated in parallel batches like the tests themselves
    (see :func:`eval_drvs`), then built in one ``nix build``, which builds
    what they share once and the rest side by side. A driver that does not
    build, or not before the ``limit``'s deadline, is a RunError.
    """
    drvs = evaluate.evaluate(
        attr_prefix,
        tests,
        "t: t.driver.drvPath",
        workers=workers or evaluate.auto_workers(),
        batch_size=batch_size,
    )
    try:
        completed = subprocess.run(
            [
                "nix",
                "build",
                "--no-link",
                "--json",
                *(f"{drv}^*" for drv in drvs.values()),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=None if limit is None else limit.left(),
        )
    except subprocess.TimeoutExpired:
        raise RunError(
            "the test drivers did not build before the run's time limit"
        ) from None
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-LOG_TAIL_LINES:]
        raise RunError(
            "the test drivers did not build:\n" + "\n".join(detail)
            if detail
            else f"the test drivers did not build (exit {completed.returncode})"
        )
    outputs = {
        str(built["drvPath"]): str(built["outputs"]["out"])
        for built in json.loads(completed.stdout)
    }
    return {test: Path(outputs[str(drv)]) for test, drv in drvs.items()}


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
    timeout: float,
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

    The driver runs in a process group of its own, with the QEMU, virtiofsd
    and VLAN processes it starts. A driver still running after ``timeout``
    seconds timed out: the whole group is stopped, as it is whenever the driver
    ends, so no VM outlives its test into the next one.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=base))
    env = {**os.environ, "TMPDIR": str(scratch), "XDG_RUNTIME_DIR": str(scratch)}
    start = clock()
    timed_out = False
    try:
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(driver / "bin" / "nixos-test-driver")],
                cwd=scratch,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                _stop_group(process)
        result = "pass" if process.returncode == 0 and not timed_out else "fail"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return TestOutcome(result, round(clock() - start), timed_out=timed_out)


def _stop_group(process: subprocess.Popen[bytes]) -> None:
    """Stop every process left in a driver's process group, the driver too.

    The group keeps its id while any member lives, so it is signalled after
    the driver itself exited, too.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except (ProcessLookupError, PermissionError):
            break
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=STOP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
    process.wait()


def run_drivers(
    tests: Sequence[str],
    timeouts: Mapping[str, int],
    attr_prefix: str = DEFAULT_ATTR_PREFIX,
    durations_out: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
    retries: int = 0,
    log_dir: Path | None = None,
    report: Callable[[Sequence[str], Mapping[str, TestOutcome]], None] | None = None,
    eval_batch: int | None = None,
    eval_workers: int | None = None,
    limit: TimeLimit | None = None,
) -> int:
    """Execute every test's driver one after another, ignoring cached results.

    The drivers are built first, all at once (see :func:`build_drivers`).
    Logs of failed tests stay in ``log_dir`` (passing logs are removed); the
    retry and flaky rules match ``run_build``. A driver runs at most its own
    timeout and a grace beyond it, and with a ``limit`` at most its share of
    the run and no further than the run's deadline; past that it timed out and
    is stopped with its VMs. No test starts, and none is retried, with less
    than MIN_TEST_SECONDS left: one never started was not run. Returns 0 when
    every test passed and 1 otherwise. Before any driver is built, a scratch
    base that is too long for the drivers' sockets, or not a directory, raises
    RunError, and a hard open-file limit too low for virtiofsd prints a
    warning.
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
    drivers = build_drivers(tests, attr_prefix, eval_batch, eval_workers, limit)
    outcomes: dict[str, TestOutcome] = {}
    for attempt in range(retries + 1):
        pending = [
            test
            for test in tests
            if test not in outcomes or outcomes[test].result == "fail"
        ]
        if not pending:
            break
        if attempt and limit is not None and limit.left() < MIN_TEST_SECONDS:
            print(
                f"no time left to retry {len(pending)} failed test(s): "
                f"{' '.join(pending)}",
                file=sys.stderr,
            )
            break
        if attempt:
            print(
                f"retrying {len(pending)} failed test(s): {' '.join(pending)}",
                file=sys.stderr,
            )
        for test in pending:
            if limit is not None and limit.left() < MIN_TEST_SECONDS:
                # A failure keeps its outcome; only a test that never ran is
                # reported as not run.
                if test not in outcomes:
                    outcomes[test] = TestOutcome("fail", 0, not_run=True)
                    print(f"{test}: not run, out of time", file=sys.stderr)
                continue
            print(f"running {test}", file=sys.stderr)
            log_path = logs / f"{test}.log"
            own = timeouts.get(test, 900)
            seconds = own + DRIVER_GRACE_SECONDS
            if limit is not None:
                seconds = min(seconds, limit.for_test())
            outcome = _execute_driver(drivers[test], seconds, log_path, clock, base)
            if outcome.result == "pass":
                outcome.flaky = attempt > 0
                log_path.unlink(missing_ok=True)
            else:
                # The driver's own global timeout ends it with a failure too.
                outcome.timed_out = outcome.timed_out or ran_out(outcome.seconds, own)
                print(_tail(log_path, LOG_TAIL_LINES), file=sys.stderr)
            shown = "timed out" if outcome.timed_out else outcome.result
            print(f"{test}: {shown} in {outcome.seconds}s", file=sys.stderr)
            outcomes[test] = outcome
    if not keep_logs:
        shutil.rmtree(logs, ignore_errors=True)
    if durations_out is not None:
        write_durations(durations_out, tests, outcomes)
    if report is not None:
        report(tests, outcomes)
    return 1 if any(o.result == "fail" for o in outcomes.values()) else 0


def _label(outcome: TestOutcome) -> str:
    if outcome.not_booted:
        return "FAIL (not booted)"
    if outcome.not_run:
        return "FAIL (not run)"
    if outcome.timed_out:
        return "FAIL (timed out)"
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
        if outcome.not_booted:
            annotations.append(
                f"::error title=E2E test not booted::{test} did not boot: the "
                "store or a binary cache already held its result, and this run "
                "must boot every test"
            )
        elif outcome.not_run:
            annotations.append(
                f"::error title=E2E test not run::{test} did not start: the run "
                "reached its time limit first"
            )
        elif outcome.timed_out:
            annotations.append(
                f"::error title=E2E test timed out::{test} ran out of time after "
                f"{outcome.seconds}s and was stopped; its log so far is kept with "
                "the logs of the failed tests"
            )
        elif outcome.result == "fail":
            annotations.append(f"::error title=E2E test failed::{test} failed")
        elif outcome.flaky:
            annotations.append(
                f"::warning title=FLAKY E2E test::{test} failed, then passed on retry"
            )
    return annotations
