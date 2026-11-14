"""The gate scenario of an enforcing Fedora decoy, before Fedora is admitted.

``nix/distro-tests/fedora-gate.nix`` builds one host driver per pinned Fedora
image (``<image>-gate``, and ``<image>-gate-noda`` with the policy's dontaudit
rules off, where only NAILS's new denials fail and the others are recorded)
and calls :func:`run` with the driver's machine. The image boots
with SELinux enforcing, and NAILS is a test-only build that admits Fedora.
Every ``nails`` command runs from a real operator domain: a login session of
its own, a transient unit with the login PAM stack, whose pam_selinux gives
the user its default context (``unconfined_t``), checked with ``id -Z``
first. The harness's own shell runs as a service, in the domain the gate
records (``unconfined_service_t``), not in an operator's.

The scenario runs the assertions of the gate's smoke and way-back lists in one
QEMU process:

1. a power cycle, the reference of the login and boot records;
2. on the decoy: SELinux enforcing with the targeted policy; check refuses the
   stock persistent journal and the running auditd, and passes once the
   journal is volatile and auditd is off by the documented commands, without
   a reboot; tuned, firewalld and ABRT installed from the shared closure with
   every repository disabled and started: check refuses tuned and warns of
   firewalld and ABRT, and names none of them once the documented fixes are
   in; the locate database; lsm-status, before and after ``setenforce 0``;
   check clean on the prepared decoy; a failed login, which btmp records;
3. a plain soft-reboot, the control whose denials, failed units and changes
   on the decoy disk are no sign of NAILS;
4. a first session, ended with ``deactivate``: SELinux enforcing in it; the
   labels of the hidden ``/``, ``/home`` and ``/var``; a copied-up file keeps
   its type and a new one gets the policy's; NAILS's processes never in
   ``init_t``; the overlay feature options pinned; the canaries land in the
   uppers; no NAILS unit and no unit the hidden root masks failed; a login
   and a failed login in the session, each recorded in the session's own
   files; a kernel log marker and a file in ``/run``; a disk attached in the
   session read-only by the disk guard's udev rule; the rehearsal planted;
   and after the way back: enforcing; the marker not in the decoy's journal,
   which took no kernel record of the session, and the cursor above it;
   nothing the session made left in ``/run``; ``utab`` given back, a line of
   a bind mount the decoy made among it; ``/run/initramfs`` unchanged; the
   attached disk writable again; none of the session's files on the decoy;
   no failed unit but one a soft-reboot is known to leave; the login and boot
   records as a power cycle leaves them, with no record of the hidden logins;
   the rehearsal's scan, which names the compressing btrfs root as not
   checked;
5. a package the decoy removes after a hidden session changed its own copy of
   the package database: check warns of it with its fix;
6. a second session, as a user through sudo with the fresh-home persona: its
   home labelled ``user_home_dir_t``; the same assertions in it, the
   rehearsal's aside; the entry's drift advisory; ended with the emergency,
   and the same way-back assertions;
7. a last plain soft-reboot, the second control; the decoy disk after each way
   back changed only where a control changed it; and a login on the decoy,
   the positive control of the login records.

Every denial and SELinux error is counted from the boot before NAILS ran, in
both roots, from the kernel log and, while auditd runs on the stock decoy,
from its log: one is new when it is NAILS's own, or when neither the decoy
before the first entry (each check aside) nor the first plain soft-reboot
logged its signature (``selinux_gate``). The audit serial numbers of the boot
from the gate's first marker on must leave no gap between the two logs. Each
assertion is recorded with its outcome and the run goes on where it can, so
one run says which assertions hold and which do not; ``<name>.json``,
``<name>.kmsg.txt`` and ``<name>.audit.log`` in the directory
``NAILS_GATE_OUT`` names hold them, and the run fails at its end when one does
not hold.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
import traceback
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

import distro_checks
import fedora_rpms
import selinux_gate as sg

NAILS = "/run/tools/nails"
RUNTIME = "/run/overlay-runtime"
RAM = f"{RUNTIME}/control"
CONFIG = "/run/nails-gate.toml"
FRESH_CONFIG = "/run/nails-gate-fresh.toml"
HIDDEN = "/mnt/data"
UPPER = f"{HIDDEN}/root/upper"
# The hidden root's configuration: the disk guard on, so that a disk attached
# in the session is set read-only. The watcher sweeps the disks, the guard's
# fallback, at the start of the session and then once an hour, so a disk the
# gate attaches later is set read-only by the guard's udev rule or not at all.
CONFIG_TEXT = (
    f'hidden_volume_root = "{HIDDEN}"\n'
    "minimum_space_mb = 100\n"
    "\n[session_mounts]\nread_only = true\n"
    "\n[backend_watch]\npoll_interval_secs = 3600\n"
)
FRESH_TEXT = '\n[persona]\nmode = "fresh-home"\n'
# The disk guard's udev rule in a session, and its record of the disks it set
# read-only.
GUARD_RULE = "/run/udev/rules.d/60-overlay-runtime.rules"
GUARD_RECORD = f"{RUNTIME}/read-only-devices"
# The operator of the second session: a user who runs nails through sudo, with
# a home on the decoy's /home.
USER = "gate"
OPERATOR_TYPE = "unconfined_t"
# The shares the driver mounts: the binary and the package closure.
SHARES = (("tools", "/run/tools"), ("rpms", "/run/rpms"))
# Where the operator's commands leave their output and exit status: a
# directory every user may write, in RAM.
OP_DIR = "/run/gate-op"
# The terminal of the console logins that write login records.
LOGIN_TTY = "tty5"
# The terminal of the operator's own console login on the decoy, right before
# each entry, as an operator logs in to run the activation: its records are the
# decoy's, and the judgment must keep them apart from the hidden session's.
OPERATOR_TTY = "tty4"
# A file each session writes in /run, which its way back must take away.
RUN_PROBE = "/run/gate-probe"
# A bind mount the decoy makes before the first entry with a userspace option,
# which libmount keeps in utab: the way back must give its line back.
UTAB_BIND = "/srv/gate-utab"
UTAB_OPTION = "x-gate.utab"
# A disk attached in a session, as a USB disk would be.
HOTPLUG_BYTES = 64 << 20
# The hidden volume: a disk of its own, attached at the start of the run and
# backed by a file on the driver's host, so that it survives every switch and
# the second session finds the first one's upper on it, and nothing of it is
# on the decoy disk. The Cloud image has no cryptsetup, so it holds plain
# ext4. Its serial, like every name the decoy can see, is neutral.
HIDDEN_DISK = "disk2"
HIDDEN_BYTES = 1 << 30
HIDDEN_DEVICE = f"/dev/disk/by-id/virtio-{HIDDEN_DISK}"
HIDDEN_ROOT = f"""
set -eu
for i in $(seq 30); do [ -b {HIDDEN_DEVICE} ] && break; sleep 1; done
if ! mountpoint -q {HIDDEN} ; then
  blkid {HIDDEN_DEVICE} >/dev/null 2>&1 || mkfs.ext4 -q {HIDDEN_DEVICE}
  mkdir -p {HIDDEN}
  mount {HIDDEN_DEVICE} {HIDDEN}
fi
mkdir -p {HIDDEN}/root/work {HIDDEN}/config
"""
# The decoy prepared as its requirements ask, beyond what the gate checks
# before and after its fix: core dumps discarded, the lid switch locking the
# screen, freed memory zeroed (init_on_free=1, from the next boot on), and
# sssd off with the state files its warning looks for removed.
PREPARE_DECOY = """
set -eu
mkdir -p /etc/systemd/coredump.conf.d /etc/systemd/logind.conf.d
printf '%s\\n' '[Coredump]' Storage=none ProcessSizeMax=0 \\
  > /etc/systemd/coredump.conf.d/50-discard.conf
printf '%s\\n' '[Login]' HandleLidSwitch=lock HandleLidSwitchExternalPower=lock \\
  HandleLidSwitchDocked=ignore IdleAction=ignore \\
  > /etc/systemd/logind.conf.d/10-lid.conf
grubby --update-kernel=ALL --args=init_on_free=1
systemctl disable --now sssd.service sssd-kcm.socket sssd-kcm.service || true
rm -f /var/lib/sss/db/config.ldb /var/lib/sss/db/config_kcm.ldb \\
  /var/lib/sss/mc/passwd /var/lib/sss/mc/group /var/lib/sss/mc/initgroups \\
  /var/lib/sss/mc/sid /var/lib/sss/secrets/secrets.ldb \\
  /var/lib/sss/pipes/nss /var/lib/sss/pipes/pam
"""
# The policy without its dontaudit rules, for the variant that counts the
# denials those rules keep out of the log: libsemanage rebuilds and loads it,
# and keeps the setting in its store as a flag file, so the next boot loads it
# the same way.
NO_DONTAUDIT = "semodule -DB"
NO_DONTAUDIT_FLAG = "disable_dontaudit"
NO_DONTAUDIT_STORE = "/var/lib/selinux/targeted"
# The kernel's queue of audit records waiting for its log or a daemon. A burst
# beyond it is lost (audit_lost), as the variant without dontaudit rules showed
# at the switches with the kernel's 64, so the gate makes room for one.
AUDIT_BACKLOG = "auditctl -b 8192"
# A failed console login of the user the script is given: util-linux's login
# on a terminal of its own, given a wrong password once, which it records in
# btmp before it says "Login incorrect". The script ends login then and prints
# what the terminal showed.
FAILED_LOGIN = r"""
import errno, os, pty, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/login", ["login", sys.argv[1]])
seen, sent, deadline = b"", False, time.monotonic() + 40
while time.monotonic() < deadline:
    if os.waitpid(pid, os.WNOHANG)[0]:
        pid = 0
        break
    if not select.select([fd], [], [], 0.5)[0]:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError as error:
        if error.errno != errno.EIO:
            raise
        time.sleep(0.2)
        continue
    seen += data
    if not sent and b"assword" in seen:
        os.write(fd, b"not-the-password\n")
        sent = True
    elif sent and b"incorrect" in seen:
        break
if pid:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
sys.stdout.write(seen.decode("utf-8", "replace"))
"""
# What check warns of on the prepared decoy because of the harness and the VM,
# not the decoy: each with why.
HARNESS_WARNINGS = {
    "backend-encryption": "the hidden volume is plain ext4, as the image has no "
    "cryptsetup",
    "binary-location": "the harness shares the binary into /run over 9p",
    "decoy-nix-trace": "the harness mounts its own Nix store into the VM",
    "dma-protection": "the VM has no IOMMU",
}
# The trees the canaries go to: the whole root is overlaid, /home and /var
# are filesystems of their own on Fedora's btrfs.
CANARY_TREES = ("home", "etc", "var", "usr", "root", "opt", "srv")
# The files each session writes besides the canaries, which the decoy must
# not hold after the way back.
SESSION_FILES = (
    "/etc/gate-new",
    "/root/gate-new",
    "/var/tmp/gate-new",
    "/home/gate-dir",
)
# The units the hidden root keeps from running: none may be failed in either
# root.
HIDDEN_MASKED = (
    "systemd-remount-fs.service",
    "systemd-growfs-root.service",
    "systemd-boot-random-seed.service",
    "grub-boot-indeterminate.service",
    "grub-boot-success.timer",
    "grub-boot-success.service",
)
# The prefix of every unit NAILS runs: the session's watcher and the decoy's
# reconcile step.
NAILS_UNITS = "overlay-runtime"
# The units a switch is known to leave failed on these images, with why. Any
# other failed unit fails the gate, unless the first plain soft-reboot left it
# failed as well.
SOFT_REBOOT_FAILURES = {
    "systemd-zram-setup@zram0.service": "the stop of the zram swap at a switch "
    "can fail to reset the device (status=1/FAILURE), and the next root then "
    "cannot set it up (zram: Cannot change disksize for initialized device): "
    "that root and every later one run without the zram swap until power-off",
}
# The pieces the way back leaves in /run for the decoy's first start, which
# its reconcile step removes.
WAY_BACK_PIECES = (
    "/run/overlay-runtime-boot",
    "/run/systemd/system/overlay-runtime-boot.service",
)
# The decoy's login and boot record files: the records checks judge them, so
# the comparison of the decoy disk leaves them out, with the folders sqlite
# writes its journal in beside them.
RECORD_PATHS = (
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/wtmp.db",
    "/var/lib/lastlog",
    "/var/lib/wtmpdb",
)
# The filesystem types of the decoy's disk mounts.
DISK_FSTYPES = ("btrfs", "ext4", "xfs", "vfat")
# The blind spot the rehearsal's scan must name for a btrfs root mounted to
# compress, and its exit status when it names one and finds nothing.
COMPRESSED_BLIND_SPOT = "compresses file contents"
SCAN_WARNINGS_EXIT = 9
# What a check depends on that next does not have yet.
NEEDS_LABEL = "the RAM copy labelled as a program (bin_t)"
NEEDS_POSTURE = "the posture checks of tuned, firewalld and ABRT"
NEEDS_LSM = "the lsm-status check"
NEEDS_AUDITD_TEXT = "the corrected auditd text of decoy-persistence"
TUNED_DROPIN = "[Service]\nExecStart=\nExecStart=/usr/sbin/tuned -P\n"
# What PID 1 logs when the policy of the root it starts in is not loaded, and
# when a policy is.
POLICY_KEPT = "Failed to load new SELinux policy. Continuing with old policy."
POLICY_LOADED = "Successfully loaded SELinux policy"


def judged_row(rows: Mapping[str, Mapping[str, Any]], name: str) -> bool:
    """Whether check's report holds the row ``name`` with a verdict: a report
    check could not print holds no row, so an assertion that a row no longer
    names something holds only where this does. The row may fail for another
    reason than the one judged."""
    row = rows.get(name)
    return row is not None and row.get("status") in ("pass", "warn", "fail")


def failed_units_problems(
    failed: Iterable[str], allowed: Mapping[str, str]
) -> dict[str, list[str]]:
    """The failed units of a root, sorted by what they say: NAILS's own, those
    the hidden root masks, those ``allowed`` names (each with why), and the
    others."""
    found: dict[str, list[str]] = {"nails": [], "masked": [], "known": [], "other": []}
    for unit in failed:
        if unit.startswith(NAILS_UNITS):
            found["nails"].append(unit)
        elif unit in HIDDEN_MASKED:
            found["masked"].append(unit)
        elif unit in allowed:
            found["known"].append(unit)
        else:
            found["other"].append(unit)
    return found


# The private temporary folder systemd makes for a unit at each of its starts
# (PrivateTmp=): named after the boot, the unit and six random characters.
_PRIVATE_TMP = re.compile(
    r"^(/var/tmp/systemd-private-[0-9a-f]{32}-[^/]+)-[A-Za-z0-9]{6}(/.*)?$"
)


def changed_paths(listing: str, mount_points: Iterable[str] = ()) -> set[str]:
    """The paths of a listing of changed files on the decoy, without those the
    records checks judge (:data:`RECORD_PATHS`, a folder of them with what is
    below it), and without ``mount_points``, which ``find -xdev`` lists with
    the times of the filesystem mounted there. A unit's private temporary
    folder is named by its unit alone, its random part as ``*``: each start of
    the unit makes a new one, after a way back as after a plain
    soft-reboot."""
    mounted = set(mount_points)
    found = set()
    for line in listing.splitlines():
        path = line.strip()
        if not path.startswith("/") or path in mounted:
            continue
        if any(path == kept or path.startswith(kept + "/") for kept in RECORD_PATHS):
            continue
        private = _PRIVATE_TMP.match(path)
        if private:
            path = f"{private.group(1)}-*{private.group(2) or ''}"
        found.add(path)
    return found


def decoy_disk_residue(
    way_back: set[str], controls: Iterable[set[str]]
) -> list[str]:
    """What a way back changed on the decoy disk that no plain soft-reboot
    changed: the paths of ``way_back`` in none of ``controls``."""
    seen: set[str] = set()
    for control in controls:
        seen |= control
    return sorted(way_back - seen)


def rehearse_scan_problems(
    rc: int, scan: Mapping[str, Any], root_device: str
) -> list[str]:
    """Why the rehearsal's scan of the decoy after a clean session is not what
    a decoy whose btrfs root compresses must give; empty when it is: every
    device read without an error or a hit, some bytes read, the root's device
    among them with the compression blind spot and no other device with one,
    and the exit status of a scan that names a blind spot."""
    problems: list[str] = []
    devices = scan.get("devices") or []
    if not devices:
        return ["the scan read no device"]
    if not any(int(device.get("bytes_scanned", 0) or 0) > 0 for device in devices):
        problems.append("the scan read no byte")
    names = [device.get("device") for device in devices]
    if root_device not in names:
        problems.append(
            f"the scan did not read the root's device {root_device}: {names}"
        )
    for device in devices:
        name = device.get("device")
        if "error" in device:
            problems.append(f"{name}: {device['error']}")
        if device.get("hits"):
            problems.append(f"{name}: hits {device['hits']}")
        blind = device.get("blind_spot")
        if name == root_device:
            if not blind or COMPRESSED_BLIND_SPOT not in str(blind):
                problems.append(
                    f"{name}: the blind spot should say {COMPRESSED_BLIND_SPOT!r}, "
                    f"it says {blind!r}"
                )
        elif blind is not None:
            problems.append(f"{name}: an unexpected blind spot: {blind}")
    if rc != SCAN_WARNINGS_EXIT:
        problems.append(f"the scan exited {rc}, not {SCAN_WARNINGS_EXIT}")
    return problems


def in_window(
    audit: Iterable[Mapping[str, Any]], start: float | None, end: float | None
) -> list[Mapping[str, Any]]:
    """The records of auditd's log written from ``start`` up to ``end``."""
    return [
        record
        for record in audit
        if (start is None or float(record["time"]) >= start)
        and (end is None or float(record["time"]) < end)
    ]


def wall_of(marker: Mapping[str, Any]) -> float | None:
    """The guest's wall clock when a marker was written, or None."""
    try:
        return float(str(marker.get("wall", "")).split()[0])
    except (ValueError, IndexError):
        return None


class Gate:
    """One gate run on the machine ``vm``."""

    def __init__(
        self,
        vm: Any,
        session: Any,
        utab: Any,
        records: Any,
        settings: dict[str, Any],
        out_dir: str,
    ) -> None:
        self.vm = vm
        self.session = session
        self.utab = utab
        self.records = records
        self.settings = settings
        self.out_dir = out_dir
        self.image = str(settings["image"])
        variant = str(settings.get("variant", ""))
        self.name = f"{self.image}-gate" + (f"-{variant}" if variant else "")
        self.nonce = uuid.uuid4().hex[:10]
        self.boot = -1
        self.boots: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        self.facts: dict[str, Any] = {}
        self.raw: dict[str, Any] = {}
        self.calls = 0
        self.where = "decoy before the first entry"
        self.lost = False
        # The changes on the decoy disk across each switch, by its label.
        self.disk: dict[str, set[str]] = {}
        # The failed units a plain soft-reboot left, which a way back may leave
        # too, with why.
        self.allowed_failed: dict[str, str] = dict(SOFT_REBOOT_FAILURES)

    # --- recording -------------------------------------------------------

    def check(
        self, name: str, passed: bool, detail: object = "", needs: str = ""
    ) -> bool:
        """Record one assertion and its outcome; the run goes on either way."""
        text = detail if isinstance(detail, str) else repr(detail)
        entry = {
            "name": name,
            "passed": bool(passed),
            "where": self.where,
            "detail": text,
            "needs": needs,
        }
        self.checks.append(entry)
        word = "PASS" if passed else "FAIL"
        extra = f" (needs {needs})" if needs and not passed else ""
        print(f"GATE {word}: {name}{extra}: {text[:2000]}")
        return bool(passed)

    def sh(self, label: str, cmd: str, timeout: int = 300) -> tuple[int, str]:
        """Run ``cmd`` in the guest and keep its output; never fails."""
        self.calls += 1
        key = f"{self.calls:04}.b{self.boot}.{label}"
        try:
            status, out = self.vm.execute(
                f"( set +euo pipefail; {cmd} ) 2>&1", timeout=timeout
            )
        except Exception as error:  # noqa: BLE001 - a dead guest is a result
            status, out = -1, f"<{type(error).__name__}: {error}>"
        self.raw[key] = {"cmd": cmd, "status": status, "out": out}
        print(f"=== {key} (exit {status}) ===\n{out.rstrip()}")
        return status, out

    def fact(self, label: str, cmd: str, timeout: int = 300) -> str:
        _, out = self.sh(label, cmd, timeout)
        self.facts[f"b{self.boot}.{label}"] = out.strip()
        return out.strip()

    def wall(self) -> str:
        """The guest's wall clock, to the nanosecond."""
        return self.vm.succeed("date +%s.%N").strip()

    # --- the operator ----------------------------------------------------

    def operator(self, cmd: str, user: str = "root") -> str:
        """``cmd`` as the operator runs it: in a login session of its own,
        whose PAM stack gives ``user`` its default SELinux context. systemd-run
        cannot pass its descriptors across the context change, so the output
        and the exit status go through files in a directory every user may
        write (:data:`OP_DIR`); the standard error goes after the output."""
        out = f"{OP_DIR}/{user}"
        inner = f"( {cmd} ) > {out}.out 2> {out}.err; echo $? > {out}.rc"
        return (
            f"( rm -f {out}.out {out}.err {out}.rc; "
            f"systemd-run --quiet --wait --collect -p PAMName=login -p User={user} "
            f"/bin/sh -c {shlex.quote(inner)}; "
            f"cat {out}.out {out}.err; exit $(cat {out}.rc 2>/dev/null || echo 125) )"
        )

    def pam_login(self, user: str, tty: str = LOGIN_TTY) -> str:
        """A console login of ``user`` on ``tty`` through PAM's login stack,
        as a getty's login runs it on a terminal: systemd opens the PAM
        session and writes the session's utmp and wtmp records, and
        pam_lastlog2 its row."""
        return (
            "systemd-run --wait --collect --quiet -p PAMName=login "
            f"-p User={user} -p TTYPath=/dev/{tty} "
            f"-p UtmpIdentifier={tty} -p UtmpMode=user /bin/true"
        )

    def failed_login(self, label: str, user: str) -> str:
        """A console login of ``user`` that fails (:data:`FAILED_LOGIN`)."""
        script = f"<<'GATEEOF'\n{FAILED_LOGIN}\nGATEEOF\n"
        _, out = self.sh(label, f"python3 - {shlex.quote(user)} {script}")
        return out

    def nails(
        self, args: str, user: str = "root", config: str = CONFIG, to: str = ""
    ) -> str:
        """The operator's command line for ``nails <args>``: root's directly,
        another user's through sudo. ``to`` names a file that takes the
        output, written as root."""
        line = f"{NAILS} --config {config} {args}"
        if to:
            line = f"{line} > {to} 2>&1"
        if user != "root":
            line = f"sudo -n /bin/sh -c {shlex.quote(line)}"
        return self.operator(line, user)

    def check_rows(
        self, label: str, user: str = "root", config: str = CONFIG
    ) -> tuple[int, dict[str, dict[str, Any]]]:
        """``nails check --overlay-only --json`` as the operator: its exit
        status and its rows by name. The check runs between markers of its
        own (``check-<label>``), so its denials are judged alone, and the
        harness's next preparation starts a ``prep-`` phase."""
        self.mark(f"check-{label}")
        status, out = self.sh(
            label, self.nails("check --overlay-only --json", user, config), 600
        )
        self.mark(f"prep-after-{label}")
        rows: dict[str, dict[str, Any]] = {}
        start = out.find("{")
        try:
            report, _ = (
                json.JSONDecoder().raw_decode(out[start:]) if start >= 0 else ({}, 0)
            )
            for row in report.get("data", {}).get("checks", []):
                rows[str(row.get("name"))] = row
        except ValueError:
            pass
        return status, rows

    def rehearse(self, label: str, args: str) -> tuple[int, dict[str, Any], str]:
        """``nails --json rehearse <args>`` as root's operator: its exit status,
        its report and its whole output."""
        status, out = self.sh(label, self.nails(f"--json rehearse {args}"), 1200)
        start = out.find("{")
        report: dict[str, Any] = {}
        try:
            if start >= 0:
                report, _ = json.JSONDecoder().raw_decode(out[start:])
        except ValueError:
            pass
        return status, report, out

    # --- the kernel log --------------------------------------------------

    def read_kmsg(self) -> None:
        current = self.boots[self.boot]
        first = max(current["records"], default=0)
        status, out = self.vm.execute(sg.kmsg_command(first), timeout=300)
        found, dropped = sg.parse_kmsg(out)
        current["dropped"] += dropped
        sg.merge(current["records"], found)

    def mark(self, label: str) -> int | None:
        text = sg.marker(label, self.nonce)
        _, wall = self.vm.execute(
            f"date +%s.%N; echo {shlex.quote(text)} > /dev/kmsg",
            check_return=False,
            timeout=60,
        )
        self.read_kmsg()
        seq = sg.marker_seq(self.boots[self.boot]["records"].values(), text)
        self.boots[self.boot]["markers"].append(
            {"label": label, "seq": seq, "wall": wall.strip()}
        )
        return seq

    def seq_of(self, label: str) -> int | None:
        for marker in self.boots[self.boot]["markers"]:
            if marker["label"] == label:
                return marker["seq"]
        return None

    def read_audit_log(self) -> None:
        """What auditd wrote of this boot while it ran: the kernel gives a
        running auditd every audit record instead of its log, so the denials
        of those moments are only there."""
        current = self.boots[self.boot]
        _, out = self.vm.execute(
            "cat $(ls -r /var/log/audit/audit.log* 2>/dev/null) 2>/dev/null; true",
            check_return=False,
            timeout=300,
        )
        os.makedirs(self.out_dir, exist_ok=True)
        with open(
            os.path.join(self.out_dir, f"{self.name}.audit.log"), "w", encoding="utf-8"
        ) as handle:
            handle.write(out)
        current["audit"], info = sg.boot_audit_log(out, float(current.get("btime", 0)))
        info["records"] = len(current["audit"])
        self.facts[f"b{self.boot}.audit-log"] = info

    # --- boots and switches ----------------------------------------------

    def new_boot(self, why: str) -> None:
        self.boot += 1
        self.boots.append(
            {
                "why": why,
                "records": {},
                "dropped": 0,
                "markers": [],
                "console": [],
                "audit": [],
                "btime": 0,
            }
        )

    def prepare(self) -> None:
        """What every boot and every switch needs: the shares mounted again,
        the configuration in /run, and the kernel log's limits lifted."""
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        for tag, target in SHARES:
            vm.succeed(
                f"mkdir -p {target} && {{ mountpoint -q {target} || mount -t 9p "
                "-o defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
                f"{tag} {target}; }}"
            )
        vm.succeed(f"test -x {NAILS}")
        vm.succeed(f"mkdir -p {OP_DIR} && chmod 1777 {OP_DIR}")
        vm.succeed(f"cat > {CONFIG} <<'EOF'\n{CONFIG_TEXT}EOF")
        vm.succeed(f"cat > {FRESH_CONFIG} <<'EOF'\n{CONFIG_TEXT}{FRESH_TEXT}EOF")
        self.sh("limits", f"{sg.KMSG_LIMITS}; {AUDIT_BACKLOG}")

    def follow(self, trigger: str, label: str) -> str:
        """Follow a soft-reboot; the place after it, or ``lost``."""
        console_from = len(self.vm.full_console_log)
        try:
            self.session.follow_soft_reboot(self.vm, trigger, label, deadline_s=600)
        except Exception as error:  # noqa: BLE001 - recorded, the run stops
            lines = self.vm.full_console_log[console_from:]
            self.boots[self.boot]["console"].append(
                {"label": label, "lines": lines[-400:]}
            )
            self.check(f"{label}: the switch comes back", False, str(error))
            self.lost = True
            return "lost"
        self.prepare()
        fstype = self.vm.execute("findmnt -no FSTYPE /", timeout=60)[1].strip()
        return "hidden" if fstype == "overlay" else "decoy"

    def power_cycle(self, label: str) -> None:
        """A real reboot in the same QEMU process: QEMU runs with -no-reboot,
        so this one reboot resets the machine instead, and a full reboot in
        place of a soft-reboot still ends the run."""
        before = self.vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        client = self.vm.qmp_client
        assert client is not None, "the QMP socket is not connected"
        client.send("set-action", {"reboot": "reset"})
        try:
            self.session.follow_soft_reboot(
                self.vm, "systemctl reboot", label, deadline_s=600
            )
        finally:
            client.send("set-action", {"reboot": "shutdown"})
        after = self.vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()
        assert after != before, f"{label}: the kernel did not restart"
        self.new_boot(label)
        btime = self.vm.succeed("awk '$1 == \"btime\" {print $2}' /proc/stat").strip()
        self.boots[self.boot]["btime"] = int(btime) if btime.isdigit() else 0
        self.prepare()

    def wait_reconcile(self) -> None:
        self.sh(
            "reconcile-wait",
            "timeout 90 bash -c 'while test -e /run/overlay-runtime-boot; "
            "do sleep 1; done'; systemctl is-system-running --wait; true",
            150,
        )

    # --- facts of a root -------------------------------------------------

    def enforcing(self, where: str) -> None:
        mode = self.fact(f"getenforce.{where}", "getenforce")
        self.check(f"SELinux enforces {where}", mode == "Enforcing", mode)

    def failed_units(self, label: str) -> list[str]:
        out = self.fact(
            label, "systemctl list-units --failed --all --plain --no-legend --no-pager"
        )
        return [line.split()[0] for line in out.splitlines() if line.strip()]

    def judge_failed(self, where: str, label: str) -> list[str]:
        """The failed units of the root the gate is in: none of NAILS's, none
        the hidden root masks, and no other but one a soft-reboot is known to
        leave failed (:data:`SOFT_REBOOT_FAILURES`) or the first plain
        soft-reboot left failed. Each known one is recorded with where it was
        seen, and the swap the root runs with beside it."""
        failed = self.failed_units(label)
        swap = self.fact(f"swap-{label}", "swapon --show --noheadings; true")
        found = failed_units_problems(failed, self.allowed_failed)
        self.check(f"{where}: no NAILS unit failed", not found["nails"], failed)
        self.check(
            f"{where}: no unit the hidden root keeps off failed",
            not found["masked"],
            failed,
        )
        self.check(
            f"{where}: no unit failed but one a switch is known to leave failed",
            not found["other"],
            {
                "failed": failed,
                "known": {unit: self.allowed_failed[unit] for unit in found["known"]},
                "swap": swap,
            },
        )
        self.facts.setdefault("known-failed-units", {})[where] = found["known"]
        return failed

    def records_capture(self, label: str) -> Any:
        """The decoy's login and boot records, read live: wtmp, btmp,
        lastlog, lastlog2 and wtmpdb where the image has them. In a session
        they are the session's own."""
        records = self.records
        _, found = self.vm.execute(
            "find /var -name 'wtmp*.db' 2>/dev/null | head -n1", check_return=False
        )
        guest = {key: "/" + rel for key, rel in records.DEFAULT_PATHS.items()}
        guest["wtmpdb"] = found.strip() or "/var/log/wtmp.db"
        tree = tempfile.mkdtemp(prefix=f"gate-records-{label}-")
        for key, path in guest.items():
            q = shlex.quote(path)
            out = self.vm.succeed(
                f"if test -s {q}; then od -An -v -tx1 {q} | tr -d ' \\n'; echo; "
                "else echo; fi"
            )
            text = out.splitlines()[0].strip() if out.splitlines() else ""
            if not text:
                continue
            dest = os.path.join(tree, records.DEFAULT_PATHS[key])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(bytes.fromhex(text))
        capture = records.capture_from_tree(label, tree)
        self.facts[f"records.{label}"] = capture.as_dict()
        return capture

    def run_listing(self) -> set[str]:
        return set(self.session.run_entries(self.vm))

    def initramfs(self) -> str:
        return self.fact(
            "run-initramfs",
            "test -e /run/initramfs || { echo absent; exit 0; }; "
            "find /run/initramfs -xdev -printf '%y %m %s %p\\n' | sort; "
            "find /run/initramfs -xdev -type f -exec sha256sum {} + | sort",
        )

    def disk_changes(self, label: str, since: str) -> set[str]:
        """Every file and folder on the decoy's disk mounts whose contents or
        inode (its labels among the extended attributes) changed since the
        wall clock ``since``: the hidden volume and the gate's bind left out,
        and the record files the records checks judge."""
        listing = self.fact(
            f"disk-changes-{label}",
            "findmnt -rn -o TARGET,FSTYPE | while read -r target fstype; do "
            f'case "$fstype" in {"|".join(DISK_FSTYPES)}) ;; *) continue ;; esac; '
            f'case "$target" in {HIDDEN}|{HIDDEN}/*|{UTAB_BIND}) continue ;; esac; '
            f'find "$target" -xdev \\( -newerct @{since} -o -newermt @{since} \\) '
            "-print; done | sort -u",
            600,
        )
        # find lists the mount points of other filesystems with the times of
        # what is mounted there; the roots of the decoy's own stay listed.
        others = [
            target
            for target, _, fstype in (
                line.partition(" ")
                for line in self.vm.succeed("findmnt -rn -o TARGET,FSTYPE").splitlines()
            )
            if fstype not in DISK_FSTYPES
            or target in (HIDDEN, UTAB_BIND)
            or target.startswith(HIDDEN + "/")
        ]
        changed = changed_paths(listing, others)
        self.disk[label] = changed
        return changed

    # --- the decoy -------------------------------------------------------

    def decoy(self) -> None:
        """Everything on the decoy before the first entry, with a hidden root
        mounted, which check needs to judge the decoy."""
        vm = self.vm
        self.mark("prep-decoy")
        self.sh("hidden-root", HIDDEN_ROOT)
        self.enforcing("on the decoy before the first entry")
        config = self.fact(
            "selinux-config", "grep -E '^SELINUX(TYPE)?=' /etc/selinux/config"
        )
        self.check(
            "the decoy runs the targeted policy, enforcing",
            "SELINUX=enforcing" in config and "SELINUXTYPE=targeted" in config,
            config,
        )
        if self.settings.get("dontaudit") is False:
            flag = self.fact(
                "no-dontaudit",
                f"find {NO_DONTAUDIT_STORE} -maxdepth 2 -name {NO_DONTAUDIT_FLAG}",
            )
            self.check(
                "the policy runs without its dontaudit rules",
                flag.endswith("/" + NO_DONTAUDIT_FLAG),
                flag,
            )
        self.fact(
            "versions",
            "rpm -q selinux-policy-targeted systemd kernel audit plocate 2>&1; "
            "uname -r",
        )
        # What a VeraCrypt backend could use on this decoy: the kernel's FIPS
        # mode, the cryptsetup the image holds, and the ciphers and hashes
        # its kernel ships as modules or has loaded.
        self.fact(
            "crypto",
            "cat /proc/sys/crypto/fips_enabled; rpm -q cryptsetup 2>&1; "
            "ls /usr/lib/modules/$(uname -r)/kernel/crypto/ | sort; "
            "grep -E '^name' /proc/crypto | sort -u",
        )
        backdoor = self.fact("backdoor-id", "id -Z")
        self.facts["harness-domain"] = sg.context_type(backdoor)
        op = self.fact("operator-id", self.operator("id -Z"))
        self.check(
            "the operator's login runs in unconfined_t",
            f":{OPERATOR_TYPE}:" in op and "denied" not in op.lower(),
            op,
        )
        # The user of the second session, with a home on /home and sudo
        # without a password, as a decoy's operator has it.
        vm.succeed(
            f"id {USER} >/dev/null 2>&1 || useradd -m {USER}; "
            f"printf '%s\\n' '{USER} ALL=(ALL) NOPASSWD: ALL' "
            f"> /etc/sudoers.d/90-{USER}; "
            f"chmod 0440 /etc/sudoers.d/90-{USER}"
        )
        user_op = self.fact("user-id", self.operator("id -Z; sudo -n id -Z", USER))
        self.check(
            "the user's login and sudo keep unconfined_t",
            user_op.count(f":{OPERATOR_TYPE}:") == 2,
            user_op,
        )
        self.journal()
        self.auditd()
        self.posture()
        self.locate()
        self.lsm()
        self.clean_check()
        self.failed_positive()

    def journal(self) -> None:
        status, rows = self.check_rows("check-journal")
        row = rows.get("decoy-persistence", {})
        self.check(
            "check refuses the stock persistent journal",
            status == 4
            and row.get("status") == "fail"
            and "journal" in str(row.get("message", "")).lower(),
            row or status,
        )
        self.vm.succeed(
            "printf '\\n[Journal]\\nStorage=volatile\\n' "
            ">> /etc/systemd/journald.conf; "
            "mkdir -p /etc/systemd/journald.conf.d; "
            "printf '[Journal]\\nStorage=volatile\\n' > "
            "/etc/systemd/journald.conf.d/zz-volatile.conf; "
            "systemctl restart systemd-journald"
        )
        _, rows = self.check_rows("check-journal-volatile")
        row = rows.get("decoy-persistence", {})
        self.check(
            "check no longer names the journal once it is volatile",
            judged_row(rows, "decoy-persistence")
            and "journal" not in str(row.get("message", "")).lower(),
            row or "check printed no decoy-persistence row",
        )

    def auditd(self) -> None:
        running = self.fact("auditd-before", "pgrep -x auditd || true")
        if not running:
            self.check("auditd runs on the stock image", False, "no auditd process")
            return
        _, rows = self.check_rows("check-auditd")
        row = rows.get("decoy-persistence", {})
        message = str(row.get("message", "")) + str(row.get("remediation", ""))
        self.check(
            "check refuses a running auditd",
            row.get("status") == "fail" and "audit" in message.lower(),
            row,
        )
        fix = str(row.get("remediation", ""))
        self.check(
            "check's fix for auditd is disable, mask and auditctl --signal stop",
            "auditctl --signal stop" in fix and "mask" in fix,
            fix,
            NEEDS_AUDITD_TEXT,
        )
        self.sh(
            "auditd-off",
            "systemctl disable auditd.service; systemctl mask auditd.service; "
            "auditctl --signal stop; "
            "for i in $(seq 30); do pgrep -x auditd >/dev/null || break; "
            "sleep 1; done; "
            "pgrep -x auditd; systemctl is-active auditd.service; true",
        )
        gone = self.fact("auditd-after", "pgrep -x auditd || echo gone")
        self.check(
            "auditd stops for good by the documented commands, without a reboot",
            gone == "gone",
            gone,
        )
        if gone == "gone":
            self.read_audit_log()
        _, rows = self.check_rows("check-auditd-off")
        row = rows.get("decoy-persistence", {})
        self.check(
            "check no longer names auditd once it is off",
            judged_row(rows, "decoy-persistence")
            and "audit"
            not in (
                str(row.get("message", "")) + str(row.get("remediation", ""))
            ).lower(),
            row or "check printed no decoy-persistence row",
        )

    def posture(self) -> None:
        """tuned, firewalld and ABRT, installed offline and started."""
        held = self.fact(
            "posture-in-image",
            "rpm -q " + " ".join(fedora_rpms.REQUESTED) + " 2>&1; true",
        )
        self.facts["posture-in-image"] = held
        status, out = self.sh(
            "posture-install", fedora_rpms.install_command("/run/rpms"), 1200
        )
        installed = status == 0 and all(
            f"{name}-" in out for name in fedora_rpms.REQUESTED
        )
        self.check(
            "the closure installs offline with every repository disabled",
            installed,
            out[-1500:],
        )
        # What the install leaves in the decoy's package database besides
        # the packages: the key it was checked with, recorded as a package.
        self.fact(
            "rpm-keys",
            "rpm -q gpg-pubkey "
            "--qf '%{NAME}-%{VERSION}-%{RELEASE} %{SUMMARY}\\n'; true",
        )
        if not installed:
            return
        self.sh(
            "posture-start",
            "systemctl daemon-reload; "
            "systemctl enable --now tuned.service firewalld.service abrtd.service; "
            "for u in tuned firewalld abrtd; do systemctl is-active $u.service; done",
            300,
        )
        self.fact(
            "posture-units",
            "systemctl cat tuned.service firewalld.service abrtd.service 2>&1 | "
            "grep -E '^(# /|ExecStart|EnvironmentFile)'; "
            "cat /etc/sysconfig/firewalld 2>&1; ps -eo comm,args | "
            "grep -E 'tuned|firewalld|abrtd' | grep -v grep",
        )
        # A refusal hides the warnings of its row, so each daemon is judged
        # where it shows: tuned's refusal first, then, with tuned fixed, the
        # warnings of firewalld and ABRT, then none of them with all fixed.
        status, rows = self.check_rows("check-posture")
        row = rows.get("decoy-persistence", {})
        found = {"tuned": row.get("status") == "fail" and "tuned" in json.dumps(row)}
        self.check(
            "check refuses tuned while it logs to its file",
            found["tuned"] and status == 4,
            row or status,
            NEEDS_POSTURE,
        )
        # tuned's documented fix: its units start it without -l.
        self.vm.succeed(
            "mkdir -p /etc/systemd/system/tuned.service.d && "
            f"printf %s {shlex.quote(TUNED_DROPIN)} > "
            "/etc/systemd/system/tuned.service.d/50-journal.conf && "
            "if systemctl cat tuned-ppd.service >/dev/null 2>&1; then "
            "mkdir -p /etc/systemd/system/tuned-ppd.service.d && printf %s "
            + shlex.quote("[Service]\nExecStart=\nExecStart=/usr/sbin/tuned-ppd\n")
            + " > /etc/systemd/system/tuned-ppd.service.d/50-journal.conf; fi; "
            "systemctl daemon-reload && systemctl restart tuned.service"
        )
        status, rows = self.check_rows("check-posture-tuned")
        row = rows.get("decoy-persistence", {})
        text = json.dumps(row)
        found["firewalld"] = row.get("status") == "warn" and "firewalld" in text
        found["ABRT"] = row.get("status") == "warn" and "abrt" in text.lower()
        self.check(
            "check names tuned no more after its documented fix",
            found["tuned"]
            and judged_row(rows, "decoy-persistence")
            and "tuned" not in text
            and status != 4,
            text,
            NEEDS_POSTURE,
        )
        self.check(
            "check warns of firewalld's log file",
            found["firewalld"],
            text,
            NEEDS_POSTURE,
        )
        self.check("check warns of ABRT", found["ABRT"], text, NEEDS_POSTURE)
        # The documented fixes of the other two: firewalld logs to the
        # journal, ABRT off.
        self.vm.succeed(
            "printf 'FIREWALLD_ARGS=--log-target=syslog\\n' "
            "> /etc/sysconfig/firewalld && "
            "systemctl restart firewalld.service && "
            "systemctl disable --now abrtd.service"
        )
        status, rows = self.check_rows("check-posture-fixed")
        text = json.dumps(rows.get("decoy-persistence", {}))
        for daemon in ("firewalld", "ABRT"):
            # Where check never named a daemon, a pass here would say nothing.
            self.check(
                f"check names {daemon} no more after its documented fix",
                found[daemon]
                and judged_row(rows, "decoy-persistence")
                and daemon.lower() not in text.lower(),
                text if found[daemon] else "not judged: check never named it",
                NEEDS_POSTURE,
            )

    def locate(self) -> None:
        plocate = self.fact("plocate", "rpm -q plocate 2>&1; true")
        _, rows = self.check_rows("check-locate")
        row = rows.get("locate-database", {})
        if "not installed" in plocate:
            self.check(
                "locate-database passes where plocate is not installed",
                row.get("status") == "pass",
                row,
            )
            self.facts["locate"] = "plocate absent"
            return
        self.facts["locate"] = plocate
        self.check(
            "locate-database refuses an updatedb that does not skip the volume",
            row.get("status") == "fail",
            row,
        )

    def lsm(self) -> None:
        _, rows = self.check_rows("check-lsm")
        row = rows.get("lsm-status")
        self.check(
            "lsm-status passes on the enforcing decoy",
            row is not None and row.get("status") == "pass",
            row,
            NEEDS_LSM,
        )
        self.sh("permissive", "setenforce 0; getenforce")
        _, rows = self.check_rows("check-lsm-permissive")
        self.sh("enforcing-again", "setenforce 1; getenforce")
        row = rows.get("lsm-status")
        self.check(
            "lsm-status warns once SELinux is permissive",
            row is not None and row.get("status") == "warn",
            row,
            NEEDS_LSM,
        )
        self.enforcing("again after setenforce 1")

    def clean_check(self) -> None:
        """check on the prepared decoy: nothing refuses, and what warns is
        only what the family table says of the release."""
        status, rows = self.check_rows("check-clean")
        failed = {
            name: row for name, row in rows.items() if row.get("status") == "fail"
        }
        warned = {
            name: row for name, row in rows.items() if row.get("status") == "warn"
        }
        self.facts["clean-check-warnings"] = warned
        self.check(
            "check refuses nothing on the prepared decoy",
            bool(rows) and not failed and status in (0, 9),
            {"exit": status, "rows": len(rows), "failed": failed},
        )
        allowed = dict(HARNESS_WARNINGS)
        if not self.settings.get("validated"):
            allowed["platform"] = "the family table does not validate the release yet"
        self.facts["clean-check-allowed"] = allowed
        self.check(
            "check warns of nothing on the prepared decoy but what the harness, "
            "the VM and an untested release bring",
            bool(rows) and set(warned) <= set(allowed),
            {name: row.get("message", "") for name, row in warned.items()},
        )

    def failed_positive(self) -> None:
        """A failed login on the decoy is recorded where the reader sees it:
        the records the gate reads can show one."""
        before = self.records_capture("before-decoy-failed-login")
        self.facts["decoy-failed-login"] = self.failed_login("decoy-failed-login", USER)
        after = self.records_capture("after-decoy-failed-login")
        added = self.records.utmp_added(before.btmp, after.btmp)
        self.check(
            "a failed login on the decoy writes a btmp record the reader sees",
            bool(added),
            added or self.facts["decoy-failed-login"][-500:],
        )

    # --- a session -------------------------------------------------------

    def before_entry(self, n: int) -> dict[str, Any]:
        """What the way back is compared with, taken on the decoy right before
        the entry."""
        state: dict[str, Any] = {}
        if n == 1:
            bind = self.fact(
                "utab-bind",
                f"mkdir -p {UTAB_BIND}; mountpoint -q {UTAB_BIND} || "
                f"mount --bind -o {UTAB_OPTION} {UTAB_BIND} {UTAB_BIND}; "
                f"grep -F TARGET={UTAB_BIND} /run/mount/utab",
            )
            self.check(
                "the decoy's utab holds the line of its bind mount before the entry",
                UTAB_OPTION in bind,
                bind,
            )
        state["bound"] = self.vm.execute(f"mountpoint -q {UTAB_BIND}")[0] == 0
        state["mountinfo"] = self.vm.succeed("cat /proc/self/mountinfo")
        state["utab"] = self.vm.succeed("cat /run/mount/utab 2>/dev/null || true")
        state["initramfs"] = self.initramfs()
        state["records"] = self.records_capture(f"before-{n}")
        state["noexec"] = "noexec" in self.vm.succeed("findmnt -no OPTIONS /run")
        state["failed"] = self.failed_units(f"failed-before-{n}")
        self.fact(f"swap-before-{n}", "swapon --show --noheadings; true")
        return state

    def enter(self, n: int, user: str, config: str, state: dict[str, Any]) -> bool:
        # The operator logs in on the decoy's console first, then checks and
        # activates.
        self.facts[f"operator-{n}"] = user
        self.sh(f"operator-login-{n}", self.pam_login(user, OPERATOR_TTY))
        status, rows = self.check_rows(f"check-before-{n}", user, config)
        self.facts[f"check-before-{n}"] = rows
        drift = rows.get("package-drift", {})
        self.facts[f"drift-{n}"] = drift
        # What the way back is held to, taken as close to the entry as the
        # harness can: /run as the decoy has it, and the time from which the
        # decoy disk's changes count.
        state["run"] = self.run_listing()
        state["since"] = self.wall()
        self.mark(f"enter-{n}")
        place = self.follow(
            self.nails("activate -y", user, config, to=f"{HIDDEN}/activate-{n}.log"),
            f"activate-{n}",
        )
        if place == "lost":
            return False
        self.where = f"hidden session {n}"
        self.mark(f"hidden-{n}")
        log = self.fact(f"activate-{n}.log", f"cat {HIDDEN}/activate-{n}.log")
        self.facts[f"activate-{n}.log"] = log
        if not self.check(f"session {n} starts", place == "hidden", log[-2000:]):
            return False
        return True

    def hidden(self, n: int, user: str, state: dict[str, Any]) -> None:
        """The assertions inside a hidden session."""
        vm = self.vm
        self.enforcing(f"in hidden session {n}")
        root = self.fact(f"root-{n}", "findmnt -no FSTYPE,OPTIONS /")
        self.check(
            f"session {n}'s / is the overlay on the hidden root",
            root.startswith("overlay") and f"upperdir={UPPER}" in root,
            root,
        )
        labels = self.fact(f"labels-{n}", "stat -c '%C %n' / /home /var")
        types = {
            line.split()[-1]: sg.context_type(line.split()[0])
            for line in labels.splitlines()
            if line.split()
        }
        self.check(
            f"session {n}: / is root_t, /home home_root_t, /var var_t",
            types == {"/": "root_t", "/home": "home_root_t", "/var": "var_t"},
            labels,
        )
        work = self.operator(
            "echo '# gate' >> /etc/protocols; echo n > /etc/gate-new; "
            "echo n > /root/gate-new; echo n > /var/tmp/gate-new; "
            "mkdir -p /home/gate-dir && echo n > /home/gate-dir/f"
        )
        made = self.fact(
            f"new-files-{n}",
            f"{work}; stat -c '%C %n' /etc/protocols /etc/gate-new /root/gate-new "
            f"/var/tmp/gate-new /home/gate-dir/f {UPPER}/etc/protocols "
            f"{UPPER}/etc/gate-new",
        )
        got = {
            line.split()[-1]: sg.context_type(line.split()[0])
            for line in made.splitlines()
            if len(line.split()) == 2
        }
        expected = {
            "/etc/protocols": "etc_t",
            f"{UPPER}/etc/protocols": "etc_t",
            "/etc/gate-new": "etc_t",
            f"{UPPER}/etc/gate-new": "etc_t",
            "/root/gate-new": "admin_home_t",
            "/home/gate-dir/f": "user_home_t",
        }
        self.check(
            f"session {n}: a copied-up file keeps its type, "
            "a new one gets the policy's",
            all(got.get(path) == kind for path, kind in expected.items()),
            made,
        )
        if user != "root":
            home = self.fact(
                f"fresh-home-{n}", f"stat -c '%C %n' /home/{user}; ls -A /home/{user}"
            )
            first = home.splitlines()[0].split() if home else []
            self.check(
                f"session {n}: the fresh home is user_home_dir_t",
                bool(first) and sg.context_type(first[0]) == "user_home_dir_t",
                home,
            )
        processes = self.fact(
            f"processes-{n}",
            "ps -e -o label=,pid=,comm=,args= | grep -E 'overlay-runtime|control' | "
            "grep -v grep; true",
        )
        nails_lines = [
            line for line in processes.splitlines() if "overlay-runtime" in line
        ]
        self.check(
            f"session {n}: NAILS's processes run unconfined, none in init_t",
            bool(nails_lines)
            and all(sg.unconfined(line.split()[0]) for line in nails_lines),
            processes,
            NEEDS_LABEL,
        )
        copy = self.fact(f"ram-copy-{n}", f"stat -c '%C' {RAM}")
        self.check(
            f"session {n}: the RAM copy is labelled bin_t",
            sg.context_type(copy) == "bin_t",
            copy,
            NEEDS_LABEL,
        )
        pairs = distro_checks.parse_findmnt_pairs(
            vm.succeed("findmnt -rn -t overlay -o TARGET,OPTIONS")
        )
        ours = distro_checks.nails_overlays(pairs, HIDDEN)
        violations = distro_checks.overlay_targets_with_violations(ours)
        self.check(
            f"session {n}: every NAILS overlay pins its feature options",
            bool(ours) and not violations,
            {"overlays": ours, "violations": violations},
        )
        mounts = distro_checks.parse_mount_targets(vm.succeed("findmnt -rn -o TARGET"))
        missing = []
        for tree in CANARY_TREES:
            path = f"/{tree}/{distro_checks.canary_name(tree)}-{n}"
            vm.succeed(f"mkdir -p /{tree} && echo {self.nonce}-{tree}-{n} > {path}")
            upper = distro_checks.canary_upper(HIDDEN, tree, mounts) + f"-{n}"
            if (
                vm.execute(f"grep -qF {self.nonce}-{tree}-{n} {shlex.quote(upper)}")[0]
                != 0
            ):
                missing.append(upper)
        self.check(f"session {n}: each canary lands in its upper", not missing, missing)
        failed = self.judge_failed(f"session {n}", f"failed-hidden-{n}")
        self.facts[f"failed-hidden-{n}"] = failed
        # A login and a failed login in the hidden session: their records land
        # in the session's own files, and none may reach the decoy.
        start = self.fact(
            f"hidden-start-{n}",
            "systemctl show -P UserspaceTimestamp --timestamp=unix",
        )
        self.facts[f"hidden-start-{n}"] = start.lstrip("@")
        self.sh(f"hidden-login-{n}", self.pam_login(USER))
        self.facts[f"hidden-failed-login-{n}"] = self.failed_login(
            f"hidden-failed-login-{n}", USER
        )
        inside = self.records_capture(f"hidden-{n}")
        before = state["records"]
        logins = [
            row
            for row in self.records.utmp_added(before.wtmp, inside.wtmp)
            if row.get("line") == LOGIN_TTY and row.get("type") == "USER_PROCESS"
        ]
        self.check(
            f"session {n}: the session's own wtmp records its login",
            bool(logins),
            logins or self.records.utmp_added(before.wtmp, inside.wtmp),
        )
        failures = self.records.utmp_added(before.btmp, inside.btmp)
        self.check(
            f"session {n}: the session's own btmp records its failed login",
            bool(failures),
            failures or self.facts[f"hidden-failed-login-{n}"][-500:],
        )
        state["hidden-btmp"] = failures
        _, label = self.sh(
            f"rt-{n}",
            f"touch {HIDDEN}/.gate-rt && chcon -t etc_t {HIDDEN}/.gate-rt && "
            f"stat -c %C {HIDDEN}/.gate-rt; rm -f {HIDDEN}/.gate-rt",
        )
        self.check(
            f"session {n}: the hidden volume keeps a security.selinux label",
            ":etc_t:" in label,
            label,
        )
        vm.succeed(f"echo {self.nonce}-{n} > {RUN_PROBE}-{n}")
        self.vm.execute(f"echo GATEIN-{self.nonce}-{n} > /dev/kmsg", check_return=False)
        self.read_kmsg()
        self.facts[f"in-session-seq-{n}"] = sg.marker_seq(
            self.boots[self.boot]["records"].values(), f"GATEIN-{self.nonce}-{n}"
        )

    def plant(self) -> None:
        """The rehearsal's first step in the first session, and the refusal
        of its scan there."""
        status, report, out = self.rehearse("rehearse-plant", "plant --user root")
        data = report.get("data", {})
        channels = data.get("channels", []) if isinstance(data, dict) else []
        self.facts["rehearse-plant"] = {"exit": status, "data": data}
        self.check(
            "session 1: the rehearsal plants its canary",
            status == 0
            and str(data.get("next_step", "")).startswith("Step 2 of 3")
            and any(
                c.get("kind") == "overlay-file" and "skipped" not in c for c in channels
            ),
            out[-2000:],
        )
        status, report, out = self.rehearse("rehearse-scan-in-session", "scan")
        self.check(
            "session 1: the rehearsal refuses its scan in the planting session",
            status == 6 and report.get("error", {}).get("code") == "same_boot",
            out[-1000:],
        )

    def scan(self) -> None:
        """The rehearsal's scan on the decoy, in the planting boot, after its
        first way back: nothing found, and the compressing root named as not
        checked."""
        self.sh("rehearse-hidden-root", HIDDEN_ROOT)
        _, token = self.sh(
            "rehearse-token",
            f"python3 -c 'import json; print(json.load(open(\"{HIDDEN}/rehearse/"
            "state.json\"))[\"token\"])'",
        )
        token = token.strip()
        status, report, out = self.rehearse("rehearse-status", "status")
        self.check(
            "way back 1: the rehearsal's next step is its scan",
            status == 0
            and str(report.get("data", {}).get("next_step", "")).startswith(
                "Step 3 of 3"
            ),
            out[-1000:],
        )
        root_device = self.fact("root-device", "findmnt -nvo SOURCE /")
        status, report, out = self.rehearse("rehearse-scan", "scan")
        scan = report.get("data", {}).get("scan", {}) or {}
        self.facts["rehearse-scan"] = {"exit": status, "scan": scan}
        problems = rehearse_scan_problems(status, scan, root_device)
        if token and token in out:
            problems.append("the scan printed the token")
        if not token:
            problems.append("the rehearsal's state holds no token")
        self.check(
            "way back 1: the rehearsal's scan finds nothing and names the "
            "compressing root as not checked",
            not problems,
            problems or scan,
        )

    def attach(self, serial: str, size: int) -> str:
        """Attach a sparse disk of ``size`` bytes, backed by a file on the
        driver's host, whose serial is ``serial``; the device's path."""
        image = os.path.abspath(f"gate-{self.nonce}-{serial}.img")
        with open(image, "wb") as handle:
            handle.truncate(size)
        self.vm.send_monitor_command(
            f"drive_add 0 if=none,id={serial},file={image},format=raw"
        )
        self.vm.send_monitor_command(
            f"device_add virtio-blk-pci,drive={serial},id={serial}d,serial={serial}"
        )
        return f"/dev/disk/by-id/virtio-{serial}"

    def hotplug(self, n: int) -> str:
        """A disk attached during the session, as a USB disk would be: the
        disk guard's udev rule sets it read-only as udev handles it, and
        records it. Its read-only flag is read as soon as udev has settled,
        and the watcher's sweep, the fallback, does not run again in the
        gate's sessions (:data:`CONFIG_TEXT`)."""
        rule = self.fact(f"guard-rule-{n}", f"cat {GUARD_RULE} 2>&1; true")
        self.check(
            f"session {n}: the disk guard's udev rule is in place",
            "guard-device" in rule,
            rule,
            NEEDS_LABEL,
        )
        disk = self.attach(f"extra{n}", HOTPLUG_BYTES)
        out = self.fact(
            f"hotplug-{n}",
            f"for i in $(seq 30); do [ -b {disk} ] && break; sleep 1; done; "
            f"udevadm settle -t 30; readlink -f {disk}; blockdev --getro {disk}",
        )
        lines = out.strip().splitlines()
        self.check(
            f"session {n}: a disk attached in the session reads getro 1",
            lines[-1:] == ["1"],
            out,
            NEEDS_LABEL,
        )
        node = lines[-2] if len(lines) >= 2 else disk
        record = self.fact(f"guard-record-{n}", f"cat {GUARD_RECORD} 2>&1; true")
        self.check(
            f"session {n}: the disk guard recorded the attached disk",
            any(line.split()[-1:] == [node] for line in record.splitlines()),
            {"disk": node, "record": record},
            NEEDS_LABEL,
        )
        return disk

    def leave(self, n: int, how: str, user: str, config: str) -> bool:
        self.mark(f"leave-{n}")
        self.facts[f"leave-wall-{n}"] = self.session.wall_clock(self.vm)
        if how == "deactivate":
            trigger = self.nails("deactivate -y", user, config)
        else:
            trigger = self.operator(
                f"{RAM} --config {config} emergency --json > /dev/null"
            )
        place = self.follow(trigger, f"{how}-{n}")
        if place == "lost":
            return False
        self.where = f"decoy after way back {n} ({how})"
        self.mark(f"back-{n}")
        return self.check(
            f"way back {n} ({how}) reaches the decoy", place == "decoy", place
        )

    def run_residue(self, n: int, state: dict[str, Any]) -> list[str]:
        """What the session left in /run: the entries carried over the way
        back (changed before it started, :data:`leave-wall`) that /run did not
        hold right before the entry."""
        return list(
            self.session.carried_run_residue(
                self.vm, state["run"], str(self.facts[f"leave-wall-{n}"])
            )
        )

    def after(self, n: int, state: dict[str, Any], disk: str | None) -> None:
        """The way-back assertions, on the decoy: taken before any login on it."""
        vm = self.vm
        # The records first, once the reconcile step is done, before any
        # login on the decoy writes its own, and the decoy disk's changes
        # before the harness writes anything.
        self.wait_reconcile()
        after = self.records_capture(f"after-{n}")
        self.disk_changes(f"way-back-{n}", state["since"])
        self.enforcing(f"after way back {n}")
        try:
            self.session.assert_decoy_root(vm)
            self.check(f"way back {n}: / is the plain decoy root", True)
        except AssertionError as error:
            self.check(f"way back {n}: / is the plain decoy root", False, str(error))
        self.read_kmsg()
        records = list(self.boots[self.boot]["records"].values())
        journal = self.fact(
            f"journal-k-json-{n}",
            "journalctl -D /run/log/journal -k -b 0 -o json "
            "--output-fields=_SOURCE_MONOTONIC_TIMESTAMP,MESSAGE --no-pager",
            300,
        )
        found = sg.cursor(
            records,
            journal,
            self.seq_of(f"enter-{n}"),
            self.seq_of(f"leave-{n}"),
            self.seq_of(f"back-{n}"),
        )
        self.facts[f"cursor-{n}"] = found
        self.check(
            f"way back {n}: the decoy's journal took no kernel record of the session",
            found["known"] and found["leakedFromSession"] == 0,
            found,
            NEEDS_LABEL,
        )
        marker = f"GATEIN-{self.nonce}-{n}"
        shown = self.fact(
            f"marker-in-journal-{n}",
            f"journalctl -k -b 0 -o cat --no-pager | grep -cF {marker}; true",
        )
        self.check(
            f"way back {n}: the session's kernel log marker "
            "is not in the decoy's journal",
            shown.strip() == "0",
            shown,
        )
        seqnum = sg.seqnum_from_od(
            self.fact(
                f"kernel-seqnum-{n}", "od -An -t u8 /run/systemd/journal/kernel-seqnum"
            )
        )
        marker_seq = self.facts.get(f"in-session-seq-{n}")
        self.check(
            f"way back {n}: journald's kmsg cursor is above the session's marker",
            seqnum is not None and isinstance(marker_seq, int) and seqnum > marker_seq,
            {"cursor": seqnum, "marker": marker_seq},
        )
        post = f"GATEPOST-{self.nonce}-{n}"
        vm.execute(f"echo {post} > /dev/kmsg", check_return=False)
        seen = self.fact(
            f"positive-{n}",
            f"sleep 3; journalctl -k -b 0 -o cat --no-pager | grep -cF {post}; true",
        )
        self.check(
            f"way back {n}: a marker written after it reaches the decoy's journal",
            seen.strip() == "1",
            seen,
        )
        gone = self.fact(
            f"run-probe-{n}",
            f"for p in {RUN_PROBE}-{n} {RUNTIME}; do "
            'test -e "$p" -o -L "$p" && echo "$p"; done; true',
        )
        self.check(
            f"way back {n}: the session's file in /run and NAILS's runtime "
            "folder are gone",
            not gone,
            gone,
        )
        residue = self.run_residue(n, state)
        self.facts[f"run-residue-{n}"] = residue
        self.check(
            f"way back {n}: nothing of the session stays in /run", not residue, residue
        )
        pieces = [
            p for p in WAY_BACK_PIECES if vm.execute(f"test -e {p} -o -L {p}")[0] == 0
        ]
        # Without the RAM copy's label, the decoy's policy keeps the reconcile
        # unit from running the copy, and the unit's pieces stay.
        self.check(
            f"way back {n}: the reconcile step left none of its pieces",
            not pieces,
            pieces,
            NEEDS_LABEL,
        )
        noexec = "noexec" in vm.succeed("findmnt -no OPTIONS /run")
        self.check(
            f"way back {n}: /run is "
            + ("noexec again, as" if state["noexec"] else "not noexec, as before")
            + " the decoy had it",
            noexec == state["noexec"],
            {"before": state["noexec"], "after": noexec},
        )
        utab_now = vm.succeed("cat /run/mount/utab 2>/dev/null || true")
        mountinfo = vm.succeed("cat /proc/self/mountinfo")
        foreign, lost = self.session_utab(state, utab_now, mountinfo)
        self.check(
            f"way back {n}: utab holds the lines it held, under their new mount IDs",
            not foreign and not lost,
            {"foreign": foreign, "lost": lost, "utab": utab_now},
        )
        bound = vm.execute(f"mountpoint -q {UTAB_BIND}")[0] == 0
        if state["bound"]:
            self.check(
                f"way back {n}: the decoy's bind mount is back with its utab line",
                bound
                and any(
                    f"TARGET={UTAB_BIND}" in line and UTAB_OPTION in line
                    for line in utab_now.splitlines()
                ),
                {"mounted": bound, "utab": utab_now},
            )
        else:
            self.facts[f"utab-bind-{n}"] = "not judged: the bind was not there before"
        self.check(
            f"way back {n}: /run/initramfs is unchanged",
            self.initramfs() == state["initramfs"],
            "",
        )
        if disk is not None:
            ro = self.fact(f"hotplug-after-{n}", f"blockdev --getro {disk}")
            self.check(
                f"way back {n}: the attached disk reads getro 0", ro.strip() == "0", ro
            )
        files = [f"/{t}/{distro_checks.canary_name(t)}-{n}" for t in CANARY_TREES]
        on_decoy = self.fact(
            f"session-files-{n}",
            "for p in "
            + " ".join(shlex.quote(p) for p in (*files, *SESSION_FILES))
            + '; do test -e "$p" -o -L "$p" && echo "$p"; done; '
            "grep -nx '# gate' /etc/protocols; true",
        )
        self.check(
            f"way back {n}: none of the session's files is on the decoy",
            not on_decoy,
            on_decoy,
        )
        failed = self.judge_failed(f"way back {n}", f"failed-after-{n}")
        self.facts[f"failed-after-{n}"] = failed
        self.records_judged(n, state, after)

    def session_utab(
        self, state: dict[str, Any], utab_now: str, mountinfo: str
    ) -> tuple[list[str], list[str]]:
        foreign, lost = self.utab.not_given_back(
            state["utab"], state["mountinfo"], utab_now, mountinfo
        )
        return list(foreign), list(lost)

    def records_judged(self, n: int, state: dict[str, Any], after: Any) -> None:
        """The login and boot records after the way back read as a plain
        shutdown and boot at the same moments: one boot record added, dated at
        the way back, and no record of the hidden session's login or failed
        login. The operator's own logins on the decoy, before the entry, are
        the decoy's: a row of theirs is dated before the switch."""
        records = self.records
        before = state["records"]
        window = (
            float(self.facts[f"leave-wall-{n}"]),
            float(self.session.wall_clock(self.vm)),
        )
        problems = records.classic_way_back_problems(before.wtmp, after.wtmp, window)
        self.check(
            f"way back {n}: wtmp gained the one boot a power cycle adds",
            not problems,
            problems or records.utmp_added(before.wtmp, after.wtmp),
        )
        hidden_login = [
            row
            for row in records.utmp_added(before.wtmp, after.wtmp)
            if row.get("line") == LOGIN_TTY
            and row.get("type") in ("USER_PROCESS", "LOGIN_PROCESS", "DEAD_PROCESS")
        ]
        self.check(
            f"way back {n}: wtmp holds no login of the hidden session",
            not hidden_login,
            hidden_login,
        )
        failed = records.utmp_added(before.btmp, after.btmp)
        self.check(
            f"way back {n}: btmp holds no failed login of the hidden session",
            bool(state.get("hidden-btmp")) and not failed,
            {"added": failed, "in the session": state.get("hidden-btmp")},
        )
        operator = str(self.facts.get(f"operator-{n}", ""))
        # The hidden session's own time: from the start of its userspace,
        # which the operator's logins for check and activate come before,
        # to its way back.
        start = str(self.facts.get(f"hidden-start-{n}", ""))
        entered = float(start) if start.replace(".", "", 1).isdigit() else 0.0
        left = float(self.facts[f"leave-wall-{n}"])
        added = records.sql_rows_added(before.lastlog2, after.lastlog2)
        inside = [
            row
            for row in after.lastlog2
            if isinstance(row.get("Time"), int) and entered <= row["Time"] <= left + 2
        ]
        self.check(
            f"way back {n}: lastlog2 holds no row dated inside the session",
            not inside,
            {"added": added, "inside": inside},
        )
        self.facts[f"lastlog2-added-{n}"] = added
        self.check(
            f"way back {n}: lastlog2 rows added are the operator's own, "
            "before the entry",
            entered > 0
            and all(
                isinstance(row.get("Time"), int)
                and row["Time"] < entered
                and row.get("Name") in ("root", USER)
                for row in added
            )
            and not inside,
            added,
        )
        # The operator's console login right before the entry is the decoy's
        # own: the records keep it, dated before the session.
        console = [
            row
            for row in records.utmp_added(before.wtmp, after.wtmp)
            if row.get("line") == OPERATOR_TTY
            and row.get("type") == "USER_PROCESS"
            and row.get("user") == operator
            and 0 < float(str(row.get("tv_sec", 0))) < entered
        ]
        self.check(
            f"way back {n}: wtmp keeps the operator's console login, dated "
            "before the entry",
            bool(console),
            console or records.utmp_added(before.wtmp, after.wtmp),
        )
        if self.settings.get("lastlog2"):
            # lastlog2 keeps one row a user, the last login: the operator's
            # commands after the console login are logins of theirs too
            # (pam_lastlog2 writes them without a terminal), so the row is
            # the last of those, dated from the console login to the entry.
            since = min((int(row.get("tv_sec", 0)) for row in console), default=0)
            last = [
                row
                for row in after.lastlog2
                if row.get("Name") == operator
                and isinstance(row.get("Time"), int)
                and 0 < since <= row["Time"] < entered
            ]
            self.check(
                f"way back {n}: lastlog2 keeps the operator's last login on the "
                "decoy, dated from the console login to the entry",
                bool(last),
                {"console": since, "entered": entered, "rows": after.lastlog2},
            )

    # --- the controls ----------------------------------------------------

    def control(self, label: str) -> None:
        since = self.wall()
        self.mark(f"{label}-start")
        place = self.follow("systemctl soft-reboot", label)
        if place == "lost":
            return
        self.mark(f"{label}-end")
        self.wait_reconcile()
        self.disk_changes(label, since)
        self.enforcing(f"after {label}")
        failed = self.failed_units(f"failed-{label}")
        swap = self.fact(f"swap-{label}", "swapon --show --noheadings; true")
        found = failed_units_problems(failed, self.allowed_failed)
        self.check(f"after {label}: no NAILS unit failed", not found["nails"], failed)
        if label == "control-1":
            # What a plain soft-reboot leaves failed before any session may
            # be failed after a way back too.
            for unit in found["other"]:
                self.allowed_failed[unit] = f"failed after the plain {label} as well"
        self.facts.setdefault("known-failed-units", {})[f"after {label}"] = [
            *found["known"],
            *found["other"],
        ]
        self.facts[f"failed-{label}"] = {"failed": failed, "swap": swap}

    def judge_disk(self) -> None:
        """The decoy disk after each way back changed only where a plain
        soft-reboot changed it, its login records aside, which the records
        checks judge: a label or a file the session or NAILS wrote on the
        decoy would show as a path no control changed."""
        self.where = "the decoy disk"
        controls = [paths for label, paths in self.disk.items() if "control" in label]
        self.facts["disk-controls"] = {
            label: sorted(paths)
            for label, paths in self.disk.items()
            if "control" in label
        }
        for label, paths in self.disk.items():
            if not label.startswith("way-back-"):
                continue
            residue = decoy_disk_residue(paths, controls)
            self.check(
                f"{label.replace('-', ' ')}: the decoy disk changed only where a "
                "plain soft-reboot changes it",
                bool(controls) and not residue,
                {"changed": sorted(paths), "not in a control": residue}
                if controls
                else "no control was taken",
            )

    def records_positive(self) -> None:
        """A login on the decoy is recorded where the reader sees it: the
        records the gate reads can show a login."""
        before = self.records_capture("before-decoy-login")
        self.sh("decoy-login", self.pam_login(USER))
        after = self.records_capture("after-decoy-login")
        logged = [
            row
            for row in self.records.utmp_added(before.wtmp, after.wtmp)
            if row.get("line") == LOGIN_TTY and row.get("type") == "USER_PROCESS"
        ]
        self.check(
            "a login on the decoy writes wtmp records the reader sees",
            bool(logged),
            logged,
        )
        rows = self.records.sql_rows_added(before.lastlog2, after.lastlog2)
        self.facts["decoy-login-lastlog2"] = rows
        if self.settings.get("lastlog2"):
            self.check(
                "a login on the decoy writes a lastlog2 row the reader sees",
                bool(rows),
                rows,
            )

    # --- the denials -----------------------------------------------------

    @staticmethod
    def baseline_labels(boot: Mapping[str, Any]) -> set[str]:
        """The phases of ``boot`` whose denials, NAILS's aside, are what the
        decoy logs without NAILS: those of the reference boot before the
        first entry (the decoy prepared as a user prepares it: accounts,
        packages, settings, logins, and the first plain soft-reboot), each
        run of check aside, which runs in a phase of its own."""
        if boot.get("why") != "reference":
            return set()
        found = set()
        for marker in boot.get("markers", []):
            label = str(marker["label"])
            if label == "enter-1":
                break
            if not label.startswith("check-"):
                found.add(label)
        return found

    def phases(
        self, boot: Mapping[str, Any]
    ) -> list[tuple[str | None, int | None, int | None, list[Mapping[str, Any]]]]:
        """The phases of ``boot``: the part before its first marker, then one
        a marker, each with its bounds in the kernel log and the records
        auditd's log holds of it, by the wall clock of its markers."""
        markers = [m for m in boot["markers"] if m["seq"] is not None]
        audit = boot.get("audit", [])
        found: list[
            tuple[str | None, int | None, int | None, list[Mapping[str, Any]]]
        ] = []
        if markers:
            first = markers[0]
            found.append(
                (None, None, first["seq"], in_window(audit, None, wall_of(first)))
            )
        for start, end in zip(markers, [*markers[1:], None], strict=False):
            found.append(
                (
                    start["label"],
                    start["seq"],
                    end["seq"] if end else None,
                    in_window(audit, wall_of(start), wall_of(end) if end else None),
                )
            )
        return found

    def baseline(self) -> set[str]:
        """The signatures of the denials logged without NAILS: the reference
        boot before the first entry, each check aside (:meth:`baseline_labels`).
        A denial of a NAILS process or path never counts."""
        found: set[str] = set()
        for boot in self.boots:
            if boot["why"] != "reference":
                continue
            records = list(boot["records"].values())
            labels = self.baseline_labels(boot)
            for label, first, last, audit in self.phases(boot):
                if label is not None and label not in labels:
                    continue
                window = sg.phase(records, first, last, audit=audit)
                found |= {
                    a["signature"] for a in window["denials"] if a["source"] != "nails"
                }
        return found

    def judge_denials(self) -> None:
        """Every phase NAILS ran in, in both roots, holds no new denial, and
        no phase holds a denial of NAILS's own; the kernel lost no record, and
        no audit record of the boot reached neither log."""
        known = self.baseline()
        self.facts["baseline-signatures"] = sorted(known)
        for boot in self.boots:
            records = list(boot["records"].values())
            dropped = boot["dropped"] or sg.gaps(sorted(boot["records"]))
            self.where = f"boot {boot['why']}"
            self.check("the kernel log lost no record", not dropped, dropped)
            missing = [m["label"] for m in boot["markers"] if m["seq"] is None]
            self.check("every marker reached the kernel log", not missing, missing)
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            if not markers:
                continue
            audit = boot.get("audit", [])
            serials = sg.audit_serials(r["msg"] for r in records) | {
                int(r["serial"]) for r in audit
            }
            # From the first marker on, after the gate lifted printk's rate
            # limit: what the boot's start lost there, before NAILS ran, is
            # recorded only.
            first = markers[0]
            later = sg.audit_serials(
                r["msg"] for r in records if int(r["seq"]) > int(first["seq"])
            ) | {
                int(r["serial"])
                for r in in_window(audit, wall_of(first), None)
            }
            start = min(later, default=None)
            holes = sg.serial_gaps(serials, start) if start is not None else []
            self.facts[f"audit-serials-{boot['why']}"] = {
                "fromFirstMarker": start,
                "highest": max(serials, default=None),
                "lostAtTheBootsStart": sg.serial_gaps(
                    {s for s in serials if start is None or s <= start}
                ),
            }
            self.check(
                "every audit record of the boot from its first marker on is in the "
                "kernel log or auditd's log",
                start is not None and not holes,
                {
                    "from": start,
                    "gaps": holes[:20],
                    "highest": max(serials, default=None),
                },
            )
            labels = self.baseline_labels(boot)
            for label, first, last, audit in self.phases(boot):
                found = sg.phase(records, first, last, known, audit)
                name = label or "the boot's start"
                boot.setdefault("phases", []).append({"label": name, **found})
                self.check(
                    f"the kernel lost no record from {name} on",
                    not found["suppressed"],
                    found["suppressed"][:10],
                )
                new = found["new"]
                where = f"{'marker ' + label if label else name}"
                if label is None or label in labels:
                    new = [a for a in new if a["source"] == "nails"]
                elif self.settings.get("dontaudit") is False:
                    # Without the dontaudit rules the policy's quiet denials of
                    # every program show: those of NAILS are judged, the others
                    # recorded.
                    self.facts.setdefault("noda-other-new", {})[where] = [
                        f"{a['signature']} ({a['why']}, {a['log']} log)"
                        for a in new
                        if a["source"] != "nails"
                    ]
                    new = [a for a in new if a["source"] == "nails"]
                needs = NEEDS_LABEL if any(a["source"] == "nails" for a in new) else ""
                self.check(
                    f"no new denial from {where} on",
                    not new,
                    [f"{a['signature']} ({a['why']}, {a['log']} log)" for a in new],
                    needs,
                )
                if label is None:
                    continue
                if label.split("-")[0] in ("enter", "leave", "control") and not (
                    label.endswith("-end")
                ):
                    # Each switch keeps the decoy's loaded policy: PID 1's load
                    # of the new root's policy fails, as at a plain
                    # soft-reboot, and nothing else is loaded.
                    loads = found["policy"]
                    self.check(
                        f"the switch from marker {label} keeps the decoy's policy",
                        any(POLICY_KEPT in line for line in loads)
                        and not any(POLICY_LOADED in line for line in loads),
                        loads,
                    )

    # --- the run ---------------------------------------------------------

    def write(self) -> None:
        os.makedirs(self.out_dir, exist_ok=True)
        base = os.path.join(self.out_dir, self.name)
        failed = [c for c in self.checks if not c["passed"]]
        result = {
            "image": self.image,
            "settings": self.settings,
            "nonce": self.nonce,
            "passed": not failed,
            "checks": self.checks,
            "failed": [c["name"] for c in failed],
            "facts": self.facts,
            "boots": [
                {key: value for key, value in boot.items() if key != "records"}
                for boot in self.boots
            ],
        }
        with open(base + ".json", "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=1, sort_keys=True, default=str)
        with open(base + ".raw.json", "w", encoding="utf-8") as handle:
            json.dump(self.raw, handle, indent=1, sort_keys=True)
        with open(base + ".kmsg.txt", "w", encoding="utf-8") as handle:
            for index, boot in enumerate(self.boots):
                for seq in sorted(boot["records"]):
                    record = boot["records"][seq]
                    handle.write(f"{index} {seq} {record['us']} {record['msg']}\n")
        print(
            f"=== the gate of {self.image}: {len(self.checks) - len(failed)} of "
            f"{len(self.checks)} assertions hold ==="
        )
        for entry in self.checks:
            word = "PASS" if entry["passed"] else "FAIL"
            needs = (
                f" [needs {entry['needs']}]"
                if entry["needs"] and not entry["passed"]
                else ""
            )
            print(f"{word} {entry['where']}: {entry['name']}{needs}")

    def run(self) -> None:
        self.new_boot("first")
        try:
            self.flows()
        except Exception as error:  # noqa: BLE001 - recorded, then the run fails
            self.check(
                "the run reaches its end", False, f"{error}\n{traceback.format_exc()}"
            )
        finally:
            try:
                self.judge_disk()
            except Exception as error:  # noqa: BLE001
                self.check("the decoy disk is judged", False, str(error))
            try:
                self.judge_denials()
            except Exception as error:  # noqa: BLE001
                self.check("the denials are judged", False, str(error))
            self.write()
        failed = [c["name"] for c in self.checks if not c["passed"]]
        assert not failed, f"{len(failed)} assertions of the gate do not hold: {failed}"

    def flows(self) -> None:
        """The run's steps, in order; a switch that is lost ends them."""
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        self.prepare()
        self.attach(HIDDEN_DISK, HIDDEN_BYTES)
        self.sh("prepare-decoy", PREPARE_DECOY)
        if self.settings.get("dontaudit") is False:
            self.sh("no-dontaudit", NO_DONTAUDIT, 900)
        self.power_cycle("reference")
        self.fact("cmdline", "cat /proc/cmdline")
        self.mark("boot-ready")
        self.decoy()
        self.control("control-1")
        # The first session: shared home, ended with deactivate.
        self.sh("hidden-root-1", HIDDEN_ROOT)
        state = self.before_entry(1)
        self.mark("prep-session-1")
        if self.enter(1, "root", CONFIG, state):
            self.hidden(1, "root", state)
            disk = self.hotplug(1)
            self.plant()
            self.sh(
                "hidden-rpm-1",
                "rpm -e --nodeps --noscripts "
                + shlex.quote(self.settings["hiddenRemoves"]),
            )
            if self.leave(1, "deactivate", "root", CONFIG):
                self.after(1, state, disk)
                self.scan()
        if self.lost:
            return
        # The decoy changes its own packages after the hidden session
        # copied the database: the next entry's drift.
        self.where = "decoy between the sessions"
        self.mark("prep-drift")
        removed = self.settings["decoyRemoves"]
        self.sh(
            "decoy-rpm",
            f"rpm -e --nodeps --noscripts {shlex.quote(removed)}; "
            f"rpm -q {shlex.quote(removed)}",
        )
        self.sh("hidden-root-2", HIDDEN_ROOT)
        _, rows = self.check_rows("check-drift")
        row = rows.get("package-drift", {})
        # The row's message names each drifted package and what to run in a
        # hidden session to bring the copy back in line.
        text = str(row.get("message", "")) + str(row.get("remediation", ""))
        self.check(
            "package-drift warns of the package the decoy removed, with its fix",
            row.get("status") == "warn" and removed in text and "sudo dnf" in text,
            row,
        )
        state = self.before_entry(2)
        if self.enter(2, USER, FRESH_CONFIG, state):
            log = self.facts.get("activate-2.log", "")
            self.check(
                "the entry shows the drift advisory with its fix",
                removed in log,
                log[-2000:],
            )
            self.hidden(2, USER, state)
            disk = self.hotplug(2)
            if self.leave(2, "emergency", "root", FRESH_CONFIG):
                self.after(2, state, disk)
        if self.lost:
            return
        self.control("control-2")
        self.mark("prep-login")
        self.records_positive()
        # The kernel log read to the end: the audit serials are judged up to
        # the last record read.
        self.mark("run-end")


def run(
    vm: Any,
    session: Any,
    utab: Any,
    records: Any,
    settings: dict[str, Any],
) -> None:
    """Run the gate of the image ``settings`` names on ``vm``, with the e2e
    package's ``session`` and ``utab`` helpers and the ``records`` readers."""
    out_dir = os.environ.get("NAILS_GATE_OUT") or os.getcwd()
    Gate(vm, session, utab, records, settings, out_dir).run()
