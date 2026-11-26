"""The gate scenario of an Arch decoy, before Arch is admitted.

``nix/distro-tests/arch-gate.nix`` builds one host driver per Arch image of
the gate (``<image>-gate``) and calls :func:`run` with the driver's machine.
NAILS is a test-only build that admits Arch (``lib/admitted.nix``). The
scenario is the Fedora gate's (:mod:`fedora_gate`), run on Arch: the same
switches in one QEMU process, the same reading of the kernel log, of the
decoy's journal and of its login and boot records, and the same comparisons
with a plain soft-reboot. What differs is what Arch is:

- no mandatory access control runs. The Arch kernel starts neither SELinux nor
  AppArmor, so there is no denial to count and no label to read. Where the
  Fedora gate asserts SELinux enforcing, this one asserts the kernel's list of
  security modules (``/sys/kernel/security/lsm``): no SELinux and no AppArmor
  in it, no selinuxfs, and the same list in every root. ``lsm-status`` must
  pass on the decoy and name each module of that list. Where the Fedora gate
  holds a way back to the SELinux booleans the decoy had, this one holds it to
  the kernel's security state a session could change and a soft-reboot would
  keep: the module list, the lockdown mode and Yama's ptrace scope. In place
  of the denials, the kernel log of every boot is judged whole
  (:meth:`ArchGate.judge_denials`): no record lost, every marker in it, no
  notice of a suppressed record from the gate's first marker on, and no gap
  in the audit serial numbers;
- the decoy is prepared as ``docs/decoy-requirements.md`` asks of any decoy
  (what NAILS enforces, and the lid switch), in the way arch-boxes needs it:
  the journal volatile (check refuses the stock persistent one first), the
  fstab's swap line ``noauto`` and the swap off, ``init_on_free=1`` and the
  Fedora gate's ``log_buf_len`` on the kernel command line through GRUB, core
  dumps discarded, the lid switch locking the screen. auditd is installed but
  off on arch-boxes, and check must name no auditd; plocate is judged where
  the image has it;
- the hidden volume is LUKS on a disk of its own, as the image ships
  cryptsetup;
- the package-drift control is pacman's: a package the gate builds in RAM
  (:func:`drift_package`, three versions), installed on the decoy, updated
  in the first hidden session and updated again on the decoy after it, so
  that hidden sessions list it twice: check warns of it with pacman's fix,
  and the second entry shows the advisory with that fix. pacman's hook marks
  /etc and /var out of date with /usr after each transaction, which the next
  start of PID 1 brings up to date (``ConditionNeedsUpdate=``): the first
  version is installed before the reference boot, and the gate runs that
  update by hand after the third. The state reads out of date right after
  the first and the third install, the positive control
  (:meth:`ArchGate.left_pending`), and up to date after the reference boot
  and the run by hand; no control's changes of a pending update excuse a way
  back's (:func:`fedora_gate.same_state`);
- zram: arch-boxes sets up no zram device and has no zram-generator. The
  cold boot decides (:func:`zram_applies`): where it set zram up, every zram
  check of the Fedora gate runs; where not, none does and the run records
  why. An archinstall image with its default zram swap would run them. Each
  session must run no swap on a disk;
- NAILS's processes in a session run as root from its copy in RAM
  (``/proc/<pid>/exe``, :func:`processes_from_ram`), and no process runs a
  program of NAILS's from elsewhere (:func:`nails_elsewhere`); each session
  writes a file on ``/efi`` (:data:`EFI_PROBE`) that must not be on the
  decoy after the way back;
- the guest runs the driver's own Python (``python`` of the settings) from
  the Nix store the harness mounts, for the reading of the kernel log, the
  failed console logins and the rehearsal's state, so the gate does not
  depend on a Python in the image. The run records whether the image has
  one (``image-python``).

The run writes ``<image>-gate.json``, ``<image>-gate.raw.json`` and
``<image>-gate.kmsg.txt`` into the directory ``NAILS_GATE_OUT`` names, and
fails at its end when an assertion does not hold.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import distro_checks
import fedora_gate as fg
import selinux_gate as sg

# The share the driver mounts: the binary alone, as no package closure is
# installed offline on Arch.
SHARES = (("tools", "/run/tools"),)
# The hidden volume: LUKS on a disk of its own, attached at the start of the
# run and backed by a file on the driver's host, so that it survives every
# switch, the second session finds the first one's upper on it, and nothing
# of it is on the decoy disk. The mapping keeps a neutral name. Opened again
# after a way back where the way back closed it.
PASSPHRASE = "test-passphrase"
MAPPING = "data"
HIDDEN_ROOT = f"""
set -eu
for i in $(seq 30); do [ -b {fg.HIDDEN_DEVICE} ] && break; sleep 1; done
if ! mountpoint -q {fg.HIDDEN} ; then
  if ! cryptsetup isLuks {fg.HIDDEN_DEVICE}; then
    printf %s {PASSPHRASE} | cryptsetup luksFormat -q --type luks2 \\
      --pbkdf pbkdf2 --iter-time 1 {fg.HIDDEN_DEVICE} -
  fi
  [ -e /dev/mapper/{MAPPING} ] || printf %s {PASSPHRASE} | \\
    cryptsetup open --key-file - {fg.HIDDEN_DEVICE} {MAPPING}
  blkid /dev/mapper/{MAPPING} >/dev/null 2>&1 || mkfs.ext4 -q /dev/mapper/{MAPPING}
  mkdir -p {fg.HIDDEN}
  mount /dev/mapper/{MAPPING} {fg.HIDDEN}
fi
mkdir -p {fg.HIDDEN}/root/work {fg.HIDDEN}/config
"""
# The decoy prepared as its requirements ask, beyond what the gate checks
# before and after its fix: the kernel log's settings at every start, core
# dumps discarded, the lid switch locking the screen, freed memory zeroed, and
# the kernel's log buffer as large as the Fedora gate makes it
# (:data:`fedora_gate.LOG_BUF_LEN`), which every power cycle checks. Both
# arguments go on the kernel command line through GRUB, from the next boot on:
# arch-boxes boots SeaBIOS and GRUB; an image that boots systemd-boot needs
# them in its loader entries instead. The swap is turned off apart
# (:meth:`ArchGate.swap_off`).
PREPARE_DECOY = (
    """
set -eu
printf '%s\\n' """
    + " ".join(f"'{key} = {value}'" for key, value in sg.KMSG_SETTINGS)
    + """ \\
  > /etc/sysctl.d/50-kmsg.conf
mkdir -p /etc/systemd/logind.conf.d
printf '%s\\n' '[Login]' HandleLidSwitch=lock HandleLidSwitchExternalPower=lock \\
  HandleLidSwitchDocked=ignore IdleAction=ignore \\
  > /etc/systemd/logind.conf.d/10-lid.conf
for arg in init_on_free=1 log_buf_len=""" + fg.LOG_BUF_LEN + """; do
  grep -q "$arg" /etc/default/grub ||
    sed -i "s|^\\(GRUB_CMDLINE_LINUX_DEFAULT=\\"[^\\"]*\\)\\"|\\1 $arg\\"|" \\
      /etc/default/grub
done
grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub
grub-mkconfig -o /boot/grub/grub.cfg
"""
)
# What check warns of on the prepared decoy because of the harness and the VM,
# not the decoy: each with why.
HARNESS_WARNINGS = {
    "binary-location": "the harness shares the binary into /run over 9p",
    "decoy-nix-trace": "the harness mounts its own Nix store into the VM",
    "dma-protection": "the VM has no IOMMU",
}
# The kernel's security state a session could change and a soft-reboot keeps:
# the security modules it runs, its lockdown mode, Yama's ptrace scope, and
# whether a selinuxfs exists.
SECURITY_STATE = (
    "cat /sys/kernel/security/lsm; echo; "
    "echo lockdown: $(cat /sys/kernel/security/lockdown 2>&1); "
    "echo ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>&1); "
    "test -e /sys/fs/selinux && echo selinuxfs || echo no selinuxfs"
)
# The mandatory access control modules NAILS would have to be tested with: on
# Arch none may run.
MAC_MODULES = ("selinux", "apparmor", "smack", "tomoyo")
# pacman's settings for the drift control: the package the gate builds is not
# signed, and the image's keyring is never set up (the image masks its
# pacman-init unit), so the gate's pacman checks no signature. Everything else
# is pacman's default: the decoy's database, log and hooks.
PACMAN_CONF = "/run/gate-pacman.conf"
PACMAN_CONF_TEXT = "[options]\nSigLevel = Never\nLocalFileSigLevel = Never\n"
# The drift control's package and the folder in RAM it is built in.
DRIFT_PACKAGE = "gate-drift"
DRIFT_DIR = "/run/gate-pkg"
# The fix check's package-drift row gives for pacman.
DRIFT_FIX = "sudo pacman -U"
# The units that bring /etc and /var up to date with /usr, which PID 1 runs at
# a start where an update is pending (``ConditionNeedsUpdate=``): pacman's
# hook for systemd marks one pending after every transaction that changes
# /usr.
UPDATE_UNITS = (
    "grep -l '^ConditionNeedsUpdate=' /usr/lib/systemd/system/*.service "
    "2>/dev/null | xargs -rn1 basename | sort -u"
)
# The update state of a decoy whose /etc and /var follow /usr
# (:func:`fedora_gate.update_state`), and the one pacman's hook leaves after a
# transaction, the positive control of that reading.
UP_TO_DATE = "/etc current; /var current"
PENDING = "/etc pending; /var pending"
# Every process with the program it runs (``/proc/<pid>/exe``), the kernel's
# threads, which run none, aside.
PROCESS_EXES = (
    'for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue; '
    'echo "${p#/proc/} $e"; done'
)
# What readlink of /proc/<pid>/exe adds for a program deleted since it started.
DELETED = " (deleted)"
# The names of NAILS's programs: the binary the harness shares and the copy
# in RAM it runs from.
NAILS_PROGRAMS = ("nails", "control")
# A file each session tries to write on the ESP (``/efi``), which the hidden
# session masks and binds read-only: whatever the write does, the file must
# not be on the decoy's ESP after the way back, whose files the way back's
# comparison of the FAT filesystems also holds to their bytes.
EFI_PROBE = "/efi/gate-efi"
# What check gives on the stock arch-boxes image before the decoy is prepared:
# each row, its verdict, the words its message and fix name, and the
# assertion. The swap row is arch-boxes's swap file; an image with another
# swap or none needs rows of its own.
STOCK_VERDICTS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("swap", "fail", (), "check refuses the stock image's active swap file"),
    (
        "decoy-persistence",
        "fail",
        ("journal",),
        "check refuses the stock image's persistent journal",
    ),
    ("sleep-policy", "warn", ("lid",), "check warns of a lid that suspends"),
    (
        "memory-wipe",
        "warn",
        ("init_on_free=1",),
        "check warns that the stock kernel does not zero freed memory",
    ),
)
# zram-generator's program, where an image ships it.
ZRAM_GENERATOR = "/usr/lib/systemd/system-generators/zram-generator"


def lsm_list(state: str) -> list[str]:
    """The security modules the kernel runs, from the first line of
    :data:`SECURITY_STATE` (``/sys/kernel/security/lsm``)."""
    first = state.splitlines()[0] if state.splitlines() else ""
    return [name.strip() for name in first.split(",") if name.strip()]


def mac_running(lsms: Iterable[str], state: str) -> list[str]:
    """The mandatory access control modules among ``lsms``, and selinuxfs
    where :data:`SECURITY_STATE` found one."""
    found = [name for name in lsms if name in MAC_MODULES]
    if "selinuxfs" in (line.strip() for line in state.splitlines()):
        found.append("selinuxfs")
    return found


def lsm_not_named(message: str, lsms: Iterable[str]) -> list[str]:
    """The modules of ``lsms`` that lsm-status's message does not name."""
    lowered = message.lower()
    return [name for name in lsms if name.lower() not in lowered]


def pkginfo(version: str, builddate: int) -> str:
    """The ``.PKGINFO`` of the drift control's package at ``version``."""
    return (
        f"pkgname = {DRIFT_PACKAGE}\n"
        f"pkgbase = {DRIFT_PACKAGE}\n"
        f"pkgver = {version}-1\n"
        "pkgdesc = the admission gate's package-drift control\n"
        f"builddate = {builddate}\n"
        "packager = gate\n"
        "size = 2\n"
        "arch = any\n"
        "license = GPL-3.0-or-later\n"
    )


def drift_file(version: str) -> str:
    """Where :func:`drift_package` builds the package of ``version``."""
    return f"{DRIFT_DIR}/{DRIFT_PACKAGE}-{version}-1-any.pkg.tar.zst"


def drift_package(version: str, builddate: int) -> str:
    """The guest command that builds the drift control's package of
    ``version`` in RAM: one file, its ``.PKGINFO``, packed by bsdtar as
    makepkg packs one."""
    tree = f"{DRIFT_DIR}/{version}"
    info = shlex.quote(pkginfo(version, builddate))
    return (
        f"rm -rf {tree} && mkdir -p {tree}/usr/share/{DRIFT_PACKAGE} && "
        f"echo {version} > {tree}/usr/share/{DRIFT_PACKAGE}/version && "
        f"printf %s {info} > {tree}/.PKGINFO && "
        f"( cd {tree} && bsdtar --zstd -cf {drift_file(version)} .PKGINFO usr ) && "
        f"ls -l {drift_file(version)}"
    )


def pacman_install(version: str, builddate: int) -> str:
    """The guest command that installs the drift control's package of
    ``version`` with :data:`PACMAN_CONF`, then lists what pacman holds of
    it."""
    return (
        f"printf %s {shlex.quote(PACMAN_CONF_TEXT)} > {PACMAN_CONF} && "
        f"{drift_package(version, builddate)} && "
        f"pacman --config {PACMAN_CONF} -U --noconfirm {drift_file(version)}; "
        f"echo rc=$?; pacman -Q {DRIFT_PACKAGE}; "
        f"ls -d /var/lib/pacman/local/{DRIFT_PACKAGE}-*"
    )


def installed_version(listing: str) -> str | None:
    """The version ``pacman -Q`` lists for the drift control's package."""
    for line in listing.splitlines():
        words = line.split()
        if len(words) == 2 and words[0] == DRIFT_PACKAGE:
            return words[1]
    return None


# How fstab-policy's warning begins, and the one note of it the image's own
# layout brings: its masked filesystems are not in the hidden session.
FSTAB_SUMMARY = "decoy filesystems in the hidden root: "
FSTAB_NOTE = "Masked and skipped filesystems are not available in the hidden session."


def fstab_items(message: str) -> list[str]:
    """What fstab-policy's warning names, each as ``<path>: <verdict>``
    without its reason, sorted: the items between ``hidden root:`` and the
    end of that sentence (:func:`fstab_notes` gives what follows it)."""
    _, _, rest = message.partition("hidden root: ")
    rest = rest.split(". ", 1)[0]
    items = []
    for item in rest.split("; "):
        path, _, verdict = item.partition(": ")
        if not path or not verdict:
            continue
        items.append(f"{path.strip()}: {verdict.split(' (', 1)[0].strip()}")
    return sorted(items)


def fstab_notes(message: str) -> str | None:
    """What fstab-policy's warning says after the sentence that names its
    items, or None where the warning does not begin as fstab-policy's does
    (:data:`FSTAB_SUMMARY`)."""
    if not message.startswith(FSTAB_SUMMARY):
        return None
    _, _, notes = message[len(FSTAB_SUMMARY) :].partition(". ")
    return notes.strip()


def process_exes(text: str) -> dict[str, str]:
    """Each process :data:`PROCESS_EXES` listed, with its program."""
    found = {}
    for line in text.splitlines():
        pid, _, exe = line.partition(" ")
        if pid.isdigit() and exe:
            found[pid] = exe
    return found


def nails_elsewhere(exes: str) -> list[str]:
    """The processes :data:`PROCESS_EXES` listed that run a program of
    NAILS's (:data:`NAILS_PROGRAMS`, or one below its runtime folder or the
    hidden volume) from anywhere but its copy in RAM, a program deleted
    since it started (``readlink`` adds `` (deleted)``) judged by its path,
    and the copy in RAM deleted as well."""
    found = []
    for pid, read in process_exes(exes).items():
        exe = read.removesuffix(DELETED)
        if read != fg.RAM and (
            exe.rsplit("/", 1)[-1] in NAILS_PROGRAMS
            or exe.startswith(fg.RUNTIME + "/")
            or exe.startswith(fg.HIDDEN + "/")
        ):
            found.append(f"{pid} {read}")
    return sorted(found)


def processes_from_ram(lines: Sequence[str], exes: str) -> bool:
    """Whether NAILS's processes (``lines`` of ``ps -o user=,pid=,...``) run
    as root, each from its copy in RAM (:data:`fedora_gate.RAM`) as ``exes``
    (:data:`PROCESS_EXES`) gives them, and no process runs a program of
    NAILS's from anywhere else (:func:`nails_elsewhere`)."""
    read = process_exes(exes)
    return (
        bool(lines)
        and all(
            line.split()[0] == "root" and read.get(line.split()[1]) == fg.RAM
            for line in lines
        )
        and not nails_elsewhere(exes)
    )


def zram_applies(cold: str, generator: bool) -> bool:
    """Whether the zram checks apply: the cold boot (:data:`fedora_gate.ZRAM_STATE`)
    set up a zram device or a swap on one, or the image ships zram-generator."""
    if generator:
        return True
    for line in cold.splitlines():
        words = line.split()
        if not words:
            continue
        if words[0].startswith("zram") and "initstate=1" in line:
            return True
        if words[0].startswith("/dev/zram"):
            return True
    return False


class ArchGate(fg.Gate):
    """One gate run on an Arch image."""

    shares: Sequence[tuple[str, str]] = SHARES
    hidden_root: str = HIDDEN_ROOT
    harness_warnings: Mapping[str, str] = HARNESS_WARNINGS
    session_files: Sequence[str] = (
        *fg.SESSION_FILES,
        f"{EFI_PROBE}-1",
        f"{EFI_PROBE}-2",
    )
    security_state_name = (
        "the kernel's security modules, lockdown mode and Yama ptrace scope"
    )

    def __init__(
        self,
        vm: Any,
        session: Any,
        utab: Any,
        records: Any,
        settings: dict[str, Any],
        out_dir: str,
    ) -> None:
        super().__init__(vm, session, utab, records, settings, out_dir)
        # Decided at the cold boot (:func:`zram_applies`).
        self.zram = False
        # The kernel's security modules at the first read, which every root
        # must run.
        self.first_lsms: list[str] | None = None
        # What fstab-policy must say of the image's own layout on the prepared
        # decoy: its warning is the image's, as long as it names exactly
        # these (:func:`fstab_items`).
        self.fstab_policy = sorted(
            str(item) for item in settings.get("fstabPolicy", [])
        )
        if self.fstab_policy:
            self.harness_warnings = {
                **HARNESS_WARNINGS,
                "fstab-policy": "the image's own filesystems, which the hidden "
                "session masks or binds read-only: " + "; ".join(self.fstab_policy),
            }
            self.warning_sources = (
                "the harness, the VM, an untested release and, from fstab-policy, "
                "the image's own filesystems"
            )

    # --- the kernel's security state -------------------------------------

    def enforcing(self, where: str) -> None:
        """Where the Fedora gate asserts SELinux enforcing: no mandatory
        access control runs, and the kernel runs the security modules it ran
        at the first read."""
        state = self.fact(f"lsm.{where}", SECURITY_STATE)
        lsms = lsm_list(state)
        if self.first_lsms is None:
            self.first_lsms = lsms
            self.facts["lsm"] = lsms
        self.check(
            f"no SELinux and no AppArmor run {where}",
            bool(lsms) and not mac_running(lsms, state),
            state,
        )
        self.check(
            f"the kernel runs the security modules of the first boot {where}",
            bool(lsms) and lsms == self.first_lsms,
            {"first": self.first_lsms, "now": lsms},
        )

    def booleans(self, label: str) -> str:
        """The kernel's security state a session could change and a way back
        would keep (:data:`SECURITY_STATE`)."""
        return self.fact(f"security-state-{label}", SECURITY_STATE)

    # --- a session -------------------------------------------------------

    def session_security(self, n: int, user: str) -> None:
        """Without labels: the file the session copied up is in the upper
        with its line, and the fresh home is the user's."""
        upper = self.fact(
            f"copied-up-{n}",
            f"tail -n1 {fg.UPPER}/etc/protocols; ls {fg.UPPER}/etc/gate-new",
        )
        self.check(
            f"session {n}: the copied-up file and a new one are in the upper",
            upper.splitlines() == ["# gate", f"{fg.UPPER}/etc/gate-new"],
            upper,
        )
        swaps = self.fact(f"swaps-session-{n}", "cat /proc/swaps", again=True)
        self.check(
            f"session {n}: no swap is on a disk",
            "Filename" in swaps and not distro_checks.disk_swaps(swaps),
            swaps,
        )
        self.facts[f"efi-probe-{n}"] = self.fact(
            f"efi-probe-{n}", f"touch {EFI_PROBE}-{n} 2>&1; echo rc=$?"
        )
        if user != "root":
            home = self.fact(
                f"fresh-home-{n}",
                f"stat -c '%U %a %n' /home/{user}; ls -A /home/{user}",
            )
            first = home.splitlines()[0].split() if home else []
            self.check(
                f"session {n}: the fresh home is the user's",
                first[:1] == [user],
                home,
            )

    def nails_processes(self, n: int) -> None:
        """NAILS's processes in the session run from its copy in RAM
        (``/proc/<pid>/exe``), as root."""
        processes = self.fact(
            f"processes-{n}",
            "ps -e -o user=,pid=,comm=,args= | grep -E 'overlay-runtime|control' | "
            "grep -v grep; true",
        )
        lines = [line for line in processes.splitlines() if "overlay-runtime" in line]
        exes = self.fact(f"processes-exe-{n}", PROCESS_EXES, again=True)
        self.check(
            f"session {n}: NAILS's processes run from its copy in RAM, as root",
            processes_from_ram(lines, exes),
            {"processes": processes, "fromElsewhere": nails_elsewhere(exes)},
        )

    def volume_label(self, n: int) -> None:
        """No label to keep: no security module labels files on Arch."""

    # --- the decoy -------------------------------------------------------

    def stock(self) -> None:
        """check on the stock image, with a hidden root mounted, before the
        decoy is prepared (:data:`STOCK_VERDICTS`): it refuses the swap file
        arch-boxes turns on and its persistent journal, and warns of a lid
        that suspends and of freed memory that is not zeroed. Its warning of
        the core dumps systemd-coredump keeps shows once the journal is
        volatile (:meth:`ArchGate.coredump`)."""
        self.sh("hidden-root-stock", self.hidden_root)
        status, rows = self.check_rows("check-stock")
        self.facts["check-stock"] = {
            name: {k: row.get(k) for k in ("status", "message", "remediation")}
            for name, row in rows.items()
        }
        for name, verdict, words, what in STOCK_VERDICTS:
            row = rows.get(name, {})
            text = (
                str(row.get("message", "")) + str(row.get("remediation", ""))
            ).lower()
            self.check(
                what,
                status == 4
                and row.get("status") == verdict
                and all(word.lower() in text for word in words),
                row or f"check printed no {name} row (exit {status})",
            )
        self.sh("hidden-root-stock-off", f"umount {fg.HIDDEN}; true")

    def swap_off(self) -> None:
        """The decoy's disk swap off, at every boot: every swap line of the
        fstab made noauto, as the requirements ask, and each disk swap
        turned off."""
        fstab = self.whole_file("fstab", "/etc/fstab")
        noauto = distro_checks.with_swaps_noauto(fstab) if fstab is not None else None
        if noauto is not None and noauto != fstab:
            self.vm.succeed(
                f"printf %s {shlex.quote(noauto)} > /etc/fstab && "
                "systemctl daemon-reload"
            )
        for name in distro_checks.disk_swaps(
            self.fact("swaps-before-swapoff", "cat /proc/swaps", again=True)
        ):
            self.vm.succeed(f"swapoff {shlex.quote(name)}")
        swaps = self.fact("swaps-prepared", "cat /proc/swaps", again=True)
        now = self.whole_file("fstab-prepared", "/etc/fstab")
        lines = distro_checks.fstab_swaps(now or "")
        self.check(
            "the decoy's disk swap is off, and every swap line of its fstab noauto",
            fstab is not None
            and now is not None
            and "Filename" in swaps
            and not distro_checks.disk_swaps(swaps)
            and all("noauto" in options for _, options in lines),
            {"swaps": swaps, "fstab": now if now is not None else "not read whole"},
        )

    def whole_file(self, label: str, path: str) -> str | None:
        """The text of ``path``, read twice through the gate's check of whole
        output, or None where either read came torn or the two differ: the
        gate writes back nothing it may have read garbled."""
        reads = []
        for i in (1, 2):
            torn = len(self.torn)
            _, out = self.sh(f"{label}-{i}", f"cat {shlex.quote(path)}", again=True)
            if len(self.torn) != torn:
                return None
            reads.append(out)
        return reads[0] if reads[0] == reads[1] else None

    def decoy(self) -> None:
        """Everything on the decoy before the first entry, with a hidden root
        mounted, which check needs to judge the decoy."""
        vm = self.vm
        self.mark("prep-decoy")
        self.sh("hidden-root", self.hidden_root)
        self.enforcing("on the decoy before the first entry")
        self.fact("image-python", "command -v python3 python || echo none")
        self.fact(
            "versions",
            "pacman -Q linux systemd util-linux pam cryptsetup audit sudo 2>&1; "
            "uname -r",
        )
        op = self.fact("operator-id", self.operator("id -un; id -u"))
        self.check(
            "the operator's login through PAM's login stack runs as root",
            op.splitlines()[-2:] == ["root", "0"],
            op,
        )
        # The user of the second session, with a home on /home and sudo
        # without a password, as a decoy's operator has it.
        vm.succeed(
            f"id {fg.USER} >/dev/null 2>&1 || useradd -m {fg.USER}; "
            f"printf '%s\\n' '{fg.USER} ALL=(ALL) NOPASSWD: ALL' "
            f"> /etc/sudoers.d/90-{fg.USER}; "
            f"chmod 0440 /etc/sudoers.d/90-{fg.USER}"
        )
        user_op = self.fact("user-id", self.operator("id -un; sudo -n id -un", fg.USER))
        self.check(
            "the user's login runs as the user, and sudo as root",
            user_op.splitlines()[-2:] == [fg.USER, "root"],
            user_op,
        )
        self.journal()
        self.coredump()
        self.auditd_off()
        self.locate()
        self.lsm()
        self.clean_check()
        self.failed_positive()

    def coredump(self) -> None:
        """With the journal volatile, check warns of the core dumps
        systemd-coredump keeps on the disk (a refusal of the row hid the
        warning before), and names them no more once they are discarded."""
        _, rows = self.check_rows("check-coredump")
        row = rows.get("decoy-persistence", {})
        text = (str(row.get("message", "")) + str(row.get("remediation", ""))).lower()
        found = row.get("status") == "warn" and "coredump" in text
        self.check(
            "check warns of the core dumps systemd-coredump keeps on the disk",
            found,
            row or "check printed no decoy-persistence row",
        )
        self.vm.succeed(
            "mkdir -p /etc/systemd/coredump.conf.d && "
            "printf '%s\\n' '[Coredump]' Storage=none ProcessSizeMax=0 "
            "> /etc/systemd/coredump.conf.d/50-discard.conf"
        )
        _, rows = self.check_rows("check-coredump-fixed")
        row = rows.get("decoy-persistence", {})
        text = (str(row.get("message", "")) + str(row.get("remediation", ""))).lower()
        self.check(
            "check names the core dumps no more once they are discarded",
            found
            and fg.judged_row(rows, "decoy-persistence")
            and "coredump" not in text,
            row if found else "not judged: check never named them",
        )

    def clean_check(self) -> None:
        """check on the prepared decoy, as Fedora's gate judges it, with
        fstab-policy's warning held to what the image's own layout brings."""
        super().clean_check()
        row = self.facts.get("clean-check-warnings", {}).get("fstab-policy")
        if not self.fstab_policy:
            return
        message = str((row or {}).get("message", ""))
        named = fstab_items(message)
        notes = fstab_notes(message)
        self.check(
            "fstab-policy names on the prepared decoy what the image's layout "
            "brings, and nothing else",
            named == self.fstab_policy and notes == FSTAB_NOTE,
            {
                "expected": self.fstab_policy,
                "named": named,
                "notes": notes,
                "expectedNotes": FSTAB_NOTE,
                "row": row,
            },
        )

    def auditd_off(self) -> None:
        """auditd is installed but off on the stock image: check names no
        auditd."""
        running = self.fact("auditd", "pgrep -x auditd || echo none")
        self.facts["auditd-unit"] = self.fact(
            "auditd-unit", "systemctl is-enabled auditd.service 2>&1; true"
        )
        self.check("auditd does not run on the stock image", running == "none", running)
        _, rows = self.check_rows("check-auditd")
        row = rows.get("decoy-persistence", {})
        self.check(
            "check names no auditd where it does not run",
            fg.judged_row(rows, "decoy-persistence")
            and "audit"
            not in (
                str(row.get("message", "")) + str(row.get("remediation", ""))
            ).lower(),
            row or "check printed no decoy-persistence row",
        )

    def locate(self) -> None:
        held = self.fact("locate", "pacman -Q plocate mlocate 2>&1; true")
        self.facts["locate"] = held
        _, rows = self.check_rows("check-locate")
        row = rows.get("locate-database", {})
        if "was not found" in held and held.count("was not found") == 2:
            self.check(
                "locate-database passes where no locate is installed",
                row.get("status") == "pass",
                row,
            )
            return
        self.check(
            "locate-database refuses an updatedb that does not skip the volume",
            row.get("status") == "fail",
            row,
        )

    def lsm(self) -> None:
        """lsm-status passes on the decoy, where no SELinux runs, and names
        each module the kernel runs."""
        _, rows = self.check_rows("check-lsm")
        row = rows.get("lsm-status")
        message = str((row or {}).get("message", ""))
        lsms = self.first_lsms or []
        self.check(
            "lsm-status passes on the decoy, where no SELinux runs",
            row is not None and row.get("status") == "pass",
            row,
        )
        self.check(
            "lsm-status names each security module the kernel runs",
            bool(lsms) and not lsm_not_named(message, lsms),
            {"kernel": lsms, "not named": lsm_not_named(message, lsms), "row": row},
        )

    def builddate(self) -> int:
        """The guest's clock in whole seconds, the build date of a package
        the gate builds."""
        return int(float(self.wall()))

    def drift_install(self) -> None:
        """The drift control's package, version 1, on the decoy, before the
        reference boot, which brings /etc and /var up to date with the /usr
        pacman changed: the first plain soft-reboot then starts from the
        state each entry starts from."""
        out = self.fact("drift-install-1", pacman_install("1", self.builddate()))
        self.check(
            "pacman installs the drift control's package on the decoy",
            "rc=0" in out and installed_version(out) == "1-1",
            out[-1500:],
        )
        self.left_pending("1")

    def drift_update(self) -> None:
        """Between the sessions: the decoy updates the drift control's
        package the hidden session updated, which leaves /etc and /var out of
        date with /usr, and the gate brings them up to date by hand before the
        second entry."""
        out = self.fact("drift-install-3", pacman_install("3", self.builddate()))
        self.check(
            "the decoy updates the drift control's package after the session",
            "rc=0" in out and installed_version(out) == "3-1",
            out[-1500:],
        )
        self.left_pending("3")
        self.up_to_date("drift", "second")

    def left_pending(self, version: str) -> None:
        """The positive control of the update state's reading: right after
        pacman changed /usr, /etc and /var read out of date with it."""
        state = self.needs_update(f"after-drift-{version}")
        self.check(
            f"pacman's install of version {version} leaves /etc and /var out of "
            "date with /usr, as the next start of PID 1 reads them",
            state == PENDING,
            state,
        )

    def up_to_date(self, label: str, entry: str) -> None:
        """/etc and /var brought up to date with the /usr pacman changed, as a
        start of PID 1 does where an update is pending, by the units that
        start does it with (:data:`UPDATE_UNITS`): the next entry then starts
        from the state the plain soft-reboots start from, and no control's
        changes of that pending update excuse its way back's."""
        units = self.fact(f"update-units-{label}", UPDATE_UNITS).split()
        if units:
            self.sh(
                f"update-done-{label}",
                "systemctl restart " + " ".join(shlex.quote(u) for u in units),
            )
        state = self.needs_update(f"after-{label}")
        self.check(
            f"/etc and /var are up to date with /usr before the {entry} entry, as "
            "a start of PID 1 leaves them",
            bool(units) and state == UP_TO_DATE,
            {"units": units, "state": state},
        )

    # --- the kernel log --------------------------------------------------

    def judge_denials(self) -> None:
        """No mandatory access control runs on Arch, so there is no denial
        to count: the kernel log of every boot is judged whole instead. No
        record lost, every marker in it, from the first marker on every
        audit record's serial number and no notice that the kernel
        suppressed or lost a record, so that what the way back's checks read
        of the kernel log is all of it."""
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
            first = markers[0]
            serials = sg.audit_serials(r["msg"] for r in records)
            later = sg.audit_serials(
                r["msg"] for r in records if int(r["seq"]) > int(first["seq"])
            )
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
                "kernel log",
                start is not None and not holes,
                {
                    "from": start,
                    "gaps": holes[:20],
                    "highest": max(serials, default=None),
                },
            )
            for label, low, high, _ in self.phases(boot):
                found = sg.phase(records, low, high)
                name = label or "the boot's start"
                boot.setdefault("phases", []).append(
                    {
                        "label": name,
                        "records": found["records"],
                        "suppressed": found["suppressed"],
                    }
                )
                if label is None:
                    self.facts[f"lost-at-the-boots-start-{boot['why']}"] = found[
                        "suppressed"
                    ]
                    continue
                self.check(
                    f"the kernel lost no record from {name} on",
                    not found["suppressed"],
                    found["suppressed"][:10],
                )

    # --- the run ---------------------------------------------------------

    def flows(self) -> None:
        """The run's steps, in order; a switch that is lost ends them."""
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        self.prepare()
        self.attach(fg.HIDDEN_DISK, fg.HIDDEN_BYTES)
        self.stock()
        self.swap_off()
        self.sh("prepare-decoy", PREPARE_DECOY, 600)
        self.drift_install()
        self.power_cycle("reference")
        cmdline = self.fact("cmdline", "cat /proc/cmdline")
        self.check(
            "the decoy boots with init_on_free=1, as its requirements ask",
            "init_on_free=1" in cmdline.split(),
            cmdline,
        )
        update = self.needs_update("reference")
        self.check(
            "/etc and /var are up to date with /usr after the reference boot, "
            "which ran the units of the update pacman left pending",
            update == UP_TO_DATE,
            update,
        )
        self.mark("boot-ready")
        self.decoy()
        self.control("control-1")
        # The first entry starts from a cold boot, as an operator's does: the
        # numbers its consoles' units get are those a way back must give them again.
        self.where = "decoy at the cold boot"
        self.power_cycle("cold")
        self.mark("prep-cold")
        self.cold_units = self.getty_numbers("cold")
        self.cold_lines = fg.getty_logins(self.records_capture("cold").wtmp)
        self.cold_sockets = fg.socket_identity(
            self.fact("journal-sockets-cold", fg.JOURNAL_SOCKETS)
        )
        self.fact("pids-cold", fg.PID_LISTING)
        self.cold_zram = self.fact("zram-cold", fg.ZRAM_STATE)
        generator = self.fact(
            "zram-generator", f"test -e {ZRAM_GENERATOR} && echo present || echo absent"
        )
        self.zram = zram_applies(self.cold_zram, generator == "present")
        self.facts["zram-checks"] = (
            "run: the cold boot set zram up or the image ships zram-generator"
            if self.zram
            else "not run: the cold boot set up no zram device and the image has "
            "no zram-generator"
        )
        self.where = "decoy before the first entry"
        # The first session: shared home, ended with deactivate.
        self.sh("hidden-root-1", self.hidden_root)
        state = self.before_entry(1)
        self.mark("prep-session-1")
        if self.enter(1, "root", fg.CONFIG, state):
            self.hidden(1, "root", state)
            disk = self.hotplug(1)
            self.plant()
            out = self.fact(
                "drift-install-hidden", pacman_install("2", self.builddate())
            )
            self.check(
                "session 1: pacman updates the drift control's package",
                "rc=0" in out and installed_version(out) == "2-1",
                out[-1500:],
            )
            if self.leave(1, "deactivate", "root", fg.CONFIG):
                self.after(1, state, disk)
                self.scan()
        if self.lost:
            return
        # The decoy updates the package the hidden session updated: hidden
        # sessions list it twice, theirs and the decoy's.
        self.where = "decoy between the sessions"
        self.mark("prep-drift")
        self.drift_update()
        self.sh("hidden-root-2", self.hidden_root)
        _, rows = self.check_rows("check-drift")
        row = rows.get("package-drift", {})
        text = str(row.get("message", "")) + str(row.get("remediation", ""))
        self.check(
            "package-drift warns of the package the decoy updated after a hidden "
            "session updated it, with pacman's fix",
            row.get("status") == "warn" and DRIFT_PACKAGE in text and DRIFT_FIX in text,
            row,
        )
        state = self.before_entry(2)
        state["sleep_guard"] = True
        if self.enter(2, fg.USER, fg.FRESH_CONFIG, state):
            log = self.facts.get("activate-2.log", "")
            advisory = fg.advisory_text(log, "package-drift")
            self.check(
                "the entry shows the drift advisory with its fix",
                DRIFT_PACKAGE in advisory and DRIFT_FIX in advisory,
                advisory or log[-2000:],
            )
            self.hidden(2, fg.USER, state)
            disk = self.hotplug(2)
            if self.leave(2, "emergency", "root", fg.FRESH_CONFIG):
                self.after(2, state, disk)
        if self.lost:
            return
        self.control("control-2")
        self.mark("prep-login")
        self.records_positive()
        self.mark("run-end")


def run(
    vm: Any,
    session: Any,
    utab: Any,
    records: Any,
    settings: dict[str, Any],
) -> None:
    """Run the gate of the Arch image ``settings`` names on ``vm``, with the
    e2e package's ``session`` and ``utab`` helpers and the ``records``
    readers."""
    out_dir = os.environ.get("NAILS_GATE_OUT") or os.getcwd()
    ArchGate(vm, session, utab, records, settings, out_dir).run()
