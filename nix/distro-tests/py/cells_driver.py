"""The run of one SELinux cell on an enforcing Fedora image (research only).

``nix/distro-tests/cells.nix`` builds one host driver per cell and calls
:func:`run` with the driver's machine. A cell is an image, a way of starting
the RAM copy of the binary (``none``, ``env``, ``context`` or ``relabel``, see
the research build's ``research_cell`` module), whether the policy's dontaudit
rules are on, whether the opt-in units run, and whether the operator relabels
the RAM copy in each session. The operator's commands run in a login session
of their own: a transient unit with the login PAM stack, whose pam_selinux
gives root its default context (``unconfined_t``), checked with ``id -Z``
first. ``runcon`` from the harness's shell is tried before it, and that shell
itself is the last resort; the cell records which one ran. The run:

1. boots the image, makes the decoy amnesic (volatile journal, auditd
   masked), lifts the kernel log's rate limits, optionally rebuilds the policy
   without its dontaudit rules (``semodule -DB``: the test VM's policy store
   only), names the cell's mechanism in ``/run/dsx/dsxcell``, backs the hidden
   root with plain dm-crypt on a loop device where the image has ``dmsetup``
   and records the decoy's facts;
2. soft-reboots once with no NAILS involved, the control whose denials are
   not counted as new;
3. enters a hidden session, attaches a disk to the machine and lets the
   operator format and mount it read-write, runs a command in the session and
   deactivates;
4. enters again and ends that session with the operator's emergency;
5. where the cell names it, enters a third time with the watcher's automatic
   emergency on, makes the hidden volume's mount read-only and lets the
   watcher end the session on its own;
6. soft-reboots once more with no NAILS involved.

It writes a marker to ``/dev/kmsg`` at every step, reads the whole kernel log
after every step, and keeps every command's output. A step that fails is
recorded and the run goes on where it can: after a power-off, or a switch whose
new userspace never reconnects, the next flow starts on a fresh boot of the
image, after a plain soft-reboot of its own. The result is ``<cell>.json``
(facts, flows and denials per phase), ``<cell>.raw.json`` (every command's
output) and ``<cell>.kmsg.txt`` in the output directory.
"""

from __future__ import annotations

import json
import os
import shlex
import time
import traceback
import uuid
from typing import Any

import selinux_cells as sc

OPERATOR = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
NAILS = "/run/tools/nails"
RAM = "/run/overlay-runtime/control"
CONFIG = "/run/nails-cell.toml"
CONFIG_TEXT = 'hidden_volume_root = "/mnt/data"\nminimum_space_mb = 100\n'
# The opt-in units that run the RAM copy: the sleep guard and the disk guard.
OPTIN_TEXT = '\n[sleep_policy]\nmode = "block"\n\n[session_mounts]\nread_only = true\n'
# The third entry's configuration: the watcher ends the session on its own
# once the hidden volume has failed its probe for the debounce window.
AUTO_CONFIG = "/run/nails-cell-auto.toml"
AUTO_TEXT = "\n[backend_watch]\nauto_emergency = true\n"
# The disk the session attaches: a sparse file on the host, attached through
# the QEMU monitor, which the guest names by its serial.
HOTPLUG_BYTES = 64 << 20

# The hidden root of a cell with ``backend = "dm-crypt"``: the suite's layout
# (hidden-root.nix: a sparse file on a tmpfs below /run, which a soft-reboot
# does not carry, on a loop device without autoclear, mounted at /mnt/data),
# with a plain dm-crypt mapping between the loop device and ext4, made with
# the image's own dmsetup and a random key, so that the way back marks a
# device-mapper backend for deferred removal as it does for a LUKS volume.
# Each fresh hidden root gets a mapping of its own name ($1), so one the last
# way back left behind shows instead of being reused. Without dmsetup it
# exits 3 and the cell uses the suite's plain loop device.
DM_HIDDEN_ROOT = r"""
set -eu
name=$1
mountpoint=/mnt/data
store=/run/blk
backing="$store/data.img"
if mountpoint -q "$mountpoint"; then
  echo "Hidden root already mounted at $mountpoint"
else
  command -v dmsetup >/dev/null 2>&1 || { echo 'dmsetup absent'; exit 3; }
  mkdir -p "$store"
  if ! mountpoint -q "$store"; then
    mount -t tmpfs -o size=1200m,mode=0700 tmpfs "$store"
  fi
  truncate -s 1G "$backing"
  loop=$(losetup --show -f "$backing")
  printf '%s\n' "$loop" > /run/blk.dev
  key=$(od -An -N64 -tx1 /dev/urandom | tr -d ' \n')
  sectors=$(blockdev --getsz "$loop")
  printf '0 %s crypt aes-xts-plain64 %s 0 %s 0\n' "$sectors" "$key" "$loop" |
    dmsetup create "$name"
  mkfs.ext4 -q "/dev/mapper/$name"
  mkdir -p "$mountpoint"
  mount "/dev/mapper/$name" "$mountpoint"
  echo "backing the hidden root with plain dm-crypt mapping $name on $loop"
fi
mkdir -p "$mountpoint"/root/work "$mountpoint"/config
echo "Hidden root ready at $mountpoint"
"""
# The device-mapper devices there are, with their open counts.
DM_STATE = "dmsetup info -c --noheadings -o name,open,attr 2>&1 || true"

TOOLS_MOUNT = (
    "mkdir -p /run/tools && { mountpoint -q /run/tools || mount -t 9p -o "
    "defaults,trans=virtio,version=9p2000.L,cache=loose,msize=268435456 "
    "tools /run/tools; }"
)
# Every message reaches the kernel log and nothing is dropped by a rate
# limit; the console shows notices (the AVC lines) so a power-off keeps them.
LIMITS = (
    "sysctl -w kernel.printk_ratelimit=0 kernel.printk_devkmsg=on; "
    "dmesg -n 6; auditctl -b 16384 >/dev/null 2>&1 || true"
)
UNITS = (
    "systemd-soft-reboot.service",
    "overlay-runtime-monitor.service",
    "overlay-runtime-power.service",
    "overlay-runtime-boot.service",
)
LABEL_PATHS = (
    "/ /home /var /etc /usr /root /boot /mnt/data /mnt/data/root "
    "/mnt/data/root/upper /mnt/data/root/work /mnt/data/root/mounts "
    "/mnt/data/root/mounts/*/upper /mnt/data/root/mounts/*/work"
)
RUN_FILES = (
    "/run/utmp /run/mount/utab /run/systemd/journal/kernel-seqnum "
    "/run/NetworkManager/devices/* /run/overlay-runtime /run/overlay-runtime/* "
    "/run/overlay-runtime-boot /run/overlay-runtime-boot/*"
)
DECOY_MOUNTS = "/ /home /var /boot /boot/efi"
# The markers that start a plain soft-reboot: the first, the last, and the one
# after a restart.
CONTROL_STARTS = ("control-start", "control2-start", "controlr-start")


class Cell:
    """One cell's run on the machine ``vm``."""

    def __init__(
        self,
        vm: Any,
        session: Any,
        settings: dict[str, Any],
        scripts: dict[str, str],
        out_dir: str,
    ) -> None:
        self.vm = vm
        self.session = session
        self.settings = settings
        self.scripts = scripts
        self.out_dir = out_dir
        self.name = settings["name"]
        self.nonce = uuid.uuid4().hex[:10]
        self.op = ""
        self.raw: dict[str, Any] = {}
        self.calls = 0
        self.decoy_source = ""
        self.lost = False
        self.restarted = False
        self.mappings = 0
        self.boot = -1
        self.boots: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {
            "cell": self.name,
            "settings": settings,
            "nonce": self.nonce,
            "facts": {},
            "flows": {},
            "boots": [],
        }

    # --- commands --------------------------------------------------------

    def sh(self, label: str, cmd: str, timeout: int = 180) -> tuple[int, str]:
        """Run ``cmd`` in the guest, keep and print its output; never fails."""
        self.calls += 1
        key = f"{self.calls:04}.b{self.boot}.{label}"
        try:
            # The driver runs every command under set -euo pipefail; a fact
            # is a plain script that goes on past a failed command.
            status, out = self.vm.execute(
                f"( set +euo pipefail; {cmd} ) 2>&1", timeout=timeout
            )
        except Exception as error:  # noqa: BLE001 - a dead guest is a result
            status, out = -1, f"<{type(error).__name__}: {error}>"
        self.raw[key] = {"cmd": cmd, "status": status, "out": out}
        print(f"=== {key} (exit {status}) ===\n{out.rstrip()}")
        return status, out

    def fact(self, label: str, cmd: str, timeout: int = 180) -> str:
        """The output of ``cmd``, also kept as a fact of the current boot."""
        _, out = self.sh(label, cmd, timeout)
        self.boots[self.boot]["facts"][label] = out.strip()
        return out.strip()

    def monitor(self, label: str, command: str) -> str:
        """Send ``command`` to the QEMU monitor; its answer is kept as a fact."""
        self.calls += 1
        key = f"{self.calls:04}.b{self.boot}.{label}"
        try:
            out = self.vm.send_monitor_command(command)
        except Exception as error:  # noqa: BLE001 - recorded, the run goes on
            out = f"<{type(error).__name__}: {error}>"
        answer = sc.monitor_answer(out, command)
        self.raw[key] = {"cmd": f"(monitor) {command}", "status": 0, "out": out}
        self.boots[self.boot]["facts"][label] = answer
        print(f"=== {key} (monitor) ===\n{answer}")
        return answer

    # --- the kernel log --------------------------------------------------

    def read_kmsg(self, where: str) -> None:
        current = self.boots[self.boot]
        first = max(current["records"], default=0)
        status, out = self.vm.execute(sc.kmsg_command(first), timeout=180)
        records, dropped = sc.parse_kmsg(out)
        current["dropped"] += dropped
        sc.merge(current["records"], records)
        print(f"kmsg {where}: {len(records)} records from {first} (exit {status})")

    def mark(self, label: str) -> int | None:
        text = sc.marker(label, self.nonce)
        # The guest's wall clock as the marker is written, so that a time a
        # file on the decoy carries can be placed between two steps.
        _, wall = self.vm.execute(
            f"date +%s.%N; echo {shlex.quote(text)} > /dev/kmsg",
            check_return=False,
            timeout=60,
        )
        self.read_kmsg(label)
        seq = sc.marker_seq(self.boots[self.boot]["records"].values(), text)
        self.boots[self.boot]["markers"].append(
            {"label": label, "seq": seq, "wall": wall.strip()}
        )
        return seq

    # --- boots and switches ----------------------------------------------

    def new_boot(self, why: str) -> None:
        self.boot += 1
        self.boots.append(
            {
                "why": why,
                "records": {},
                "dropped": 0,
                "markers": [],
                "facts": {},
                "console": [],
            }
        )

    def after_switch(self) -> None:
        self.vm.succeed(TOOLS_MOUNT)
        self.sh("settle", "timeout 300 systemctl is-system-running --wait", 330)

    def prepare(self) -> None:
        """Everything a fresh boot of the image needs before the cell runs."""
        vm = self.vm
        vm.wait_for_unit("multi-user.target")
        vm.succeed(TOOLS_MOUNT)
        text = CONFIG_TEXT + (OPTIN_TEXT if self.settings["optin"] else "")
        vm.succeed(f"cat > {CONFIG} <<'EOF'\n{text}EOF")
        vm.succeed(f"cat > {AUTO_CONFIG} <<'EOF'\n{text}{AUTO_TEXT}EOF")
        self.sh("limits", LIMITS)
        # The harness's own shell starts through /usr/bin/env; from the next
        # start on it does not, so an access of env on the decoy is NAILS's.
        self.sh(
            "backdoor-without-env",
            "sed -i 's|exec /usr/bin/env bash|exec /usr/bin/bash|' "
            "/usr/bin/backdoorScript; tail -1 /usr/bin/backdoorScript; "
            "ls -Z /usr/bin/backdoorScript",
        )
        self.sh("amnesic", self.scripts["amnesic"], 300)
        if self.settings["dontaudit"] == "off":
            self.fact("semodule-DB", "time semodule -DB && echo rebuilt", 900)
        mechanism = shlex.quote(self.settings["mechanism"])
        vm.succeed(
            "mkdir -p /run/dsx/dsxrec && "
            f"printf '%s\\n' {mechanism} > /run/dsx/dsxcell && "
            "touch /run/dsx/dsxrec/dsxtrace && chmod 0666 /run/dsx/dsxrec/dsxtrace"
        )
        self.sh("settle", "timeout 300 systemctl is-system-running --wait", 330)
        self.decoy_source = self.fact("decoy-source", "findmnt -rn -o SOURCE /")

    def as_operator(self, cmd: str, how: str | None = None) -> str:
        """``cmd`` as the operator runs it, in the way :meth:`operator` chose."""
        how = self.op if how is None else how
        if how == "runcon":
            return f"runcon {OPERATOR} /bin/sh -c {shlex.quote(cmd)}"
        if how == "pam-login":
            # A login session: the login PAM stack's pam_selinux gives root
            # its default context. systemd-run's --pipe cannot pass the
            # descriptors across the context change, so the output goes
            # through a file.
            out = "/run/dsx/dsxrec/op.out"
            inner = f"{cmd}; echo $? > {out}.rc"
            return (
                "( systemd-run --quiet --wait --collect -p PAMName=login -p User=root "
                f"/bin/sh -c {shlex.quote(f'( {inner} ) > {out} 2>&1')}; "
                f"cat {out}; exit $(cat {out}.rc 2>/dev/null || echo 125) )"
            )
        return cmd

    def operator(self) -> None:
        """Decide how NAILS runs: from unconfined_t, through runcon if the
        backdoor's domain may change to it, else in a login session of its own
        (a transient unit with the login PAM stack, ``systemd-run -p
        PAMName=login``), each checked with id -Z first; else from the
        backdoor's own domain."""
        self.fact("backdoor-id", "id -Z")
        self.fact("su-l-id", "su -l root -c 'id -Z'")
        self.op = ""
        self.result["operator"] = "backdoor (nothing gave unconfined_t)"
        for how in ("runcon", "pam-login"):
            out = self.fact(f"{how}-id", self.as_operator("id -Z; id -u", how))
            if ":unconfined_t:" in out and "denied" not in out.lower():
                self.op = how
                self.result["operator"] = f"{how} (id -Z: {out})"
                break
        self.fact(
            "operator-nails",
            self.as_operator(f"{NAILS} --version; cat /proc/self/attr/current"),
        )

    def switch(self, trigger: str, label: str) -> str:
        """Follow a soft-reboot; the place after it, or why there is none."""
        console_from = len(self.vm.full_console_log)
        try:
            self.session.follow_soft_reboot(self.vm, trigger, label, deadline_s=420)
        except Exception as error:  # noqa: BLE001 - recorded, the run goes on
            lines = self.vm.full_console_log[console_from:]
            self.boots[self.boot]["console"].append(
                {"label": label, "lines": lines[-400:]}
            )
            self.result["flows"][label] = {
                "ok": False,
                "error": str(error),
                "console_avcs": [line for line in lines if "avc:  denied" in line],
            }
            print(f"{label} failed: {error}")
            self.lost = True
            return "lost"
        self.after_switch()
        fstype = self.vm.execute("findmnt -no FSTYPE /", timeout=60)[1]
        place = "hidden" if fstype.strip() == "overlay" else "decoy"
        self.result["flows"][label] = {
            "ok": True,
            "place": place,
            "afterRestart": self.restarted,
        }
        return place

    def where(self) -> str:
        """Where the machine is: the hidden root, the decoy, or down."""
        if self.lost:
            return "down"
        status, out = self.vm.execute("findmnt -no FSTYPE /", timeout=60)
        if status != 0:
            return "down"
        return "hidden" if out.strip() == "overlay" else "decoy"

    def restart(self, why: str, settle: bool = True) -> None:
        """A fresh boot of the image after the machine went down.

        The fresh boot starts from the image's own disk, so its first switch
        runs (and stamps the access time of) what the decoy's userspace runs
        to stop: a plain soft-reboot first, as at the start of a cell, keeps
        that out of the next flow's lists. The flows after a restart are
        marked ``afterRestart``."""
        process = getattr(self.vm, "process", None)
        try:
            if process is not None and process.poll() is None:
                self.vm.crash()
            else:
                self.vm.wait_for_shutdown()
        except Exception as error:  # noqa: BLE001
            print(f"stopping the machine: {error}")
        self.vm.start(allow_reboot=False)
        self.lost = False
        self.restarted = True
        self.new_boot(why)
        self.prepare()
        self.operator()
        self.mark("boot-ready")
        if settle:
            self.step("controlr", self.control_after_restart)

    def hidden_root(self, label: str) -> None:
        """A hidden root at /mnt/data, unless one is mounted there: plain
        dm-crypt on a loop device for a ``dm-crypt`` cell whose image has
        dmsetup, else the suite's plain loop device."""
        if self.settings.get("backend") == "dm-crypt":
            self.fact(f"{label}.dm-before", DM_STATE)
            name = f"data{self.mappings + 1}"
            status, _ = self.sh(
                label,
                f"sh -s {shlex.quote(name)} <<'DSXEOF'\n{DM_HIDDEN_ROOT}\nDSXEOF",
                300,
            )
            if status == 0:
                self.mappings += 1
                self.fact(f"{label}.dm", DM_STATE)
                return
            print(f"{label}: no dm-crypt hidden root (exit {status}); a plain loop")
        self.sh(label, self.scripts["setup_hidden_root"], 300)

    # --- facts -----------------------------------------------------------

    def decoy_facts(self) -> None:
        self.fact("getenforce", "getenforce")
        self.fact("sestatus", "sestatus")
        self.fact("selinux-config", "grep -E '^SELINUX(TYPE)?=' /etc/selinux/config")
        self.fact(
            "packages",
            "rpm -q selinux-policy selinux-policy-targeted systemd kernel coreutils "
            "policycoreutils audit",
        )
        self.fact("kernel", "uname -r")
        self.fact(
            "soft-reboot-unit",
            "systemctl show -p NoNewPrivileges -p SELinuxContext -p ExecStart "
            f"{UNITS[0]}; systemctl cat {UNITS[0]}",
        )
        self.fact("env", "ls -Z /usr/bin/env; stat -c '%x|%y|%z' /usr/bin/env")
        self.fact(
            "context-valid",
            "exec 3<>/sys/fs/selinux/context && "
            "printf %s system_u:system_r:unconfined_service_t:s0 >&3 && "
            "cat <&3; echo",
        )
        self.fact("tools", "command -v sesearch seinfo semodule runcon chcon || true")
        self.fact(
            "hidden-volume", "ls -Zd /mnt/data /mnt/data/root /mnt/data/root/work"
        )
        self.fact(
            "round-trip",
            self.as_operator(
                "touch /mnt/data/.dsxrt && chcon -t etc_t /mnt/data/.dsxrt"
                " && stat -c %C /mnt/data/.dsxrt; rm -f /mnt/data/.dsxrt"
            ),
        )
        self.fact("decoy-root", "findmnt -rn -o SOURCE,OPTIONS /")
        if self.settings["mechanism"] == "none" and self.settings["dontaudit"] == "on":
            if not self.settings["optin"]:
                self.save_policy()

    def save_policy(self) -> None:
        """The loaded policy's file, for reading its rules on the host."""
        name = self.fact("policy-file", "ls /etc/selinux/targeted/policy/").split()
        if not name:
            return
        status, out = self.vm.execute(
            f"base64 -w0 /etc/selinux/targeted/policy/{name[-1]}", timeout=600
        )
        if status == 0:
            os.makedirs(self.out_dir, exist_ok=True)
            path = os.path.join(self.out_dir, f"{self.name}.{name[-1]}.b64")
            with open(path, "w", encoding="ascii") as handle:
                handle.write(out.strip())

    def run_labels(self, label: str) -> None:
        self.fact(
            label,
            "find /run -xdev -maxdepth 4 \\( -path /run/dsx -o -path /run/tools "
            "-o -path /run/user \\) -prune -o -printf '%Z %y %p\\n' | sort -k3",
        )

    def place_facts(self, tag: str) -> None:
        self.fact(f"{tag}.getenforce", "getenforce")
        self.fact(f"{tag}.root", "findmnt -no FSTYPE,SOURCE,OPTIONS /")
        self.fact(f"{tag}.trace", "cat /run/dsx/dsxrec/dsxtrace")
        # ps takes -Z or a format with the label, not both.
        self.fact(
            f"{tag}.ps",
            "ps -eZ | grep -E ' control$|overlay-runtime' || true; "
            "ps -e -o label,pid,ppid,comm,args | grep -E 'control|overlay-runtime'"
            " | grep -v grep || true",
        )
        for unit in UNITS:
            self.fact(
                f"{tag}.unit.{unit}",
                f"systemctl show -p LoadState -p ActiveState -p SubState -p MainPID "
                f"-p NoNewPrivileges -p SELinuxContext -p ExecStart -p DropInPaths "
                f"{unit}; pid=$(systemctl show -P MainPID {unit}); "
                'if [ "${pid:-0}" != 0 ]; then echo "context of $pid: '
                '$(cat /proc/$pid/attr/current)"; fi; '
                f"systemctl cat {unit} 2>&1 | head -60",
            )
        self.fact(
            f"{tag}.failed",
            "systemctl list-units --failed --all --plain --no-legend --no-pager",
        )
        self.fact(f"{tag}.run-files", f"ls -Zd {RUN_FILES} 2>&1")
        self.fact(f"{tag}.issue-d", "ls -laZ /etc/issue.d/ 2>&1")

    def hidden_facts(self, n: int) -> None:
        tag = f"hidden-{n}"
        self.place_facts(tag)
        self.fact(f"{tag}.labels", f"ls -Zd {LABEL_PATHS} 2>&1")
        work = self.as_operator(
            "echo '# x' >> /etc/protocols; echo n > /etc/dsx-new; "
            "echo n > /root/dsx-new; echo n > /var/tmp/dsx-new; "
            "mkdir -p /home/dsx-dir; echo n > /home/dsx-dir/f"
        )
        self.fact(
            f"{tag}.new-files",
            f"{work}; ls -Z /etc/protocols /etc/dsx-new /root/dsx-new "
            "/var/tmp/dsx-new /home/dsx-dir /home/dsx-dir/f; "
            "ls -Z /mnt/data/root/upper/etc/protocols "
            "/mnt/data/root/upper/etc/dsx-new /mnt/data/root/upper/root/dsx-new 2>&1",
        )
        source = self.decoy_source
        device = source.split("[", 1)[0]
        subvol = source.split("[", 1)[1].rstrip("]") if "[" in source else ""
        if device:
            options = f"ro,subvol={subvol}" if subvol else "ro"
            self.fact(
                f"{tag}.decoy-env",
                f"mkdir -p /run/dsx/ro && mount -o {options} {device} /run/dsx/ro && "
                "stat -c '%x|%y|%z' /run/dsx/ro/usr/bin/env; "
                "umount /run/dsx/ro; rmdir /run/dsx/ro",
            )

    def decoy_after(self, n: int, how: str) -> None:
        tag = f"decoy-{how}-{n}"
        self.place_facts(tag)
        marker = f"DSXIN-{self.nonce}-{n}"
        self.fact(
            f"{tag}.journal-k-json",
            "journalctl -D /run/log/journal -k -b 0 -o json --output-fields="
            "_SOURCE_MONOTONIC_TIMESTAMP,MESSAGE --no-pager",
            300,
        )
        self.fact(
            f"{tag}.kmsg-marker-in-journal-k",
            f"journalctl -k -b 0 -o cat --no-pager | grep -cF {marker} || true",
        )
        self.fact(
            f"{tag}.kmsg-marker-in-journal",
            f"journalctl -b 0 -o cat --no-pager | grep -cF {marker} || true",
        )
        self.fact(
            f"{tag}.kernel-seqnum",
            "od -An -t u8 /run/systemd/journal/kernel-seqnum",
        )
        post = f"DSXPOST-{self.nonce}-{n}"
        self.vm.execute(f"echo {post} > /dev/kmsg", check_return=False)
        self.fact(
            f"{tag}.positive-control",
            f"sleep 3; journalctl -k -b 0 -o cat --no-pager | grep -cF {post} || true",
        )
        self.fact(
            f"{tag}.journal-head",
            "journalctl -b 0 -o short-monotonic --no-pager | head -40",
        )
        self.fact(
            f"{tag}.reconcile",
            "systemctl status --no-pager overlay-runtime-boot.service 2>&1 | head -20",
        )
        self.fact(f"{tag}.env", "stat -c '%x|%y|%z' /usr/bin/env")
        self.fact(f"{tag}.dm", DM_STATE)
        self.fact(f"{tag}.disks", "lsblk -rno NAME,RO,TYPE,MOUNTPOINTS")
        self.disk_changes(f"{tag}.disk", f"/run/dsx/ref-{n}")
        self.run_labels(f"{tag}.run-labels")

    def disk_changes(self, label: str, ref: str) -> None:
        for kind, test in (
            ("mc", "\\( -newer {r} -o -cnewer {r} \\)"),
            ("a", "-anewer {r}"),
        ):
            self.fact(
                f"{label}.{kind}",
                f"for m in {DECOY_MOUNTS}; do mountpoint -q $m || continue; "
                f"find $m -xdev {test.format(r=ref)} "
                "-printf '%TY-%Tm-%Td %TT|%CY-%Cm-%Cd %CT|%AY-%Am-%Ad %AT %p\\n'"
                " 2>/dev/null; done | sort -u",
                600,
            )

    # --- flows -----------------------------------------------------------

    def age_env(self, label: str) -> None:
        """The decoy's env as one nothing has run for a day, so that the next
        access through a mount that updates access times shows."""
        self.sh(
            label,
            "touch -a -d '2 days ago' /usr/bin/env; "
            "stat -c '%x|%y|%z' /usr/bin/env; sleep 1.1",
        )

    def control(self) -> None:
        self.age_env("control.env-age")
        self.mark("control-start")
        self.sh("control.ref", "touch /run/dsx/ref-0")
        place = self.switch("systemctl soft-reboot", "control")
        if place == "lost":
            self.restart("after the control was lost")
            return
        self.mark("control-end")
        self.fact("control.getenforce", "getenforce")
        self.fact("control.env", "stat -c '%x|%y|%z' /usr/bin/env")
        self.disk_changes("control.disk", "/run/dsx/ref-0")
        self.run_labels("control.run-labels")

    def control_after_restart(self) -> None:
        """The plain soft-reboot after a restart (:meth:`restart`)."""
        self.age_env("controlr.env-age")
        self.mark("controlr-start")
        place = self.switch("systemctl soft-reboot", f"controlr-{self.boot}")
        if place == "lost":
            self.restart("after the control of a restart was lost", settle=False)
            return
        self.mark("controlr-end")

    def control2(self) -> None:
        """A second plain soft-reboot, once the sessions are over: what the
        decoy's own services are denied at a switch then is no denial of
        NAILS either."""
        self.age_env("control2.env-age")
        self.mark("control2-start")
        self.sh("control2.ref", "touch /run/dsx/ref-9")
        place = self.switch("systemctl soft-reboot", "control2")
        if place == "lost":
            return
        self.mark("control2-end")
        self.fact("control2.getenforce", "getenforce")
        self.fact("control2.env", "stat -c '%x|%y|%z' /usr/bin/env")
        self.fact("control2.issue-d", "ls -laZ /etc/issue.d/ 2>&1")
        self.disk_changes("control2.disk", "/run/dsx/ref-9")

    def enter(self, n: int, how: str) -> bool:
        config = AUTO_CONFIG if how == "autoemerg" else CONFIG
        self.run_labels(f"pre-{n}.run-labels")
        self.fact(f"pre-{n}.run-files", f"ls -Zd {RUN_FILES} 2>&1")
        self.fact(f"pre-{n}.disks", "lsblk -rno NAME,RO,TYPE,MOUNTPOINTS")
        self.age_env(f"pre-{n}.env-age")
        self.sh(f"pre-{n}.ref", f"touch /run/dsx/ref-{n}")
        self.fact(
            f"pre-{n}.check",
            self.as_operator(f"{NAILS} --config {config} check --overlay-only"),
            600,
        )
        self.mark(f"enter-{n}")
        place = self.switch(
            self.as_operator(
                f"{NAILS} --config {config} activate -y "
                f"> /mnt/data/activate-{n}.log 2>&1"
            ),
            f"enter-{n}",
        )
        if place == "lost":
            return False
        self.mark(f"hidden-{n}")
        self.fact(f"enter-{n}.log", f"cat /mnt/data/activate-{n}.log")
        if place != "hidden":
            self.result["flows"][f"enter-{n}"]["refused"] = True
            self.place_facts(f"refused-{n}")
            return False
        self.hidden_facts(n)
        return True

    def in_session(self, n: int) -> None:
        self.mark(f"session-{n}")
        self.fact(
            f"session-{n}.work",
            self.as_operator(
                "mkdir -p /root/work && echo hidden > /root/work/note && "
                "cp /etc/os-release /root/work/ && ls -Z /root/work"
            ),
        )
        self.fact(
            f"session-{n}.status",
            self.as_operator(f"{NAILS} --config {CONFIG} status --json"),
        )
        self.vm.execute(f"echo DSXIN-{self.nonce}-{n} > /dev/kmsg", check_return=False)
        time.sleep(25)
        self.fact(
            f"session-{n}.after",
            "systemctl list-units --failed --all --plain "
            "--no-legend --no-pager; journalctl -b 0 -p warning -o "
            "short-monotonic --no-pager | tail -60",
        )
        self.fact(f"session-{n}.trace", "cat /run/dsx/dsxrec/dsxtrace")
        self.read_kmsg(f"session-{n}")

    def in_session_marker(self, n: int) -> None:
        """The kernel log marker of a session that does nothing else, which
        the decoy's journal must not hold after the way back."""
        self.mark(f"session-{n}")
        self.vm.execute(f"echo DSXIN-{self.nonce}-{n} > /dev/kmsg", check_return=False)
        time.sleep(5)
        self.read_kmsg(f"session-{n}")

    def hotplug(self, n: int) -> None:
        """A disk attached to the machine during the session, as a USB disk
        would be, formatted and mounted read-write by the operator, written
        to and unmounted; it stays attached for the rest of the run. The disk
        guard's udev rule (opt-in) runs the RAM copy for it as it appears, and
        the watcher raises its mount alert (on by default) and, opted in, sets
        the disk read-only again under the mount."""
        self.mark(f"hotplug-{n}")
        image = os.path.abspath(f"hotplug-{self.nonce}-{n}.img")
        with open(image, "wb") as handle:
            handle.truncate(HOTPLUG_BYTES)
        drive = f"hp{n}"
        self.monitor(
            f"hotplug-{n}.drive-add",
            f"drive_add 0 if=none,id={drive},file={image},format=raw",
        )
        self.monitor(
            f"hotplug-{n}.device-add",
            f"device_add virtio-blk-pci,drive={drive},id={drive}d,serial={drive}",
        )
        disk = f"/dev/disk/by-id/virtio-{drive}"
        node = f"$(readlink -f {disk})"
        state = (
            f'echo "disk={node} ro=$(blockdev --getro {disk} 2>&1)"; '
            "echo --record; cat /run/overlay-runtime/read-only-devices 2>&1; "
            "echo --trace; grep -E 'guard-device|watch' /run/dsx/dsxrec/dsxtrace"
        )
        self.fact(
            f"hotplug-{n}.attached",
            f"for i in $(seq 30); do [ -b {disk} ] && break; sleep 1; done; "
            f"udevadm settle -t 30; {state}; echo --rules; "
            "ls -Z /run/udev/rules.d/ 2>&1",
        )
        self.mark(f"hpmount-{n}")
        # The format's last close makes udev see the disk change, which runs
        # the rule again: settled, the disk is set writable once more first.
        self.fact(
            f"hotplug-{n}.mount",
            self.as_operator(
                f"blockdev --setrw {disk} && mkfs.ext4 -q -F {disk} && "
                f"udevadm settle -t 30; blockdev --setrw {disk}; mkdir -p /mnt/hp && "
                f"mount {disk} /mnt/hp && echo hidden > /mnt/hp/f && sync; "
                f'echo "mount=$? ro=$(blockdev --getro {disk})"; '
                "findmnt -no SOURCE,OPTIONS /mnt/hp"
            ),
        )
        # Two polls of the watcher: its read-only sweep and its mount alert.
        time.sleep(12)
        self.fact(
            f"hotplug-{n}.watched",
            f"{state}; echo --mount; findmnt -no SOURCE,OPTIONS /mnt/hp",
        )
        self.fact(
            f"hotplug-{n}.umount",
            self.as_operator('umount /mnt/hp; echo "umount=$?"'),
        )
        self.read_kmsg(f"hotplug-{n}")

    def relabel_in_session(self, n: int) -> None:
        """What a relabel of /run during the session does to the RAM copy:
        restorecon gives it the type the policy names for its path."""
        self.fact(
            f"restorecon-{n}",
            self.as_operator(f"ls -Z {RAM}; restorecon -v {RAM}; ls -Z {RAM}"),
        )

    def leave(self, n: int, how: str) -> None:
        self.mark(f"leave-{n}")
        if how == "deactivate":
            trigger = self.as_operator(f"{NAILS} --config {CONFIG} deactivate -y")
        elif how == "emergency":
            trigger = self.as_operator(
                f"{RAM} --config {CONFIG} emergency --json > /dev/null"
            )
        else:
            # The watcher's automatic emergency: the hidden volume's mount
            # turns read-only, the watcher's write probe fails, and after the
            # debounce window the watcher runs the emergency in its own
            # process. Nothing else is triggered.
            self.fact(
                f"{how}-{n}.remount",
                "mount -o remount,bind,ro /mnt/data; echo remount=$?; "
                "findmnt -no SOURCE,OPTIONS /mnt/data",
            )
            trigger = "true"
        place = self.switch(trigger, f"{how}-{n}")
        if place == "lost":
            self.restart(f"after {how}-{n} was lost")
            return
        self.mark(f"decoy-{n}")
        self.decoy_after(n, how)
        self.read_kmsg(f"decoy-{n}")

    # --- the run ---------------------------------------------------------

    def control_signatures(self) -> list[str]:
        """The denials of every plain soft-reboot of the run."""
        found: set[str] = set()
        for boot in self.boots:
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            for start, end in zip(markers, markers[1:], strict=False):
                if start["label"] in CONTROL_STARTS:
                    found.update(
                        sc.phase(boot["records"].values(), start["seq"], end["seq"])[
                            "signatures"
                        ]
                    )
        return sorted(found)

    def summarise(self) -> None:
        self.result["boots"] = []
        control = self.control_signatures()
        for index, boot in enumerate(self.boots):
            records = boot["records"]
            seqs = sorted(records)
            trace = sc.trace_lines(
                "\n".join(
                    value for key, value in boot["facts"].items() if "trace" in key
                )
            )
            pids = sc.nails_pids(trace)
            relabels = sc.relabel_lines(
                "\n".join(
                    value for key, value in boot["facts"].items() if "trace" in key
                )
            )
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            phases = []
            bounds = [None, *[m["seq"] for m in markers], None]
            labels = ["boot", *[m["label"] for m in markers]]
            for label, first, last in zip(labels, bounds, bounds[1:], strict=False):
                summary = sc.phase(records.values(), first, last, control, pids)
                summary["label"] = label
                phases.append(summary)
            labels_seq = {m["label"]: m["seq"] for m in markers}
            cursors = {}
            for key, value in boot["facts"].items():
                if not key.endswith(".journal-k-json"):
                    continue
                n = key.split(".")[0].rsplit("-", 1)[-1]
                cursors[key] = sc.cursor(
                    list(records.values()),
                    value,
                    labels_seq.get(f"enter-{n}"),
                    labels_seq.get(f"leave-{n}"),
                    labels_seq.get(f"decoy-{n}"),
                )
            self.result["boots"].append(
                {
                    "cursors": cursors,
                    "index": index,
                    "why": boot["why"],
                    "markers": boot["markers"],
                    "records": len(records),
                    "firstSeq": seqs[0] if seqs else None,
                    "lastSeq": seqs[-1] if seqs else None,
                    "gaps": sc.gaps(seqs),
                    "dropped": boot["dropped"],
                    "phases": phases,
                    "facts": boot["facts"],
                    "console": boot["console"],
                    "trace": trace,
                    "relabels": relabels,
                }
            )
        self.result["controlSignatures"] = control

    def write(self) -> None:
        self.summarise()
        os.makedirs(self.out_dir, exist_ok=True)
        base = os.path.join(self.out_dir, self.name)
        with open(base + ".json", "w", encoding="utf-8") as handle:
            json.dump(self.result, handle, indent=1, sort_keys=True)
        with open(base + ".raw.json", "w", encoding="utf-8") as handle:
            json.dump(self.raw, handle, indent=1, sort_keys=True)
        with open(base + ".kmsg.txt", "w", encoding="utf-8") as handle:
            for index, boot in enumerate(self.boots):
                for seq in sorted(boot["records"]):
                    record = boot["records"][seq]
                    handle.write(f"{index} {seq} {record['us']} {record['msg']}\n")
        print(f"cell results written to {base}.json")

    def step(self, label: str, action: Any, *args: Any) -> Any:
        try:
            return action(*args)
        except Exception as error:  # noqa: BLE001 - recorded, the run goes on
            self.result["flows"].setdefault(label, {})["exception"] = (
                f"{error}\n{traceback.format_exc()}"
            )
            print(f"step {label} raised: {error}")
            return None

    def flows(self) -> list[tuple[int, str]]:
        """The cell's flows: each number with how its session ends."""
        flows = [(1, "deactivate"), (2, "emergency")]
        if self.settings.get("autoEmergency"):
            flows.append((3, "autoemerg"))
        return flows

    def run(self) -> None:
        self.new_boot("first boot")
        try:
            self.prepare()
            self.operator()
            self.hidden_root("hidden-root")
            self.mark("boot-ready")
            self.decoy_facts()
            self.run_labels("boot.run-labels")
            self.step("control", self.control)
            for n, how in self.flows():
                self.hidden_root(f"hidden-root-{n}")
                self.step(f"enter-{n}", self.enter, n, how)
                place = self.where()
                if place == "hidden":
                    if n == 1:
                        if self.settings.get("hotplug"):
                            self.step(f"hotplug-{n}", self.hotplug, n)
                        self.step(f"session-{n}", self.in_session, n)
                    else:
                        self.step(f"session-{n}", self.in_session_marker, n)
                    if self.settings.get("restorecon"):
                        self.step(f"restorecon-{n}", self.relabel_in_session, n)
                    self.step(f"{how}-{n}", self.leave, n, how)
                elif place == "down":
                    self.restart(f"after enter-{n} was lost")
            if self.where() == "decoy":
                self.step("control2", self.control2)
        finally:
            self.write()


def run(
    vm: Any,
    session: Any,
    settings: dict[str, Any],
    scripts: dict[str, str],
) -> None:
    """Run the cell ``settings`` names on ``vm`` and write its results."""
    out_dir = os.environ.get("NAILS_CELL_OUT") or os.getcwd()
    Cell(vm, session, settings, scripts, out_dir).run()
