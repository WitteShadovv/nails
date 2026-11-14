"""The run of one SELinux cell on an enforcing Fedora image (research only).

``nix/distro-tests/cells.nix`` builds one host driver per cell and calls
:func:`run` with the driver's machine. A cell is an image, a way of starting
the RAM copy of the binary (``none``, ``env`` or ``context``, see the research
build's ``research_cell`` module) and whether the policy's dontaudit rules are
on. The run:

1. boots the image, makes the decoy amnesic (volatile journal, auditd
   masked), lifts the kernel log's rate limits, optionally rebuilds the policy
   without its dontaudit rules (``semodule -DB``: the test VM's policy store
   only), names the cell's mechanism in ``/run/dsx/dsxcell`` and records the
   decoy's facts;
2. soft-reboots once with no NAILS involved, the control whose denials are
   not counted as new;
3. enters a hidden session from an unconfined operator shell (``runcon``),
   runs a command in it and deactivates;
4. enters again and ends that session with the emergency.

It writes a marker to ``/dev/kmsg`` at every step, reads the whole kernel log
after every step, and keeps every command's output. A step that fails is
recorded and the run goes on where it can: after a power-off the next flow
starts on a fresh boot of the image. The result is ``<cell>.json`` (facts,
flows and denials per phase), ``<cell>.raw.json`` (every command's output) and
``<cell>.kmsg.txt`` in the output directory.
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
CONFIG_TEXT = "\n".join(
    (
        'hidden_volume_root = "/mnt/data"',
        "minimum_space_mb = 100",
        "",
        "[sleep_policy]",
        'mode = "block"',
        "",
        "[session_mounts]",
        "read_only = true",
        "",
    )
)
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
            status, out = self.vm.execute(
                f"( {cmd} ) 2>&1", check_return=False, timeout=timeout
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

    # --- the kernel log --------------------------------------------------

    def read_kmsg(self, where: str) -> None:
        current = self.boots[self.boot]
        first = max(current["records"], default=0)
        status, out = self.vm.execute(
            sc.kmsg_command(first), check_return=False, timeout=180
        )
        records, dropped = sc.parse_kmsg(out)
        current["dropped"] += dropped
        sc.merge(current["records"], records)
        print(f"kmsg {where}: {len(records)} records from {first} (exit {status})")

    def mark(self, label: str) -> int | None:
        text = sc.marker(label, self.nonce)
        self.vm.execute(
            f"echo {shlex.quote(text)} > /dev/kmsg", check_return=False, timeout=60
        )
        self.read_kmsg(label)
        seq = sc.marker_seq(self.boots[self.boot]["records"].values(), text)
        self.boots[self.boot]["markers"].append({"label": label, "seq": seq})
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
        vm.succeed(f"cat > {CONFIG} <<'EOF'\n{CONFIG_TEXT}EOF")
        self.sh("limits", LIMITS)
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

    def operator(self) -> None:
        """Decide how NAILS runs: from unconfined_t through runcon, checked
        with id -Z first, else from the backdoor's own domain."""
        self.fact("backdoor-id", "id -Z")
        self.fact("su-l-id", "su -l root -c 'id -Z'")
        self.op = ""
        self.result["operator"] = "backdoor (no runcon gave unconfined_t)"
        for label, prefix in (
            ("runcon-id", f"runcon {OPERATOR} "),
            ("runcon-type-id", "runcon -t unconfined_t "),
        ):
            out = self.fact(label, f"{prefix}id -Z")
            if ":unconfined_t:" in out and "denied" not in out:
                self.op = prefix
                self.result["operator"] = f"{prefix.strip()} (id -Z: {out})"
                break

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
            return "lost"
        self.after_switch()
        fstype = self.vm.execute("findmnt -no FSTYPE /", check_return=False)[1]
        place = "hidden" if fstype.strip() == "overlay" else "decoy"
        self.result["flows"][label] = {"ok": True, "place": place}
        return place

    def restart(self, why: str) -> None:
        """A fresh boot of the image after the machine went down."""
        process = getattr(self.vm, "process", None)
        try:
            if process is not None and process.poll() is None:
                self.vm.crash()
            else:
                self.vm.wait_for_shutdown()
        except Exception as error:  # noqa: BLE001
            print(f"stopping the machine: {error}")
        self.vm.start(allow_reboot=False)
        self.new_boot(why)
        self.prepare()
        self.operator()
        self.mark("boot-ready")

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
            f"{self.op}sh -c 'touch /mnt/data/.dsxrt && chcon -t etc_t /mnt/data/.dsxrt"
            " && stat -c %C /mnt/data/.dsxrt; rm -f /mnt/data/.dsxrt'",
        )
        self.fact("decoy-root", "findmnt -rn -o SOURCE,OPTIONS /")

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
        self.fact(
            f"{tag}.ps",
            "ps -eZ -o label,pid,ppid,comm,args | grep -E 'control|overlay-runtime'"
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

    def hidden_facts(self, n: int) -> None:
        tag = f"hidden-{n}"
        self.place_facts(tag)
        self.fact(f"{tag}.labels", f"ls -Zd {LABEL_PATHS} 2>&1")
        op = self.op
        self.fact(
            f"{tag}.new-files",
            f"{op}sh -c 'printf x >> /etc/issue; echo n > /etc/dsx-new; "
            "echo n > /root/dsx-new; echo n > /var/tmp/dsx-new; "
            "mkdir -p /home/dsx-dir; echo n > /home/dsx-dir/f'; "
            "ls -Z /etc/issue /etc/dsx-new /root/dsx-new /var/tmp/dsx-new "
            "/home/dsx-dir /home/dsx-dir/f; "
            "ls -Z /mnt/data/root/upper/etc/issue /mnt/data/root/upper/etc/dsx-new "
            "/mnt/data/root/upper/root/dsx-new 2>&1",
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

    def control(self) -> None:
        self.mark("control-start")
        self.sh("control.ref", "touch /run/dsx/ref-0")
        place = self.switch("systemctl soft-reboot", "control")
        if place == "lost":
            self.restart("after the control was lost")
            return
        self.mark("control-end")
        self.fact("control.getenforce", "getenforce")
        self.disk_changes("control.disk", "/run/dsx/ref-0")
        self.run_labels("control.run-labels")

    def enter(self, n: int) -> bool:
        op = self.op
        self.run_labels(f"pre-{n}.run-labels")
        self.fact(f"pre-{n}.run-files", f"ls -Zd {RUN_FILES} 2>&1")
        # The decoy's env as one nothing has run for a day: a later access
        # through a mount that updates access times shows.
        self.sh(
            f"pre-{n}.env-age",
            "touch -a -d '2 days ago' /usr/bin/env; "
            "stat -c '%x|%y|%z' /usr/bin/env; sleep 1.1; "
            f"touch /run/dsx/ref-{n}",
        )
        self.fact(
            f"pre-{n}.check", f"{op}{NAILS} --config {CONFIG} check --overlay-only", 600
        )
        self.mark(f"enter-{n}")
        place = self.switch(
            f"{op}{NAILS} --config {CONFIG} activate -y "
            f"> /mnt/data/activate-{n}.log 2>&1",
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
        op = self.op
        self.mark(f"session-{n}")
        self.fact(
            f"session-{n}.work",
            f"{op}sh -c 'mkdir -p /root/work && echo hidden > /root/work/note && "
            "cp /etc/hostname /root/work/ && ls -Z /root/work'",
        )
        self.fact(f"session-{n}.status", f"{op}{NAILS} --config {CONFIG} status --json")
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

    def leave(self, n: int, how: str) -> None:
        op = self.op
        self.mark(f"leave-{n}")
        if how == "deactivate":
            trigger = f"{op}{NAILS} --config {CONFIG} deactivate -y"
        else:
            trigger = f"{op}{RAM} --config {CONFIG} emergency --json > /dev/null"
        place = self.switch(trigger, f"{how}-{n}")
        if place == "lost":
            self.restart(f"after {how}-{n} was lost")
            return
        self.mark(f"decoy-{n}")
        self.decoy_after(n, how)
        self.read_kmsg(f"decoy-{n}")

    # --- the run ---------------------------------------------------------

    def summarise(self) -> None:
        self.result["boots"] = []
        control: list[str] = []
        for index, boot in enumerate(self.boots):
            records = boot["records"]
            seqs = sorted(records)
            trace = sc.trace_lines(
                "\n".join(
                    value for key, value in boot["facts"].items() if "trace" in key
                )
            )
            pids = sc.nails_pids(trace)
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            phases = []
            bounds = [None, *[m["seq"] for m in markers], None]
            labels = ["boot", *[m["label"] for m in markers]]
            for label, first, last in zip(labels, bounds, bounds[1:], strict=False):
                summary = sc.phase(records.values(), first, last, control, pids)
                summary["label"] = label
                if label == "control-start":
                    control = summary["signatures"]
                    summary = sc.phase(records.values(), first, last, control, pids)
                    summary["label"] = label
                phases.append(summary)
            self.result["boots"].append(
                {
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

    def run(self) -> None:
        self.new_boot("first boot")
        try:
            self.prepare()
            self.operator()
            self.sh("hidden-root", self.scripts["setup_hidden_root"], 300)
            self.mark("boot-ready")
            self.decoy_facts()
            self.run_labels("boot.run-labels")
            self.step("control", self.control)
            for n, how in ((1, "deactivate"), (2, "emergency")):
                self.sh(f"hidden-root-{n}", self.scripts["setup_hidden_root"], 300)
                entered = self.step(f"enter-{n}", self.enter, n)
                if entered:
                    if n == 1:
                        self.step(f"session-{n}", self.in_session, n)
                    else:
                        self.mark(f"session-{n}")
                    self.step(f"{how}-{n}", self.leave, n, how)
                elif self.result["flows"].get(f"enter-{n}", {}).get("ok") is False:
                    self.restart(f"after enter-{n} was lost")
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
