"""The gate scenario of an enforcing Fedora decoy, before Fedora is admitted.

``nix/distro-tests/fedora-gate.nix`` builds one host driver per pinned Fedora
image (``<image>-gate``) and calls :func:`run` with the driver's machine. The
image boots with SELinux enforcing, and NAILS is a test-only build that admits
Fedora. Every ``nails`` command runs from a real operator domain: a login
session of its own, a transient unit with the login PAM stack, whose
pam_selinux gives the user its default context (``unconfined_t``), checked
with ``id -Z`` first. The harness's own shell runs as a service
(``unconfined_service_t``), so ``runcon`` and ``su -l`` from it do not reach
that domain.

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
   check clean on the prepared decoy;
3. a plain soft-reboot, the control whose denials are no denial of NAILS;
4. a first session, ended with ``deactivate``: SELinux enforcing in it; the
   labels of the hidden ``/``, ``/home`` and ``/var``; a copied-up file keeps
   its type and a new one gets the policy's; NAILS's processes never in
   ``init_t``; the overlay feature options pinned; the canaries land in the
   uppers; no unit the hidden root masks failed; a login in the session; a
   kernel log marker; a disk attached in the session reads ``getro 1``; and
   after the way back: enforcing; the marker not in the decoy's journal, which
   took no kernel record of the session, and the cursor above it; nothing the
   session made left in ``/run``; ``utab`` as recorded; ``/run/initramfs``
   unchanged; the attached disk ``getro 0``; the login and boot records as a
   power cycle leaves them, with no record of the hidden login;
5. a package the decoy removes after a hidden session changed its own copy of
   the package database: check warns of it with its fix;
6. a second session, as a user through sudo with the fresh-home persona: its
   home labelled ``user_home_dir_t``; the same assertions in it; the entry's
   drift advisory; ended with the emergency, and the same way-back assertions;
7. a last plain soft-reboot, and a login on the decoy, the positive control of
   the login records.

Every denial is counted from the boot before NAILS ran, in both roots: one is
new when it is NAILS's own, or when neither the boot before NAILS ran nor the
first plain soft-reboot logged its signature (``selinux_gate``). Each
assertion is recorded with its outcome and the run goes on where it can, so
one run says which assertions hold and which do not; ``<image>-gate.json``
and ``<image>-gate.kmsg.txt`` in the directory ``NAILS_GATE_OUT`` names hold
them, and the run fails at its end when one does not hold.
"""

from __future__ import annotations

import json
import os
import shlex
import tempfile
import traceback
import uuid
from typing import Any

import distro_checks
import fedora_rpms
import selinux_gate as sg

NAILS = "/run/tools/nails"
RAM = "/run/overlay-runtime/control"
CONFIG = "/run/nails-gate.toml"
FRESH_CONFIG = "/run/nails-gate-fresh.toml"
HIDDEN = "/mnt/data"
UPPER = f"{HIDDEN}/root/upper"
# The hidden root's configuration: the disk guard on, so that a disk attached
# in the session is set read-only.
CONFIG_TEXT = (
    f'hidden_volume_root = "{HIDDEN}"\n'
    "minimum_space_mb = 100\n"
    "\n[session_mounts]\nread_only = true\n"
)
FRESH_TEXT = '\n[persona]\nmode = "fresh-home"\n'
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
# Where a disk attached in the session appears, by its serial.
HOTPLUG_BYTES = 64 << 20
# The trees the canaries go to: the whole root is overlaid, /home and /var
# are filesystems of their own on Fedora's btrfs.
CANARY_TREES = ("home", "etc", "var", "usr", "root", "opt", "srv")
# The units the hidden root keeps from running: none may be failed in it.
HIDDEN_MASKED = (
    "systemd-remount-fs.service",
    "systemd-growfs-root.service",
    "systemd-boot-random-seed.service",
    "grub-boot-indeterminate.service",
    "grub-boot-success.timer",
    "grub-boot-success.service",
)
# The pieces the way back leaves in /run for the decoy's first start, which
# its reconcile step removes.
WAY_BACK_PIECES = (
    "/run/overlay-runtime-boot",
    "/run/systemd/system/overlay-runtime-boot.service",
)
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


class Gate:
    """One gate run on the machine ``vm``."""

    def __init__(
        self,
        vm: Any,
        session: Any,
        utab: Any,
        records: Any,
        settings: dict[str, Any],
        scripts: dict[str, str],
        out_dir: str,
    ) -> None:
        self.vm = vm
        self.session = session
        self.utab = utab
        self.records = records
        self.settings = settings
        self.scripts = scripts
        self.out_dir = out_dir
        self.image = str(settings["image"])
        self.name = f"{self.image}-gate"
        self.nonce = uuid.uuid4().hex[:10]
        self.boot = -1
        self.boots: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        self.facts: dict[str, Any] = {}
        self.raw: dict[str, Any] = {}
        self.calls = 0
        self.where = "decoy before the first entry"
        self.lost = False

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

    def pam_login(self, user: str) -> str:
        """A console login of ``user`` through PAM's login stack, as a getty's
        login runs it on a terminal: systemd opens the PAM session and writes
        the session's utmp and wtmp records, and pam_lastlog2 its row."""
        return (
            "systemd-run --wait --collect --quiet -p PAMName=login "
            f"-p User={user} -p TTYPath=/dev/{LOGIN_TTY} "
            f"-p UtmpIdentifier={LOGIN_TTY} -p UtmpMode=user /bin/true"
        )

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

    # --- boots and switches ----------------------------------------------

    def new_boot(self, why: str) -> None:
        self.boot += 1
        self.boots.append(
            {"why": why, "records": {}, "dropped": 0, "markers": [], "console": []}
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
        self.sh("limits", sg.KMSG_LIMITS)

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

    def records_capture(self, label: str) -> Any:
        """The decoy's login and boot records, read live: wtmp, btmp,
        lastlog, lastlog2 and wtmpdb where the image has them."""
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

    # --- the decoy -------------------------------------------------------

    def decoy(self) -> None:
        """Everything on the decoy before the first entry, with a hidden root
        mounted, which check needs to judge the decoy."""
        vm = self.vm
        self.mark("prep-decoy")
        self.sh("hidden-root", self.scripts["setup_hidden_root"])
        self.enforcing("on the decoy before the first entry")
        config = self.fact(
            "selinux-config", "grep -E '^SELINUX(TYPE)?=' /etc/selinux/config"
        )
        self.check(
            "the decoy runs the targeted policy, enforcing",
            "SELINUX=enforcing" in config and "SELINUXTYPE=targeted" in config,
            config,
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
        self.fact("backdoor-id", "id -Z")
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
            "journal" not in str(row.get("message", "")).lower(),
            row,
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
        _, rows = self.check_rows("check-auditd-off")
        row = rows.get("decoy-persistence", {})
        self.check(
            "check no longer names auditd once it is off",
            "audit"
            not in (
                str(row.get("message", "")) + str(row.get("remediation", ""))
            ).lower(),
            row,
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
        status, rows = self.check_rows("check-posture")
        row = rows.get("decoy-persistence", {})
        text = json.dumps(row)
        found_tuned = row.get("status") == "fail" and "tuned" in text
        self.check(
            "check refuses tuned while it logs to its file",
            found_tuned and status == 4,
            row or status,
            NEEDS_POSTURE,
        )
        found_firewalld = "firewalld" in text
        self.check(
            "check warns of firewalld's log file", found_firewalld, row, NEEDS_POSTURE
        )
        found_abrt = "abrt" in text.lower()
        self.check("check warns of ABRT", found_abrt, row, NEEDS_POSTURE)
        # The documented fixes: tuned without -l, firewalld to the journal,
        # ABRT off.
        self.vm.succeed(
            "mkdir -p /etc/systemd/system/tuned.service.d && "
            f"printf %s {shlex.quote(TUNED_DROPIN)} > "
            "/etc/systemd/system/tuned.service.d/50-journal.conf && "
            "if systemctl cat tuned-ppd.service >/dev/null 2>&1; then "
            "mkdir -p /etc/systemd/system/tuned-ppd.service.d && printf %s "
            + shlex.quote("[Service]\nExecStart=\nExecStart=/usr/sbin/tuned-ppd\n")
            + " > /etc/systemd/system/tuned-ppd.service.d/50-journal.conf; fi; "
            "systemctl daemon-reload && systemctl restart tuned.service && "
            "printf 'FIREWALLD_ARGS=--log-target=syslog\\n' "
            "> /etc/sysconfig/firewalld && "
            "systemctl restart firewalld.service && "
            "systemctl disable --now abrtd.service"
        )
        status, rows = self.check_rows("check-posture-fixed")
        text = json.dumps(rows.get("decoy-persistence", {}))
        for daemon, found in (
            ("tuned", found_tuned),
            ("firewalld", found_firewalld),
            ("ABRT", found_abrt),
        ):
            if not found:
                # Nothing was found to fix: a pass here would say nothing.
                self.check(
                    f"check names {daemon} no more after its documented fix",
                    False,
                    "not judged: check never named it",
                    NEEDS_POSTURE,
                )
                continue
            self.check(
                f"check names {daemon} no more after its documented fix",
                daemon.lower() not in text.lower(),
                text,
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
            not failed and status in (0, 9),
            {"exit": status, "failed": failed},
        )
        allowed = set()
        if not self.settings.get("validated"):
            allowed.add("platform")
        self.check(
            "check warns of nothing on the prepared decoy but an untested release",
            set(warned) <= allowed,
            warned,
        )

    # --- a session -------------------------------------------------------

    def before_entry(self, n: int) -> dict[str, Any]:
        """What the way back is compared with, taken on the decoy right before
        the entry."""
        state: dict[str, Any] = {}
        state["run"] = self.run_listing()
        state["wall"] = self.session.wall_clock(self.vm)
        state["mountinfo"] = self.vm.succeed("cat /proc/self/mountinfo")
        state["utab"] = self.vm.succeed("cat /run/mount/utab 2>/dev/null || true")
        state["initramfs"] = self.initramfs()
        state["records"] = self.records_capture(f"before-{n}")
        state["noexec"] = "noexec" in self.vm.succeed("findmnt -no OPTIONS /run")
        state["failed"] = self.failed_units(f"failed-before-{n}")
        return state

    def enter(self, n: int, user: str, config: str) -> bool:
        status, rows = self.check_rows(f"check-before-{n}", user, config)
        self.facts[f"check-before-{n}"] = rows
        drift = rows.get("package-drift", {})
        self.facts[f"drift-{n}"] = drift
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

    def hidden(self, n: int, user: str) -> None:
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
        failed = self.failed_units(f"failed-hidden-{n}")
        self.check(
            f"session {n}: no unit the hidden root keeps off failed",
            not set(failed) & set(HIDDEN_MASKED),
            failed,
        )
        self.facts[f"failed-hidden-{n}"] = failed
        # A login in the hidden session: its records land in the upper, and
        # none may reach the decoy.
        start = self.fact(
            f"hidden-start-{n}",
            "systemctl show -P UserspaceTimestamp --timestamp=unix",
        )
        self.facts[f"hidden-start-{n}"] = start.lstrip("@")
        self.sh(f"hidden-login-{n}", self.pam_login(USER))
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
        self.vm.execute(f"echo GATEIN-{self.nonce}-{n} > /dev/kmsg", check_return=False)
        self.read_kmsg()
        self.facts[f"in-session-seq-{n}"] = sg.marker_seq(
            self.boots[self.boot]["records"].values(), f"GATEIN-{self.nonce}-{n}"
        )

    def hotplug(self, n: int) -> str:
        """A disk attached during the session, as a USB disk would be: the
        disk guard sets it read-only."""
        image = os.path.abspath(f"gate-hotplug-{self.nonce}-{n}.img")
        with open(image, "wb") as handle:
            handle.truncate(HOTPLUG_BYTES)
        drive = f"gate{n}"
        self.vm.send_monitor_command(
            f"drive_add 0 if=none,id={drive},file={image},format=raw"
        )
        self.vm.send_monitor_command(
            f"device_add virtio-blk-pci,drive={drive},id={drive}d,serial={drive}"
        )
        disk = f"/dev/disk/by-id/virtio-{drive}"
        out = self.fact(
            f"hotplug-{n}",
            f"for i in $(seq 30); do [ -b {disk} ] && break; sleep 1; done; "
            f"udevadm settle -t 30; sleep 2; blockdev --getro {disk}",
        )
        self.check(
            f"session {n}: a disk attached in the session reads getro 1",
            out.strip().splitlines()[-1:] == ["1"],
            out,
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

    def after(self, n: int, state: dict[str, Any], disk: str | None) -> None:
        """The way-back assertions, on the decoy: taken before any login on it."""
        vm = self.vm
        # The records first, once the reconcile step is done, before any
        # login on the decoy writes its own.
        self.wait_reconcile()
        after = self.records_capture(f"after-{n}")
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
        residue = self.session.carried_run_residue(vm, state["run"], state["wall"])
        self.check(
            f"way back {n}: nothing of the session stays in /run", not residue, residue
        )
        pieces = [
            p for p in WAY_BACK_PIECES if vm.execute(f"test -e {p} -o -L {p}")[0] == 0
        ]
        self.check(
            f"way back {n}: the reconcile step left none of its pieces",
            not pieces,
            pieces,
        )
        noexec = "noexec" in vm.succeed("findmnt -no OPTIONS /run")
        self.check(
            f"way back {n}: /run is noexec again where the decoy had it so",
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
        failed = self.failed_units(f"failed-after-{n}")
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
        the way back, and no record of the hidden session's login. The
        operator's own logins on the decoy, before the entry, are the decoy's:
        a row of theirs is dated before the switch."""
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
        self.check(f"way back {n}: btmp gained nothing", not failed, failed)
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

    # --- the controls ----------------------------------------------------

    def control(self, label: str) -> None:
        self.mark(f"{label}-start")
        place = self.follow("systemctl soft-reboot", label)
        if place == "lost":
            return
        self.mark(f"{label}-end")
        self.enforcing(f"after {label}")
        self.failed_units(f"failed-{label}")

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
    def is_baseline(label: str) -> bool:
        """Whether the phase that starts at the marker ``label`` is one of the
        harness's own: the decoy prepared as a user prepares it (accounts,
        packages, settings, a login, nothing of NAILS but a check, which runs
        in its own phase), or the first plain soft-reboot, before any session.
        Their denials, NAILS's aside, are what the decoy logs without NAILS."""
        return label.startswith("prep-") or label in (
            "control-1-start",
            "control-1-end",
        )

    def baseline(self) -> set[str]:
        """The signatures of the denials logged without NAILS: the reference
        boot up to its first marker, the harness's own phases and the first
        plain soft-reboot. A denial of a NAILS process or path never counts."""
        found: set[str] = set()
        for boot in self.boots:
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            records = list(boot["records"].values())
            if markers and boot["why"] == "reference":
                found |= {
                    a["signature"]
                    for a in sg.denials(records, None, markers[0]["seq"])
                    if a["source"] != "nails"
                }
            for start, end in zip(markers, [*markers[1:], None], strict=False):
                if self.is_baseline(start["label"]):
                    found |= {
                        a["signature"]
                        for a in sg.denials(
                            records, start["seq"], end["seq"] if end else None
                        )
                        if a["source"] != "nails"
                    }
        return found

    def judge_denials(self) -> None:
        """Every phase NAILS ran in, in both roots, holds no new denial, and
        no phase holds a denial of NAILS's own."""
        known = self.baseline()
        self.facts["baseline-signatures"] = sorted(known)
        for boot in self.boots:
            markers = [m for m in boot["markers"] if m["seq"] is not None]
            records = list(boot["records"].values())
            dropped = boot["dropped"] or sg.gaps(sorted(boot["records"]))
            self.where = f"boot {boot['why']}"
            self.check("the kernel log lost no record", not dropped, dropped)
            missing = [m["label"] for m in boot["markers"] if m["seq"] is None]
            self.check("every marker reached the kernel log", not missing, missing)
            for start, end in zip(markers, [*markers[1:], None], strict=False):
                label = start["label"]
                found = sg.phase(
                    records, start["seq"], end["seq"] if end else None, known
                )
                boot.setdefault("phases", []).append({"label": label, **found})
                new = found["new"]
                if self.is_baseline(label) or label == "boot-ready":
                    new = [a for a in new if a["source"] == "nails"]
                needs = NEEDS_LABEL if any(a["source"] == "nails" for a in new) else ""
                self.check(
                    f"no new denial from marker {label} on",
                    not new,
                    [f"{a['signature']} ({a['why']})" for a in new],
                    needs,
                )
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
        self.power_cycle("reference")
        self.mark("boot-ready")
        self.decoy()
        self.control("control-1")
        # The first session: shared home, ended with deactivate.
        self.sh("hidden-root-1", self.scripts["setup_hidden_root"])
        state = self.before_entry(1)
        self.mark("prep-session-1")
        if self.enter(1, "root", CONFIG):
            self.hidden(1, "root")
            disk = self.hotplug(1)
            self.sh(
                "hidden-rpm-1",
                "rpm -e --nodeps --noscripts "
                + shlex.quote(self.settings["hiddenRemoves"]),
            )
            if self.leave(1, "deactivate", "root", CONFIG):
                self.after(1, state, disk)
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
        self.sh("hidden-root-2", self.scripts["reopen_hidden_root"])
        _, rows = self.check_rows("check-drift")
        row = rows.get("package-drift", {})
        self.check(
            "package-drift warns of the package the decoy removed, with its fix",
            row.get("status") == "warn"
            and removed in str(row.get("message", ""))
            and bool(row.get("remediation")),
            row,
        )
        state = self.before_entry(2)
        if self.enter(2, USER, FRESH_CONFIG):
            log = self.facts.get("activate-2.log", "")
            self.check(
                "the entry shows the drift advisory with its fix",
                removed in log,
                log[-2000:],
            )
            self.hidden(2, USER)
            if self.leave(2, "emergency", "root", FRESH_CONFIG):
                self.after(2, state, None)
        if self.lost:
            return
        self.control("control-2")
        self.mark("prep-login")
        self.records_positive()


def run(
    vm: Any,
    session: Any,
    utab: Any,
    records: Any,
    settings: dict[str, Any],
    scripts: dict[str, str],
) -> None:
    """Run the gate of the image ``settings`` names on ``vm``, with the e2e
    package's ``session`` and ``utab`` helpers and the ``records`` readers."""
    out_dir = os.environ.get("NAILS_GATE_OUT") or os.getcwd()
    Gate(vm, session, utab, records, settings, scripts, out_dir).run()
