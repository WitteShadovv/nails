# The mechanics of the whole-root session, by hand: enter a whole-root
# overlay with `systemctl soft-reboot` and power off from it, twice.
#
# This began as the research spike that decided the whole-root design and is
# now a regular test: it pins, independently of the `nails` code, the kernel
# and systemd behaviour the session mode is built on (the /run bind for PID 1's
# init check, the read-only ESP, the utab lines a switch carries, a power-off
# from the hidden root and a clean raw decoy disk). The same steps through
# `nails` are covered by session-lifecycle, session-emergency and the other
# session tests. A hidden session never goes back to the decoy: it ends in a
# power-off, as here.
#
# What it does, twice (cycle 1 and cycle 2):
#
#   1. Builds an overlay at /run/nextroot: lower = a read-only bind of the decoy
#      root, upper/work on the LUKS hidden volume (/mnt/data/root/{upper,work}).
#   2. Writes a canary through the overlay, so it lands in the upper.
#   3. `systemctl soft-reboot`: PID 1 stops userspace, switches root into
#      /run/nextroot and starts a fresh userspace there. Its last step keeps
#      of libmount's utab only the lines whose mount the switch carries, as
#      nails does: libmount joins a line to the mount with the line's mount ID,
#      and the kernel hands the IDs of the mounts left behind to the next ones.
#   4. In the hidden root: asserts the canary is at /, a new write lands in the
#      upper and not on the decoy disk, and that the vital paths work (units,
#      network, login, modprobe, /boot untouched, the Nix store and daemon,
#      the hidden volume, journald writing into the overlay).
#   5. `systemctl poweroff` from the hidden root: the kernel powers the machine
#      off for real. The cold boot through OVMF and systemd-boot is the plain
#      decoy root with the hidden mapping closed; it asserts the same vital
#      paths, that the ESP and the EFI boot entries changed no more than a
#      plain-reboot control, and that no hidden token is in the decoy journal.
#
# Timings of the switch in are measured in the guest from PID 1's own
# timestamps (ShutdownStart, Userspace and Finish) and /proc/uptime, not on the
# host.
#
# Finally it checks the firmware surfaces against the first boot and greps the
# raw decoy disk for every hidden token.
#
# The VM boots through a real bootloader (as forensic/80 does), so the Nix
# store lives on the root disk like on a real install, not on a host share, and
# the root overlay covers it. journald is set to persistent storage on purpose:
# that is the stricter case for "the hidden journal lands in the overlay".
#
# How to read the log: lines starting with `FINDING:` are research output
# (timings, residue, RAM-only traces), not assertions. Vital-path failures are
# collected and asserted together at the very end, so one run reports all of
# them; structural failures (the switch itself, the canary) fail at once.
{ pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
in
{
  name = "soft-reboot-mechanics";
  meta.tags = [
    "session"
    "forensic"
    "slow"
  ];
  # Estimate, not measured: four OVMF boots (a control and a cold boot after
  # each session), two soft-reboots, two power-offs, four trivial Nix builds
  # and one raw pass over the 20 GiB decoy disk.
  globalTimeout = 2400;

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];

      virtualisation = {
        useBootLoader = true;
        useEFIBoot = true;
        efi.keepVariables = true;
      };

      boot.loader = {
        systemd-boot.enable = true;
        efi.canTouchEfiVariables = true;
        timeout = lib.mkForce 1;
      };

      # Stricter than the suite default (volatile): the hidden journal must be
      # shown to land in the overlay upper, never in the decoy's
      # /var/log/journal.
      services.journald.settings.Journal.Storage = lib.mkForce "persistent";

      # soft-reboot.target and systemd-soft-reboot.service are among the
      # units the pinned nixpkgs installs from systemd.

      # The trivial offline build uses this bash as its builder, so it must be
      # in the system closure (and therefore registered in the VM's Nix DB).
      system.extraDependencies = [ pkgs.bash ];

      environment.systemPackages = [
        pkgs.efibootmgr
        pkgs.kmod
      ];
    };

  testScript = ''
    import secrets
    import shlex
    import signal
    import time

    from nails_e2e import session, utab

    BASH_STORE_PATH = "${pkgs.bash}"
    HIDDEN = "/mnt/data"
    UPPER = HIDDEN + "/root/upper"
    WORK = HIDDEN + "/root/work"
    PEEK = "/run/decoy-peek"

    # systemd-boot-random-seed.service rewrites loader/random-seed on every
    # userspace start, a boot's included. Nothing else on the ESP may change.
    ESP_SOFT_REBOOT_CHURN = {"loader/random-seed"}
    # In the hidden root /boot is a read-only bind of the ESP (see enter_hidden),
    # so the random-seed refresh may fail there. That failure is the policy
    # working, not a breakage.
    HIDDEN_ALLOWED_FAILED = {"systemd-boot-random-seed.service"}

    vital_failures = []
    findings = []
    timings = []
    hidden_tokens = {}


    def finding(message):
        findings.append(message)
        machine.log("FINDING: " + message)


    def token(kind):
        value = "nails-spike-" + kind + "-" + secrets.token_hex(12)
        return value


    def out_of(command, timeout=900):
        """Run a command and return (rc, stdout) without failing the test."""
        return machine.execute(command, timeout=timeout)


    # ------------------------------------------------------------------
    # Snapshots of the firmware-visible surfaces (the same three forensic/80
    # uses): ESP file hashes, EFI boot entries and the EFI variable names.
    # ------------------------------------------------------------------
    def snapshot():
        esp = machine.succeed(
            "cd /boot && find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum"
        )
        nvram = machine.succeed(
            "efibootmgr -v | grep -E '^(Boot[0-9A-Fa-f]{4}|BootOrder:)' || true"
        )
        efivars = machine.succeed("ls -1 /sys/firmware/efi/efivars | LC_ALL=C sort")
        return {"esp": esp, "nvram": nvram, "efivars": efivars}


    def esp_map(block):
        result = {}
        for line in block.splitlines():
            digest, _, path = line.strip().partition("  ")
            if path:
                result[path.removeprefix("./")] = digest
        return result


    def esp_changed(before, after):
        b, a = esp_map(before["esp"]), esp_map(after["esp"])
        return {p for p in set(b) | set(a) if b.get(p) != a.get(p)}


    def lines(block):
        return {line.strip() for line in block.splitlines() if line.strip()}


    def nvram_changed(before, after):
        return lines(before["nvram"]) ^ lines(after["nvram"])


    def efivars_changed(before, after):
        return lines(before["efivars"]) ^ lines(after["efivars"])


    def vital(label, name, ok, detail=""):
        if ok:
            machine.log(f"[{label}] ok: {name}")
        else:
            vital_failures.append(f"{label}: {name}: {detail}")
            machine.log(f"[{label}] VITAL CHECK FAILED: {name}: {detail}")


    # ------------------------------------------------------------------
    # The vital paths. Every check records a pass or a failure; the failures
    # are asserted together at the end of the test.
    # ------------------------------------------------------------------
    def check_vital_paths(label, allowed_failed=frozenset(), previous=None):
        machine.wait_for_unit("multi-user.target")
        _, state = out_of("timeout 300 systemctl is-system-running --wait || true")
        machine.log(f"[{label}] system state: {state.strip()}")

        _, failed = out_of(
            "systemctl list-units --failed --plain --no-legend --full | awk '{print $1}'"
        )
        failed_units = {u for u in failed.split() if u}
        for unit in sorted(failed_units):
            _, status = out_of(
                f"systemctl status --no-pager --full {shlex.quote(unit)} 2>&1 | tail -n 40"
            )
            machine.log(f"[{label}] failed unit {unit}:\n{status}")
        unexpected = failed_units - set(allowed_failed)
        vital(
            label,
            "no unexpected failed units",
            not unexpected,
            f"failed={sorted(failed_units)} allowed={sorted(allowed_failed)}",
        )
        if failed_units & set(allowed_failed):
            finding(f"{label}: allowed unit failures: {sorted(failed_units & set(allowed_failed))}")

        # Networking. The kernel keeps addresses across a soft-reboot, so an
        # address alone does not prove the network stack restarted; the failed
        # units list above covers the network services themselves.
        rc, _ = out_of("systemctl is-active network.target")
        vital(label, "network.target active", rc == 0)
        rc, addrs = out_of("ip -4 -o addr show scope global")
        vital(label, "a global IPv4 address", rc == 0 and "inet " in addrs, addrs)

        # Login: getty must be a fresh instance in this userspace, and a real
        # password login on tty1 must create a logind session. The previous
        # phase recorded getty's InvocationID after its own logout, so an equal
        # ID here means getty was not restarted by the soft-reboot.
        _, invocation = out_of("systemctl show -p InvocationID --value getty@tty1.service")
        invocation = invocation.strip()
        rc, _ = out_of("systemctl is-active getty@tty1.service")
        vital(label, "getty@tty1 active", rc == 0)
        if previous is not None:
            vital(
                label,
                "getty@tty1 restarted in this userspace",
                invocation != previous.get("getty"),
                f"InvocationID {invocation} unchanged",
            )
        try:
            # Wait for login's own "Password:" prompt before typing the
            # password: login turns echo off with a flush, which discards
            # typeahead. The final cold boot of the last run sent the password
            # 0.05 s after `pgrep -x login` matched and failed authentication;
            # the soft-reboot phases only passed because pgrep happened to
            # need one more 1 s poll. Clear tty1 first, so a "Password:" left on
            # the screen by an earlier phase cannot match (VT 1 is never
            # deallocated by a soft-reboot).
            machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
            machine.send_chars("testuser\n")
            machine.wait_until_tty_matches("1", "Password: ", timeout=60)
            machine.send_chars("test\n")
            machine.wait_until_succeeds(
                "loginctl list-sessions --no-legend | grep -q testuser", timeout=60
            )
            vital(label, "password login on tty1", True)
        except Exception as exc:  # noqa: BLE001 - record and continue
            vital(label, "password login on tty1", False, str(exc))
        out_of("loginctl terminate-user testuser || true")
        out_of(
            "for i in $(seq 1 30); do loginctl list-sessions --no-legend | grep -q testuser || exit 0; sleep 1; done"
        )
        out_of("for i in $(seq 1 30); do systemctl is-active -q getty@tty1.service && exit 0; sleep 1; done")
        _, invocation = out_of("systemctl show -p InvocationID --value getty@tty1.service")

        # Kernel modules: load one that is not loaded yet (proves the module
        # tree, /run/booted-system/kernel-modules on NixOS, is reachable),
        # then unload it again so the next phase can repeat the check.
        rc, module = out_of(
            'for m in dummy veth bonding nlmon; do '
            'if ! grep -q "^$m " /proc/modules && modinfo "$m" >/dev/null 2>&1; then '
            'modprobe "$m" && grep -q "^$m " /proc/modules && rmmod "$m" && echo "$m" && exit 0; '
            'exit 1; fi; done; exit 2'
        )
        vital(label, "modprobe of an unloaded module", rc == 0, f"rc={rc} module={module.strip()}")

        # The Nix store and the daemon.
        rc, _ = out_of(
            "systemctl start nix-daemon.socket && "
            "nix-store --verify-path $(readlink -f /run/current-system)"
        )
        vital(label, "nix-store --verify-path of the running system", rc == 0)

        return {"getty": invocation.strip()}


    def nix_build(name, content):
        """A trivial offline build through the daemon; returns the output path."""
        expr = (
            'derivation { name = "%s"; system = "${pkgs.stdenv.hostPlatform.system}"; '
            'builder = builtins.storePath "%s" + "/bin/bash"; '
            'args = [ "-c" "echo %s > $out" ]; }'
        ) % (name, BASH_STORE_PATH, content)
        rc, out = out_of(
            "NIX_REMOTE=daemon nix-build --no-out-link --option substitute false -E "
            + shlex.quote(expr)
        )
        path = out.strip().splitlines()[-1] if out.strip() else ""
        return rc, path


    def peek_decoy(command):
        """Run `command` against a read-only mount of the decoy root at PEEK.

        The decoy superblock is still mounted read-write (it is the overlay's
        lower), so a plain read-only mount would fail with EBUSY ("would change
        RO state"). Mount it, then make this mount read-only.
        """
        machine.succeed(
            f"mkdir -p {PEEK} && mount {decoy_dev} {PEEK} && mount -o remount,bind,ro {PEEK}"
        )
        try:
            return out_of(command)
        finally:
            machine.succeed(f"umount {PEEK}")


    def precheck_nextroot():
        # PID 1 (systemd >= 258) refuses to switch into a root where neither
        # its own binary nor /sbin/init resolves, and freezes the machine. On
        # NixOS its binary is /run/current-system/systemd/lib/systemd/systemd,
        # which resolves inside /run/nextroot only because /run is bound there.
        # path_is_os_tree() also needs /etc/os-release to resolve.
        machine.succeed(
            "chroot /run/nextroot /run/current-system/sw/bin/test "
            "-x /run/current-system/systemd/lib/systemd/systemd"
        )
        machine.succeed("chroot /run/nextroot /run/current-system/sw/bin/test -e /etc/os-release")


    class ReconnectTimeout(Exception):
        pass


    def _alarm(_signum, _frame):
        raise ReconnectTimeout()


    def guest_uptime():
        return float(machine.succeed("cut -d' ' -f1 /proc/uptime").strip())


    # Console lines that mean the new userspace will never start the backdoor.
    STUCK_MARKERS = (
        "Reached target Emergency Mode",
        "Started Emergency Shell",
        "Reached target Rescue Mode",
        "Freezing execution",
        "Switch root target contains no usable init",
    )


    def console_since(index):
        return machine.full_console_log[index:]


    def soft_reboot(label):
        """Trigger a soft-reboot and reconnect the backdoor shell.

        The backdoor is an ordinary service, so it dies with the old userspace
        and the new userspace starts it again. As machine.switch_root() does
        for the initrd, send the command without reading its output, mark the
        shell disconnected and reconnect; connect() discards everything until
        the new backdoor prints its ready marker.

        Before connecting, poll the full console log (appended directly by the
        driver's reader thread, unlike the one-line-per-second queue behind
        the driver's console-text wait) until the new backdoor announces itself on
        ttyS0, and fail at once with diagnostics if the new userspace lands in
        emergency mode or PID 1 freezes. connect() itself stays bounded by an
        alarm as a last resort.

        Returns the guest uptime at the trigger, for later log filtering.
        """
        trigger = guest_uptime()
        console_index = len(machine.full_console_log)
        machine.execute(
            "(systemctl soft-reboot --check-inhibitors=no || "
            "systemctl start --no-block --job-mode=replace-irreversibly soft-reboot.target)"
            " </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        machine.connected = False
        deadline = time.monotonic() + 600
        while True:
            lines = console_since(console_index)
            stuck = [line for line in lines if any(m in line for m in STUCK_MARKERS)]
            if stuck:
                causes = [
                    line
                    for line in lines
                    if any(k in line for k in ("Timed out", "timed out", "Dependency failed", "Failed to"))
                ]
                machine.log(f"{label}: causes on the console:\n" + "\n".join(causes[-60:]))
                machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
                raise AssertionError(f"{label}: the new userspace is stuck: {stuck[0]}")
            if any("connecting to host" in line for line in lines):
                break
            if time.monotonic() > deadline:
                machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
                raise AssertionError(f"{label}: no backdoor 600 s after the soft-reboot")
            time.sleep(0.5)
        previous_handler = signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(120)
        try:
            machine.connect()
        except ReconnectTimeout:
            raise AssertionError(f"{label}: backdoor announced itself but never connected") from None
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
        backdoor = guest_uptime()
        machine.wait_for_unit("multi-user.target")
        out_of("timeout 300 systemctl is-system-running --wait || true")
        settled = guest_uptime()

        # PID 1's own timestamps, all CLOCK_MONOTONIC in microseconds.
        # ShutdownStartTimestamp is carried over a soft-reboot (systemd 256+),
        # UserspaceTimestamp is the new PID 1's start, FinishTimestamp the end
        # of the new boot transaction.
        _, props = out_of(
            "systemctl show -p ShutdownStartTimestampMonotonic "
            "-p UserspaceTimestampMonotonic -p FinishTimestampMonotonic"
        )
        values = {}
        for line in props.splitlines():
            key, _, value = line.partition("=")
            if value.strip().isdigit():
                values[key] = int(value.strip()) / 1e6
        shutdown_start = values.get("ShutdownStartTimestampMonotonic", 0.0)
        userspace = values.get("UserspaceTimestampMonotonic", 0.0)
        finish = values.get("FinishTimestampMonotonic", 0.0)
        _, pid1_line = out_of(
            "journalctl -b --no-pager -o cat | grep 'Soft-reboot finished' | tail -n 1 || true"
        )
        record = {
            "label": label,
            "shutdown_phase": userspace - shutdown_start if shutdown_start and userspace else None,
            "startup_phase": finish - userspace if finish and userspace else None,
            "grey_out": finish - shutdown_start if finish and shutdown_start else None,
            "trigger_to_backdoor": backdoor - trigger,
            "trigger_to_settled": settled - trigger,
        }
        timings.append(record)
        finding(
            f"{label}: in-guest timings: {record}; raw PID 1 timestamps {values}; "
            f"PID 1 says: {pid1_line.strip()}"
        )
        _, count = out_of("systemctl show -p SoftRebootsCount --value || true")
        finding(f"{label}: SoftRebootsCount={count.strip()} (RAM-only, visible to anyone with a shell)")
        return trigger


    def log_ram_traces(label):
        _, kmsg = out_of(
            "dmesg | grep -iE 'overlay|EXT4-fs \\(dm-|device-mapper|crypt' | tail -n 20 || true"
        )
        finding(f"{label}: kernel ring buffer lines naming overlay/dm (RAM-only):\n{kmsg}")
        _, journal = out_of(
            "journalctl -b --no-pager -o short-monotonic | "
            "grep -iE 'soft-reboot|soft reboot|switch.root|nextroot' | tail -n 20 || true"
        )
        finding(f"{label}: journal lines about the transition:\n{journal}")


    # ==================================================================
    # Boot, confirm the firmware surface, and take the plain-reboot control.
    # ==================================================================
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -d /sys/firmware/efi/efivars")

    decoy_dev = machine.succeed("findmnt -no SOURCE /").strip()
    decoy_disk = machine.succeed(f"lsblk -npo PKNAME {decoy_dev}").strip()
    assert machine.succeed("findmnt -no FSTYPE /").strip() == "ext4"
    assert decoy_disk.startswith("/dev/"), f"no parent disk for {decoy_dev}: {decoy_disk!r}"
    machine.log(f"decoy root {decoy_dev} on disk {decoy_disk}")

    with subtest("plain-reboot control for the ESP and EFI variables"):
        control_before = snapshot()
        assert len(esp_map(control_before["esp"])) >= 2, control_before["esp"]
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        control_after = snapshot()
        control_esp = esp_changed(control_before, control_after)
        control_nvram = nvram_changed(control_before, control_after)
        control_efivars = efivars_changed(control_before, control_after)
        finding(
            f"plain reboot churn: esp={sorted(control_esp)} nvram={sorted(control_nvram)} "
            f"efivars={sorted(control_efivars)}"
        )
        previous = check_vital_paths("decoy-initial")
        rc, decoy_build = nix_build("nails-spike-decoy-initial", "decoy-initial")
        vital("decoy-initial", "trivial offline nix build", rc == 0 and decoy_build != "", decoy_build)

    pre_session = snapshot()


    # libmount's utab across a switch, the rule nails follows: a line stays only
    # while it names a mount the switch carries, one at or below /run/nextroot,
    # under that mount's ID now. It reads the mount table and utab; ENTER_UTAB
    # runs it as the last step of the entry.
    UTAB_AWK = r"""
    function sep(    j) { for (j = 7; j <= NF; j++) if ($j == "-") return j; return 0 }
    FNR == 1 { file++ }
    file == 1 {
        if (!(j = sep())) next
        if ($5 != "/run/nextroot" && index($5, "/run/nextroot/") != 1) next
        at = substr($5, 14); if (at == "") at = "/"
        carried[$1] = at SUBSEP $(j + 2) SUBSEP $4
        newest[at SUBSEP $(j + 2) SUBSEP $4] = $1
        next
    }
    {
        line = $0; sub(/\r$/, "", line)
        if (line ~ /^[ \t]*(#|$)/) next
        n = split(line, tok, / /); id = ""; s = t = r = "\001"
        for (i = 1; i <= n; i++) {
            v = tok[i]; sub(/\t.*/, "", v)
            if (id == "" && v ~ /^ID=/) {
                id = substr(v, 4)
                if (id == "" && i == n) continue
                if (id !~ /^[+-]?[0-9]+$/) next
                id += 0
            }
            else if (s == "\001" && v ~ /^SRC=/) s = substr(v, 5)
            else if (t == "\001" && v ~ /^TARGET=/) t = substr(v, 8)
            else if (r == "\001" && v ~ /^ROOT=/) r = substr(v, 6)
        }
        if (id > 0) {
            if (!(id in carried)) next
            split(carried[id], c, SUBSEP)
            if ((s == "\001" || s == c[2]) && (r == "\001" || r == c[3])) print line
            next
        }
        if (t == "\001") next
        for (k in newest) {
            split(k, c, SUBSEP)
            if (c[1] == t && (s == "\001" || s == c[2]) && (r == "\001" || r == c[3])) { print line; next }
        }
    }
    """

    ENTER_UTAB = r"""#!/run/current-system/sw/bin/bash
    PATH=/run/current-system/sw/bin
    if [ -e /run/mount/utab ]; then
        awk '@UTAB_AWK@' /proc/self/mountinfo /run/mount/utab > /run/mount/utab.new &&
            mv /run/mount/utab.new /run/mount/utab
    fi
    # Once only: the hidden userspace must not run it again.
    rm -f /run/systemd/system/systemd-soft-reboot.service.d/40-nails-utab.conf /run/nails-enter-utab.sh
    exit 0
    """.replace("@UTAB_AWK@", UTAB_AWK)


    def install_enter_utab():
        machine.succeed(
            "cat > /run/nails-enter-utab.sh <<'NAILS_EOF'\n" + ENTER_UTAB + "NAILS_EOF\n"
            "mkdir -p /run/systemd/system/systemd-soft-reboot.service.d\n"
            "printf '[Service]\\nType=oneshot\\n"
            "ExecStart=-/run/current-system/sw/bin/bash /run/nails-enter-utab.sh\\n' "
            "> /run/systemd/system/systemd-soft-reboot.service.d/40-nails-utab.conf\n"
            "systemctl daemon-reload"
        )


    def enter_hidden(cycle):
        global previous
        label = f"cycle{cycle}-hidden"
        canary = token(f"canary{cycle}")
        write = token(f"write{cycle}")
        jtoken = token(f"journal{cycle}")
        build_token = token(f"build{cycle}")
        hidden_tokens.update({canary: "canary", write: "write", jtoken: "journal", build_token: "build"})
        # Per-cycle ESP/NVRAM baseline: the previous cycle's cold boot
        # legitimately refreshed loader/random-seed.
        baseline = snapshot()

        with subtest(f"cycle {cycle}: build the overlay at /run/nextroot"):
            if cycle == 1:
                machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            else:
                machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            machine.succeed(
                "set -eux; "
                f"mkdir -p {UPPER} {WORK} /run/nails-lower /run/nextroot; "
                # Lower: a non-recursive, read-only bind of the decoy root, so
                # the overlay sees only the root filesystem (no submounts) and
                # can never update atimes on it.
                "mount --bind / /run/nails-lower; "
                "mount -o remount,bind,ro /run/nails-lower; "
                "mount -t overlay overlay "
                f"-o lowerdir=/run/nails-lower,upperdir={UPPER},workdir={WORK} /run/nextroot; "
                # The overlay keeps a private clone of each layer, so the
                # helper mount of the lower can go now.
                "umount /run/nails-lower; "
                # /run is carried across the switch anyway (non-recursively);
                # binding it here as well makes PID 1's pre-switch check find
                # /run/current-system, see precheck_nextroot().
                "mount --bind /run /run/nextroot/run; "
                # The hidden volume must stay reachable at the same path in the
                # hidden root: everything outside /run/nextroot is detached.
                f"mount --bind {HIDDEN} /run/nextroot{HIDDEN}; "
                # /boot policy for the hidden root: a read-only bind of the
                # ESP. Pre-mounting it here also stops the hidden fstab from
                # mounting the ESP read-write.
                "mount --bind /boot /run/nextroot/boot; "
                "mount -o remount,bind,ro /run/nextroot/boot; "
                # No propagation to or from the rest of the system.
                "mount --make-rprivate /run/nextroot"
            )
            machine.log(machine.succeed("findmnt -R /run/nextroot"))

        with subtest(f"cycle {cycle}: drop the canary into the upper"):
            machine.succeed(f"echo {canary} > /run/nextroot/nails-canary && sync")
            assert machine.succeed(f"cat {UPPER}/nails-canary").strip() == canary
            machine.fail("test -e /nails-canary")
            precheck_nextroot()

        with subtest(f"cycle {cycle}: keep the static address through the switch"):
            # NixOS starts network-addresses-<interface>.service only when its
            # device appears, which a soft-reboot does not replay, and the
            # unit's stop deletes the address. As nails does (STOP_GUARDED_UNITS
            # in nails-teardown), clear that stop for the session, so the kernel
            # keeps the address through the switch. The drop-in goes with /run
            # at the power-off.
            machine.succeed(
                "mkdir -p /run/systemd/system/network-addresses-.service.d && "
                "printf '[Service]\\nExecStop=\\n' "
                "> /run/systemd/system/network-addresses-.service.d/zz-overlay-runtime.conf && "
                "systemctl daemon-reload"
            )

        install_enter_utab()
        soft_reboot(f"cycle{cycle}-enter")

        with subtest(f"cycle {cycle}: the hidden root is the overlay"):
            assert machine.succeed("findmnt -no FSTYPE /").strip() == "overlay"
            assert machine.succeed("cat /nails-canary").strip() == canary
            # The switch kept no line whose mount it left behind.
            wrong = utab.wrong_lines(
                machine.succeed("cat /run/mount/utab 2>/dev/null || true"),
                machine.succeed("cat /proc/self/mountinfo"),
            )
            assert not wrong, f"utab lines naming no live mount or another: {wrong}"
            if cycle > 1:
                # The upper persists across sessions on the hidden volume.
                machine.succeed("test -s /root/nails-hidden-write-1")

        with subtest(f"cycle {cycle}: a new write lands in the upper, not on the decoy"):
            machine.succeed(f"echo {write} > /root/nails-hidden-write-{cycle} && sync")
            assert machine.succeed(f"cat {UPPER}/root/nails-hidden-write-{cycle}").strip() == write
            rc, _ = peek_decoy(
                f"test ! -e {PEEK}/root/nails-hidden-write-{cycle} && test ! -e {PEEK}/nails-canary"
            )
            assert rc == 0, "a hidden file is visible on the decoy root filesystem"

        with subtest(f"cycle {cycle}: vital paths in the hidden root"):
            previous = check_vital_paths(label, HIDDEN_ALLOWED_FAILED, previous)

            hidden_snapshot = snapshot()
            changed = esp_changed(baseline, hidden_snapshot)
            vital(label, "ESP unchanged in the hidden session", not changed, sorted(changed))
            vital(
                label,
                "EFI boot entries unchanged",
                not nvram_changed(baseline, hidden_snapshot),
                sorted(nvram_changed(baseline, hidden_snapshot)),
            )
            rc, _ = out_of("touch /boot/nails-spike-write-probe")
            vital(label, "/boot is read-only in the hidden root", rc != 0)

            rc, _ = out_of(f"mountpoint -q {HIDDEN} && cryptsetup status data | grep -q 'is active'")
            vital(label, "hidden volume mounted and LUKS open", rc == 0)

            out_of(f"logger -t nails-spike {jtoken} && journalctl --flush && journalctl --sync")
            rc, _ = out_of(f"grep -r -a -q -F {jtoken} {UPPER}/var/log/journal")
            vital(label, "the hidden journal is written into the upper", rc == 0)
            rc, _ = peek_decoy(f"! grep -r -a -q -F {jtoken} {PEEK}/var/log/journal")
            vital(label, "the hidden journal is not on the decoy filesystem", rc == 0)

            rc, out_path = nix_build(f"nails-spike-hidden-{cycle}", build_token)
            vital(label, "trivial offline nix build", rc == 0 and out_path != "", out_path)
            if out_path:
                rc, _ = out_of(f"test -e {UPPER}{out_path}")
                vital(label, "the hidden build output is in the upper", rc == 0)
                rc, _ = peek_decoy(f"test ! -e {PEEK}{out_path}")
                vital(label, "the hidden build output is not on the decoy", rc == 0)

        return baseline, out_path


    def power_off_hidden(cycle, baseline, hidden_out_path):
        global previous
        label = f"cycle{cycle}-decoy"

        with subtest(f"cycle {cycle}: the hidden root powers off for real"):
            log_ram_traces(f"cycle{cycle}-hidden")
            session.follow_power_off(machine, "systemctl poweroff", f"cycle{cycle}-poweroff")

        with subtest(f"cycle {cycle}: the cold boot is the plain decoy root"):
            machine.start()
            machine.wait_for_unit("multi-user.target")
            assert machine.succeed("findmnt -no FSTYPE /").strip() == "ext4"
            assert machine.succeed("findmnt -no SOURCE /").strip() == decoy_dev
            machine.fail("test -e /nails-canary")
            machine.fail(f"test -e /root/nails-hidden-write-{cycle}")
            machine.fail("test -e /dev/mapper/data")
            if hidden_out_path:
                machine.fail(f"test -e {hidden_out_path}")
                machine.fail(f"nix-store --check-validity {hidden_out_path}")

        with subtest(f"cycle {cycle}: vital paths on the decoy"):
            rc, overlays = out_of("findmnt -n -t overlay")
            vital(label, "no overlay mount", overlays.strip() == "", overlays)
            rc, _ = out_of("grep -q ' /run/nextroot' /proc/self/mountinfo")
            vital(label, "no /run/nextroot mount", rc != 0)
            previous = check_vital_paths(label, frozenset(), previous)
            rc, decoy_build = nix_build(f"nails-spike-decoy-{cycle}", f"decoy-{cycle}")
            vital(label, "trivial offline nix build", rc == 0 and decoy_build != "", decoy_build)

            back = snapshot()
            changed = esp_changed(baseline, back)
            vital(
                label,
                "ESP changed no more than a boot does",
                changed <= control_esp | ESP_SOFT_REBOOT_CHURN,
                sorted(changed),
            )
            extra_nvram = nvram_changed(baseline, back) - control_nvram
            vital(label, "EFI boot entries within the control", not extra_nvram, sorted(extra_nvram))

        with subtest(f"cycle {cycle}: no hidden token in the decoy journal"):
            patterns = " ".join(f"-e {t}" for t in hidden_tokens)
            _, hits = out_of(f"journalctl --no-pager -o cat | grep -a -o -F {patterns} || true")
            assert not hits.strip(), f"hidden tokens in the decoy journal: {hits}"
            _, count = out_of("systemctl show -p SoftRebootsCount --value")
            finding(f"{label}: SoftRebootsCount={count.strip()} after the cold boot")


    for cycle in (1, 2):
        baseline, hidden_out_path = enter_hidden(cycle)
        power_off_hidden(cycle, baseline, hidden_out_path)

    # ==================================================================
    # The firmware surfaces against the first boot, then the dead-disk checks.
    # ==================================================================
    with subtest("after the last cold boot the firmware surfaces are within the control"):
        machine.fail("test -e /root/nails-hidden-write-1")
        machine.fail("test -e /root/nails-hidden-write-2")
        final = snapshot()
        extra_esp = esp_changed(pre_session, final) - control_esp - ESP_SOFT_REBOOT_CHURN
        vital("final-boot", "ESP within the plain-reboot control", not extra_esp, sorted(extra_esp))
        extra_nvram = nvram_changed(pre_session, final) - control_nvram
        vital("final-boot", "EFI boot entries within the control", not extra_nvram, sorted(extra_nvram))
        extra_vars = efivars_changed(pre_session, final) - control_efivars
        vital("final-boot", "EFI variables within the control", not extra_vars, sorted(extra_vars))

    with subtest("no hidden token anywhere on the raw decoy disk"):
        # One pass over the whole disk (ESP and root) for every token, in
        # bounded windows: a raw disk has almost no newlines, so a single grep
        # over the device buffers gigabyte-sized "lines" and the first run was
        # OOM-killed. Each window is 65 MiB read every 64 MiB, so a token that
        # straddles a boundary is still seen whole; grep never holds more than
        # one window.
        all_tokens = list(hidden_tokens)
        patterns = " ".join(f"-e {t}" for t in all_tokens)
        raw = machine.succeed(
            "sync; echo 3 > /proc/sys/vm/drop_caches; "
            f"size=$(blockdev --getsize64 {decoy_disk}); "
            "mib=$(( (size + 1048575) / 1048576 )); "
            "for (( off = 0; off < mib; off += 64 )); do "
            f"dd if={decoy_disk} bs=1M skip=$off count=65 status=none | grep -a -o -F {patterns} || true; "
            "done | sort | uniq -c",
            timeout=1800,
        )
        hits = [line for line in raw.splitlines() if line.strip()]
        finding(f"raw decoy disk scan: {hits or 'no hidden token'}")
        assert not hits, "hidden tokens found on the raw decoy disk:\n" + "\n".join(hits)

    machine.log("FINDING: in-guest timings of the switches in (seconds):")
    for record in timings:
        machine.log(f"FINDING:   {record}")
    assert not vital_failures, "vital-path failures:\n" + "\n".join(vital_failures)
  '';
}
