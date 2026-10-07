# The mechanics of the whole-root session (ADR 0008), by hand: enter a
# whole-root overlay with `systemctl soft-reboot` and come back, twice.
#
# This began as the research spike that decided ADR 0008 and is now a regular
# test: it pins, independently of the `nails` code, the kernel and systemd
# behaviour the session mode is built on (the /run bind for PID 1's init check,
# the read-only ESP, the allowlist /run scrub, the kmsg cursor, the utab
# restore, strict and deferred backend close, and a clean raw decoy disk). The
# same steps through `nails` are covered by session-lifecycle and the other
# session tests.
#
# What it does, twice (cycle 1 and cycle 2):
#
#   1. Builds an overlay at /run/nextroot: lower = a read-only bind of the decoy
#      root, upper/work on the LUKS hidden volume (/mnt/data/root/{upper,work}).
#   2. Writes a canary through the overlay, so it lands in the upper.
#   3. `systemctl soft-reboot`: PID 1 stops userspace, switches root into
#      /run/nextroot and starts a fresh userspace there.
#   4. In the hidden root: asserts the canary is at /, a new write lands in the
#      upper and not on the decoy disk, and that the vital paths work (units,
#      network, login, modprobe, /boot untouched, the Nix store and daemon,
#      the hidden volume, journald writing into the overlay).
#   5. Mounts the decoy root at /run/nextroot, installs the last-step /run
#      scrub and kmsg cursor (a runtime drop-in on systemd-soft-reboot.service)
#      and soft-reboots back. On the decoy it asserts the same vital paths,
#      that no overlay or nextroot mount is left, that the hidden volume can be
#      closed, that nothing of the hidden /run survived and that no hidden
#      kernel record reached the decoy journal.
#
# Timings are measured in the guest from PID 1's own timestamps
# (ShutdownStart, Userspace and Finish) and /proc/uptime, not on the host.
#
# Finally it does a full power cycle through OVMF and systemd-boot, asserts the
# decoy boots cleanly, that the ESP and the EFI boot entries changed no more
# than a plain-reboot control, and greps the raw decoy disk for every hidden
# token.
#
# The VM boots through a real bootloader (as forensic/80 does), so the Nix
# store lives on the root disk like on a real install, not on a 9p share, and
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
  # Estimate, not measured: two OVMF boots, four soft-reboots, four trivial Nix
  # builds and one raw pass over the 20 GiB decoy disk.
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
      services.journald.storage = lib.mkForce "persistent";

      # soft-reboot.target and systemd-soft-reboot.service come from
      # vm-config.nix (lib/soft-reboot-units.nix): the pinned nixpkgs does not
      # install them.

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

    BASH_STORE_PATH = "${pkgs.bash}"
    HIDDEN = "/mnt/data"
    UPPER = HIDDEN + "/root/upper"
    WORK = HIDDEN + "/root/work"
    PEEK = "/run/decoy-peek"

    # systemd-boot-random-seed.service rewrites loader/random-seed on every
    # userspace start, so a soft-reboot into the decoy changes that file the
    # same way a boot does. Nothing else on the ESP may change.
    ESP_SOFT_REBOOT_CHURN = {"loader/random-seed"}
    # In the hidden root /boot is a read-only bind of the ESP (see enter_hidden),
    # so the random-seed refresh may fail there. That failure is the policy
    # working, not a breakage.
    HIDDEN_ALLOWED_FAILED = {"systemd-boot-random-seed.service"}

    vital_failures = []
    findings = []
    timings = []
    hidden_tokens = {}
    late_kmsg_tokens = []
    run_snapshots = {}
    utab_snapshots = {}


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


    # The /run scrub and kmsg cursor for the way back (ADR 0008, section 5).
    #
    # It runs as the ExecStart of systemd-soft-reboot.service in the hidden
    # root, added by a drop-in under the hidden /run. That service is ordered
    # after shutdown.target, umount.target and final.target, so this is the last
    # userspace code before PID 1 switches root: every hidden unit (journald
    # included) has stopped and the hidden volume is unmounted.
    #
    # 1. Scrub, as an allowlist of what to DELETE. The second run showed why a
    #    "keep" list is wrong: deleting /run/udev left the decoy without a
    #    device database, and systemd-udev-trigger.service (DefaultDependencies=no,
    #    RemainAfterExit=yes, no shutdown conflict) stays "active" across a
    #    soft-reboot and never re-triggers, so every .device job timed out
    #    after 300 s and the decoy fell into emergency mode. /run is the state
    #    the next userspace is built to inherit; only remove what the hidden
    #    session added:
    #    a. known per-session state of units that are all stopped by now:
    #       the runtime journal, logind's sessions/users/seats/inhibitors,
    #       transient and runtime unit files (including this drop-in), utmp,
    #       and the leftover mountpoint dirs of /run/user/<uid>;
    #    b. every entry up to two levels below /run that is not in the
    #       snapshot taken in the decoy just before entering (written to
    #       /run/nails-run-snapshot): what hidden services created, and what
    #       the hidden shutdown created (/run/nologin, the /run/initramfs
    #       exitrd mount, which is unmounted first).
    #    Never touched: sockets (PID 1's notify and varlink sockets and the
    #    never-stopped socket units are carried as fds bound to these inodes),
    #    /run/udev, /run/credentials, /run/current-system, /run/booted-system
    #    and the mounted /run/nextroot.
    # 2. Cursor: the decoy journald skips kernel records whose sequence number
    #    is below /run/systemd/journal/kernel-seqnum and imports the rest from
    #    the start of the ring buffer. Writing "last record + 1" here makes it
    #    skip every record the hidden session produced, including those logged
    #    after the hidden journald stopped.
    #
    # The script lives in the hidden /run: the hidden volume is already
    # unmounted when it runs, and nothing of it reaches any disk.
    LEAVE_SCRUB = r"""#!/run/current-system/sw/bin/bash
    PATH=/run/current-system/sw/bin
    snap=/run/nails-run-snapshot
    del() {
        [ -S "$1" ] && return 0
        [ -e "$1" ] || [ -L "$1" ] || return 0
        # A mount made under /run during the hidden shutdown (NixOS mounts a
        # tmpfs at /run/initramfs for its exitrd) is not carried by the
        # non-recursive /run move anyway; unmount it so its mountpoint can go
        # too. Nothing after this service uses it: systemd-shutdown, which
        # would exec /run/initramfs/shutdown, never runs on a soft-reboot.
        if [ -d "$1" ] && [ ! -L "$1" ] && mountpoint -q -- "$1"; then
            umount -- "$1" 2>/dev/null || umount -l -- "$1"
        fi
        # Spike diagnostics only: the names land in the kernel ring buffer
        # (RAM). The cursor below keeps them out of the decoy journal; a real
        # implementation must not log them at all.
        echo "nails-scrub: removing $1" > /dev/kmsg
        rm -rf --one-file-system -- "$1"
    }
    for p in /run/log/journal/* /run/systemd/sessions/* /run/systemd/users/* /run/systemd/seats/* \
             /run/systemd/inhibit/* /run/systemd/shutdown/* /run/systemd/transient/* \
             /run/systemd/system/* /run/systemd/system.control/* /run/utmp; do
        del "$p"
    done
    for p in /run/user/*; do
        [ -d "$p" ] && rmdir -- "$p" 2>/dev/null
    done
    if [ -r "$snap" ]; then
        # The same two levels the snapshot and the residue check cover.
        mapfile -t entries < <(find /run -xdev -mindepth 1 -maxdepth 2 \( -path /run/nextroot \
            -o -path /run/udev -o -path /run/credentials -o -path /run/current-system \
            -o -path /run/booted-system \) -prune -o ! -path "$snap" -print)
        for p in "''${entries[@]}"; do
            grep -qxF -- "$p" "$snap" || del "$p"
        done
    fi
    if [ -f /run/nails-utab-snapshot ] && [ -e /run/mount/utab ]; then
        cat /run/nails-utab-snapshot > /run/mount/utab
    fi
    rm -f -- "$snap" /run/nails-utab-snapshot /run/nails-leave-scrub.sh
    last=$(dd if=/dev/kmsg bs=16384 iflag=nonblock 2>/dev/null | grep -av '^ ' | tail -n 1 | cut -d, -f2)
    if [ -n "$last" ]; then
        next=$((last + 1))
        bytes=""
        for i in 0 1 2 3 4 5 6 7; do
            bytes="$bytes$(printf '\\%03o' $(( (next >> (8 * i)) & 255 )))"
        done
        mkdir -p /run/systemd/journal
        printf "$bytes" > /run/systemd/journal/kernel-seqnum
    fi
    exit 0
    """

    LEAVE_DROPIN = (
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=-/run/current-system/sw/bin/bash /run/nails-leave-scrub.sh\n"
    )


    def install_leave_scrub():
        machine.succeed(
            "cat > /run/nails-leave-scrub.sh <<'NAILS_EOF'\n" + LEAVE_SCRUB + "NAILS_EOF\n"
            "mkdir -p /run/systemd/system/systemd-soft-reboot.service.d\n"
            "printf '" + LEAVE_DROPIN.replace("\n", "\\n") + "' "
            "> /run/systemd/system/systemd-soft-reboot.service.d/50-nails-scrub.conf\n"
            "systemctl daemon-reload\n"
            "systemctl cat systemd-soft-reboot.service"
        )


    def enter_hidden(cycle):
        global previous
        label = f"cycle{cycle}-hidden"
        canary = token(f"canary{cycle}")
        write = token(f"write{cycle}")
        jtoken = token(f"journal{cycle}")
        build_token = token(f"build{cycle}")
        hidden_tokens.update({canary: "canary", write: "write", jtoken: "journal", build_token: "build"})
        # Per-cycle ESP/NVRAM baseline: the previous cycle's soft-reboot into
        # the decoy legitimately refreshed loader/random-seed.
        baseline = snapshot()

        with subtest(f"cycle {cycle}: build the overlay at /run/nextroot"):
            if cycle == 1:
                machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
            else:
                machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            # The decoy's /run, two levels deep, just before entering. The
            # leave scrub deletes what is not in it; the residue check below
            # compares against it.
            snapshot_text = machine.succeed(
                "find /run -xdev -mindepth 1 -maxdepth 2 | LC_ALL=C sort > /run/nails-run-snapshot.tmp && "
                "mv /run/nails-run-snapshot.tmp /run/nails-run-snapshot && cat /run/nails-run-snapshot"
            )
            run_snapshots[cycle] = set(snapshot_text.splitlines())
            # libmount's utab (userspace mount options) is a kept file whose
            # content the hidden session extends: every userspace start adds
            # lines for its x-* mounts, and mounts dropped by the switch are
            # never removed from it. Save the decoy's copy; the scrub restores
            # it.
            utab_snapshots[cycle] = machine.succeed(
                "if [ -e /run/mount/utab ]; then cp /run/mount/utab /run/nails-utab-snapshot; "
                "cat /run/mount/utab; fi"
            )
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

        soft_reboot(f"cycle{cycle}-enter")

        with subtest(f"cycle {cycle}: the hidden root is the overlay"):
            assert machine.succeed("findmnt -no FSTYPE /").strip() == "overlay"
            assert machine.succeed("cat /nails-canary").strip() == canary
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

        with subtest(f"cycle {cycle}: plant RAM-residue probes for the way back"):
            # /run is carried across a soft-reboot; the scrub must remove all of
            # these (the login check above also left logind state in /run).
            machine.succeed(
                f"echo {canary} > /run/nails-hidden-run-probe && "
                f"mkdir -p /run/nails-probe-dir/nested && echo {canary} > /run/nails-probe-dir/nested/file && "
                f"echo {canary} > /run/systemd/nails-probe && "
                f"mkdir -p /run/log/journal && echo {canary} > /run/log/journal/nails-probe"
            )
            # A unit that stops after journald during the soft-reboot back and
            # writes to the kernel log, i.e. a record no hidden journald sees.
            # Does the decoy's journald import it from /dev/kmsg?
            late = token(f"latekmsg{cycle}")
            late_kmsg_tokens.append(late)
            machine.succeed(
                f"systemd-run --unit nails-spike-late-kmsg-{cycle} -p Type=oneshot -p RemainAfterExit=yes "
                "-p DefaultDependencies=no -p Before=systemd-journald.service "
                "-p Conflicts=soft-reboot.target "
                f"-p ExecStop='/bin/sh -c \"echo {late} > /dev/kmsg\"' /run/current-system/sw/bin/true"
            )
            log_ram_traces(label)
        return baseline, out_path


    def leave_hidden(cycle, baseline, hidden_out_path):
        global previous
        label = f"cycle{cycle}-decoy"
        deferred = cycle == 2

        with subtest(f"cycle {cycle}: mount the decoy root at /run/nextroot"):
            if deferred:
                # Cycle 2: mark the LUKS mapping for removal on last close, so
                # the key is dropped the moment the old root is released.
                machine.succeed("cryptsetup close --deferred data")
                machine.log(machine.succeed("dmsetup info data || true"))
            machine.succeed(
                "set -eux; mkdir -p /run/nextroot; "
                # Same superblock as the overlay's lower; mounting it is not a
                # write. Nothing is created on the decoy disk: /run already
                # exists there as an empty mountpoint directory.
                f"mount {decoy_dev} /run/nextroot; "
                "mount --bind /run /run/nextroot/run; "
                "mount --make-rprivate /run/nextroot"
            )
            precheck_nextroot()
            install_leave_scrub()

        leave_wall = machine.succeed("date +%s").strip()
        leave_uptime = soft_reboot(f"cycle{cycle}-leave")

        with subtest(f"cycle {cycle}: back on the plain decoy root"):
            assert machine.succeed("findmnt -no FSTYPE /").strip() == "ext4"
            assert machine.succeed("findmnt -no SOURCE /").strip() == decoy_dev
            machine.fail("test -e /nails-canary")
            machine.fail(f"test -e /root/nails-hidden-write-{cycle}")
            if hidden_out_path:
                machine.fail(f"test -e {hidden_out_path}")
                machine.fail(f"nix-store --check-validity {hidden_out_path}")

        with subtest(f"cycle {cycle}: vital paths on the decoy"):
            rc, overlays = out_of("findmnt -n -t overlay")
            vital(label, "no overlay mount remains", overlays.strip() == "", overlays)
            rc, _ = out_of("grep -q ' /run/nextroot' /proc/self/mountinfo")
            vital(label, "no /run/nextroot mount remains", rc != 0)
            previous = check_vital_paths(label, frozenset(), previous)
            rc, decoy_build = nix_build(f"nails-spike-decoy-{cycle}", f"decoy-{cycle}")
            vital(label, "trivial offline nix build", rc == 0 and decoy_build != "", decoy_build)

            back = snapshot()
            changed = esp_changed(baseline, back)
            vital(
                label,
                "ESP changed no more than a soft-reboot does",
                changed <= ESP_SOFT_REBOOT_CHURN,
                sorted(changed),
            )
            vital(
                label,
                "EFI boot entries unchanged",
                not nvram_changed(baseline, back),
                sorted(nvram_changed(baseline, back)),
            )

        with subtest(f"cycle {cycle}: the hidden volume closes"):
            if deferred:
                try:
                    machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
                    vital(label, "deferred LUKS removal completed", True)
                except Exception as exc:  # noqa: BLE001 - record and continue
                    vital(label, "deferred LUKS removal completed", False, str(exc))
                    machine.log(machine.succeed("dmsetup info data || true"))
            else:
                rc, _ = out_of(f"! mountpoint -q {HIDDEN} || umount {HIDDEN}")
                vital(label, "hidden volume unmounted", rc == 0)
                try:
                    machine.wait_until_succeeds("cryptsetup close data", timeout=60)
                    vital(label, "cryptsetup close succeeds", True)
                except Exception as exc:  # noqa: BLE001 - record and continue
                    vital(label, "cryptsetup close succeeds", False, str(exc))
                    machine.log(machine.succeed("dmsetup info data || true; fuser -vm /dev/mapper/data || true"))

        with subtest(f"cycle {cycle}: nothing of the hidden /run reaches the decoy"):
            for probe in (
                "/run/nails-hidden-run-probe",
                "/run/nails-probe-dir",
                "/run/systemd/nails-probe",
                "/run/log/journal/nails-probe",
                "/run/nails-leave-scrub.sh",
                "/run/systemd/system/systemd-soft-reboot.service.d/50-nails-scrub.conf",
                f"/run/systemd/transient/nails-spike-late-kmsg-{cycle}.service",
            ):
                machine.fail(f"test -e {probe}")
            # An entry two levels deep whose inode predates the trigger (ctime,
            # which a copy preserving mtime cannot fake) was carried over the
            # switch; the decoy boot creates its own entries later. Carried
            # entries must have existed in the decoy before entering, apart from
            # the transition's own /run/nextroot. Sockets are carried by design.
            # /run/udev is kept on purpose (device database) and reported.
            carried = set(
                machine.succeed(
                    "find /run -xdev -mindepth 1 -maxdepth 2 \\( -path /run/udev -o -path /run/credentials \\) "
                    f"-prune -o ! -type s ! -newerct @{leave_wall} -print"
                ).splitlines()
            )
            residue = sorted(carried - run_snapshots[cycle] - {"/run/nextroot"})
            finding(f"{label}: entries carried from before the switch, all pre-existing: {len(carried)}")
            _, udev_new = out_of(
                f"find /run/udev -xdev -mindepth 1 -maxdepth 2 ! -newerct @{leave_wall} | wc -l"
            )
            finding(f"{label}: /run/udev entries carried (kept on purpose): {udev_new.strip()}")
            # Files that existed before entering are kept by design; report the
            # ones whose content the hidden session may have rewritten.
            _, kept_content = out_of(
                "for f in /run/mount/utab /run/cryptsetup/*; do [ -e \"$f\" ] && "
                "{ echo \"== $f\"; cat \"$f\" 2>/dev/null | head -n 20; }; done; true"
            )
            finding(f"{label}: content of kept files the hidden session could touch:\n{kept_content}")
            # Every utab line must either predate entering (restored by the
            # scrub) or describe a mount that is live in the decoy now.
            live_ids = set(
                machine.succeed("cut -d' ' -f1 /proc/self/mountinfo").split()
            )
            _, utab_now = out_of("cat /run/mount/utab 2>/dev/null || true")
            before = set(utab_snapshots[cycle].splitlines())
            foreign = []
            for line in utab_now.splitlines():
                if not line.strip() or line in before:
                    continue
                ident = next((f[3:] for f in line.split() if f.startswith("ID=")), None)
                if ident not in live_ids:
                    foreign.append(line)
            stale = [line for line in before if line.strip() and line in utab_now.splitlines()]
            finding(
                f"{label}: utab lines kept from before entering: {len(stale)}, "
                f"lines from the decoy's new mounts: {len(utab_now.splitlines()) - len(stale)}"
            )
            assert not foreign, f"utab lines from the hidden session in the decoy: {foreign}"
            _, scrub_log = out_of("dmesg | grep 'nails-scrub:' | tail -n 40 || true")
            finding(f"{label}: what the scrub removed (from its own kmsg lines):\n{scrub_log}")
            assert not residue, f"hidden /run residue in the decoy: {residue}"

        with subtest(f"cycle {cycle}: no hidden kernel record in the decoy journal"):
            late = late_kmsg_tokens[-1]
            in_journal = int(out_of(f"journalctl --no-pager -o cat | grep -c -F {late} || true")[1].strip() or 0)
            in_dmesg = int(out_of(f"dmesg | grep -c -F {late} || true")[1].strip() or 0)
            finding(
                f"{label}: late hidden kmsg record: in decoy journal x{in_journal}, "
                f"in kernel ring buffer x{in_dmesg} (RAM-only)"
            )
            # The kernel records the decoy journald imported from the window of
            # the transition: with the cursor only PID 1's last generic lines
            # ("Soft-rebooting.") and the decoy's own may remain.
            _, kernel_records = out_of("journalctl -b --no-pager -o short-monotonic _TRANSPORT=kernel")
            window = []
            for line in kernel_records.splitlines():
                stamp = line.strip().lstrip("[").split("]", 1)[0].strip()
                try:
                    if leave_uptime <= float(stamp) <= leave_uptime + 60:
                        window.append(line)
                except ValueError:
                    continue
            finding(f"{label}: kernel-transport journal records from the transition window:\n" + "\n".join(window))
            assert in_journal == 0, "a kernel record from the hidden session reached the decoy journal"
            _, count = out_of("systemctl show -p SoftRebootsCount --value")
            finding(f"{label}: remaining RAM tells: SoftRebootsCount={count.strip()}, kernel ring buffer (dmesg)")
            log_ram_traces(label)


    for cycle in (1, 2):
        baseline, hidden_out_path = enter_hidden(cycle)
        leave_hidden(cycle, baseline, hidden_out_path)

    # ==================================================================
    # Full power cycle through the bootloader, then the dead-disk checks.
    # ==================================================================
    with subtest("full reboot through OVMF and systemd-boot"):
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        assert machine.succeed("findmnt -no FSTYPE /").strip() == "ext4"
        machine.fail("test -e /nails-canary")
        machine.fail("test -e /root/nails-hidden-write-1")
        machine.fail("test -e /root/nails-hidden-write-2")
        machine.fail("test -e /dev/mapper/data")
        check_vital_paths("final-boot", frozenset(), previous)

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
        # one window. The late kmsg tokens are asserted too: with the kmsg
        # cursor (ADR 0008, section 5) they must not reach the decoy journal.
        all_tokens = list(hidden_tokens) + late_kmsg_tokens
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

    machine.log("FINDING: in-guest soft-reboot timings (seconds):")
    for record in timings:
        machine.log(f"FINDING:   {record}")
    assert not vital_failures, "vital-path failures:\n" + "\n".join(vital_failures)
  '';
}
