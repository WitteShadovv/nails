# Research spike (T-132, ADR 0008): enter a whole-root overlay with
# `systemctl soft-reboot` and come back.
#
# This is NOT a regression test. It carries the `research` tag, which keeps it
# out of every default group (`ci`, `all`, the shards and `--affected`); build
# it explicitly:
#
#   nix build .#legacyPackages.x86_64-linux.e2e.research-soft-reboot-whole-root -L
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
#   5. Mounts the decoy root at /run/nextroot and soft-reboots back, then
#      asserts the same vital paths, that no overlay or nextroot mount is left
#      and that the hidden volume can be closed.
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
  name = "research-soft-reboot-whole-root";
  meta.tags = [ "research" ];
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

      # The pinned nixpkgs (systemd 259) does not install soft-reboot.target
      # and systemd-soft-reboot.service, so `systemctl soft-reboot` would fail
      # with "Unit soft-reboot.target not found". nixpkgs PR #514100 (merged
      # 2026-05-14) adds them to upstreamSystemUnits. The text below is the
      # upstream v259 unit text. It is declared through systemd.units rather
      # than additionalUpstreamSystemUnits, because a duplicate entry there
      # breaks the unit build once nixpkgs ships the units itself, whereas
      # systemd.units then turns into a harmless drop-in.
      systemd.units = {
        "soft-reboot.target".text = ''
          [Unit]
          Description=Reboot System Userspace
          Documentation=man:systemd.special(7)
          DefaultDependencies=no
          Requires=systemd-soft-reboot.service
          After=systemd-soft-reboot.service
          AllowIsolate=yes
          JobTimeoutSec=30min
          JobTimeoutAction=soft-reboot-force
        '';
        "systemd-soft-reboot.service".text = ''
          [Unit]
          Description=Reboot System Userspace
          Documentation=man:systemd-soft-reboot.service(8)
          DefaultDependencies=no
          Requires=shutdown.target umount.target final.target
          After=shutdown.target umount.target final.target
          SuccessAction=soft-reboot-force
        '';
      };

      # The trivial offline build uses this bash as its builder, so it must be
      # in the system closure (and therefore registered in the VM's Nix DB).
      system.extraDependencies = [ pkgs.bash ];

      environment.systemPackages = [
        pkgs.efibootmgr
        pkgs.kmod
      ];
    };

  testScript = ''
    import queue
    import secrets
    import shlex
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
            machine.send_chars("testuser\n")
            machine.wait_until_succeeds("pgrep -x login", timeout=60)
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
            'derivation { name = "%s"; system = builtins.currentSystem; '
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


    def drain_console():
        while True:
            try:
                machine.last_lines.get_nowait()
            except queue.Empty:
                return


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


    def soft_reboot(label):
        """Trigger a soft-reboot and reconnect the backdoor shell.

        The backdoor is an ordinary service, so it dies with the old userspace
        and the new userspace starts it again. As machine.switch_root() does
        for the initrd, send the command without reading its output, mark the
        shell disconnected and reconnect; connect() discards everything until
        the new backdoor prints its ready marker. The wait on the serial
        console first turns a frozen PID 1 into a timeout instead of a hang.
        """
        drain_console()
        start = time.monotonic()
        machine.execute(
            "(systemctl soft-reboot --check-inhibitors=no || "
            "systemctl start --no-block --job-mode=replace-irreversibly soft-reboot.target)"
            " </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        machine.connected = False
        machine.wait_for_console_text("connecting to host", timeout=600)
        machine.connect()
        backdoor = time.monotonic() - start
        machine.wait_for_unit("multi-user.target")
        multi_user = time.monotonic() - start
        out_of("timeout 300 systemctl is-system-running --wait || true")
        settled = time.monotonic() - start
        timings.append((label, backdoor, multi_user, settled))
        finding(
            f"{label}: backdoor back after {backdoor:.1f}s, multi-user.target after "
            f"{multi_user:.1f}s, system settled after {settled:.1f}s (host clock)"
        )
        _, count = out_of("systemctl show -p SoftRebootsCount --value || true")
        finding(f"{label}: SoftRebootsCount={count.strip()} (RAM-only, visible to anyone with a shell)")


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
            # /run is carried across a soft-reboot; does this file reach the decoy?
            machine.succeed(f"echo {canary} > /run/nails-hidden-run-probe")
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

        soft_reboot(f"cycle{cycle}-leave")

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

        with subtest(f"cycle {cycle}: RAM residue visible to the decoy"):
            rc, _ = out_of("test -e /run/nails-hidden-run-probe")
            finding(f"{label}: file written to /run in the hidden session survives into the decoy: {rc == 0}")
            out_of("rm -f /run/nails-hidden-run-probe")
            rc, _ = out_of(f"test -e /run/systemd/transient/nails-spike-late-kmsg-{cycle}.service")
            finding(f"{label}: the hidden session's transient unit file survives in /run/systemd/transient: {rc == 0}")
            late = late_kmsg_tokens[-1]
            _, in_journal = out_of(f"journalctl --no-pager -o cat | grep -c -F {late} || true")
            _, in_dmesg = out_of(f"dmesg | grep -c -F {late} || true")
            finding(
                f"{label}: late hidden kmsg record: in decoy journal x{in_journal.strip()}, "
                f"in kernel ring buffer x{in_dmesg.strip()}"
            )
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
        # One pass over the whole disk (both partitions) for every token. The
        # late kmsg records are a reported finding, not an assertion: that
        # channel is a known open question (ADR 0008, section 5).
        patterns = " ".join(f"-e {t}" for t in list(hidden_tokens) + late_kmsg_tokens)
        raw = machine.succeed(
            f"sync; echo 3 > /proc/sys/vm/drop_caches; "
            f"grep -a -o -F {patterns} {decoy_disk} | sort | uniq -c || true",
            timeout=1800,
        )
        hits = [line for line in raw.splitlines() if any(t in line for t in hidden_tokens)]
        late_hits = [line for line in raw.splitlines() if any(t in line for t in late_kmsg_tokens)]
        finding(f"late hidden kmsg records on the raw decoy disk: {late_hits or 'none'}")
        assert not hits, "hidden tokens found on the raw decoy disk:\n" + "\n".join(hits)

    machine.log("FINDING: soft-reboot timings (label, backdoor, multi-user, settled):")
    for label, backdoor, multi_user, settled in timings:
        machine.log(f"FINDING:   {label}: {backdoor:.1f}s / {multi_user:.1f}s / {settled:.1f}s")
    assert not vital_failures, "vital-path failures:\n" + "\n".join(vital_failures)
  '';
}
