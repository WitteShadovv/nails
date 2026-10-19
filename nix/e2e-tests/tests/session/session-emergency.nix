# Emergency and shell history in the whole-root session, from a real login
# shell on a tty, the way an operator runs it.
#
# Replaces the live-overlay emergency, invoking-shell-history, real-sudo
# history and emergency power-off tests:
#
#   1. Activation typed into an interactive bash on the decoy's tty1 (through
#      sudo): the soft-reboot ends that shell, and NAILS SIGKILLs it first, so
#      the activation command never reaches the decoy's ~/.bash_history.
#   2. In the hidden session, a login shell on tty1 runs commands and then
#      `sudo nails emergency`. Every hidden process dies at once (the login
#      session included), the machine soft-reboots back to the plain decoy and
#      the decoy greeter (here: getty) comes back; nothing typed in the hidden
#      session reaches the decoy's history file. The decoy's services that
#      keep a PID file in /run start again although the kill left their hidden
#      copies' files behind: avahi-daemon (with resolvconf, which signals it)
#      and a probe that, like avahi, refuses to start while its file is there.
#      The boot-loader units are masked in the hidden session only, and the
#      kernel log names no session drop-in and no failed unmount of the hidden
#      volume. On either side of each switch, every line of libmount's utab
#      that libmount joins to a mount names the mount it was written for: by
#      its mount ID, a live mount with the line's source and root at the
#      line's target (an initrd's target seen from the root it switched to);
#      without an ID, a live mount at its target with its source and root.
#      The kernel reuses the IDs of the mounts a switch leaves behind, and a
#      stale x-initrd.mount line would take a reused or a new mount out of the
#      shutdown order. A stale line without an ID for /run/wrappers, added on
#      the decoy before the first entry, is gone in the hidden session, whose
#      start would have joined it to its own /run/wrappers. After the way
#      back the decoy has its own lines again: each line it had before the
#      entry whose mount came back, under that mount's new ID, and besides
#      those only lines for filesystems it mounted itself after the switch.
#      libmount marks the same mount points x-initrd.mount as at boot, so the
#      decoy's next shutdown leaves them alone as a fresh boot's does. Every
#      mount outside /run and the hidden volume is back as before the entry
#      (its filesystem, directory, place, options and propagation type, in the
#      decoy's order, and no mount more): the store's overlay with NixOS's
#      read-only bind of it stacked on top, and the tmpfs at /nix/.rw-store
#      that holds the overlay's upper.
#   3. A scratch disk mounted over the hidden root in the session: the
#      session watcher, polling every second with its automatic emergency on,
#      keeps running past its debounce without writing a probe or ending the
#      session, deactivate is refused with root_covered, emergency still ends
#      the session (the mounts the way back needs sit under the covered root,
#      so it powers off instead, as it does whenever the way back cannot be
#      prepared), and the scratch disk received nothing: no logs/, state.json,
#      .lock or write probe, and its root directory's mtime and ctime are
#      unchanged.
#   4. `nails emergency --poweroff` in the hidden session powers the machine
#      off; the next cold boot is the plain decoy with the backend closed.
{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "session-emergency";
  meta.tags = [
    "security"
    "shell"
    "session"
  ];
  globalTimeout = 1800;

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nails ];
      # On by default with GNOME: its unit may not remove a stale PID file.
      services.avahi.enable = true;
      # A service that keeps a PID file in /run the way avahi-daemon does: it
      # removes the file when it stops and refuses to start while one is left.
      # The stop signal goes to the shell alone, as a daemon removes its file
      # itself: sent to every process, it can also reach the trap's rm.
      systemd.services.pidfile-probe = {
        wantedBy = [ "multi-user.target" ];
        path = [ pkgs.coreutils ];
        serviceConfig.KillMode = "mixed";
        script = ''
          set -C
          mkdir -p /run/pidfile-probe
          echo $$ > /run/pidfile-probe/pid
          trap 'rm -f /run/pidfile-probe/pid; exit 0' TERM
          while :; do sleep 1 & wait $!; done
        '';
      };
      # The disk a covered-root subtest mounts over the hidden root.
      virtualisation.emptyDiskImages = [
        {
          size = 64;
          driveConfig.deviceExtraOpts.serial = "scratch";
        }
      ];
    };

  testScript = _: ''
    import secrets

    from nails_e2e import mounts, session, utab

    ${testHelpers.canonicalActivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    WATCH_UNIT = "overlay-runtime-monitor.service"
    BOOT_WRITERS = (
        "systemd-boot-random-seed.service",
        "grub-common.service",
        "grub-initrd-fallback.service",
    )


    def load_states():
        return {
            unit: machine.succeed(f"systemctl show --property=LoadState --value {unit}").strip()
            for unit in BOOT_WRITERS
        }


    def assert_quiet_kernel_log(where):
        for command in (
            "dmesg | grep -F world-inaccessible | grep -F overlay-runtime",
            "dmesg | grep -F 'Failed unmounting mnt-data.mount'",
        ):
            rc, out = machine.execute(command)
            assert rc != 0, f"{where}: {command}:\n{out}"


    #: A stale utab line without an ID: libmount joins it to whatever is
    #: mounted at its target with its source and root, also a mount made later.
    STALE_WRAPPERS = "SRC=tmpfs TARGET=/run/wrappers ROOT=/ OPTS=x-initrd.mount"


    def outside_the_decoy_tree(point):
        # A soft-reboot into a new root carries /run without the mounts below
        # it, and the hidden volume goes with the session.
        return (
            point.startswith("/run/") or point == "/mnt/data" or point.startswith("/mnt/data/")
        )


    def utab_and_mounts():
        return (
            machine.succeed("cat /run/mount/utab 2>/dev/null || true"),
            machine.succeed("cat /proc/self/mountinfo"),
        )


    def assert_utab_names_live_mounts(where):
        text, mountinfo = utab_and_mounts()
        wrong = utab.wrong_lines(text, mountinfo)
        assert not wrong, f"{where}: utab lines naming no live mount or another: {wrong}"


    def initrd_mounts():
        # The mount points that libmount, joining utab to the mount table,
        # marks x-initrd.mount: systemd leaves them out of the shutdown order.
        marked = set()
        for line in machine.succeed("findmnt --mtab -rn -o TARGET,OPTIONS").splitlines():
            target, _, options = line.partition(" ")
            if "x-initrd.mount" in options.split(","):
                marked.add(target)
        return marked


    def write_config(extra=""):
        machine.succeed(
            f"cat > {CONFIG} <<'EOF'\n"
            "hidden_volume_root = \"/mnt/data\"\n"
            "minimum_space_mb = 100\n"
            f"{extra}"
            "EOF"
        )


    def login_tty1():
        # Clear tty1 first, so a "Password:" left by an earlier phase cannot
        # match; wait for login's own prompt before typing the password (login
        # flushes typeahead when it turns echo off).
        machine.wait_for_unit("getty@tty1.service")
        machine.succeed("printf '\\033[H\\033[2J' > /dev/tty1")
        machine.send_chars("testuser\n")
        machine.wait_until_tty_matches("1", "Password: ", timeout=60)
        machine.send_chars("test\n")
        machine.wait_until_succeeds(
            "loginctl list-sessions --no-legend | grep -q testuser", timeout=60
        )


    def decoy_history():
        rc, out = machine.execute("cat /home/testuser/.bash_history 2>/dev/null")
        return out if rc == 0 else ""


    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    write_config()

    machine.wait_for_unit("avahi-daemon.service")
    machine.wait_for_unit("pidfile-probe.service")
    decoy_boot_writers = load_states()
    machine.log(f"boot-loader units on the decoy: {decoy_boot_writers}")
    decoy_initrd_mounts = initrd_mounts()
    machine.log(f"initrd mounts on the decoy: {sorted(decoy_initrd_mounts)}")
    assert "/" in decoy_initrd_mounts, decoy_initrd_mounts
    decoy_utab, decoy_mountinfo = utab_and_mounts()
    machine.log(f"utab on the decoy:\n{decoy_utab}")
    machine.succeed(f"echo '{STALE_WRAPPERS}' >> /run/mount/utab")

    activation_token = "act-" + secrets.token_hex(6)
    with subtest("activation typed on the decoy tty never reaches its history"):
        login_tty1()
        # A comment carrying the token rides along in the same command line,
        # so the token is in bash's history exactly when the command is.
        # A failed activation reports its status and the system's state on
        # the serial console, so the wait stops at once instead of running out
        # its deadline.
        command = (
            f"sudo nails --config {CONFIG} activate -y --overlay-only || echo "
            f"{session.TRIGGER_EXIT_MARKER}$? $(sudo systemctl is-system-running) "
            f"| sudo tee {session.SERIAL_CONSOLE} # {activation_token}\n"
        )
        session.follow_soft_reboot(
            machine,
            command.strip(),
            "activate-from-tty",
            start=lambda: machine.send_chars(command),
        )
        session.assert_hidden_root(machine)
        for unit, state in load_states().items():
            if decoy_boot_writers[unit] != "not-found":
                assert state == "masked", f"{unit} in the hidden session: {state}"
        assert_quiet_kernel_log("the hidden session")
        assert_utab_names_live_mounts("the hidden session")
        hidden_utab, _ = utab_and_mounts()
        assert STALE_WRAPPERS not in hidden_utab.splitlines(), hidden_utab
        # The hidden copies that the emergency below kills.
        machine.wait_for_unit("avahi-daemon.service")
        machine.wait_until_succeeds("test -s /run/pidfile-probe/pid", timeout=30)

    hidden_token = "hidden-" + secrets.token_hex(6)
    with subtest("emergency from a hidden login shell kills it and returns"):
        machine.succeed(
            "systemctl reset-failed hidden-writer.service 2>/dev/null || true; "
            + "systemd-run --unit hidden-writer --property=Type=exec "
            + "sleep infinity"
        )
        login_tty1()
        machine.send_chars(f"echo {hidden_token}\n")
        machine.wait_until_tty_matches("1", hidden_token, timeout=30)
        command = (
            f"sudo nails --config {CONFIG} emergency || echo "
            f"{session.TRIGGER_EXIT_MARKER}$? $(sudo systemctl is-system-running) "
            f"| sudo tee {session.SERIAL_CONSOLE}\n"
        )
        timings = session.follow_soft_reboot(
            machine,
            command.strip(),
            "emergency-from-tty",
            start=lambda: machine.send_chars(command),
        )
        machine.log(f"emergency timings: {timings}")
        session.assert_decoy_root(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.fail("loginctl list-sessions --no-legend | grep -q testuser")
        machine.wait_for_unit("getty@tty1.service")
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)

    with subtest("the decoy's services start again after the emergency killed their copies"):
        machine.wait_for_unit("pidfile-probe.service")
        machine.wait_for_unit("avahi-daemon.service")
        machine.wait_for_unit("resolvconf.service")
        _, avahi = machine.execute("journalctl -b -u avahi-daemon.service --no-pager")
        assert "trying to remove PID file" not in avahi, avahi
        assert load_states() == decoy_boot_writers, "the decoy's own units again"
        assert_quiet_kernel_log("after the emergency")
        assert_utab_names_live_mounts("after the emergency")
        back_utab, back_mountinfo = utab_and_mounts()
        foreign, lost = utab.not_given_back(
            decoy_utab, decoy_mountinfo, back_utab, back_mountinfo
        )
        assert not foreign and not lost, (
            f"the decoy's utab after the way back:\n{back_utab}\n"
            f"lines not its own: {foreign}; its lines not given back: {lost}"
        )
        assert initrd_mounts() == decoy_initrd_mounts, sorted(initrd_mounts())

    with subtest("the decoy has every mount back as it had it before the entry"):
        # The store is the initrd's overlay with NixOS's read-only bind of it
        # on top, and /nix/.rw-store the tmpfs that holds the overlay's upper.
        found = mounts.differences(
            mounts.shape(decoy_mountinfo, outside_the_decoy_tree),
            mounts.shape(back_mountinfo, outside_the_decoy_tree),
        )
        assert not found, "mounts not as before the entry:\n" + "\n".join(found)

    with subtest("nothing typed in either shell reached the decoy history"):
        history = decoy_history()
        assert activation_token not in history, history
        assert hidden_token not in history, history
        assert "emergency" not in history, history

    with subtest("a disk mounted over the hidden root in the session receives nothing"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        # A watcher that took the cover for a failed backend would end the
        # session on its own after the debounce: fast polls and a short
        # debounce make that show within the wait below.
        write_config(
            "\n[backend_watch]\n"
            "enabled = true\n"
            "auto_emergency = true\n"
            "poll_interval_secs = 1\n"
            "debounce_secs = 2\n"
        )
        canonical_activate(CONFIG, "--overlay-only", "activate-covered")
        session.assert_hidden_root(machine)
        machine.wait_for_unit(WATCH_UNIT)
        assert_utab_names_live_mounts("the second hidden session")
        # The configuration on the volume is hidden by the disk on top, so
        # the commands below read a copy in /run.
        covered_config = "/run/covered.toml"
        machine.succeed(f"cp {CONFIG} {covered_config}")
        machine.succeed(
            "mkfs.ext4 -q -L scratch /dev/disk/by-id/virtio-scratch && "
            "mount /dev/disk/by-id/virtio-scratch /mnt/data"
        )
        scratch_times = machine.succeed("stat -c '%Y %Z' /mnt/data").strip()
        # Let the session watcher poll the covered root about ten times, well
        # past its debounce: it must write no probe there, which would change
        # the disk's root directory times, and must not take the cover for a
        # failed backend, whose automatic emergency would end the session and
        # the watcher with it. A covered poll leaves no trace by design, so
        # there is no signal to wait on.
        # sync-lint: allow sleep -- watcher polls on a covered root leave nothing to wait for; the assertions below are the finding
        machine.sleep(10)
        machine.succeed(f"systemctl is-active {WATCH_UNIT}")
        session.assert_hidden_root(machine)
        assert machine.succeed("stat -c '%Y %Z' /mnt/data").strip() == scratch_times
        rc, out = machine.execute(
            f"nails --config {covered_config} --json deactivate -y 2>/dev/null"
        )
        assert rc == 4, (rc, out)
        assert '"code":"root_covered"' in out, out
        session.assert_hidden_root(machine)
        # The state lock refuses the covered root, but emergency proceeds
        # without it. The way back's mounts are under the covered root, so it
        # cannot be prepared and emergency powers off instead.
        machine.execute(
            f"(nails --config {covered_config} emergency) </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_power_off(machine, 300)
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.succeed(
            "mkdir -p /run/scratch && "
            "mount -o ro,noload /dev/disk/by-id/virtio-scratch /run/scratch"
        )
        for name in ["logs", "state.json", ".lock", ".nails_write_test"]:
            machine.fail(f"test -e /run/scratch/{name}")
        after = machine.succeed("stat -c '%Y %Z' /run/scratch").strip()
        assert after == scratch_times, (scratch_times, after)
        machine.succeed("umount /run/scratch")

    with subtest("emergency --poweroff in the hidden session powers off"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config()
        canonical_activate(CONFIG, "--overlay-only", "activate-poweroff")
        machine.execute(
            f"(nails --config {CONFIG} emergency --poweroff) </dev/null >/dev/null 2>&1 &",
            check_return=False,
            check_output=False,
        )
        session.wait_for_power_off(machine, 300)

    with subtest("the next cold boot is the plain decoy with the backend closed"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        session.assert_decoy_root(machine)
        machine.fail("test -e /dev/mapper/data")
        assert activation_token not in decoy_history()
  '';
}
