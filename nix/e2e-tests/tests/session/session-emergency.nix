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
#      session included) and the machine powers off for real (a hidden session
#      never goes back to the decoy); the next cold boot is the plain decoy
#      with its greeter (here: getty), its services (avahi-daemon and a probe
#      that keeps a PID file in /run) and its own units, and nothing typed in
#      the hidden session reaches the decoy's history file. The units the
#      hidden root does not need (the boot-loader and root-filesystem units)
#      and systemd's GPT auto-generator are masked in the hidden session only,
#      and the hidden session's kernel log names no session drop-in. In the
#      hidden session every line of libmount's utab that libmount joins to a
#      mount names the mount it was written for: by its mount ID, a live mount
#      with the line's source and root at the line's target (an initrd's
#      target seen from the root it switched to); without an ID, a live mount
#      at its target with its source and root. A stale line without an ID for
#      /run/wrappers, added on the decoy before the first entry, is gone in the
#      hidden session, whose start would have joined it to its own
#      /run/wrappers.
#   3. In the hidden session, a desktop shell stand-in leads a session and a
#      process group of its own, as a unit's main process does, and starts
#      an app as its direct child in both, as GNOME Shell and niri start menu
#      entries; the app ignores SIGTERM, and the unit never escalates its stop.
#      The stand-in's terminal (a pseudo-terminal of script's) runs
#      `sudo nails emergency` itself, as a menu entry that asks for a terminal
#      does. The emergency's kill ends the app at once, or the power-off would
#      wait for it for ever, and the emergency itself lives on past its kill:
#      it logs its phases on the hidden volume.
#   4. A scratch disk mounted over the hidden root in the session: the
#      session watcher, polling every second with its automatic emergency on,
#      keeps running past its debounce without writing a probe or ending the
#      session, deactivate is refused with root_covered, emergency still ends
#      the session with a real power-off, and the scratch disk received
#      nothing: no logs/, state.json, .lock or write probe, and its root
#      directory's mtime and ctime are unchanged.
#   5. `nails emergency --poweroff` in the hidden session powers the machine
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
      # A desktop shell stand-in, started in the hidden session only. Its
      # main process leads a session and a process group of its own, and its
      # app is its direct child in both. The app ignores SIGTERM and the stop
      # never escalates: only the emergency's kill can end it before the
      # switch. Its terminal runs the command written to the launch fifo.
      systemd.services.desktop-standin = {
        path = [
          pkgs.bash
          pkgs.coreutils
          pkgs.util-linux
        ];
        serviceConfig = {
          User = "testuser";
          RuntimeDirectory = "desktop-standin";
          TimeoutStopSec = "infinity";
        };
        script = ''
          sh -c 'trap "" TERM; exec sleep infinity' &
          echo $! > /run/desktop-standin/app.pid
          mkfifo /run/desktop-standin/launch
          exec 3<>/run/desktop-standin/launch
          read -r command <&3
          script -qfec "$command" /dev/null <&3 >/dev/null 2>&1 &
          wait
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

    from nails_e2e import session, utab

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalEmergencyFn}

    CONFIG = "/mnt/data/config/nails.toml"
    WATCH_UNIT = "overlay-runtime-monitor.service"
    # The units the hidden root masks where the decoy has them, as the distro
    # smoke lists them, and the generator it always masks.
    HIDDEN_MASKED_UNITS = (
        "systemd-boot-random-seed.service",
        "grub-common.service",
        "grub2-common.service",
        "grub-initrd-fallback.service",
        "systemd-remount-fs.service",
        "systemd-growfs-root.service",
    )
    GPT_AUTO_MASK = "/run/systemd/system-generators/systemd-gpt-auto-generator"


    def load_states():
        return {
            unit: machine.succeed(f"systemctl show --property=LoadState --value {unit}").strip()
            for unit in HIDDEN_MASKED_UNITS
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
    decoy_masked_units = load_states()
    machine.log(f"units the hidden root masks, on the decoy: {decoy_masked_units}")
    machine.fail(f"test -L {GPT_AUTO_MASK}")
    decoy_initrd_mounts = initrd_mounts()
    machine.log(f"initrd mounts on the decoy: {sorted(decoy_initrd_mounts)}")
    assert "/" in decoy_initrd_mounts, decoy_initrd_mounts
    decoy_utab, _ = utab_and_mounts()
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
            if decoy_masked_units[unit] != "not-found":
                assert state == "masked", f"{unit} in the hidden session: {state}"
        mask = machine.succeed(f"readlink {GPT_AUTO_MASK}").strip()
        assert mask == "/dev/null", f"{GPT_AUTO_MASK} -> {mask}"
        assert_quiet_kernel_log("the hidden session")
        assert_utab_names_live_mounts("the hidden session")
        hidden_utab, _ = utab_and_mounts()
        assert STALE_WRAPPERS not in hidden_utab.splitlines(), hidden_utab
        # The hidden copies that the emergency below kills.
        machine.wait_for_unit("avahi-daemon.service")
        machine.wait_until_succeeds("test -s /run/pidfile-probe/pid", timeout=30)

    hidden_token = "hidden-" + secrets.token_hex(6)
    with subtest("emergency from a hidden login shell kills it and powers off"):
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
        # Typed, so the ending starts outside the follower: it reads the
        # console from before the keystrokes, the typed command's own report
        # of a failure among it.
        since = len(machine.full_console_log)
        machine.send_chars(command)
        session.follow_power_off(machine, None, "emergency-from-tty", console_index=since)

    with subtest("the next cold boot is the plain decoy with its own services and units"):
        session.boot_decoy(machine)
        machine.fail("systemctl is-active hidden-writer.service")
        machine.fail("loginctl list-sessions --no-legend | grep -q testuser")
        machine.wait_for_unit("getty@tty1.service")
        machine.wait_for_unit("pidfile-probe.service")
        machine.wait_for_unit("avahi-daemon.service")
        assert load_states() == decoy_masked_units, "the decoy's own units again"
        machine.fail(f"test -L {GPT_AUTO_MASK}")
        assert_utab_names_live_mounts("after the emergency")
        assert initrd_mounts() == decoy_initrd_mounts, sorted(initrd_mounts())

    with subtest("nothing typed in either shell reached the decoy history"):
        history = decoy_history()
        assert activation_token not in history, history
        assert hidden_token not in history, history
        assert "emergency" not in history, history

    with subtest("an emergency from a desktop's terminal ends the desktop's app at once"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        write_config()
        canonical_activate(CONFIG, "--overlay-only", "activate-desktop")
        session.assert_hidden_root(machine)
        finished = (
            "cat /mnt/data/logs/*.log 2>/dev/null | grep -c 'emergency hot path finished' || true"
        )
        logged = int(machine.succeed(finished).strip() or 0)
        machine.succeed("systemctl start desktop-standin.service")
        machine.wait_until_succeeds(
            "test -s /run/desktop-standin/app.pid && test -p /run/desktop-standin/launch",
            timeout=60,
        )
        desktop = machine.succeed("systemctl show -p MainPID --value desktop-standin").strip()
        app = machine.succeed("cat /run/desktop-standin/app.pid").strip()
        # The app is in the desktop's session and process group.
        ids = machine.succeed(f"ps -o sid=,pgid= -p {app}").split()
        assert ids == [desktop, desktop], (ids, desktop)
        command = (
            "/run/wrappers/bin/sudo /run/current-system/sw/bin/nails "
            f"--config {CONFIG} emergency"
        )
        # A spared app would hold the power-off for ever: the deadline fails it.
        session.follow_power_off(
            machine,
            f"echo '{command}' > /run/desktop-standin/launch",
            "emergency-from-a-desktop-terminal",
            deadline_s=300,
        )
        session.boot_decoy(machine)
        # The emergency outlived its kill, which took its terminal, sudo and
        # the desktop: it logged its phases after it.
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        assert int(machine.succeed(finished).strip() or 0) == logged + 1

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
        # without it and powers off.
        canonical_emergency(covered_config, "emergency-covered")
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
        canonical_emergency(CONFIG, "emergency-poweroff", "--poweroff", boot=False)

    with subtest("the next cold boot is the plain decoy with the backend closed"):
        session.boot_decoy(machine)
        assert activation_token not in decoy_history()
  '';
}
