# Test 80: Emergency From A Graphical Session
#
# Activates from a real graphical session (lightdm autologin as testuser) with a
# hidden configuration that adds a long-running service unit, then triggers
# `nails emergency` and asserts the NAILS overlays are released and the
# hidden-added service is stopped WHILE the desktop is left untouched: emergency
# never logs the operator out and never stops or restarts the display manager or
# X server, so nothing on screen hints at the teardown. The live X server keeps
# the lazily detached overlay busy, so the backend cannot be closed yet — which
# emergency reports honestly instead of force-closing it or failing the teardown.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "emergency-graphical";
  # Boots a full graphical VM and drives an in-VM NixOS switch before the
  # emergency teardown, so it needs more than the default budget.
  globalTimeout = 1800;
  meta.tags = [
    "security"
    "graphical"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}

    def unit_is_active(unit):
        return machine.execute(f"systemctl is-active {unit}")[0] == 0

    # NixOS's lightdm starts the server through its xserver wrapper, which execs
    # ''${xorgserver}/bin/X, so the process is named "X" and its command line
    # carries the lowercase store path "xorg-server". Match the executable's
    # basename at the start of the command line (X, Xorg, or a .Xorg-wrapped
    # wrapper) instead of a substring, so neither the comm nor the store path
    # decides the match and the invoking shell never matches itself.
    xorg_pgrep = "pgrep -f '^[^ ]*/(X|Xorg|[.]Xorg-wrapped)( |$)'"

    def xorg_pids():
        rc, out = machine.execute(xorg_pgrep)
        return sorted(out.split()) if rc == 0 else []

    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("prepare the hidden volume and a hidden-config service"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        # The hidden configuration adds a long-running service unit. After the
        # switch it is active, so activation records it in hidden_added_units and
        # emergency must stop exactly that unit.
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
      environment.etc."nails-graphical-marker".text = "graphical-rebuild-active";
      systemd.services.hidden-marker = {
        description = "Hidden configuration marker service";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "/run/current-system/sw/bin/sleep infinity";
        };
      };
    }
    EOF""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

    with subtest("activate from the graphical session"):
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {headless_config} activate -y"
        )
        wait_for_activation_transient_unit()
        machine.wait_until_succeeds(
            "/bin/sh -lc 'mountpoint -q /home && [ \"$(findmnt -n -o FSTYPE /home)\" = overlay ]'"
        )
        # Wait for the detached worker to finish before asserting the overlay set.
        # A full activate runs the hidden `switch-to-configuration` after the
        # mounts, which transiently unmounts the overlays over the base-OS trees it
        # manages (/etc, /usr, /bin, /lib64); the worker re-mounts them before it
        # restarts the session and reaches the Active state. Asserting only once
        # activation has completed checks the steady-state overlay set the hidden
        # session actually runs under, not the mid-switch window.
        wait_for_status_state("active", config_path=headless_config)
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")
        # Record whether the hidden switch brought the marker service up; the
        # offline VM may preserve a failed switch, in which case the service was
        # never added and the stop assertion below is simply vacuous.
        hidden_service_came_up = unit_is_active("hidden-marker.service")

    with subtest("emergency detaches the overlays and leaves the desktop untouched"):
        # Activation restarts the display manager to bring the hidden session up,
        # and reaching Active does not wait for the new X server and autologin
        # session to appear. Wait for both before snapshotting the desktop the
        # teardown must leave alone.
        machine.wait_for_unit("display-manager.service")
        machine.wait_until_succeeds(xorg_pgrep, timeout=60)
        machine.wait_until_succeeds("systemctl is-active user@1000.service", timeout=60)

        # Snapshot the live desktop immediately before the teardown.
        dm_active_enter_before = read_systemd_active_enter_monotonic("display-manager.service")
        dm_main_pid_before = machine.succeed(
            "systemctl show display-manager.service -p MainPID --value"
        ).strip()
        xorg_pids_before = xorg_pids()
        assert xorg_pids_before, "the X server must be running before the teardown"

        # Interactive shells the operator owns, each with a controlling pty — the
        # terminal window's own shell is one of them. The pre-unmount cleanup
        # SIGKILLs interactive shells so none flushes its history onto the decoy;
        # with a window manager as the session's main process that only closes the
        # terminal window, leaving the session (and X) alive.
        def interactive_user_shells():
            rc, out = machine.execute(
                "ps -u testuser -o pid=,tty=,comm= | "
                "awk '$2 ~ /pts/ && ($3 == \"bash\" || $3 == \"zsh\" || $3 == \"fish\") "
                "{ print $1 }'"
            )
            return sorted(out.split()) if rc == 0 else []

        shells_before = interactive_user_shells()

        # Emergency must complete the overlay teardown even though a live process
        # (the X server) holds a path busy, so capture its output and exit rather
        # than demanding a clean exit. Always log it: the teardown runs detached,
        # so this is the only place its reasoning is visible when an assertion
        # below fails.
        emergency_rc, emergency_out = machine.execute(
            f"nails --config {headless_config} emergency 2>&1"
        )
        print(f"nails emergency exited rc={emergency_rc}; output follows:")
        print(emergency_out)

        # Every hidden overlay is released (lazily where the X server still held
        # it), and the hidden-added service is stopped.
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert not unit_is_active("hidden-marker.service"), (
            "emergency must stop the service the hidden configuration added"
        )
        if hidden_service_came_up:
            machine.succeed("test ! -e /etc/nails-graphical-marker")

        # The desktop is untouched: the display manager was neither stopped nor
        # restarted (same activation timestamp and MainPID), the X server keeps the
        # same PID, and the operator's user session is still running.
        dm_active_enter_after = read_systemd_active_enter_monotonic("display-manager.service")
        assert dm_active_enter_after == dm_active_enter_before, (
            "emergency must not restart the display manager: "
            f"{dm_active_enter_before} -> {dm_active_enter_after}"
        )
        dm_main_pid_after = machine.succeed(
            "systemctl show display-manager.service -p MainPID --value"
        ).strip()
        assert dm_main_pid_after == dm_main_pid_before, (
            f"display manager PID changed: {dm_main_pid_before} -> {dm_main_pid_after}"
        )
        xorg_pids_after = xorg_pids()
        assert xorg_pids_after == xorg_pids_before, (
            f"X server PID changed: {xorg_pids_before} -> {xorg_pids_after}"
        )
        machine.succeed("systemctl is-active user@1000.service")

        # The terminal's interactive shell was SIGKILLed by the pre-unmount
        # cleanup even though its session was spared: the kill still does its job
        # (no history flushed to the decoy), it just no longer ends the desktop.
        if shells_before:
            survivors = set(shells_before) & set(interactive_user_shells())
            assert not survivors, (
                "pre-unmount cleanup must kill the terminal's interactive shell: "
                f"{sorted(survivors)} survived"
            )

        assert_status_state("inactive", config_path=headless_config)

    with subtest("the live session keeps the backend open, reported honestly"):
        # The still-running X server holds the lazily detached overlay, so the
        # hidden backend cannot be closed yet. Emergency must say so (rather than
        # claim a clean close or force one under the live session), and the hidden
        # root stays mounted for the operator to close by hand once it is safe.
        lowered = emergency_out.lower()
        assert ("forced detach" in lowered) or ("could not" in lowered) or (
            "still" in lowered and "mount" in lowered
        ) or ("cannot be closed" in lowered), (
            f"emergency must report that the backend could not be released yet: {emergency_out!r}"
        )
        machine.succeed("mountpoint -q /mnt/data")
  '';
}
