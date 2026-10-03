# Test 33: Session Kill Graphical

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "session-kill-graphical";
  meta.tags = [ "session" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    from nails_e2e import run_command_capture

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}
    ${sessionHelpers.waitForUnitRestartedFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    def count_started_messages(unit):
        import shlex

        return int(
            machine.succeed(
                "bash -lc "
                + shlex.quote(
                    "journalctl -u "
                    + shlex.quote(unit)
                    + " -b --no-pager -o cat | grep -c '^Started '"
                )
            ).strip()
        )

    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    headless_config = "/tmp/nails-headless.toml"
    shell_path = "/run/current-system/sw/bin/bash"
    osc_sequence = "\x1b]11;#1a1a2e\x07\x1b]10;#e0e0e0\x07"
    shell_command = (
        "sudo -u testuser env HOME=/home/testuser "
        + shell_path
        + " -ic ':'"
    )
    write_headless_config(headless_config)

    with subtest("prepare hidden volume and capture baseline service timestamps"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("""cat > /mnt/data/config/nixos/configuration.nix <<'EOF'
    { ... }: {
      documentation.nixos.enable = false;
      environment.etc."nails-graphical-marker".text = "graphical-rebuild-active";
    }
    EOF""")
        machine.succeed("cat > /home/testuser/.bashrc <<'EOF'\nexport PS1=\"decoy$ \"\nEOF")
        machine.succeed("chown testuser:users /home/testuser/.bashrc")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        display_manager_before = read_systemd_active_enter_monotonic("display-manager.service")
        user_manager_before = read_systemd_active_enter_monotonic("user@1000.service")
        display_started_before = count_started_messages("display-manager.service")
        before_shell = run_command_capture(
            machine, "session-graphical-shell-before", shell_command
        )
        assert before_shell["rc"] == 0, before_shell
        assert osc_sequence not in before_shell["stdout"], before_shell

    with subtest("activate from graphical context via transient systemd unit"):
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            # Overlay-only: this test covers the graphical session kill and
            # restart, not the hidden NixOS rebuild. A full activate would run a
            # real switch before the restart, which the offline VM cannot complete
            # in time and which disrupts the very session restart under test; the
            # switch-before-restart ordering is covered by the nixos test group.
            + f"nails --config {headless_config} activate --overlay-only -y"
        )
        activation_unit = wait_for_activation_transient_unit()
        assert_unit_in_system_slice(activation_unit)

    with subtest("display manager and user manager are restarted after the overlays mount"):
        # The activation runs in a detached unit, so the pre-kill display and
        # user managers may still be up here; wait for fresh activation
        # timestamps rather than `is-active`. LightDM autologin recreates the
        # user manager a moment after the display manager starts, independently
        # of the activation finishing.
        display_manager_after = wait_for_unit_restarted(
            "display-manager.service", display_manager_before
        )
        user_manager_after = wait_for_unit_restarted("user@1000.service", user_manager_before)
        machine.wait_until_succeeds(
            "/bin/sh -lc 'mountpoint -q /home && [ \"$(findmnt -n -o FSTYPE /home)\" = overlay ]'"
        )
        wait_for_status_state("active", config_path=headless_config)
        assert display_manager_after > display_manager_before, (
            f"display-manager.service did not restart: before={display_manager_before} after={display_manager_after}"
        )
        assert user_manager_after > user_manager_before, (
            f"user@1000.service did not restart: before={user_manager_before} after={user_manager_after}"
        )
        display_started_after = count_started_messages("display-manager.service")
        assert display_started_after == display_started_before + 1, (
            f"display manager restarted more than once: before={display_started_before} after={display_started_after}"
        )
        # ActiveEnterTimestampMonotonic is the stable signal for the user
        # manager restart. Recent systemd/NixOS combinations can emit more than
        # one "Started" journal line during a single graphical restart cycle,
        # so counting those log records is too brittle here.
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")
        assert_status_state("active", config_path=headless_config)
        active_shell = run_command_capture(
            machine, "session-graphical-shell-active", shell_command
        )
        assert active_shell["rc"] == 0, active_shell
        assert osc_sequence in active_shell["stdout"], repr(active_shell["stdout"])

    with subtest("deactivate back to decoy state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-session-kill-graphical")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=headless_config)
        machine.fail("test -e /etc/nails-graphical-marker")
        after_shell = run_command_capture(
            machine, "session-graphical-shell-after", shell_command
        )
        assert after_shell["rc"] == 0, after_shell
        assert osc_sequence not in after_shell["stdout"], repr(after_shell["stdout"])
  '';
}
