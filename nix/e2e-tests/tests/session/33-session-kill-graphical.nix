# Test 33: Session Kill Graphical
# Self-check: subtests used, no sleep sync, hard assertions, session tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in {
  name = "session-kill-graphical";
  meta.tags = [ "session" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/graphical-vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    machine.start()
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare hidden volume and capture baseline service timestamps"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        display_manager_before = read_systemd_active_enter_monotonic("display-manager.service")
        user_manager_before = read_systemd_active_enter_monotonic("user@1000.service")

    with subtest("activate from graphical context via transient systemd unit"):
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {headless_config} activate --overlay-only -y"
        )
        activation_unit = wait_for_activation_transient_unit()
        assert_unit_in_system_slice(activation_unit)

    with subtest("display manager and user manager are restarted and overlays stay active"):
        machine.wait_until_succeeds("systemctl is-active display-manager.service")
        machine.wait_until_succeeds("systemctl is-active user@1000.service")
        machine.wait_until_succeeds(
            "/bin/sh -lc 'mountpoint -q /home && [ \"$(findmnt -n -o FSTYPE /home)\" = overlay ]'"
        )
        display_manager_after = read_systemd_active_enter_monotonic("display-manager.service")
        user_manager_after = read_systemd_active_enter_monotonic("user@1000.service")
        assert display_manager_after > display_manager_before, (
            f"display-manager.service did not restart: before={display_manager_before} after={display_manager_after}"
        )
        assert user_manager_after > user_manager_before, (
            f"user@1000.service did not restart: before={user_manager_before} after={user_manager_after}"
        )
        assert_overlay_mounted("/home")
        assert_status_state("active", config_path=headless_config)

    with subtest("deactivate back to decoy state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-session-kill-graphical")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=headless_config)
  '';
}
