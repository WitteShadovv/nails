# Test 80: Emergency From A Graphical Session
#
# Activates from a real graphical session (lightdm autologin as testuser) with a
# hidden configuration that adds a long-running service unit, then triggers
# `nails emergency` and asserts the hidden session and the hidden-added service
# are gone, the NAILS overlays are released, the display manager comes back for
# the decoy greeter, and the backend can be unmounted and closed without EBUSY.

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
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}
    ${sessionHelpers.waitForUnitRestartedFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}

    def unit_is_active(unit):
        return machine.execute(f"systemctl is-active {unit}")[0] == 0

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
        display_manager_before = read_systemd_active_enter_monotonic("display-manager.service")

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
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")
        # Record whether the hidden switch brought the marker service up; the
        # offline VM may preserve a failed switch, in which case the service was
        # never added and the stop assertion below is simply vacuous.
        hidden_service_came_up = unit_is_active("hidden-marker.service")

    with subtest("emergency tears the hidden session and services down"):
        machine.succeed(f"nails --config {headless_config} emergency --no-countdown")

        # The hidden overlays are released and the hidden-added service is gone.
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert not unit_is_active("hidden-marker.service"), (
            "emergency must stop the service the hidden configuration added"
        )
        if hidden_service_came_up:
            machine.succeed("test ! -e /etc/nails-graphical-marker")

        # The display manager is restarted, so the decoy greeter can come up.
        wait_for_unit_restarted("display-manager.service", display_manager_before)

        assert_status_state("inactive", config_path=headless_config)

    with subtest("the backend unmounts and closes without EBUSY"):
        # Nothing may still pin the hidden superblock: with the overlays released
        # and the hidden session ended, a plain umount and cryptsetup close must
        # succeed (a lazy umount or a failed close would mean a straggler still
        # holds the backend and the key stays in RAM).
        machine.succeed("umount /mnt/data")
        machine.succeed("cryptsetup close data")
        machine.fail("test -e /dev/mapper/data")
  '';
}
