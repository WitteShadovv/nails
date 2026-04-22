# Test 24: Config Extended Overlays
# Historical file name only: covers explicit persistent overlays for additional
# targets, not `extended_overlays`.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  extendedFixture = ./../../fixtures/configs/extended-overlays.yaml;
in
{
  name = "config-extended-overlays";
  meta.tags = [ "config" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${assertions.assertHiddenVolumeHasFn}

    configured_targets = ["/etc", "/home", "/root", "/var", "/tmp", "/srv", "/opt"]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /srv /opt /var/lib")
    machine.succeed("cp ${extendedFixture} /tmp/extended-overlays.yaml")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("explicit persistent overlay config mounts every configured target"):
        machine.succeed("nails --config /tmp/extended-overlays.yaml activate --overlay-only --no-kill-session -y")
        for path in configured_targets:
            assert_overlay_mounted(path)
        status = assert_status_state("active", config_path="/tmp/extended-overlays.yaml")
        assert {overlay["path"] for overlay in status["overlays"]} == set(configured_targets), status

    with subtest("writes land on hidden storage for explicitly configured persistent overlays"):
        machine.succeed("touch /var/lib/extended-proof")
        machine.succeed("touch /tmp/extended-proof")
        machine.succeed("mkdir -p /srv/extended /opt/extended")
        machine.succeed("touch /srv/extended/proof")
        machine.succeed("touch /opt/extended/proof")
        assert_hidden_volume_has("/var/lib/extended-proof")
        assert_hidden_volume_has("/tmp/extended-proof")
        assert_hidden_volume_has("/srv/extended/proof")
        assert_hidden_volume_has("/opt/extended/proof")

    with subtest("reactivation restores persisted data for explicitly configured extended targets"):
        canonical_deactivate("/tmp/extended-overlays.yaml", unit_name="nails-deactivate-config-extended-phase-1")
        assert_status_state("inactive")
        assert_no_overlays(configured_targets)
        machine.fail("test -e /var/lib/extended-proof")
        machine.fail("test -e /tmp/extended-proof")
        machine.fail("test -e /srv/extended/proof")
        machine.fail("test -e /opt/extended/proof")

        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        assert_hidden_volume_has("/var/lib/extended-proof")
        assert_hidden_volume_has("/tmp/extended-proof")
        assert_hidden_volume_has("/srv/extended/proof")
        assert_hidden_volume_has("/opt/extended/proof")

        machine.succeed("nails --config /tmp/extended-overlays.yaml activate --overlay-only --no-kill-session -y")
        for path in configured_targets:
            assert_overlay_mounted(path)
        machine.succeed("test -e /var/lib/extended-proof")
        machine.succeed("test -e /tmp/extended-proof")
        machine.succeed("test -e /srv/extended/proof")
        machine.succeed("test -e /opt/extended/proof")

    with subtest("clean deactivation removes explicit overlays and hides persisted writes from the decoy boot"):
        canonical_deactivate("/tmp/extended-overlays.yaml", unit_name="nails-deactivate-config-extended-phase-2")
        assert_status_state("inactive")
        assert_no_overlays(configured_targets)
        machine.fail("test -e /var/lib/extended-proof")
        machine.fail("test -e /tmp/extended-proof")
        machine.fail("test -e /srv/extended/proof")
        machine.fail("test -e /opt/extended/proof")

    with subtest("hidden storage still contains persisted writes for explicitly configured extended targets"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        assert_hidden_volume_has("/var/lib/extended-proof")
        assert_hidden_volume_has("/tmp/extended-proof")
        assert_hidden_volume_has("/srv/extended/proof")
        assert_hidden_volume_has("/opt/extended/proof")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
