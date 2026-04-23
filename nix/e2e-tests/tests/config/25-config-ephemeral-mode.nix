# Test 25: Config Ephemeral Mode

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  ephemeralFixture = ./../../fixtures/configs/ephemeral.yaml;
in
{
  name = "config-ephemeral-mode";
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
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkdir -p /srv /opt /var/lib")
    machine.succeed("cp ${ephemeralFixture} /tmp/ephemeral.yaml")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("ephemeral overlay config activates with shared tmpfs backing"):
        machine.succeed(
            "nails --config /tmp/ephemeral.yaml activate --overlay-only --no-kill-session -y"
        )
        assert_status_state("active", config_path="/tmp/ephemeral.yaml")
        for path in ["/var", "/tmp", "/srv", "/opt"]:
            assert_overlay_mounted(path)
        for tmpfs_root in [
            "/run/nails/var-ephemeral",
            "/run/nails/tmp-ephemeral",
            "/run/nails/srv-ephemeral",
            "/run/nails/opt-ephemeral",
        ]:
            machine.succeed(f"mountpoint -q {tmpfs_root}")
            machine.succeed(f"test -d {tmpfs_root}/upper")
            machine.succeed(f"test -d {tmpfs_root}/work")

    with subtest("deactivation removes ephemeral overlays and shared tmpfs roots"):
        canonical_deactivate("/tmp/ephemeral.yaml", unit_name="nails-deactivate-config-ephemeral-mode")
        assert_status_state("inactive", config_path="/tmp/ephemeral.yaml")
        assert_no_overlays(["/etc", "/home", "/root", "/var", "/tmp", "/srv", "/opt"])
        for tmpfs_root in [
            "/run/nails/var-ephemeral",
            "/run/nails/tmp-ephemeral",
            "/run/nails/srv-ephemeral",
            "/run/nails/opt-ephemeral",
        ]:
            machine.fail(f"mountpoint -q {tmpfs_root}")

    with subtest("ephemeral activation leaves hidden storage untouched"):
        machine.fail("test -e /mnt/hidden-volume/var/lib/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/tmp/ephemeral-proof")
        machine.fail("test -e /mnt/hidden-volume/srv/ephemeral/proof")
        machine.fail("test -e /mnt/hidden-volume/opt/ephemeral/proof")
  '';
}
