# Test 81: Activate — default auto-mode overlay lifecycle
#
# Every other overlay test lists its overlays explicitly, but the product default
# is auto mode: NAILS derives the overlay set from the live base OS, which on
# NixOS covers /var and /nix as well as /etc and /home. This test exercises that
# default end to end — activate in auto mode, confirm /var and /nix are really
# overlaid (not just /etc and /home), then deactivate and confirm the system
# returns to Inactive with no overlays left behind. It is deliberately kept to an
# overlay-only activation (no hidden rebuild, no session kill) so it is cheap
# enough to sit in the per-PR `ci` subset.
#
# NOTE (evaluate under nix): overlaying /nix drives the NixOS-specific nix-store
# handling (daemon stop/start, store self-bind), which can only be confirmed by
# `nix build .#checks.x86_64-linux.activate-auto-lifecycle` on a Nix host.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "activate-auto-lifecycle";
  meta.tags = [
    "nixos"
    "lifecycle"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeAutoConfigFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-auto.toml"
    write_auto_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("auto mode is Inactive before activation"):
        assert_status_state("inactive", config_path=config_path)

    with subtest("auto-mode activation overlays the full default set, including /var and /nix"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        assert_status_state("active", config_path=config_path)

        # The point of auto mode: /var and /nix are overlaid as well as the trees
        # the explicit test configs list. An explicit config would leave these on
        # the decoy.
        for path in ["/etc", "/home", "/var", "/nix"]:
            assert_overlay_mounted(path)

        status = read_status_json(config_path=config_path)
        active_paths = {overlay["mount_point"] for overlay in status["overlays"]}
        assert {"/var", "/nix"}.issubset(active_paths), status

    with subtest("deactivation returns the host to Inactive with no overlays"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-auto-lifecycle")
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/etc", "/home", "/var", "/nix"])
  '';
}
