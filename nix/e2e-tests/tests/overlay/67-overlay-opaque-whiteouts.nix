# Test 67: Overlay Opaque Whiteouts
# Uses subtests, deterministic waits, hard assertions, and overlay tags only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "overlay-opaque-whiteouts";
  meta.tags = [ "overlay" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-whiteouts.yaml"
    whiteout_path = "/mnt/hidden-volume/home/testuser/whiteout-target.txt"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: prepare decoy file and activate /home overlay"):
        machine.succeed(
            "su - testuser -c 'printf %s decoy-data > ~/whiteout-target.txt'"
        )
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y"
        )
        assert_overlay_mounted("/home")
        machine.succeed("su - testuser -c 'test -f ~/whiteout-target.txt'")

    with subtest("phase 2: removing a decoy file creates an overlay whiteout"):
        machine.succeed("su - testuser -c 'rm ~/whiteout-target.txt'")
        machine.fail("su - testuser -c 'test -e ~/whiteout-target.txt'")
        machine.succeed(f"test -c {whiteout_path}")
        machine.succeed(f"stat -c '%t:%T' {whiteout_path} | grep -qx '0:0'")

    with subtest("phase 3: deactivation reveals the lower file again"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-overlay-whiteouts")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
        machine.succeed("su - testuser -c 'test -f ~/whiteout-target.txt'")
        content = machine.succeed("su - testuser -c 'cat ~/whiteout-target.txt'").strip()
        assert content == "decoy-data", f"Expected lower file to reappear intact, got: {content!r}"
  '';
}
