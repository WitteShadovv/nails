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

    config_path = "/tmp/nails-whiteouts.toml"
    whiteout_path = "/mnt/data/home/testuser/whiteout-target.txt"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: prepare decoy file and activate /home overlay"):
        machine.succeed(
            "su - testuser -c 'printf %s decoy-data > ~/whiteout-target.txt'"
        )
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
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

    # Phases 4-6 pin down the T-040 scoping contract: a recreated directory sets
    # an opaque marker on the upper, and across a deactivate/re-activate cycle
    # NAILS clears that marker ONLY on its managed path (/etc/nixos), never on a
    # user-data upper. So the decoy's /etc/nixos/flake.nix reappears (nixos-rebuild
    # keeps working) while a user's deliberate `rm -rf ~/dir && mkdir ~/dir`
    # survives (the decoy data stays hidden).
    with subtest("phase 4: seed decoy data and activate /home + /etc overlays"):
        # The hidden volume was closed by phase 3's deactivation reboot.
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")

        # Decoy (lower) state, written while no overlay is mounted: a user data
        # directory and a lower /etc/nixos/flake.nix.
        machine.succeed(
            "su - testuser -c 'rm -rf ~/dir; mkdir -p ~/dir; printf %s decoy-a > ~/dir/a'"
        )
        machine.succeed("mkdir -p /etc/nixos")
        machine.succeed("echo '# decoy flake' > /etc/nixos/flake.nix")

        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

        # Both lower entries show through the fresh merged view.
        machine.succeed("su - testuser -c 'test -f ~/dir/a'")
        machine.succeed("test -f /etc/nixos/flake.nix")

    with subtest("phase 5: recreating dirs in the hidden session marks them opaque"):
        # The kernel sets trusted.overlay.opaque on each recreated upper dir, so
        # the lower contents vanish from the merged view for this session.
        machine.succeed("su - testuser -c 'rm -rf ~/dir && mkdir ~/dir'")
        machine.fail("su - testuser -c 'test -e ~/dir/a'")

        machine.succeed("rm -rf /etc/nixos && mkdir /etc/nixos")
        machine.fail("test -e /etc/nixos/flake.nix")

    with subtest("phase 6: re-activation strips only the managed opaque marker"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-opaque-scoping")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
        # With the overlays gone the decoy (lower) entries are back.
        machine.succeed("su - testuser -c 'test -f ~/dir/a'")
        machine.succeed("test -f /etc/nixos/flake.nix")

        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        assert_overlay_mounted("/home")
        assert_overlay_mounted("/etc")

        # The user-data upper kept its opaque marker: the decoy ~/dir/a must NOT
        # resurface, though the recreated (empty) ~/dir is still there.
        machine.fail("su - testuser -c 'test -e ~/dir/a'")
        machine.succeed("su - testuser -c 'test -d ~/dir'")

        # The managed /etc/nixos marker was cleared in the mount step, so the
        # lower flake.nix is visible again and nixos-rebuild would keep working.
        machine.succeed("test -f /etc/nixos/flake.nix")
        flake = machine.succeed("cat /etc/nixos/flake.nix").strip()
        assert flake == "# decoy flake", f"Expected the lower flake.nix to reappear, got: {flake!r}"

        canonical_deactivate(config_path, unit_name="nails-deactivate-opaque-scoping-final")
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
