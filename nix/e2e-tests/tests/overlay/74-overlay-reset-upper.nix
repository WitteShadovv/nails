# Test 74: reset-upper clears a target's persistent overlay upper
# Activates /home, writes into the hidden upper, deactivates, resets the /home
# upper, and asserts the decoy home shows through on the next activation.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "overlay-reset-upper";
  meta.tags = [ "overlay" ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/var/lib/nails-tests/nails-headless.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("phase 1: decoy file, activate, and copy up hidden changes"):
        machine.succeed(
            "su - testuser -c 'printf %s decoy-data > ~/reset-target.txt'"
        )
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=config_path)
        assert_overlay_mounted("/home")

        # reset-upper must refuse while the system is Active and /home is mounted.
        machine.fail(f"nails --config {config_path} reset-upper /home -y")

        # Overwrite the decoy file (full copy-up) and create a hidden-only file.
        machine.succeed(
            "su - testuser -c 'printf %s hidden-data > ~/reset-target.txt'"
        )
        machine.succeed("su - testuser -c 'printf %s secret > ~/hidden-only.txt'")
        machine.succeed("test -f /mnt/data/home/testuser/hidden-only.txt")

    with subtest("phase 2: deactivate, reopen the volume, and reset the /home upper"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-reset-upper")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        assert_status_state("Inactive", config_path=config_path)

        # The upper carries the hidden changes until reset.
        machine.succeed("test -f /mnt/data/home/testuser/hidden-only.txt")

        machine.succeed(f"nails --config {config_path} reset-upper /home -y")

        # The upper and its work directory are gone after the reset.
        machine.fail("test -e /mnt/data/home")
        machine.fail("test -e /mnt/data/.work/home")

    with subtest("phase 3: the decoy home shows through on the next activation"):
        machine.succeed(
            f"nails --config {config_path} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=config_path)
        assert_overlay_mounted("/home")

        content = machine.succeed("su - testuser -c 'cat ~/reset-target.txt'").strip()
        assert content == "decoy-data", f"Expected decoy file to show through, got: {content!r}"
        machine.fail("su - testuser -c 'test -e ~/hidden-only.txt'")

        canonical_deactivate(
            config_path, unit_name="nails-deactivate-reset-upper-final"
        )
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
  '';
}
