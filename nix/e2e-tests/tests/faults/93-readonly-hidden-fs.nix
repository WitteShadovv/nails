# Fault test (g): the hidden filesystem goes read-only while the hidden session
# runs.
#
# An ext4 error, or a backing device flipped read-only, leaves the hidden
# filesystem (the root overlay's upper) unwritable while the overlay is still
# `/`. The way out must not depend on writing to it: `emergency`, run from the
# RAM copy at /run/overlay-runtime/control, must power the machine off for
# real within a bound, and the next cold boot is the plain decoy with the
# hidden mapping closed.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-readonly-hidden-fs";
  meta.tags = [
    "faults"
    "security"
  ];
  globalTimeout = 1200;

  testScript = _: ''
    ${testHelpers.canonicalActivateFn}
    ${backendFault.emergencyOutcomeFn}
    ${backendFault.assertFaultExitFn}

    CONFIG = "/mnt/data/config/nails.toml"

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("activate a hidden session"):
        canonical_activate(CONFIG, "--overlay-only", "activate")

    with subtest("the backing device is forced read-only"):
        # Flipping the device read-only at the block layer makes every write to
        # the hidden filesystem fail, whatever the overlay holds open.
        machine.succeed("blockdev --setro /dev/mapper/data")

    with subtest("emergency from the RAM copy powers off within the bound"):
        outcome = emergency_outcome("/run/overlay-runtime/control emergency", "emergency")
        assert_fault_exit(outcome)
  '';
}
