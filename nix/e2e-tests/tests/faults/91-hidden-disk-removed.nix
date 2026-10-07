# Fault test (b): the hidden backing device vanishes while the hidden session
# runs.
#
# A pulled USB key, a failed disk, or a yanked device-mapper node makes every
# read and write to the hidden filesystem fail while the root overlay above it
# is still `/`. The binary on the hidden volume may be unreadable then, so the
# RAM copy at /run/overlay-runtime/control is what still runs `emergency`: it
# must get the machine out of the hidden session within a bound, back on the
# plain decoy (with the hidden mapping released and no hidden /run residue) or,
# as the documented fallback, powered off.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-hidden-disk-removed";
  meta.tags = [
    "faults"
    "security"
  ];
  globalTimeout = 1200;

  testScript = _: ''
    from nails_e2e import session

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
    run_before = session.run_entries(machine)

    with subtest("activate a hidden session"):
        canonical_activate(CONFIG, "--overlay-only", "activate")
        machine.succeed("test -x /run/overlay-runtime/control")

    with subtest("the backing device is yanked out from under the hidden root"):
        # Replacing the dm table with an error target makes the hidden
        # filesystem return EIO for every access, simulating a removed backing
        # disk while the overlay above it stays mounted. `dmsetup remove`
        # cannot be used: the node is held open by the hidden mounts.
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("emergency from the RAM copy leaves the hidden session within the bound"):
        wall = session.wall_clock(machine)
        outcome = emergency_outcome("/run/overlay-runtime/control emergency", "emergency")
        machine.log(f"emergency on a removed backend ended: {outcome}")
        assert_fault_exit(outcome, run_before, wall)
  '';
}
