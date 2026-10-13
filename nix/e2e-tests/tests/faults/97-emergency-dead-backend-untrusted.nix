# Fault test: emergency with a corrupt state and a config on a dead backend.
#
# The operator runs the ordinary `nails --config <hidden config> emergency`,
# not the RAM copy, after the state file was corrupted and the backing device
# then died: the config and the state on the hidden volume are both
# unreadable. The emergency's hot path works from the plan in /run before any
# config or state is read, so neither may stop it: the machine must leave the
# hidden session within a bound, back on the plain decoy (hidden mapping
# released, no hidden /run residue) or powered off.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  backendFault = import ./../../lib/backend-fault.nix;
in
{
  name = "faults-emergency-dead-backend-untrusted";
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

    with subtest("corrupt the state, then kill the backing device"):
        machine.succeed("printf 'not json' > /mnt/data/state.json && sync")
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("emergency leaves the hidden session within the bound"):
        wall = session.wall_clock(machine)
        outcome = emergency_outcome(f"nails --config {CONFIG} emergency --json", "emergency")
        machine.log(f"emergency with a dead config and state ended: {outcome}")
        assert_fault_exit(outcome, run_before, wall)
  '';
}
