# Fault test: emergency with a corrupt state and a config on a dead backend.
#
# The operator runs the ordinary `nails --config <hidden config> emergency`,
# not the RAM copy, after the state file was corrupted and the backing device
# then died: the config and the state on the hidden volume are both
# unreadable. The emergency's hot path works from the plan in /run before any
# config or state is read, so neither may stop it: the machine must power off
# for real within a bound, and the next cold boot is the plain decoy with the
# hidden mapping closed.

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

    with subtest("corrupt the state, then kill the backing device"):
        machine.succeed("printf 'not json' > /mnt/data/state.json && sync")
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("emergency powers off within the bound"):
        outcome = emergency_outcome(f"nails --config {CONFIG} emergency --json", "emergency")
        assert_fault_exit(outcome)
  '';
}
