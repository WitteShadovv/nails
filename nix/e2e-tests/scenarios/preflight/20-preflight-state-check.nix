# Scenario `preflight-state-check` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
# Formerly the stand-alone test
#   tests/preflight/20-preflight-state-check.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 20: Preflight State Check Integrity
#
# A completed session (activate: a soft-reboot into the hidden root;
# deactivate: a soft-reboot back) must leave a signed state file behind on the
# hidden volume, and status must read it as the plain decoy. Refusing a
# tampered state file is covered once, in state/52-state-corruption.nix.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "preflight-state-check";
  tags = [ "preflight" ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
    testHelpers.canonicalActivateFn
    testHelpers.canonicalDeactivateFn
    testHelpers.readStatusJsonFn
  ];

  script = ''
    def scenario_preflight_state_check() -> None:
        import json

        machine.wait_for_unit("multi-user.target")

        # On the hidden volume: a config on the decoy /tmp would be visible in
        # the hidden root too, but this keeps the session's files together.
        config_path = "/mnt/data/config/preflight-state-check.toml"
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        write_headless_config(config_path)

        with subtest("a full session leaves a signed state file behind"):
            canonical_activate(config_path, "--overlay-only", "preflight-state-activate")
            status = read_status_json(config_path=config_path)
            assert status["posture"] == "active", status
            canonical_deactivate(config_path, "preflight-state-deactivate")
            # The way back closed the hidden volume; reopen it to read the state
            # file the session left behind.
            machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
            persisted = json.loads(machine.succeed("cat /mnt/data/state.json"))
            assert persisted.get("integrity_sha256"), (
                f"Expected an integrity digest in the persisted state: {persisted}"
            )
            assert persisted.get("state") == "Inactive", persisted
            status = read_status_json(config_path=config_path)
            assert status["posture"] == "decoy", status
            machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
