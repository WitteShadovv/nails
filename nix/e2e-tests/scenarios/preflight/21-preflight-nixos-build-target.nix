# Scenario `preflight-nixos-build-target` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
# Formerly the stand-alone test
#   tests/preflight/21-preflight-nixos-build-target.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 21: Preflight NixOS Build Target Validation
# The nixos-build-target check refuses a relative flake reference and a local
# flake directory without a flake.nix before anything is prepared: no next
# root, no state file, the machine stays on the plain decoy.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-nixos-build-target";
  tags = [
    "preflight"
    "smoke"
  ];

  helpers = [
    testHelpers.readStatusJsonFn
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_nixos_build_target() -> None:
        from nails_e2e import session

        def write_build_target_config(path, flake):
            write_text_file(path, f"""
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 100
    nixos_flake = "{flake}"
    """.strip() + "\n")

        def assert_nothing_prepared(config_path):
            session.assert_decoy_root(machine)
            status = read_status_json(config_path=config_path)
            assert status["place"] == "decoy", status
            machine.fail("test -e /mnt/data/state.json")
            machine.fail("test -e /mnt/data/state")

        machine.wait_for_unit("multi-user.target")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        config_path = "/tmp/preflight-build-target.toml"

        with subtest("relative nixos flake references are rejected during preflight"):
            write_build_target_config(config_path, "relative/flake#test-host")
            result = run_command_capture(
                "preflight-nixos-build-target",
                f"nails --config {config_path} activate -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                ["nixos-build-target", "relative/flake", "absolute"],
                stream="stderr",
            )
            assert_nothing_prepared(config_path)

        with subtest("a local flake directory without a flake.nix is rejected"):
            machine.succeed("mkdir -p /tmp/flake-target")
            write_build_target_config(config_path, "/tmp/flake-target#test-host")
            result = run_command_capture(
                "preflight-build-target-missing-flake-nix",
                f"nails --config {config_path} activate -y",
            )
            assert_command_failed(result)
            assert_result_contains(
                result,
                ["nixos-build-target", "flake.nix not found in '/tmp/flake-target'"],
                stream="stderr",
            )
            assert_nothing_prepared(config_path)

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
