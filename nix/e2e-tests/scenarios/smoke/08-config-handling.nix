# Scenario `config-handling` of the `smoke-verify-config` batch:
#   tests/smoke/02-smoke-verify-config.nix
# Formerly the stand-alone test
#   tests/smoke/08-config-handling.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged, except the two that need no VM.
#
# Test 08: Config Handling Edge Cases
# Tests the --config flag, defaults and unreadable configs on a real system.
# The missing-config and invalid-TOML checks need no VM; they run in
# nails-cli/tests/config_command.rs (`missing_explicit_config_prints_one_line_and_exits_3`,
# `invalid_type_fixture_exits_3_and_names_the_line`).

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
in
{
  name = "config-handling";
  tags = [ "smoke" ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
  ];

  script = ''
    def scenario_config_handling() -> None:
        machine.wait_for_unit("multi-user.target")

        print("\n=== Test 2: Valid config path ===")
        headless_config = "/tmp/nails-headless.toml"
        write_headless_config(headless_config)

        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(f"nails --config {headless_config} status")
        print("✓ nails --config /valid/path status works")

        print("\n=== Test 3: Default config (no --config) ===")
        status_output = machine.succeed("nails status")
        assert "Inactive" in status_output or "Active" in status_output or "INACTIVE" in status_output, \
            f"Expected status output with state info, got: {status_output}"
        print("✓ nails status (no --config) works with defaults")

        print("\n=== Test 5: Config with restrictive permissions ===")
        machine.succeed(f"chmod 0400 {headless_config}")
        machine.succeed(f"nails --config {headless_config} status")
        print("✓ Config with 0400 permissions loads fine as root")

        machine.succeed(f"chmod 0000 {headless_config}")
        machine.succeed(f"nails --config {headless_config} status")
        print("✓ Config with 0000 permissions loads fine as root")

        machine.succeed(f"chmod 0644 {headless_config}")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        print("\n=== All Config Handling Tests Passed ===")
  '';
}
