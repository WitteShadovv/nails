# Scenario `config-unknown-key` of the `init-config` batch:
#   tests/init/45-init-config.nix
# Formerly the stand-alone test
#   tests/config/23-config-unknown-key.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged, except the two that need no VM.
#
# Test 23: Config Unknown Key
# A misspelt key must fail loudly instead of silently falling back to a
# default: activate exits 3 with a did-you-mean hint and mounts nothing, while
# emergency still proceeds. The nested-key dry run and `config validate` on the
# same fixtures need no VM; they run in nails-cli/tests/config_command.rs
# (`unknown_nested_key_fixture_is_refused_by_a_dry_run_with_a_hint`,
# `unknown_key_fixture_fails_config_validate_with_the_hint`).

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  unknownKeyFixture = ./../../fixtures/configs/unknown-key.toml;
in
{
  name = "config-unknown-key";
  tags = [
    "config"
    "smoke"
  ];

  helpers = [
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
    testHelpers.readStatusJsonFn
    assertions.assertNoOverlaysFn
    securityHelpers.capturedCommandFns
  ];

  script = ''
    def scenario_config_unknown_key() -> None:
        machine.wait_for_unit("multi-user.target")
        machine.succeed("cp ${unknownKeyFixture} /tmp/unknown-key.toml")

        with subtest("activate refuses an unknown top-level key with a hint"):
            result = run_command_capture(
                "config-unknown-key-activate",
                "nails --config /tmp/unknown-key.toml activate --overlay-only --session keep -y",
            )
            assert_exit_code(result, 3)
            assert_result_contains(
                result,
                ["invalid config /tmp/unknown-key.toml: line 4", "unknown key `nixos_flak` (did you mean `nixos_flake`?)"],
                stream="stderr",
            )
            assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

        with subtest("emergency warns once and proceeds with defaults"):
            # No hidden volume is set up, so the binary-derived defaults find no
            # active state and nothing mounted. Emergency is a best-effort
            # teardown, so it still completes: reaching its success report proves
            # the config error did not stop the teardown path.
            prefix = "/run/nails-tests/config-unknown-key-emergency"
            capture = run_captured_command(
                prefix,
                "nails --config /tmp/unknown-key.toml emergency",
                unit_name="nails-config-unknown-key-emergency",
            )
            result = read_command_result(prefix, unit_name=capture["unit_name"], timeout=30)
            assert_exit_code(result, 0)
            assert_result_contains(
                result,
                ["did you mean `nixos_flake`?", "continuing with defaults"],
                stream="stderr",
            )
            assert_result_contains(
                result,
                ["Emergency teardown complete", "No NAILS overlays were mounted"],
                stream="stdout",
            )
            assert result["stderr"].count("continuing with defaults") == 1, result
  '';
}
