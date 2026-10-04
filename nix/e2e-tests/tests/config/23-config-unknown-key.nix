# Test 23: Config Unknown Key
# A misspelt key must fail loudly instead of silently falling back to a
# default: activate and `config validate` exit 3 with a did-you-mean hint,
# while emergency still proceeds.

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  unknownKeyFixture = ./../../fixtures/configs/unknown-key.toml;
  unknownNestedKeyFixture = ./../../fixtures/configs/unknown-nested-key.toml;
in
{
  name = "config-unknown-key";
  meta.tags = [
    "config"
    "smoke"
  ];

  testScript = _: ''
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("cp ${unknownKeyFixture} /tmp/unknown-key.toml")
    machine.succeed("cp ${unknownNestedKeyFixture} /tmp/unknown-nested-key.toml")

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

    with subtest("activate refuses an unknown nested key with a hint"):
        result = run_command_capture(
            "config-unknown-nested-key-activate",
            "nails --config /tmp/unknown-nested-key.toml activate --dry-run --overlay-only --session keep",
        )
        assert_exit_code(result, 3)
        assert_result_contains(result, ["did you mean `enabled`?"], stream="stderr")

    with subtest("config validate exits 3 with the same hint"):
        result = run_command_capture(
            "config-unknown-key-validate",
            "nails config validate /tmp/unknown-key.toml",
        )
        assert_exit_code(result, 3)
        assert_result_contains(result, ["did you mean `nixos_flake`?"], stream="stderr")

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
