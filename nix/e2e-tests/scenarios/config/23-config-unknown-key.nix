# Scenario `config-unknown-key` of the `init-config` batch:
#   tests/init/45-init-config.nix
# Formerly the stand-alone test
#   tests/config/23-config-unknown-key.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 23: Config Unknown Key
# A misspelt key must fail loudly instead of silently falling back to a
# default: activate exits 3 with a did-you-mean hint, prepares no next root
# and never soft-reboots (the machine stays on the plain decoy), while
# emergency still runs: with no hidden session it reports nothing to tear
# down and exits 0. The nested-key dry run and `config validate` on the same
# fixtures need no VM; they run in nails-cli/tests/config_command.rs
# (`unknown_nested_key_fixture_is_refused_by_a_dry_run_with_a_hint`,
# `unknown_key_fixture_fails_config_validate_with_the_hint`).

_:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
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
  ];

  script = ''
    def scenario_config_unknown_key() -> None:
        from nails_e2e import session

        machine.wait_for_unit("multi-user.target")
        machine.succeed("cp ${unknownKeyFixture} /tmp/unknown-key.toml")
        boot_id = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()

        with subtest("activate refuses an unknown top-level key with a hint"):
            result = run_command_capture(
                "config-unknown-key-activate",
                "nails --config /tmp/unknown-key.toml activate --overlay-only -y",
            )
            assert_exit_code(result, 3)
            assert_result_contains(
                result,
                ["invalid config /tmp/unknown-key.toml: line 4", "unknown key `nixos_flak` (did you mean `nixos_flake`?)"],
                stream="stderr",
            )
            # Still the same userspace on the plain decoy: no next root was
            # prepared and no soft-reboot was enqueued.
            session.assert_decoy_root(machine)
            count = machine.succeed("systemctl show -p SoftRebootsCount --value").strip()
            assert count == "0", f"SoftRebootsCount={count}"
            assert machine.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_id

        with subtest("emergency still runs with the broken config"):
            # No hidden session: the emergency has nothing to tear down and
            # exits 0, so a config error never blocks the panic button.
            result = run_command_capture(
                "config-unknown-key-emergency",
                "nails --config /tmp/unknown-key.toml emergency",
            )
            assert_exit_code(result, 0)
            assert_result_contains(result, ["nothing to tear down"], stream="stdout")
            assert result["stderr"].count("continuing with defaults") <= 1, result
            session.assert_decoy_root(machine)
  '';
}
