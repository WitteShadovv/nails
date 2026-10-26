# Scenario `preflight-nixos-config` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
# Formerly the stand-alone test
#   tests/preflight/19-preflight-nixos-config.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Test 19: Preflight NixOS Configuration Validation
# A hidden hardware configuration (in the hidden root's upper,
# root/upper/etc/nixos) with a syntax error makes the nixos-config parse gate
# refuse activation before any next root is prepared: the machine stays on the
# plain decoy, and the staging kept the broken original verbatim as the base
# behind the fixed wrapper instead of patching it.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-nixos-config";
  tags = [ "preflight" ];

  helpers = [
    testHelpers.readStatusJsonFn
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_nixos_config() -> None:
        from nails_e2e import session

        def write_nixos_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 100
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")
        config_path = "/tmp/preflight-nixos-config.toml"
        write_nixos_config(config_path)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

        with subtest("broken hidden hardware configuration blocks activation"):
            # Activation stages the hidden layout before the checks, which never
            # stage it themselves: the hidden hardware-configuration.nix becomes a
            # wrapper importing ./nails/configuration.nix and the original is
            # preserved verbatim as hardware-configuration.base.nix (all on the
            # hidden volume). A file that merely lacks the import is therefore
            # valid; a genuinely broken one (a syntax error) must make the
            # nixos-config parse gate refuse before any next root is prepared.
            write_text_file(
                "/mnt/data/root/upper/etc/nixos/hardware-configuration.nix",
                "{ config, pkgs, ... }: { boot.loader.grub.enable = false;\n",
            )
            result = run_command_capture(
                "preflight-nixos-config-fail",
                f"nails --config {config_path} activate -y",
            )
            assert_command_failed(result)
            assert "failed to parse" in result["stdout"] + result["stderr"], (
                f"Expected the nixos-config parse gate to refuse, got: {result}"
            )
            session.assert_decoy_root(machine)
            machine.succeed("test -z \"$(ls -A /run/nextroot 2>/dev/null)\"")
            status = read_status_json(config_path=config_path)
            assert status["place"] == "decoy", status
            machine.succeed("test -e /mnt/data/config/nixos/configuration.nix")
            # The wrapper design: the hidden file imports the NAILS module and the
            # broken original was preserved verbatim, not patched in place.
            machine.succeed("grep -F './nails/configuration.nix' /mnt/data/root/upper/etc/nixos/hardware-configuration.nix")
            machine.succeed("grep -F 'boot.loader.grub.enable' /mnt/data/root/upper/etc/nixos/hardware-configuration.base.nix")

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
