# Scenario `preflight-nixos-config` of the `preflight-checks` batch:
#   tests/preflight/19-preflight-checks.nix
# Formerly the stand-alone test
#   tests/preflight/19-preflight-nixos-config.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Test 19: Preflight NixOS Configuration Validation

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "preflight-nixos-config";
  tags = [ "preflight" ];

  helpers = [
    testHelpers.readStatusJsonFn
    assertions.assertStatusStateFn
    assertions.assertNoOverlaysFn
    preflightHelpers.writeTextFileFn
    preflightHelpers.runCommandCaptureFn
    preflightHelpers.commandAssertionsFn
  ];

  script = ''
    def scenario_preflight_nixos_config() -> None:
        def write_nixos_config(path):
            write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "skip"

    ${baseOs.toml}
    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"
    """.strip() + "\n")

        machine.wait_for_unit("multi-user.target")
        config_path = "/tmp/preflight-nixos-config.toml"
        write_nixos_config(config_path)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

        with subtest("broken hidden hardware configuration blocks activation"):
            # Activation stages the hidden layout before the read-only checks: the
            # hidden hardware-configuration.nix becomes a wrapper importing
            # ./nails/configuration.nix and the original is preserved verbatim as
            # hardware-configuration.base.nix (all on the hidden volume). A file that
            # merely lacks the import is therefore valid; a genuinely broken one (a
            # syntax error) must make the nixos-config parse gate refuse before any
            # overlay is mounted.
            write_text_file(
                "/mnt/data/etc/nixos/hardware-configuration.nix",
                "{ config, pkgs, ... }: { boot.loader.grub.enable = false;\n",
            )
            result = run_command_capture(
                "preflight-nixos-config-fail",
                f"nails --config {config_path} activate --session keep -y",
            )
            assert_command_failed(result)
            assert "failed to parse" in result["stdout"] + result["stderr"], (
                f"Expected the nixos-config parse gate to refuse, got: {result}"
            )
            assert_status_state("inactive", config_path=config_path)
            assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
            machine.succeed("test -e /mnt/data/config/nixos/configuration.nix")
            # The wrapper design: the hidden file imports the NAILS module and the
            # broken original was preserved verbatim, not patched in place.
            machine.succeed("grep -F './nails/configuration.nix' /mnt/data/etc/nixos/hardware-configuration.nix")
            machine.succeed("grep -F 'boot.loader.grub.enable' /mnt/data/etc/nixos/hardware-configuration.base.nix")

        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
