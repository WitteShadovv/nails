# Test 19: Preflight NixOS Configuration Validation

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-nixos-config";
  meta.tags = [ "preflight" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    def write_nixos_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    config_path = "/tmp/preflight-nixos-config.yaml"
    write_nixos_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("broken hidden hardware configuration import blocks activation"):
        write_text_file(
            "/mnt/hidden-volume/etc/nixos/hardware-configuration.nix",
            "{ config, pkgs, ... }: { boot.loader.grub.enable = false; }\n",
        )
        result = run_command_capture(
            "preflight-nixos-config-fail",
            f"nails --config {config_path} activate --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
        machine.succeed("test -e /mnt/hidden-volume/config/nixos/configuration.nix")
        machine.fail("grep -F './nails/configuration.nix' /mnt/hidden-volume/etc/nixos/hardware-configuration.nix")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
