# Test 21: Preflight NixOS Build Target Validation

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-nixos-build-target";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    def write_build_target_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    nixos_flake: relative/flake#test-host
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
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    write_build_target_config("/tmp/preflight-build-target.yaml")

    with subtest("relative nixos flake references are rejected during preflight"):
        result = run_command_capture(
            "preflight-nixos-build-target",
            "nails --config /tmp/preflight-build-target.yaml activate --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_result_contains(
            result,
            ["nixos-build-target", "relative", "absolute path"],
            stream="stderr",
        )

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
