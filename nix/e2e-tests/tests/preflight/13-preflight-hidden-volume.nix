# Test 13: Preflight Hidden Volume Failure Modes

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-hidden-volume";
  meta.tags = [
    "preflight"
    "smoke"
  ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.e2fsprogs
      ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}

    def write_hidden_volume_config(path, hidden_root):
        write_text_file(path, f"""
    hidden_volume_root: {hidden_root}
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: {hidden_root}/home
        work: {hidden_root}/.work/home
        target: /home
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("unmounted hidden volume is rejected"):
        machine.succeed("mkdir -p /mnt/preflight-unmounted")
        write_hidden_volume_config("/tmp/preflight-unmounted.yaml", "/mnt/preflight-unmounted")
        result = run_command_capture(
            "preflight-hidden-unmounted",
            "nails --config /tmp/preflight-unmounted.yaml activate --dry-run --overlay-only --no-kill-session --plain",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "is not mounted"], stream="stdout")

    with subtest("nix store hidden volume is rejected as non-writable"):
        write_hidden_volume_config("/tmp/preflight-store.yaml", "${builtins.storeDir}")
        result = run_command_capture(
            "preflight-hidden-store",
            "nails --config /tmp/preflight-store.yaml activate --dry-run --overlay-only --no-kill-session --plain",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "${builtins.storeDir}", "not writable"], stream="stdout")

    with subtest("read-only hidden volume is rejected"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mount -o remount,ro /mnt/hidden-volume")
        write_hidden_volume_config("/tmp/preflight-readonly.yaml", "/mnt/hidden-volume")
        result = run_command_capture(
            "preflight-hidden-readonly",
            "nails --config /tmp/preflight-readonly.yaml activate --dry-run --overlay-only --no-kill-session --plain",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "/mnt/hidden-volume", "not writable"], stream="stdout")
        machine.succeed("mount -o remount,rw /mnt/hidden-volume")

    with subtest("immutable hidden volume root is treated as non-writable"):
        machine.succeed("command -v chattr >/dev/null")
        machine.succeed("chattr +i /mnt/hidden-volume")
        result = run_command_capture(
            "preflight-hidden-immutable",
            "nails --config /tmp/preflight-readonly.yaml activate --dry-run --overlay-only --no-kill-session --plain",
        )
        assert_command_succeeded(result)
        assert_result_contains(result, ["hidden-volume", "/mnt/hidden-volume", "not writable"], stream="stdout")
        machine.succeed("chattr -i /mnt/hidden-volume")

    with subtest("status remains inactive after all hidden volume failures"):
        assert_status_state("inactive")

    machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
