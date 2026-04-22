# Test 14: Preflight Space Checks

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-space";
  meta.tags = [ "preflight" ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    def write_space_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    minimum_space_mb: 500
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

    config_path = "/tmp/preflight-space.yaml"
    write_space_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation is refused when free space drops below threshold"):
        machine.succeed(
                "python3 - <<'PY'\n"
                "import subprocess\n"
                "avail = int(\"\".join(ch for ch in subprocess.check_output(['df', '--output=avail', '-BM', '/mnt/hidden-volume'], text=True).splitlines()[-1] if ch.isdigit()))\n"
                "fill = avail - 150\n"
                "assert fill > 0, fill\n"
                "subprocess.check_call(['fallocate', '-l', str(fill) + 'M', '/mnt/hidden-volume/filler.bin'])\n"
                "subprocess.check_call(['sync'])\n"
                "PY"
            )
        result = run_command_capture(
            "preflight-space-fail",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["space", "Only", "Free up at least"], stream="stderr")
        assert_status_state("inactive")

    with subtest("freeing space restores a clean activation path"):
        machine.succeed("rm -f /mnt/hidden-volume/filler.bin")
        machine.succeed("sync")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --no-kill-session -y")
        assert_status_state("active")
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-space")
        assert_status_state("inactive")
        assert_no_overlays(["/home"])
  '';
}
