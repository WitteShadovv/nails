# Test 14: Preflight Space Checks

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  baseOs = import ./../../lib/base-os-overlays.nix;
in
{
  name = "preflight-space";
  meta.tags = [ "preflight" ];

  baseNode = {
    python3 = true;
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
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 500
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

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-space.toml"
    write_space_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activation is a hard failure below the floor (no warn band)"):
        # Leave ~400 MB free: below the 500 MB floor but above the old 50%
        # half-threshold. The removed warn band would have let this proceed;
        # the single hard floor must now refuse it outright.
        machine.succeed(
                "python3 - <<'PY'\n"
                "import subprocess\n"
                "avail = int(\"\".join(ch for ch in subprocess.check_output(['df', '--output=avail', '-BM', '/mnt/data'], text=True).splitlines()[-1] if ch.isdigit()))\n"
                "fill = avail - 400\n"
                "assert fill > 0, fill\n"
                "subprocess.check_call(['fallocate', '-l', str(fill) + 'M', '/mnt/data/filler.bin'])\n"
                "subprocess.check_call(['sync'])\n"
                "PY"
            )
        result = run_command_capture(
            "preflight-space-fail",
            f"nails --config {config_path} activate --overlay-only --session keep -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["space", "Only", "Free up at least"], stream="stderr")
        assert_status_state("inactive", config_path=config_path)

    with subtest("freeing space restores a clean activation path"):
        machine.succeed("rm -f /mnt/data/filler.bin")
        machine.succeed("sync")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --session keep -y")
        assert_status_state("active", config_path=config_path)
        assert_overlay_mounted("/home")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-space")
        assert_status_state("inactive", config_path=config_path)
        assert_no_overlays(["/home"])
  '';
}
