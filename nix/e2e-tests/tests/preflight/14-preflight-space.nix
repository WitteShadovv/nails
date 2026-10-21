# Test 14: Preflight Space Checks
#
# The space check is one hard floor on the hidden volume (no warn band): with
# less free space than `minimum_space_mb`, activation refuses with the
# remediation and the machine stays on the plain decoy. Freeing the space lets
# the same configuration enter the hidden session (a soft-reboot into the root
# overlay) and leave it again.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
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
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    from nails_e2e import session

    def write_space_config(path):
        write_text_file(path, """
    hidden_volume_root = "/mnt/data"
    minimum_space_mb = 500
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
            f"nails --config {config_path} activate --overlay-only -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["space", "Only", "Free up at least"], stream="stderr")
        session.assert_decoy_root(machine)
        assert read_status_json(config_path=config_path)["place"] == "decoy"

    with subtest("freeing space restores a clean activation path"):
        machine.succeed("rm -f /mnt/data/filler.bin")
        machine.succeed("sync")
        canonical_activate(config_path, "--overlay-only", "preflight-space-activate")
        assert read_status_json(config_path=config_path)["place"] == "hidden"
        canonical_deactivate(config_path, "preflight-space-deactivate")
        assert read_status_json(config_path=config_path)["place"] == "decoy"
  '';
}
