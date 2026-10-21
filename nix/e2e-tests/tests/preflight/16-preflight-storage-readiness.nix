# Test 16: Preflight Storage Readiness
#
# The storage-readiness check prepares the root overlay's directories on the
# hidden volume: with root/upper and root/work missing, activation creates them
# and enters the hidden session. A read-only work
# directory (a read-only submount) is refused by name before anything is
# prepared, and the machine stays on the plain decoy.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in
{
  name = "preflight-storage-readiness";
  meta.tags = [ "preflight" ];

  testScript = _: ''
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}

    from nails_e2e import session

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-storage-readiness.toml"
    write_headless_config(config_path)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("missing root overlay directories are created and activation succeeds"):
        machine.succeed("rm -rf /mnt/data/root")
        canonical_activate(config_path, "--overlay-only", "storage-activate")
        canonical_deactivate(config_path, "storage-deactivate")

    with subtest("a read-only work directory blocks activation"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        machine.succeed("mount -t tmpfs tmpfs /mnt/data/root/work")
        machine.succeed("mount -o remount,ro /mnt/data/root/work")
        result = run_command_capture(
            "preflight-storage-readonly-work",
            f"nails --config {config_path} activate --overlay-only -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["storage-readiness", "root work"], stream="stderr")
        session.assert_decoy_root(machine)
        assert read_status_json(config_path=config_path)["place"] == "decoy"
        machine.succeed("umount /mnt/data/root/work")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
