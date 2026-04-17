# Test 16: Preflight Storage Readiness

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
in {
  name = "preflight-storage-readiness";
  meta.tags = [ "preflight" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${preflightHelpers.writeTextFileFn}
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    def write_storage_config(path):
        write_text_file(path, """
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
    """.strip() + "\n")

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/preflight-storage-readiness.yaml"
    write_storage_config(config_path)
    machine.succeed("mkdir -p /srv")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("missing overlay directories are auto-created and activation succeeds"):
        machine.succeed("rm -rf /mnt/hidden-volume/srv /mnt/hidden-volume/.work/srv")
        machine.succeed(f"nails --config {config_path} activate --overlay-only --no-kill-session -y")
        machine.succeed("test -d /mnt/hidden-volume/srv")
        machine.succeed("test -d /mnt/hidden-volume/.work/srv")
        assert_overlay_mounted("/srv")
        canonical_deactivate(config_path, unit_name="nails-deactivate-preflight-storage-pass")
        assert_status_state("inactive")

    with subtest("read-only workdir submount blocks activation"):
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed("mount -t tmpfs tmpfs /mnt/hidden-volume/.work/home")
        machine.succeed("mount -o remount,ro /mnt/hidden-volume/.work/home")
        result = run_command_capture(
            "preflight-storage-readonly-work",
            f"nails --config {config_path} activate --overlay-only --no-kill-session -y",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["storage-readiness", ".work/home"], stream="stderr")
        machine.succeed("umount /mnt/hidden-volume/.work/home")
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
        assert_status_state("inactive")
        assert_no_overlays(["/home", "/srv"])
  '';
}
