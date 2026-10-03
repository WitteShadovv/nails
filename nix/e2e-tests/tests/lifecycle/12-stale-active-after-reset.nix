# Test 12: Stale Active After Hard Reset
#
# A hard reset during an active session leaves state.json claiming Active while
# nothing is mounted. The next activation must reconcile that stale state (the
# boot id differs), reset it to Inactive, and really mount the overlays rather
# than refuse or silently no-op. It must also never write the shell rc block or
# an autostart entry onto the bare decoy home: those belong only in the hidden
# upper layer.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "stale-active-after-reset";
  meta.tags = [ "lifecycle" ];

  nodes = {
    machine =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/var/lib/nails-tests/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    print("\n=== Phase 1: Activate and create hidden data ===")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
    wait_for_status_state("Active", config_path=headless_config)
    assert_overlay_mounted("/home")
    machine.succeed("su - testuser -c 'echo STALE_RESET_DATA > ~/stale-reset.txt'")
    machine.succeed("test -f /mnt/data/home/testuser/stale-reset.txt")

    print("\n=== Phase 2: Hard reset mid-session ===")
    # state.json lives on the hidden root and survives the crash, so after the
    # reboot it still records Active even though nothing is mounted.
    machine.crash()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    write_headless_config(headless_config)
    assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

    print("\n=== Phase 3: Re-activation reconciles the stale Active ===")
    machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
    machine.succeed(f"nails --config {headless_config} activate --overlay-only --session keep -y")
    wait_for_status_state("Active", config_path=headless_config)
    assert_overlay_mounted("/home")
    assert_status_state("Active", config_path=headless_config)

    # The previously stored hidden data is visible again through the fresh overlay,
    # proving the overlays were actually mounted (not a silent no-op).
    content = machine.succeed("su - testuser -c 'cat ~/stale-reset.txt'").strip()
    assert "STALE_RESET_DATA" in content, f"Expected hidden data after reset, got: {content}"

    print("\n=== Phase 4: No shell integration leaked onto the decoy lower ===")
    canonical_deactivate(headless_config, unit_name="nails-deactivate-stale-active-after-reset")
    assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
    assert_status_state("Inactive", config_path=headless_config)

    # With the overlays gone the decoy lower is exposed again: it must carry no
    # managed shell integration block and no NAILS autostart entry.
    machine.fail("grep -rqF '# >>> managed shell integration' /home /root")
    machine.fail("find /home /root -name nails-notify.desktop -print -quit | grep -q .")
  '';
}
