# Fault test (d): the backend closes after an emergency without a reboot.
#
# Emergency is a best-effort teardown that does not reboot, so the only thing
# standing between the operator and a safe shutdown is whether the hidden backend
# can actually be closed afterwards. If emergency only lazily detached an overlay,
# the hidden superblock stays referenced by a live process and the LUKS backend
# cannot be closed, so its master key stays in RAM. The strict close helper turns
# that leak into a hard failure that lists the holders instead of masking it.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "faults-emergency-strict-close";
  meta.tags = [
    "faults"
    "security"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.loginSessionSurvivalFns}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate a hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("emergency tears every overlay down without a reboot"):
        sessions_before_emergency = login_session_ids()
        machine.succeed(f"nails --config {headless_config} emergency")
        assert_no_overlays(overlay_targets)
        # Emergency detaches the overlays without logging the operator out.
        assert_login_sessions_survived(sessions_before_emergency)
        assert_status_state("inactive", config_path=headless_config)

    with subtest("the backend then closes cleanly with the strict helper"):
        # No reboot has happened. A clean teardown lets the backend close and the
        # master key leave RAM; a lazily detached overlay would keep the hidden
        # superblock busy and fail this strict close with the holders listed.
        machine.succeed("""${hiddenVolume.unmountHiddenVolumeStrict}""")
        machine.fail("test -e /dev/mapper/data")
  '';
}
