# Fault test: emergency with a corrupt state on a dead backend.
#
# The state file is corrupt, so emergency takes the untrusted path, and the
# backing device then dies, so every state write fails with EIO. The untrusted
# path used to abort on its first write (the Degraded baseline) and leave every
# overlay mounted. Every state write is best-effort now: the overlays must come
# down and the failed writes must be reported.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "faults-emergency-dead-backend-untrusted";
  meta.tags = [
    "faults"
    "security"
  ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    overlay_targets = ["/etc", "/home", "/root", "/srv", "/tmp", "/usr", "/bin", "/lib64"]

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/run/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("activate a hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        wait_for_status_state("Active", config_path=headless_config)
        assert_overlay_mounted("/home")

    with subtest("corrupt the state, then kill the backing device"):
        machine.succeed("printf 'not json' > /mnt/data/state.json && sync")
        machine.succeed("dmsetup wipe_table --force data")

    with subtest("emergency detaches every overlay and reports the lost writes"):
        rc, output = machine.execute(
            f"timeout 30 nails --config {headless_config} emergency --json", timeout=60
        )
        assert rc == 0, f"emergency must complete on a dead backend: rc={rc} {output!r}"
        assert "state_write_errors" in output, output
        assert '"state_write_errors":[]' not in output, output
        assert_no_overlays(overlay_targets)
  '';
}
