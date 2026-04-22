# Test 34: Session Kill Headless
# Self-check: subtests used, no sleep sync, hard assertions, session tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
in
{
  name = "session-kill-headless";
  meta.tags = [ "session" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)

    with subtest("prepare headless machine"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

    with subtest("kill-session on tty is a successful no-op"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --kill-session -y")
        assert_overlay_mounted("/home")
        assert_status_state("active", config_path=headless_config)
        transient_units = machine.succeed(
            "systemctl list-units --all --plain --no-legend 'nails-activate-*' || true"
        )
        assert "nails-activate-" not in transient_units, transient_units

    with subtest("deactivate returns machine to decoy state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-session-kill-headless")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=headless_config)
  '';
}
