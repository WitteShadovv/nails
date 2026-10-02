# Test 34: Session Kill Headless

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

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)

    with subtest("prepare headless machine"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])

    with subtest("kill-session on tty is a successful no-op"):
        import shlex

        machine.succeed(f"nails --config {headless_config} activate --overlay-only --session kill -y")
        assert_overlay_mounted("/home")
        assert_status_state("active", config_path=headless_config)
        # T-066: the detached worker no longer names its transient unit after the
        # product; systemd auto-names it `run-<id>.service` with a fixed neutral
        # description. On a tty the session kill is a no-op, so no maintenance
        # unit is spawned at all: discover by that neutral description (not a
        # product unit name) and assert none leaked, plus that the obsolete
        # product-named unit never appears.
        description = "System maintenance task"
        finder = (
            "systemctl list-units --all --plain --no-legend 'run-*.service' "
            + "| while read -r unit _; do "
            + "if [ \"$(systemctl show \"$unit\" -p Description --value)\" = "
            + shlex.quote(description)
            + " ]; then printf '%s\\n' \"$unit\"; fi; "
            + "done"
        )
        maintenance_units = machine.succeed("bash -lc " + shlex.quote(finder)).strip()
        assert not maintenance_units, (
            f"kill-session on a tty must not detach a maintenance unit: {maintenance_units!r}"
        )
        legacy_units = machine.succeed(
            "systemctl list-units --all --plain --no-legend 'nails-activate-*' || true"
        )
        assert "nails-activate-" not in legacy_units, legacy_units

    with subtest("deactivate returns machine to decoy state"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-session-kill-headless")
        assert_no_overlays(["/home", "/etc", "/root", "/srv", "/tmp"])
        assert_status_state("inactive", config_path=headless_config)
  '';
}
