# Test 35: Session Detection
# Self-check: subtests used, no sleep sync, hard assertions, session tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "session-detection";
  meta.tags = [ "session" ];

  nodes = {
    tty =
      { ... }:
      {
        imports = [ ./../../lib/vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };

    graphical =
      { ... }:
      {
        imports = [ ./../../lib/graphical-vm-config.nix ];
        environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      };
  };

  testScript = _: ''
    # Shared helper snippets are written for single-node tests and reference a
    # global `machine`; bind it to one node so static lint/eval succeeds, then
    # rebind helper globals per-node below when calling them.
    machine = tty

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    start_all()
    tty.wait_for_unit("multi-user.target")
    graphical.wait_for_unit("display-manager.service")
    graphical.wait_until_succeeds("systemctl is-active user@1000.service")

    tty_config = "/var/lib/nails-tests/tty-headless.yaml"
    graphical_config = "/var/lib/nails-tests/graphical-headless.yaml"

    def bind_node(node):
        for helper in [
            write_headless_config,
            read_status_json,
            wait_for_status_state,
            assert_status_state,
            assert_overlay_mounted,
            canonical_deactivate,
            wait_for_activation_transient_unit,
            assert_unit_in_system_slice,
        ]:
            helper.__globals__["machine"] = node

    def write_headless_config_for(node, path):
        bind_node(node)
        write_headless_config(path)

    def wait_for_status_state_for(node, expected, config_path):
        bind_node(node)
        return wait_for_status_state(expected, config_path=config_path)

    write_headless_config_for(tty, tty_config)
    write_headless_config_for(graphical, graphical_config)

    def assert_status_state_for(node, expected, config_path):
        bind_node(node)
        return assert_status_state(expected, config_path=config_path)

    def assert_overlay_mounted_for(node, path):
        bind_node(node)
        return assert_overlay_mounted(path)

    def canonical_deactivate_for(node, config_path, unit_name):
        bind_node(node)
        canonical_deactivate(config_path, unit_name=unit_name)

    with subtest("tty session path skips graphical detach"):
        tty.succeed("""${hiddenVolume.setupHiddenVolume}""")
        tty.succeed(f"nails --config {tty_config} activate --overlay-only --kill-session -y")
        wait_for_status_state_for(tty, "active", tty_config)
        assert_overlay_mounted_for(tty, "/home")
        assert_status_state_for(tty, "active", tty_config)
        tty_units = tty.succeed("systemctl list-units --all --plain --no-legend 'nails-activate-*' || true")
        assert "nails-activate-" not in tty_units, tty_units
        canonical_deactivate_for(tty, tty_config, "nails-deactivate-session-detection-tty")

    with subtest("graphical x11 path detaches into transient systemd service"):
        bind_node(graphical)

        graphical.succeed("""${hiddenVolume.setupHiddenVolume}""")
        graphical.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {graphical_config} activate --overlay-only -y"
        )
        activation_unit = wait_for_activation_transient_unit()
        assert_unit_in_system_slice(activation_unit)
        graphical.wait_until_succeeds(
            "/bin/sh -lc 'mountpoint -q /home && [ \"$(findmnt -n -o FSTYPE /home)\" = overlay ]'"
        )
        wait_for_status_state_for(graphical, "active", graphical_config)
        assert_overlay_mounted_for(graphical, "/home")
        assert_status_state_for(graphical, "active", graphical_config)
        canonical_deactivate_for(graphical, graphical_config, "nails-deactivate-session-detection-graphical")
  '';
}
