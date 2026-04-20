# Test 35: Session Detection
# Self-check: subtests used, no sleep sync, hard assertions, session tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in {
  name = "session-detection";
  meta.tags = [ "session" ];

  nodes = {
    tty = { ... }: {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

    graphical = { ... }: {
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
    ${sessionHelpers.waitForActivationTransientUnitFn}
    ${sessionHelpers.assertUnitInSystemSliceFn}

    start_all()
    tty.wait_for_unit("multi-user.target")
    graphical.wait_for_unit("display-manager.service")
    graphical.wait_until_succeeds("systemctl is-active user@1000.service")

    tty_config = "/tmp/nails-headless.yaml"
    graphical_config = "/tmp/nails-headless.yaml"

    def write_headless_config_for(node, path):
        node.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root: /mnt/hidden-volume
    overlay_mode: explicit
    overlays:
      - name: etc
        lower: /etc
        upper: /mnt/hidden-volume/etc
        work: /mnt/hidden-volume/.work/etc
        target: /etc
      - name: home
        lower: /home
        upper: /mnt/hidden-volume/home
        work: /mnt/hidden-volume/.work/home
        target: /home
      - name: root
        lower: /root
        upper: /mnt/hidden-volume/root
        work: /mnt/hidden-volume/.work/root
        target: /root
      - name: srv
        lower: /srv
        upper: /mnt/hidden-volume/srv
        work: /mnt/hidden-volume/.work/srv
        target: /srv
      - name: tmp
        lower: /tmp
        upper: /mnt/hidden-volume/tmp
        work: /mnt/hidden-volume/.work/tmp
        target: /tmp
    EOF""" % path
        )

    write_headless_config_for(tty, tty_config)
    write_headless_config_for(graphical, graphical_config)

    def assert_status_state_for(node, expected, config_path):
        read_status_json.__globals__["machine"] = node
        payload = read_status_json(config_path=config_path)
        actual = str(payload["state"]).lower()
        assert actual.startswith(expected), f"Expected {expected!r}, got {payload}"

    def assert_overlay_mounted_for(node, path):
        node.succeed(f"mountpoint -q {path}")
        fs_type = node.succeed(f"findmnt -n -o FSTYPE {path}").strip()
        assert fs_type == "overlay", f"Expected overlay at {path}, got {fs_type!r}"

    def canonical_deactivate_for(node, config_path, unit_name):
        run_detached_command.__globals__["machine"] = node
        run_detached_command(
            unit_name,
            f"nails --config {config_path} deactivate",
        )
        node.wait_for_shutdown()
        node.start()
        node.wait_for_unit("multi-user.target")

    with subtest("tty session path skips graphical detach"):
        tty.succeed("""${hiddenVolume.setupHiddenVolume}""")
        tty.succeed(f"nails --config {tty_config} activate --overlay-only --kill-session -y")
        assert_overlay_mounted_for(tty, "/home")
        assert_status_state_for(tty, "active", tty_config)
        tty_units = tty.succeed("systemctl list-units --all --plain --no-legend 'nails-activate-*' || true")
        assert "nails-activate-" not in tty_units, tty_units
        canonical_deactivate_for(tty, tty_config, "nails-deactivate-session-detection-tty")

    with subtest("graphical x11 path detaches into transient systemd service"):
        wait_for_activation_transient_unit.__globals__["machine"] = graphical
        assert_unit_in_system_slice.__globals__["machine"] = graphical

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
        assert_overlay_mounted_for(graphical, "/home")
        assert_status_state_for(graphical, "active", graphical_config)
        canonical_deactivate_for(graphical, graphical_config, "nails-deactivate-session-detection-graphical")
  '';
}
