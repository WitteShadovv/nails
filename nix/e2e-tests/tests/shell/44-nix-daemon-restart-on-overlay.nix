# Test 44: Nix Daemon Restart on Overlay
# Self-check: subtests used, no sleep sync, hard assertions, shell tag, shared helpers only.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  shellHelpers = import ./../../lib/shell-helpers.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;
in
{
  name = "nix-daemon-restart-on-overlay";
  meta.tags = [ "shell" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };

  testScript = _: ''
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${shellHelpers.writeNixOverlayConfigFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${sessionHelpers.readSystemdActiveEnterMonotonicFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    config_path = "/tmp/nails-nix-overlay.yaml"
    write_nix_overlay_config(config_path)

    with subtest("prepare hidden volume and baseline nix-daemon timestamp"):
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("systemctl start nix-daemon.service")
        machine.wait_for_unit("nix-daemon.service")
        nix_daemon_before = read_systemd_active_enter_monotonic("nix-daemon.service")
        assert_no_overlays(["/nix"])

    with subtest("overlaying /nix restarts nix-daemon"):
        machine.succeed(f"nails --config {config_path} activate --overlay-only --no-kill-session -y")
        machine.wait_for_unit("nix-daemon.service")
        nix_daemon_after = read_systemd_active_enter_monotonic("nix-daemon.service")
        assert nix_daemon_after > nix_daemon_before, (
            f"nix-daemon.service did not restart: before={nix_daemon_before} after={nix_daemon_after}"
        )
        assert_overlay_mounted("/nix")
        machine.succeed("nix-instantiate --eval -E '1 + 1'")
        assert_status_state("active", config_path=config_path)

    with subtest("deactivate removes /nix overlay cleanly"):
        canonical_deactivate(config_path, unit_name="nails-deactivate-nix-daemon-overlay")
        assert_no_overlays(["/nix"])
        assert_status_state("inactive", config_path=config_path)
  '';
}
