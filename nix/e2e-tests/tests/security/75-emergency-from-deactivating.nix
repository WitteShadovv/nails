# Test 75: Emergency From Deactivating
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
  stateHelpers = import ./../../lib/state-helpers.nix;
in
{
  name = "emergency-from-deactivating";
  meta.tags = [ "security" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pkgs.python3
      ];
    };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}
    ${stateHelpers.installDeactivationGateFn}

    expected_overlays = ["/etc", "/home", "/root", "/srv", "/tmp"]

    def assert_expected_overlays(paths):
        for path in paths:
            assert_overlay_mounted(path)

    def assert_status_overlays(paths, payload):
        actual = {overlay["path"] for overlay in payload["overlays"]}
        expected = set(paths)
        assert actual == expected, f"Expected status overlays {expected}, got: {payload}"

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    env_prefix, gate_path, entered_path = install_deactivation_gate(
        gate_path="/run/nails-tests/nails-emergency-deactivating.gate",
        entered_path="/run/nails-tests/nails-emergency-deactivating-entered",
    )

    with subtest("prepare active session before real deactivation gate"):
        machine.succeed(f"nails --config {headless_config} activate --overlay-only --no-kill-session -y")
        status = read_status_json(config_path=headless_config)
        assert status["state"].startswith("Active"), status
        assert_status_overlays(expected_overlays, status)
        assert_expected_overlays(expected_overlays)

    with subtest("prepare a real in-flight deactivating state"):
        run_detached_command(
            "nails-emergency-deactivating-primary",
            f"{env_prefix} nails --config {headless_config} deactivate",
        )
        machine.wait_until_succeeds(
            f"test -f {entered_path}",
            timeout=180,
        )
        machine.succeed(f"test -f {entered_path}")
        machine.wait_until_succeeds(
            f"nails --config {headless_config} status --json | grep -F 'Deactivating'",
            timeout=180,
        )
        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert status["overlays"] == [], status
        assert_expected_overlays(expected_overlays)

    with subtest("emergency fails closed while deactivation is in progress"):
        prefix = "/run/nails-tests/emergency-from-deactivating"
        result = run_shellless_transient_command(
            prefix,
            ["nails", "--config", headless_config, "emergency", "--no-countdown"],
            unit_name="nails-emergency-from-deactivating",
            timeout=30,
        )

        assert result["rc"] == 1, f"Expected emergency to fail from Deactivating, got: {result}"
        assert "Deactivating" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("deactivating", payload=status)
        assert status["overlays"] == [], status
        assert_expected_overlays(expected_overlays)

    with subtest("releasing deactivation completes cleanup and converges to inactive"):
        machine.succeed(f"rm -f {gate_path}")
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
        assert_no_overlays(expected_overlays)
  '';
}
