# Test 76: Emergency While Inactive
# Self-checks: with subtest; no time.sleep sync; hard assertions only; meta.tags set; shared helpers only; forensic invariants preserved.

{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in {
  name = "emergency-while-inactive";
  meta.tags = [ "security" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.yaml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("precondition is inactive with no overlays"):
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])

    with subtest("emergency from inactive is explicit and leaves system unchanged"):
        prefix = "/tmp/emergency-while-inactive"
        run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency --no-countdown",
        )
        result = read_command_result(prefix)

        assert result["rc"] == 1, f"Expected explicit inactive-state failure, got: {result}"
        assert "Inactive" in result["stderr"], result
        assert "Must be ACTIVE" in result["stderr"], result
        assert result["stdout"].strip() == "", result

        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
