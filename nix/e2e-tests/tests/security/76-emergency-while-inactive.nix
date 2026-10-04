# Test 76: Emergency While Inactive

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  securityHelpers = import ./../../lib/security-helpers.nix;
in
{
  name = "emergency-while-inactive";
  meta.tags = [ "security" ];

  testScript = _: ''
    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.readStatusJsonFn}
    ${assertions.assertStatusStateFn}
    ${assertions.assertNoOverlaysFn}
    ${securityHelpers.capturedCommandFns}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    headless_config = "/tmp/nails-headless.toml"
    write_headless_config(headless_config)
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("precondition is inactive with no overlays"):
        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])

    with subtest("emergency from a clean inactive system is a no-op success"):
        prefix = "/run/nails-tests/emergency-while-inactive"
        capture = run_captured_command(
            prefix,
            f"nails --config {headless_config} emergency",
            unit_name="nails-emergency-while-inactive",
        )
        result = read_command_result(prefix, unit_name=capture["unit_name"], timeout=30)

        # With no live NAILS mount and an Inactive state there is nothing to tear
        # down: emergency exits 0 and touches nothing.
        assert result["rc"] == 0, f"Expected a no-op success from Inactive, got: {result}"
        assert "No NAILS overlays were mounted" in result["stdout"], result

        status = read_status_json(config_path=headless_config)
        assert_status_state("inactive", payload=status)
        assert_no_overlays(["/home", "/etc", "/tmp", "/srv"])
  '';
}
