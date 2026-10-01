# Test 63: Plain Rendering
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "plain-rendering";
  meta.tags = [ "contract" ];

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
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.assertNoAnsiFn}
    ${contractHelpers.assertAsciiOnlyFn}

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.toml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y"
        )
        active_status = run_command_capture(
            "plain-rendering-active-status",
            f"nails --config {headless_config} status --json",
        )
        assert active_status["rc"] == 0, active_status
        active_payload = json.loads(active_status["stdout"])
        assert active_payload["state"].startswith("Active"), active_payload

    with subtest("piped status output has no escapes and falls back to ASCII"):
        regular = run_command_capture(
            "plain-rendering-regular",
            f"nails --config {shlex.quote(headless_config)} status",
        )
        assert regular["rc"] == 0, regular
        assert "NAILS Status Report" in regular["stdout"], regular
        assert "Security Posture:" in regular["stdout"], regular
        assert_no_ansi(regular["combined"], "piped status output")
        assert "╭" not in regular["stdout"], regular

    with subtest("--ascii status output is ASCII-only without escapes"):
        plain = run_command_capture(
            "plain-rendering-ascii",
            f"nails --config {shlex.quote(headless_config)} status --ascii --details",
        )
        assert plain["rc"] == 0, plain
        assert_no_ansi(plain["combined"], "status --ascii output")
        assert_ascii_only(plain["stdout"], "status --ascii output")
        assert "NAILS Status Report" in plain["stdout"], plain
        assert "Security Posture:" in plain["stdout"], plain
        assert "Details:" in plain["stdout"], plain

    with subtest("TERM=dumb with the C locale is ASCII-only"):
        dumb = run_command_capture(
            "plain-rendering-dumb",
            f"TERM=dumb LANG=C LC_ALL= nails --config {shlex.quote(headless_config)} status --details",
        )
        assert dumb["rc"] == 0, dumb
        assert_no_ansi(dumb["combined"], "TERM=dumb status output")
        assert_ascii_only(dumb["stdout"], "TERM=dumb status output")

    with subtest("deactivate cleanly after plain rendering checks"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-plain-rendering")
  '';
}
