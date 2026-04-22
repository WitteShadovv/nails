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
    ${contractHelpers.assertAsciiOnlyFn}

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
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

    with subtest("regular status output uses non-plain decorations"):
        regular = run_command_capture(
            "plain-rendering-regular",
            f"nails --config {shlex.quote(headless_config)} status",
        )
        assert regular["rc"] == 0, regular
        assert not regular["combined"].isascii(), regular

    with subtest("plain status output is ASCII-only"):
        plain = run_command_capture(
            "plain-rendering-plain",
            f"nails --config {shlex.quote(headless_config)} status --plain -v",
        )
        assert plain["rc"] == 0, plain
        assert_ascii_only(plain["combined"], "status --plain output")
        assert "NAILS Status Report" in plain["stdout"], plain
        assert "Security Posture:" in plain["stdout"], plain
        assert "╭" not in plain["combined"], plain

    with subtest("deactivate cleanly after plain rendering checks"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-plain-rendering")
  '';
}
