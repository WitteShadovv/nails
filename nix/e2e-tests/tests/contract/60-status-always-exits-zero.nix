# Test 60: Status Always Exits Zero
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "status-always-exits-zero";
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
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.canonicalDeactivateFn}
    ${assertions.assertStatusStateFn}
    ${contractHelpers.runCommandCaptureFn}

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.toml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("inactive status exits zero"):
        inactive = run_command_capture(
            "status-zero-inactive",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert inactive["rc"] == 0, inactive
        assert_status_state("Inactive", payload=json.loads(inactive["stdout"])["data"])

    with subtest("active status exits zero"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )
        active = run_command_capture(
            "status-zero-active",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert active["rc"] == 0, active
        assert_status_state("Active", payload=json.loads(active["stdout"])["data"])

    with subtest("tampered state still yields exit zero"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-status-zero")
        machine.succeed("""${hiddenVolume.mountHiddenVolume}""")
        machine.succeed(
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "path = Path('/mnt/data/state.json')\n"
            "data = path.read_text()\n"
            "path.write_text(data[:-1] + 'X')\n"
            "PY"
        )
        tampered = run_command_capture(
            "status-zero-tampered",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert tampered["rc"] == 0, tampered
        tampered_payload = json.loads(tampered["stdout"])["data"]
        # A broken digest means the real state is untrusted; the decoy default is
        # reported, and an untrusted load surfaces as the "unknown" state kind.
        assert tampered_payload["state"]["kind"] in ("inactive", "unknown"), tampered_payload
        assert tampered_payload["security_posture"] in ("decoy", "warning"), tampered_payload
        assert tampered_payload["overlays"] == [], tampered_payload
        machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
  '';
}
