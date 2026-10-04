# Contract: the active-session CLI surface that genuinely needs a real VM.
#
# The help/version surface, the status and verify JSON schemas for the inactive,
# tampered and hand-written active states, the error envelope, the colour toggle
# in a non-TTY harness, the exit-code table and log-file suppression are all
# covered without a VM by nails-cli/tests/cli_contract.rs. This single VM test
# keeps only what needs a real overlay activation and a real terminal: the active
# status and verify JSON against the committed schemas, the ASCII/plain rendering
# of an active status, and colour auto-detection on a real TTY.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
  pythonWithJsonschema = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
in
{
  name = "contract-active-session";
  meta.tags = [ "contract" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pythonWithJsonschema
      ];
    };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.runPtyCommandCaptureFn}
    ${contractHelpers.assertJsonSchemaValidFn}
    ${contractHelpers.assertNoAnsiFn}
    ${contractHelpers.assertAsciiOnlyFn}

    status_schema = "${./../../../../docs/schemas/status.schema.json}"
    verify_schema = "${./../../../../docs/schemas/verify.schema.json}"

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.toml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("colour auto-detects on a real TTY and off a pipe"):
        # verify paints its header whenever colour is on; auto-detection can only
        # be exercised against a real terminal, so this stays in the VM tier.
        tty_default = run_pty_command_capture(
            "contract-verify-tty",
            f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
        )
        assert_has_ansi(tty_default["combined"], "verify on a TTY")
        tty_no_color = run_pty_command_capture(
            "contract-verify-tty-no-color",
            f"NO_COLOR=1 nails --no-log-file --config {shlex.quote(headless_config)} verify",
        )
        assert_no_ansi(tty_no_color["combined"], "verify on a TTY with NO_COLOR=1")
        piped = run_command_capture(
            "contract-verify-piped",
            f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
        )
        assert_no_ansi(piped["combined"], "piped verify")

    with subtest("activate the hidden session"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --session keep -y"
        )

    with subtest("active status JSON matches the schema"):
        active = run_command_capture(
            "contract-status-active",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert active["rc"] == 0, active
        assert_json_schema_valid(status_schema, active["stdout_path"], "active status JSON")
        active_payload = json.loads(active["stdout"])["data"]
        assert active_payload["state"]["kind"] == "active", active_payload
        active_paths = {overlay["mount_point"] for overlay in active_payload["overlays"]}
        assert "/etc" in active_paths and "/home" in active_paths, active_payload

    with subtest("active verify JSON matches the schema"):
        verified = run_command_capture(
            "contract-verify-active",
            f"nails --config {shlex.quote(headless_config)} verify --deep --json",
        )
        # Active overlays make verify report findings: warning => 10, critical => 11.
        assert verified["rc"] in (10, 11), verified
        assert_json_schema_valid(verify_schema, verified["stdout_path"], "active verify JSON")
        verify_payload = json.loads(verified["stdout"])["data"]
        assert verify_payload["findings"], verify_payload
        assert any(
            finding["category"] == "mount" or "overlay" in finding["message"].lower()
            for finding in verify_payload["findings"]
        ), verify_payload

    with subtest("active status renders ASCII-only without escapes"):
        piped_status = run_command_capture(
            "contract-status-piped",
            f"nails --config {shlex.quote(headless_config)} status",
        )
        assert piped_status["rc"] == 0, piped_status
        assert "NAILS Status Report" in piped_status["stdout"], piped_status
        assert_no_ansi(piped_status["combined"], "piped status")
        assert "╭" not in piped_status["stdout"], piped_status
        ascii_status = run_command_capture(
            "contract-status-ascii",
            f"nails --config {shlex.quote(headless_config)} status --ascii --details",
        )
        assert ascii_status["rc"] == 0, ascii_status
        assert_no_ansi(ascii_status["combined"], "status --ascii")
        assert_ascii_only(ascii_status["stdout"], "status --ascii")
        assert "NAILS Status Report" in ascii_status["stdout"], ascii_status
        assert "Details:" in ascii_status["stdout"], ascii_status
  '';
}
