# Scenario `contract-active-session` of the `contract-json-schema` batch:
#   tests/contract/58-contract-json-schema.nix
# Formerly the stand-alone test
#   tests/contract/58-contract-active-session.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix).
#
# Contract: the active-session CLI surface that genuinely needs a real VM.
#
# The help/version surface, the status and verify JSON schemas for the inactive,
# tampered and hand-written active states, the error envelope, the colour toggle
# in a non-TTY harness, the exit-code table and log-file suppression are all
# covered without a VM by nails-cli/tests/cli_contract.rs. This single VM test
# keeps only what needs a real hidden session and a real terminal: colour
# auto-detection on a real TTY, then (after `nails activate` soft-rebooted into
# the whole-root overlay) the status JSON with place "hidden" and the verify
# JSON, both against the committed schemas, and the ASCII/plain rendering of
# the active status.

_:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "contract-active-session";
  tags = [ "contract" ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
    testHelpers.canonicalActivateFn
    contractHelpers.runCommandCaptureFn
    contractHelpers.runPtyCommandCaptureFn
    contractHelpers.assertJsonSchemaValidFn
    contractHelpers.assertNoAnsiFn
    contractHelpers.assertAsciiOnlyFn
  ];

  script = ''
    def scenario_contract_active_session() -> None:
        import json
        import shlex

        status_schema = "${./../../../../docs/schemas/status.schema.json}"
        verify_schema = "${./../../../../docs/schemas/verify.schema.json}"

        with subtest("boot and prepare hidden volume"):
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
            tty_dumb = run_pty_command_capture(
                "contract-verify-tty-dumb",
                f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
                term="dumb",
            )
            assert_no_ansi(tty_dumb["combined"], "verify on a TTY with TERM=dumb")
            piped = run_command_capture(
                "contract-verify-piped",
                f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
            )
            assert_no_ansi(piped["combined"], "piped verify")

        with subtest("activate soft-reboots into the hidden session"):
            canonical_activate(headless_config, "--overlay-only", "contract-activate")

        with subtest("active status JSON matches the schema"):
            active = run_command_capture(
                "contract-status-active",
                f"nails --config {shlex.quote(headless_config)} status --json",
            )
            assert active["rc"] == 0, active
            assert_json_schema_valid(status_schema, active["stdout_path"], "active status JSON")
            active_payload = json.loads(active["stdout"])["data"]
            # Version-2 envelope: an active hidden session is place "hidden" with
            # no attention, in place of the version-1 posture "active".
            assert active_payload["place"] == "hidden", active_payload
            assert active_payload["attention"] is None, active_payload

        with subtest("active verify JSON matches the schema"):
            verified = run_command_capture(
                "contract-verify-active",
                f"nails --config {shlex.quote(headless_config)} verify --deep --json",
            )
            # Inside the hidden session the session's own runtime files, its
            # hidden volume and its active state are expected: verify says so
            # in one note and reports none of them. Nothing on this setup is
            # critical; a warning (10) can still come from the decoy itself.
            assert verified["rc"] in (0, 10), verified
            assert_json_schema_valid(verify_schema, verified["stdout_path"], "active verify JSON")
            verify_payload = json.loads(verified["stdout"])["data"]
            findings = verify_payload["findings"]
            assert any(
                f["category"] == "session" and f["severity"] == "info" for f in findings
            ), verify_payload
            critical = [f for f in findings if f["severity"] == "critical"]
            assert not critical, verify_payload

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
            assert "Security Posture:" in ascii_status["stdout"], ascii_status
  '';
}
