# Scenario `verify-json-schema` of the `contract-json-schema` batch:
#   tests/contract/58-contract-json-schema.nix
# Formerly the stand-alone test
#   tests/contract/59-verify-json-schema.nix
# It now shares one VM boot with the batch's other scenarios (lib/batch.nix);
# its subtests and assertions are unchanged.
#
# Contract: the verify JSON envelope across its scan modes.
#
# cli_contract.rs covers the inactive verify envelope without a VM. This test
# adds the cases that need a real host: the honest headline fields the rework
# introduced (checks_run and areas_not_checked), the deep scan, and the offline
# image mode. Every mode is validated against the committed verify.json schema.

_:
let
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
in
{
  name = "verify-json-schema";
  tags = [ "contract" ];

  helpers = [
    testHelpers.writeHeadlessConfigFn
    contractHelpers.runCommandCaptureFn
    contractHelpers.assertJsonSchemaValidFn
  ];

  script = ''
    def scenario_verify_json_schema() -> None:
        import json
        import shlex

        verify_schema = "${./../../../../docs/schemas/verify.schema.json}"

        with subtest("boot and write the headless config"):
            machine.wait_for_unit("multi-user.target")
            headless_config = "/tmp/nails-headless.toml"
            write_headless_config(headless_config)

        with subtest("standard verify JSON matches the schema and headline fields"):
            standard = run_command_capture(
                "contract-verify-standard",
                f"nails --no-log-file --config {shlex.quote(headless_config)} verify --json",
            )
            assert standard["rc"] in (0, 10, 11), standard
            assert_json_schema_valid(verify_schema, standard["stdout_path"], "standard verify JSON")
            payload = json.loads(standard["stdout"])["data"]
            # The honest headline is backed by data: a count of checks run and an
            # explicit list of areas the run did not inspect.
            assert isinstance(payload["checks_run"], int) and payload["checks_run"] > 0, payload
            assert isinstance(payload["areas_not_checked"], list) and payload["areas_not_checked"], payload
            # A standard scan never claims the skipped deep areas were covered.
            assert any("deep" in area for area in payload["areas_not_checked"]), payload

        with subtest("the old overclaiming headline is gone from the human output"):
            human = run_command_capture(
                "contract-verify-human",
                f"nails --no-log-file --config {shlex.quote(headless_config)} verify",
            )
            assert "No traces found" not in human["stdout"], human
            assert "System appears clean" not in human["stdout"], human
            assert "not proof of absence" in human["stdout"].lower(), human

        with subtest("deep verify JSON matches the schema"):
            deep = run_command_capture(
                "contract-verify-deep",
                f"nails --no-log-file --config {shlex.quote(headless_config)} verify --deep --json",
            )
            assert deep["rc"] in (0, 10, 11), deep
            assert_json_schema_valid(verify_schema, deep["stdout_path"], "deep verify JSON")

        with subtest("offline verify JSON matches the schema and skips live checks"):
            # A read-only copy of the decoy root stands in for a mounted image.
            machine.succeed("mkdir -p /mnt/decoy/run /mnt/decoy/etc")
            machine.succeed("cp /etc/passwd /mnt/decoy/etc/passwd")
            offline = run_command_capture(
                "contract-verify-offline",
                f"nails --no-log-file --config {shlex.quote(headless_config)} "
                "verify --offline --root /mnt/decoy --json",
            )
            assert offline["rc"] in (0, 10, 11), offline
            assert_json_schema_valid(verify_schema, offline["stdout_path"], "offline verify JSON")
            offline_payload = json.loads(offline["stdout"])["data"]
            assert any(
                "offline image scan" in area for area in offline_payload["areas_not_checked"]
            ), offline_payload
            # No process finding can appear in an offline scan: live checks are skipped.
            assert not any(
                finding["category"] == "process" for finding in offline_payload["findings"]
            ), offline_payload

        print("\n=== verify JSON schema contract passed ===")
  '';
}
