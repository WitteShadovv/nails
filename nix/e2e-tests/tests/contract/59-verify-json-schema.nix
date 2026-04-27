# Test 59: Verify JSON Schema Contract
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
  pythonWithJsonschema = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
in
{
  name = "verify-json-schema";
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
    ${testHelpers.canonicalDeactivateFn}
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.assertJsonSchemaValidFn}

    verify_schema = "${./../../fixtures/schemas/verify.json}"

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("baseline verify output matches schema"):
        baseline = run_command_capture(
            "verify-schema-baseline",
            f"nails --config {shlex.quote(headless_config)} verify --json",
        )
        assert baseline["rc"] in (0, 1), baseline
        assert_json_schema_valid(verify_schema, baseline["stdout_path"], "baseline verify JSON")
        baseline_payload = json.loads(baseline["stdout"])
        assert "status" in baseline_payload and "findings" in baseline_payload, baseline_payload

    with subtest("active verify output matches schema"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y"
        )
        active = run_command_capture(
            "verify-schema-active",
            f"nails --config {shlex.quote(headless_config)} verify --deep --json",
        )
        assert active["rc"] == 1, active
        assert_json_schema_valid(verify_schema, active["stdout_path"], "active verify JSON")
        active_payload = json.loads(active["stdout"])
        assert active_payload["findings"], active_payload
        assert any(
            finding["category"] == "mount"
            or "overlay" in finding["message"].lower()
            for finding in active_payload["findings"]
        ), active_payload

    with subtest("deactivate cleanly after schema validation"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-verify-schema")
  '';
}
