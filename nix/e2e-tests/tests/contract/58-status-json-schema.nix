# Test 58: Status JSON Schema Contract
# Self-check: uses subtests, hard assertions, shared lib helpers, tags contract, no sleep.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  contractHelpers = import ./../../lib/contract-helpers.nix;
  pythonWithJsonschema = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
in {
  name = "status-json-schema";
  meta.tags = [ "contract" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages =
      [ self.packages.x86_64-linux.nails pythonWithJsonschema ];
  };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.runDetachedCommandFn}
    ${testHelpers.canonicalDeactivateFn}
    ${contractHelpers.runCommandCaptureFn}
    ${contractHelpers.assertJsonSchemaValidFn}

    status_schema = "${./../../fixtures/schemas/status.json}"

    with subtest("boot and prepare hidden volume"):
        machine.start()
        machine.wait_for_unit("multi-user.target")
        headless_config = "/tmp/nails-headless.yaml"
        write_headless_config(headless_config)
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")

    with subtest("inactive status matches schema"):
        inactive = run_command_capture(
            "status-schema-inactive",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert inactive["rc"] == 0, inactive
        assert_json_schema_valid(status_schema, inactive["stdout_path"], "inactive status JSON")
        inactive_payload = json.loads(inactive["stdout"])
        assert inactive_payload["state"] == "Inactive", inactive_payload

    with subtest("active status matches schema"):
        machine.succeed(
            f"nails --config {headless_config} activate --overlay-only --no-kill-session -y"
        )
        active = run_command_capture(
            "status-schema-active",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert active["rc"] == 0, active
        assert_json_schema_valid(status_schema, active["stdout_path"], "active status JSON")
        active_payload = json.loads(active["stdout"])
        assert active_payload["state"].startswith("Active"), active_payload
        active_paths = {overlay["path"] for overlay in active_payload["overlays"]}
        assert "/etc" in active_paths and "/home" in active_paths, active_payload

    with subtest("post-deactivation status still matches schema"):
        canonical_deactivate(headless_config, unit_name="nails-deactivate-status-schema")
        post = run_command_capture(
            "status-schema-post",
            f"nails --config {shlex.quote(headless_config)} status --json",
        )
        assert post["rc"] == 0, post
        assert_json_schema_valid(status_schema, post["stdout_path"], "post-deactivation status JSON")
        post_payload = json.loads(post["stdout"])
        assert post_payload["state"] == "Inactive", post_payload
  '';
}
