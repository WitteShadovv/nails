# Test 23: Config Malformed YAML

{ self, ... }:
let
  preflightHelpers = import ./../../lib/preflight-helpers.nix;
  badYamlFixture = ./../../fixtures/configs/bad-yaml.yaml;
in {
  name = "config-malformed-yaml";
  meta.tags = [ "config" "smoke" ];

  nodes.machine = { ... }: {
    imports = [ ./../../lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.x86_64-linux.nails ];
  };

  testScript = _: ''
    ${preflightHelpers.runCommandCaptureFn}
    ${preflightHelpers.commandAssertionsFn}

    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("malformed yaml config fails closed with actionable output"):
        machine.succeed("cp ${badYamlFixture} /tmp/bad-config.yaml")
        result = run_command_capture(
            "config-malformed-yaml",
            "nails --config /tmp/bad-config.yaml status",
        )
        assert_command_failed(result)
        assert_result_contains(result, ["Error loading config", "Invalid YAML", "Example config"], stream="stderr")
  '';
}
