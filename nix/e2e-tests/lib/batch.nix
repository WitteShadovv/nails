# Run several former single-boot tests as scenarios of one VM boot.
#
# Booting is most of what a single-boot test costs, so tests that share an
# identical node run in one VM instead (see "Batched scenarios" in README.md).
# Each scenario lives in its own file under `nix/e2e-tests/scenarios/<group>/`
# and evaluates to
#
#   {
#     name = "preflight-nixos-config";   # the old test name, now an alias
#     tags = [ "preflight" ];            # the old test's tags
#     helpers = [ testHelpers.readStatusJsonFn ... ];
#     script = ''
#       def scenario_preflight_nixos_config() -> None:
#           ...                          # the old testScript, one level deeper
#     '';
#   }
#
# `mkBatch` turns a list of them into an ordinary test spec: the helpers once at
# module level (deduplicated), each scenario as a function, one boot, and then
# `nails_e2e.batch.run_scenarios`, which checks before every scenario that the
# guest is as clean as it booted and resets it between scenarios. The spec lists
# the scenario names in `replaces`, so every old name stays an alias of the
# batch (default.nix).
#
# The scenario body keeps its own subtests and assertions verbatim; only the
# `machine.start()` call goes, because the batch boots the machine once. A
# helper that two scenarios need in different versions must be renamed in one of
# them; the driver's type check rejects a second definition of the same name.
{ lib }:
let
  pythonName = name: builtins.replaceStrings [ "-" ] [ "_" ] name;

  checkScenario =
    scenario:
    let
      header = "def scenario_${pythonName scenario.name}() -> None:\n";
    in
    assert lib.assertMsg (lib.hasPrefix header scenario.script)
      "batch scenario ${scenario.name}: script must start with `${lib.removeSuffix "\n" header}`";
    scenario;
in
{
  mkBatch =
    {
      name,
      tags,
      scenarios,
      # Paths outside the scratch directories that a scenario leaves behind on
      # purpose (for example a stub outside every overlay) and that the reset
      # must delete.
      cleanupPaths ? [ ],
      ...
    }@args:
    let
      checked = map checkScenario scenarios;
      scenarioNames = map (scenario: scenario.name) checked;
      missingTags = lib.subtractLists tags (lib.concatMap (scenario: scenario.tags) checked);
      helpers = lib.unique (lib.concatMap (scenario: scenario.helpers or [ ]) checked);
      calls = lib.concatMapStringsSep "\n" (
        scenario: "        (${builtins.toJSON scenario.name}, scenario_${pythonName scenario.name}),"
      ) checked;
    in
    assert lib.assertMsg (
      builtins.length scenarioNames == builtins.length (lib.unique scenarioNames)
    ) "batch ${name}: scenario names must be unique";
    # Every group an old test belonged to must still select the batch.
    assert lib.assertMsg (
      missingTags == [ ]
    ) "batch ${name}: tags must include every scenario tag (missing: ${toString missingTags})";
    builtins.removeAttrs args [
      "tags"
      "scenarios"
      "cleanupPaths"
    ]
    // {
      meta.tags = tags;
      replaces = scenarioNames;
      testScript = _: ''
        from nails_e2e.batch import run_scenarios


        ${lib.concatStringsSep "\n\n" helpers}


        ${lib.concatMapStringsSep "\n\n" (scenario: scenario.script) checked}


        machine.start()
        machine.wait_for_unit("multi-user.target")

        run_scenarios(
            machine,
            subtest,
            [
        ${calls}
            ],
            cleanup_paths=${builtins.toJSON cleanupPaths},
        )
      '';
    };
}
