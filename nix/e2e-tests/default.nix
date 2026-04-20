{ self, pkgs }:

let
  inherit (pkgs) lib;
  testsRoot = ./tests;

  collectTestFiles = dir:
    let entries = builtins.readDir dir;
    in lib.concatMap (name:
      let
        path = dir + "/${name}";
        kind = entries.${name};
      in if kind == "directory" then
        collectTestFiles path
      else if kind == "regular" && lib.hasSuffix ".nix" name then
        [ path ]
      else
        [ ]) (builtins.attrNames entries);

  rawSpecs =
    map (path: import path { inherit self pkgs; }) (collectTestFiles testsRoot);
  rawNames = map (spec: spec.name) rawSpecs;

  _assertUniqueNames =
    if builtins.length rawNames == builtins.length (lib.unique rawNames) then
      true
    else
      throw "Duplicate E2E test name detected under nix/e2e-tests/tests";

  tests = builtins.listToAttrs (map (spec:
    let
      sanitizedMeta =
        if spec ? meta then builtins.removeAttrs spec.meta [ "tags" ] else { };
      sanitizedSpec =
        if spec ? meta then spec // { meta = sanitizedMeta; } else spec;
    in lib.nameValuePair spec.name (pkgs.testers.runNixOSTest sanitizedSpec))
    rawSpecs);

  metadata = builtins.listToAttrs (map (spec:
    lib.nameValuePair spec.name {
      tags = if spec ? meta && spec.meta ? tags then spec.meta.tags else [ ];
    }) rawSpecs);

  testNames = builtins.attrNames tests;

  linkFarmForNames = groupName: names:
    pkgs.linkFarm "e2e-${groupName}" (map (name: {
      inherit name;
      path = tests.${name};
    }) names);

  namesWithTag = tag:
    lib.filter (name: lib.elem tag (metadata.${name}.tags or [ ])) testNames;

  ciNames = lib.filter (name: builtins.elem name testNames) [
    "basic-workflow"
    "verify"
    "emergency"
    "forensic-clean"
    "config-handling"
    "status-verify"
  ];

  groups = {
    smoke = linkFarmForNames "smoke" (namesWithTag "smoke");
    config = linkFarmForNames "config" (namesWithTag "config");
    forensic = linkFarmForNames "forensic" (namesWithTag "forensic");
    lifecycle = linkFarmForNames "lifecycle" (namesWithTag "lifecycle");
    init = linkFarmForNames "init" (namesWithTag "init");
    security = linkFarmForNames "security" (namesWithTag "security");
    performance = linkFarmForNames "performance" (namesWithTag "performance");
    preflight = linkFarmForNames "preflight" (namesWithTag "preflight");
    nixos = linkFarmForNames "nixos" (namesWithTag "nixos");
    session = linkFarmForNames "session" (namesWithTag "session");
    shell = linkFarmForNames "shell" (namesWithTag "shell");
    notification =
      linkFarmForNames "notification" (namesWithTag "notification");
    overlay = linkFarmForNames "overlay" (namesWithTag "overlay");
    state = linkFarmForNames "state" (namesWithTag "state");
    contract = linkFarmForNames "contract" (namesWithTag "contract");
    ci = linkFarmForNames "ci" ciNames;
    all = linkFarmForNames "all" testNames;
  };

  interactiveDriver = pkgs.writeShellScriptBin "interactive-test" ''
    #!/usr/bin/env bash
    set -euo pipefail

    test_name="''${1:-basic-workflow}"
    exec nix run ".#checks.${pkgs.system}.e2e-$test_name" --interactive
  '';
in builtins.seq _assertUniqueNames (tests // groups // {
  _interactive-driver = interactiveDriver;
  _meta = metadata;
  _testNames = testNames;
})
