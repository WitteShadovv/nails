{ self, pkgs }:

let
  inherit (pkgs) lib;
  testsRoot = ./tests;

  collectTestFiles =
    dir:
    let
      entries = builtins.readDir dir;
    in
    lib.concatMap (
      name:
      let
        path = dir + "/${name}";
        kind = entries.${name};
      in
      if kind == "directory" then
        collectTestFiles path
      else if kind == "regular" && lib.hasSuffix ".nix" name then
        [ path ]
      else
        [ ]
    ) (builtins.attrNames entries);

  rawSpecs = map (path: import path { inherit self pkgs; }) (collectTestFiles testsRoot);
  rawNames = map (spec: spec.name) rawSpecs;

  _assertUniqueNames =
    if builtins.length rawNames == builtins.length (lib.unique rawNames) then
      true
    else
      throw "Duplicate E2E test name detected under nix/e2e-tests/tests";

  tests = builtins.listToAttrs (
    map (
      spec:
      let
        sanitizedMeta = if spec ? meta then builtins.removeAttrs spec.meta [ "tags" ] else { };
        sanitizedSpec = if spec ? meta then spec // { meta = sanitizedMeta; } else spec;
      in
      lib.nameValuePair spec.name (pkgs.testers.runNixOSTest sanitizedSpec)
    ) rawSpecs
  );

  metadata = builtins.listToAttrs (
    map (
      spec:
      lib.nameValuePair spec.name {
        tags = if spec ? meta && spec.meta ? tags then spec.meta.tags else [ ];
        nodeCount =
          let
            declaredNodes = if spec ? nodes then builtins.attrNames spec.nodes else [ ];
          in
          lib.max 1 (builtins.length declaredNodes);
      }
    ) rawSpecs
  );

  testNames = builtins.attrNames tests;

  linkFarmForNames =
    groupName: names:
    pkgs.linkFarm "e2e-${groupName}" (
      map (name: {
        inherit name;
        path = tests.${name};
      }) names
    );

  namesWithTag = tag: lib.filter (name: lib.elem tag (metadata.${name}.tags or [ ])) testNames;

  ciNames = lib.filter (name: builtins.elem name testNames) [
    "basic-workflow"
    "verify"
    "emergency"
    "forensic-clean"
    "config-handling"
    "status-verify"
    "preflight-nixos-build-target"
    "session-kill-graphical"
    "notify-autostart-lifecycle"
  ];

  groupMembers = {
    smoke = namesWithTag "smoke";
    config = namesWithTag "config";
    forensic = namesWithTag "forensic";
    lifecycle = namesWithTag "lifecycle";
    init = namesWithTag "init";
    security = namesWithTag "security";
    performance = namesWithTag "performance";
    preflight = namesWithTag "preflight";
    nixos = namesWithTag "nixos";
    session = namesWithTag "session";
    shell = namesWithTag "shell";
    notification = namesWithTag "notification";
    overlay = namesWithTag "overlay";
    state = namesWithTag "state";
    contract = namesWithTag "contract";
    ci = ciNames;
    all = testNames;
  };

  groups = lib.mapAttrs linkFarmForNames groupMembers;

  interactiveDriver = pkgs.writeShellScriptBin "interactive-test" ''
    #!/usr/bin/env bash
    set -euo pipefail

    test_name="''${1:-basic-workflow}"
    exec nix run ".#checks.${pkgs.system}.e2e-$test_name" --interactive
  '';
in
builtins.seq _assertUniqueNames (
  tests
  // groups
  // {
    _interactive-driver = interactiveDriver;
    _groups = groupMembers;
    _meta = metadata;
    _testNames = testNames;
  }
)
