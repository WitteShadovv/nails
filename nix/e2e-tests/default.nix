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

  # The driver's default globalTimeout is one hour, so a hung test held its
  # shard for an hour and the hang was then recorded as a shard weight. A test
  # that legitimately needs longer sets a top-level `globalTimeout` next to its
  # `name`, with a comment giving its measured runtime. Shard weights must stay
  # at or below half of the effective timeout; see "Timeouts and shard weights"
  # in README.md.
  defaultGlobalTimeout = 900;

  # The assertions live here rather than in the test derivation so that
  # evaluating the metadata (which the shard planner consumes) enforces them.
  effectiveTimeout =
    spec:
    let
      seconds = spec.globalTimeout or defaultGlobalTimeout;
    in
    assert lib.assertMsg (
      !((spec.meta or { }) ? timeout)
    ) "E2E test ${spec.name}: set globalTimeout; meta.timeout is derived from it";
    assert lib.assertMsg (
      builtins.isInt seconds && seconds > 0
    ) "E2E test ${spec.name}: globalTimeout must be a positive integer number of seconds";
    seconds;

  tests = builtins.listToAttrs (
    map (
      spec:
      lib.nameValuePair spec.name (
        pkgs.testers.runNixOSTest (
          spec
          // {
            globalTimeout = effectiveTimeout spec;
            # meta.timeout bounds the whole derivation for an outer builder.
            # Keeping it a minute above the driver's own deadline lets the
            # driver report the timeout and release the VMs itself.
            meta = builtins.removeAttrs (spec.meta or { }) [ "tags" ] // {
              timeout = effectiveTimeout spec + 60;
            };
          }
        )
      )
    ) rawSpecs
  );

  metadata = builtins.listToAttrs (
    map (
      spec:
      lib.nameValuePair spec.name {
        tags = if spec ? meta && spec.meta ? tags then spec.meta.tags else [ ];
        timeout = effectiveTimeout spec;
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

  # Tests and groups share one attribute set, and the runner resolves a name
  # as a test before a group, so a shared name would hide one of them.
  shadowedGroups = lib.intersectLists testNames (builtins.attrNames groupMembers);
  _assertNoShadowedGroups = lib.assertMsg (
    shadowedGroups == [ ]
  ) "E2E test names must differ from group names: ${lib.concatStringsSep ", " shadowedGroups}";
in
builtins.seq _assertUniqueNames (
  builtins.seq _assertNoShadowedGroups (
    tests
    // groups
    // {
      _groups = groupMembers;
      _meta = metadata;
      _testNames = testNames;
    }
  )
)
