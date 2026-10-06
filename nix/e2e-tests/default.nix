{
  self,
  pkgs,
  nixpkgs,
}:

let
  inherit (pkgs) lib;
  testsRoot = ./tests;

  # Shared node for specs that need nothing beyond the standard decoy VM and the
  # nails binary. A spec that declares no `nodes` gets this node as `machine`,
  # optionally parameterised through a top-level `baseNode` attribute (for
  # example `baseNode = { python3 = true; }`). A spec with its own `nodes` is
  # left untouched.
  baseNode = import ./lib/base-node.nix { inherit self pkgs; };

  applyBaseNode =
    spec:
    let
      stripped = builtins.removeAttrs spec [ "baseNode" ];
    in
    if spec ? nodes then
      stripped
    else
      stripped // { nodes.machine = baseNode.mkNode (spec.baseNode or { }); };

  # The in-VM helpers every testScript can import (run_command_capture and
  # install_nixos_rebuild_wrapper), as one importable package instead of the
  # hand-escaped copies that used to live inside each test's Nix strings. It is
  # built against the driver's own Python package set (the `ps` the driver
  # passes to extraPythonPackages below), so the interpreter stays in step.
  nailsE2eHelpers =
    ps:
    ps.buildPythonPackage {
      pname = "nails-e2e-test-helpers";
      version = "0";
      src = ./py;
      pyproject = true;
      build-system = [ ps.setuptools ];
      doCheck = false;
    };

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

  # Research spikes (tests/research/, tag `research`) are buildable as
  # `e2e.<name>` and through the `research` link farm, but they are not leaf
  # tests: they stay out of `all`, every tag group, the CI shards and
  # `--affected`, and need no shard weight. The tag and the directory must
  # agree, because the shard planner's host-side tests skip the directory
  # without evaluating any Nix.
  researchTag = "research";
  researchDir = toString testsRoot + "/research/";

  rawSpecPairs = map (path: {
    inherit path;
    spec = import path { inherit self pkgs nixpkgs; };
  }) (collectTestFiles testsRoot);
  rawSpecs = map (pair: pair.spec) rawSpecPairs;
  rawNames = map (spec: spec.name) rawSpecs;

  isResearch = spec: lib.elem researchTag (spec.meta.tags or [ ]);

  _assertResearchLayout = lib.all (
    pair:
    let
      inResearchDir = lib.hasPrefix researchDir (toString pair.path);
    in
    lib.assertMsg (inResearchDir == isResearch pair.spec)
      "E2E test ${pair.spec.name}: the `${researchTag}` tag and the tests/research/ directory must go together"
  ) rawSpecPairs;

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

  # A test that never boots a VM used to pass silently: a mis-indented Nix `''`
  # block folds the Python body into the last interpolated helper string, so
  # `machine.start()` ends up inside a string literal and never runs. Wrapping
  # every test's script with a start tracker and a closing assert turns that
  # into a build failure. The tracker monkeypatches each machine's `start()`
  # (so `start()`, `start_all()` and any lazy auto-start all trip it) and the
  # assert runs last even for scripts that end in `crash()` or `shutdown()`,
  # because it only reads a Python global.
  vmStartedPrelude = ''
    _nails_vm_started = False


    def _nails_track_start(_nails_machine):
        _nails_original_start = _nails_machine.start

        def _nails_wrapped_start(*args, **kwargs):
            global _nails_vm_started
            _nails_vm_started = True
            return _nails_original_start(*args, **kwargs)

        _nails_machine.start = _nails_wrapped_start


    for _nails_machine in machines:
        _nails_track_start(_nails_machine)
  '';

  vmStartedAssert = ''
    assert _nails_vm_started, "testScript never started a VM"
  '';

  wrapTestScript =
    original: args:
    let
      body = if builtins.isFunction original then original args else original;
    in
    vmStartedPrelude + "\n" + body + "\n" + vmStartedAssert;

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
      rawSpec:
      let
        spec = applyBaseNode rawSpec;
      in
      lib.nameValuePair spec.name (
        pkgs.testers.runNixOSTest (
          spec
          // {
            testScript = wrapTestScript spec.testScript;
            globalTimeout = effectiveTimeout spec;
            # Expose nails_e2e to every test's driver, preserving any packages a
            # test already asks for.
            extraPythonPackages =
              ps:
              (lib.optionals (spec ? extraPythonPackages) (spec.extraPythonPackages ps))
              ++ [ (nailsE2eHelpers ps) ];
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

  leafSpecs = lib.filter (spec: !isResearch spec) rawSpecs;
  researchNames = map (spec: spec.name) (lib.filter isResearch rawSpecs);

  metadata = builtins.listToAttrs (
    map (
      spec:
      lib.nameValuePair spec.name {
        tags = if spec ? meta && spec.meta ? tags then spec.meta.tags else [ ];
        timeout = effectiveTimeout spec;
      }
    ) leafSpecs
  );

  testNames = builtins.attrNames (removeAttrs tests researchNames);

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
    "activate-auto-lifecycle"
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
    faults = namesWithTag "faults";
    ci = ciNames;
    all = testNames;
  };

  groups = lib.mapAttrs linkFarmForNames groupMembers // {
    ${researchTag} = linkFarmForNames researchTag researchNames;
  };

  # Tests and groups share one attribute set, and the runner resolves a name
  # as a test before a group, so a shared name would hide one of them.
  shadowedGroups = lib.intersectLists rawNames (builtins.attrNames groups);
  _assertNoShadowedGroups = lib.assertMsg (
    shadowedGroups == [ ]
  ) "E2E test names must differ from group names: ${lib.concatStringsSep ", " shadowedGroups}";
in
builtins.seq _assertUniqueNames (
  builtins.seq _assertResearchLayout (
    builtins.seq _assertNoShadowedGroups (
      tests
      // groups
      // {
        _groups = groupMembers;
        _meta = metadata;
        _testNames = testNames;
        _researchTargets = researchNames ++ [ researchTag ];
      }
    )
  )
)
