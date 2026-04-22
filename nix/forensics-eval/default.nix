{
  pkgs,
  self ? null,
}:

let
  inherit (pkgs) lib;
  sharedHelpers = import ./lib/shared-helpers.nix { inherit pkgs self; };
  canaries = import ./lib/canaries.nix { inherit pkgs; };
  contracts = import ./lib/contracts.nix {
    inherit pkgs canaries;
  };
  profileLib = import ./lib/profiles.nix {
    inherit
      pkgs
      self
      sharedHelpers
      contracts
      ;
  };
  scenarioLib = import ./lib/scenarios.nix {
    inherit pkgs contracts canaries;
  };

  profileList = [
    (import ./profiles/direct-headless.nix {
      inherit
        pkgs
        self
        sharedHelpers
        contracts
        profileLib
        ;
    })
    (import ./profiles/graphical.nix {
      inherit
        pkgs
        self
        sharedHelpers
        contracts
        profileLib
        ;
    })
    (import ./profiles/vfat-boot.nix {
      inherit
        pkgs
        self
        sharedHelpers
        contracts
        profileLib
        ;
    })
  ];

  profiles = profileLib.byId profileList;
  profileIds = map (profile: profile.id) profileList;

  scenarioList = [
    (import ./scenarios/direct-baseline.nix {
      inherit
        pkgs
        self
        sharedHelpers
        contracts
        canaries
        profiles
        scenarioLib
        ;
    })
  ];

  scenarios = scenarioLib.byId scenarioList;
  scenarioIds = map (scenario: scenario.id) scenarioList;

  defaults = {
    profileId = "direct-headless";
    scenarioId = "direct-baseline";
  };

  mkLeafId = scenarioId: profileId: "${scenarioId}/${profileId}";

  leafList = lib.concatMap (
    scenario:
    map (
      profileId:
      let
        builtinLive = scenario.id == defaults.scenarioId && profileId == defaults.profileId;
      in
      {
        id = mkLeafId scenario.id profileId;
        inherit builtinLive profileId;
        scenarioId = scenario.id;
        recommendedMode = if builtinLive then "builtin-live" else "fixture-or-custom-exporter";
      }
    ) (lib.filter (profileId: builtins.hasAttr profileId profiles) scenario.supportedProfileIds)
  ) scenarioList;

  leafTests = map (leaf: leaf.id) leafList;
  defaultLeafId = mkLeafId defaults.scenarioId defaults.profileId;
  builtinLiveLeafTests = map (leaf: leaf.id) (lib.filter (leaf: leaf.builtinLive) leafList);
  ciLeafTests = lib.filter (leafId: builtins.elem leafId leafTests) [
    (mkLeafId "direct-baseline" "direct-headless")
  ];

  leaves = builtins.listToAttrs (
    map (leaf: lib.nameValuePair leaf.id (builtins.removeAttrs leaf [ "id" ])) leafList
  );

  groupEntries = [
    (lib.nameValuePair "ci" ciLeafTests)
    (lib.nameValuePair "live" builtinLiveLeafTests)
    (lib.nameValuePair "all" leafTests)
  ]
  ++ map (
    scenario:
    lib.nameValuePair "scenario:${scenario.id}" (
      map (leaf: leaf.id) (lib.filter (leaf: leaf.scenarioId == scenario.id) leafList)
    )
  ) scenarioList
  ++ map (
    profile:
    lib.nameValuePair "profile:${profile.id}" (
      map (leaf: leaf.id) (lib.filter (leaf: leaf.profileId == profile.id) leafList)
    )
  ) profileList;

  groups = builtins.listToAttrs groupEntries;
  availableTargets = leafTests ++ map (entry: entry.name) groupEntries;

  _assertUniqueLeafIds =
    if builtins.length leafTests == builtins.length (lib.unique leafTests) then
      true
    else
      throw "forensics-eval: duplicate scenario/profile leaf id detected";

  _assertDefaultLeafExists =
    if builtins.elem defaultLeafId leafTests then
      true
    else
      throw "forensics-eval: default scenario/profile combination is not available";
in
builtins.seq _assertUniqueLeafIds (
  builtins.seq _assertDefaultLeafExists {
    inherit
      canaries
      contracts
      defaults
      groups
      leaves
      leafTests
      profileIds
      profiles
      scenarioIds
      scenarios
      ;

    metadata = {
      inherit
        availableTargets
        groups
        leaves
        leafTests
        ;
      ci = ciLeafTests;
      defaults = defaults // {
        leafId = defaultLeafId;
      };
    };

    lib = {
      inherit
        sharedHelpers
        canaries
        contracts
        profileLib
        scenarioLib
        ;
    };
  }
)
