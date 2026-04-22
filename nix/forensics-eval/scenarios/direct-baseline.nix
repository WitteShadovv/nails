{
  contracts,
  canaries,
  profiles,
  scenarioLib,
}:

let
  scenarioId = "direct-baseline";

  acquisitionArtifacts = {
    metadata = "metadata/scenario.json";
    canaries = "metadata/canaries.json";
    baselineManifest = "captures/baseline/manifest.json";
    preActivationSnapshot = "captures/baseline/pre-activation.json";
    postDeactivationSnapshot = "captures/post-deactivation/snapshot.json";
    mountState = "captures/post-deactivation/mounts.txt";
    commandCaptures = "captures/commands";
  };

  analysisArtifacts = {
    findings = "findings/findings.json";
    baselineSubtraction = "findings/baseline-subtraction.json";
    allowlistApplied = "findings/allowlist-applied.json";
    analyzerSummary = "findings/summary.json";
  };

  mkRunPlan =
    {
      outputRoot,
      runId,
      profileId ? "direct-headless",
      lane ? "default",
      baseline ? null,
      allowlist ? null,
      runner ? { },
      extraMetadata ? { },
    }:
    let
      profile = builtins.seq (contracts.assertSupportedProfile [
        "direct-headless"
        "graphical"
        "vfat-boot"
      ] profileId) profiles.${profileId};
      canarySet = canaries.mkSet {
        inherit lane profileId scenarioId;
      };
      metadata = contracts.mkScenarioMetadata {
        inherit
          allowlist
          baseline
          outputRoot
          profileId
          runId
          runner
          scenarioId
          ;
        canaryNamespace = canarySet.namespace;
        extra = extraMetadata;
      };
      bundle = contracts.mkResultBundle {
        inherit
          metadata
          outputRoot
          profileId
          runId
          scenarioId
          ;
        inherit acquisitionArtifacts analysisArtifacts;
      };
    in
    {
      inherit
        bundle
        canarySet
        metadata
        profile
        ;

      # The runner may materialize this attrset as JSON for its executable entrypoint.
      runnerManifest = {
        inherit scenarioId profileId runId;
        bundleRoot = bundle.paths.root;
        inherit (bundle.paths) acquisitionManifest analysisManifest;
        deferredToRunner = [
          "VM startup and teardown"
          "Command execution inside the test harness"
          "JSON serialization of metadata and manifests"
          "Analyzer invocation and findings emission"
        ];
      };
    };
in
scenarioLib.mkScenario {
  id = scenarioId;
  displayName = "Direct baseline leak evaluation";
  description = ''
    Foundation scenario for the new forensic leak-evaluation pipeline. It captures
    baseline and post-deactivation acquisition outputs, while reserving a separate
    analysis subtree for later analyzer workstreams.
  '';
  defaultProfileId = "direct-headless";
  supportedProfileIds = [
    "direct-headless"
    "graphical"
    "vfat-boot"
  ];
  tags = [
    "baseline"
    "direct"
    "forensics"
  ];

  acquisition = {
    mode = "direct";
    networkFidelityInScope = false;
    supportsBaselineSubtraction = true;
    supportsAllowlist = true;
    requiresFreshRunId = true;
    phases = [
      {
        id = "capture-baseline";
        purpose = "Capture clean-state data before hidden-side activity.";
      }
      {
        id = "plant-deterministic-canaries";
        purpose = "Use the stable canary namespace to create comparable artifacts across runs.";
      }
      {
        id = "capture-post-deactivation";
        purpose = "Collect post-deactivation raw artifacts for later subtraction and analysis.";
      }
    ];
  };

  runnerContract = {
    entrypoint = {
      kind = "manifest-driven";
      requiredInputs = [
        "outputRoot"
        "runId"
      ];
      optionalInputs = [
        "profileId"
        "baseline"
        "allowlist"
        "runner"
        "extraMetadata"
      ];
      entryExpression = ''
        (import ./nix/forensics-eval { inherit pkgs self; }).scenarios.direct-baseline.mkRunPlan { ... }
      '';
    };
    requiredBehavior = [
      "The runner MUST provide a fresh runId for every execution attempt."
      "The runner MUST write raw captures only under bundle.acquisition.root."
      "The runner MUST write analyzer outputs only under bundle.analysis.root."
      "The runner SHOULD persist metadata to bundle.paths.metadata before invoking analyzers."
    ];
  };

  resultBundle = {
    contract = contracts.resultBundleContract;
    inherit acquisitionArtifacts analysisArtifacts;
  };

  inherit mkRunPlan;
}
