{ pkgs, canaries }:

let
  inherit (pkgs) lib;

  require = condition: message: if condition then true else throw message;

  isNonEmptyString = value: builtins.isString value && value != "";

  validateId =
    label: value:
    let
      matches = builtins.match "^[a-z][a-z0-9-]*$" value;
    in
    if isNonEmptyString value && matches != null then
      value
    else
      throw "forensics-eval: ${label} must match ^[a-z][a-z0-9-]*$, got ${builtins.toJSON value}";

  validateRunId =
    value:
    let
      matches = builtins.match "^[a-z0-9][a-z0-9._-]{7,63}$" value;
    in
    if isNonEmptyString value && matches != null then
      value
    else
      throw "forensics-eval: runId must match ^[a-z0-9][a-z0-9._-]{7,63}$, got ${builtins.toJSON value}";

  validateRelativePath =
    path:
    if !isNonEmptyString path then
      throw "forensics-eval: artifact path must be a non-empty string"
    else if lib.hasPrefix "/" path then
      throw "forensics-eval: artifact path must be relative, got ${path}"
    else if lib.hasInfix "../" path || lib.hasSuffix "/.." path || path == ".." then
      throw "forensics-eval: artifact path must not escape its bundle root, got ${path}"
    else
      path;

  mkArtifactMap =
    root: templates:
    lib.mapAttrs (
      _: relative:
      let
        checked = validateRelativePath relative;
      in
      {
        inherit checked;
        relative = checked;
        absolute = "${root}/${checked}";
      }
    ) templates;
in
rec {
  contractVersion = 1;

  inherit
    isNonEmptyString
    validateId
    validateRelativePath
    validateRunId
    ;

  freshRunIdPolicy = {
    required = true;
    reuseAllowed = false;
    runnerResponsibility = "The runner MUST mint a new runId for every execution attempt.";
    rationale = "Result bundles are append-only and are keyed by runId; collisions would corrupt subtraction and allowlist accounting.";
  };

  allowlistContract = {
    supported = true;
    format = "json";
    version = 1;
    requiredKeys = [
      "version"
      "rules"
    ];
    ruleKeys = [
      "id"
      "matcher"
      "value"
      "scope"
      "justification"
    ];
    supportedMatchers = [
      "exact-path"
      "path-prefix"
      "regex"
      "substring"
    ];
    supportedScopes = [
      "acquisition"
      "analysis"
      "both"
    ];
  };

  baselineContract = {
    supported = true;
    modes = [
      "none"
      "subtract-from-run"
    ];
    requiredWhenEnabled = [
      "mode"
      "runId"
    ];
    note = "Baseline subtraction is a runner/analyzer concern; this subsystem only standardizes the metadata and bundle slots.";
  };

  scenarioMetadataContract = {
    kind = "nails.forensics-eval.scenario-metadata";
    version = contractVersion;
    requiredKeys = [
      "kind"
      "version"
      "scenarioId"
      "profileId"
      "runId"
      "canaryNamespace"
      "allowlist"
      "baseline"
      "outputs"
      "runner"
    ];
  };

  resultBundleContract = {
    kind = "nails.forensics-eval.result-bundle";
    version = contractVersion;
    requiredKeys = [
      "kind"
      "version"
      "metadata"
      "paths"
      "acquisition"
      "analysis"
    ];
    separationRule = {
      acquisition = "Only runner-captured raw data and manifests belong here.";
      analysis = "Only analyzer-produced normalized outputs and findings belong here.";
    };
  };

  mkBundlePaths =
    {
      outputRoot,
      scenarioId,
      profileId,
      runId,
    }:
    let
      checkedScenarioId = validateId "scenarioId" scenarioId;
      checkedProfileId = validateId "profileId" profileId;
      checkedRunId = validateRunId runId;
      root = "${toString outputRoot}/${checkedScenarioId}/${checkedProfileId}/${checkedRunId}";
    in
    {
      inherit root;
      metadata = "${root}/metadata/scenario.json";
      acquisitionRoot = "${root}/acquisition";
      analysisRoot = "${root}/analysis";
      acquisitionManifest = "${root}/acquisition/manifest.json";
      analysisManifest = "${root}/analysis/manifest.json";
    };

  mkScenarioMetadata =
    {
      outputRoot,
      scenarioId,
      profileId,
      runId,
      canaryNamespace ? canaries.mkNamespace { inherit scenarioId profileId; },
      baseline ? null,
      allowlist ? null,
      runner ? { },
      extra ? { },
    }:
    let
      paths = mkBundlePaths {
        inherit
          outputRoot
          scenarioId
          profileId
          runId
          ;
      };
    in
    {
      inherit (scenarioMetadataContract) kind version;
      scenarioId = validateId "scenarioId" scenarioId;
      profileId = validateId "profileId" profileId;
      runId = validateRunId runId;
      inherit canaryNamespace;
      allowlist =
        if allowlist == null then
          {
            enabled = false;
            path = null;
          }
        else
          {
            enabled = true;
            path = toString allowlist;
            contract = allowlistContract;
          };
      baseline =
        if baseline == null then
          {
            enabled = false;
            mode = "none";
            runId = null;
            bundleRoot = null;
          }
        else
          {
            enabled = true;
            contract = baselineContract;
          }
          // baseline;
      outputs = {
        bundleRoot = paths.root;
        inherit (paths) metadata acquisitionRoot analysisRoot;
      };
      inherit runner;
    }
    // extra;

  mkResultBundle =
    {
      outputRoot,
      scenarioId,
      profileId,
      runId,
      metadata,
      acquisitionArtifacts ? { },
      analysisArtifacts ? { },
    }:
    let
      paths = mkBundlePaths {
        inherit
          outputRoot
          scenarioId
          profileId
          runId
          ;
      };
    in
    {
      inherit (resultBundleContract) kind version;
      inherit metadata paths;
      acquisition = {
        root = paths.acquisitionRoot;
        manifest = paths.acquisitionManifest;
        artifacts = mkArtifactMap paths.acquisitionRoot acquisitionArtifacts;
      };
      analysis = {
        root = paths.analysisRoot;
        manifest = paths.analysisManifest;
        artifacts = mkArtifactMap paths.analysisRoot analysisArtifacts;
      };
    };

  assertSupportedProfile =
    supportedProfileIds: profileId:
    require (lib.elem profileId supportedProfileIds) "forensics-eval: unsupported profileId ${profileId}";
}
