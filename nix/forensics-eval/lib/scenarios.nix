{
  pkgs,
  contracts,
  canaries,
}:

let
  inherit (pkgs) lib;
in
rec {
  scenarioContractVersion = 1;

  mkScenario =
    {
      id,
      displayName,
      description,
      defaultProfileId,
      supportedProfileIds ? [ defaultProfileId ],
      tags ? [ ],
      acquisition,
      runnerContract,
      resultBundle,
      mkRunPlan,
    }:
    {
      contractVersion = scenarioContractVersion;
      id = contracts.validateId "scenarioId" id;
      defaultProfileId = contracts.validateId "profileId" defaultProfileId;
      supportedProfileIds = map (contracts.validateId "profileId") supportedProfileIds;
      inherit
        acquisition
        description
        displayName
        resultBundle
        runnerContract
        tags
        ;

      defaultCanarySet = canaries.mkSet {
        scenarioId = id;
        profileId = defaultProfileId;
      };

      inherit mkRunPlan;
    };

  byId =
    scenarios: builtins.listToAttrs (map (scenario: lib.nameValuePair scenario.id scenario) scenarios);
}
