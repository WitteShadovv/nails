{
  pkgs,
  sharedHelpers,
  contracts,
}:

let
  inherit (pkgs) lib;
in
rec {
  profileContractVersion = 1;

  mkProfile =
    {
      id,
      displayName,
      description,
      vmModule,
      acquisitionMode ? "direct",
      inheritsFrom ? [ ],
      capabilities ? { },
      runnerHints ? { },
      tags ? [ ],
    }:
    {
      contractVersion = profileContractVersion;
      id = contracts.validateId "profileId" id;
      inherit
        acquisitionMode
        capabilities
        description
        displayName
        inheritsFrom
        runnerHints
        tags
        vmModule
        ;

      buildMachineNode = args: sharedHelpers.buildMachineNode ({ inherit vmModule; } // args);
    };

  byId =
    profiles: builtins.listToAttrs (map (profile: lib.nameValuePair profile.id profile) profiles);

  get =
    profiles: id:
    if builtins.hasAttr id profiles then
      profiles.${id}
    else
      throw "forensics-eval: unknown profile ${id}";
}
