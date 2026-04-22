{ sharedHelpers, profileLib }:

profileLib.mkProfile {
  id = "direct-headless";
  displayName = "Direct headless baseline";
  description = ''
    Baseline direct-acquisition profile. This is the mandatory profile id that the
    first runner integration should target.
  '';
  vmModule = sharedHelpers.vmModules.direct-headless;
  acquisitionMode = "direct";
  tags = [
    "baseline"
    "headless"
  ];
  capabilities = {
    deterministicCanaries = true;
    baselineSubtraction = true;
    allowlist = true;
    graphicalSession = false;
    separateBootVolume = false;
  };
  runnerHints = {
    defaultScenarioId = "direct-baseline";
    hiddenVolumeDevice = "/dev/vdb";
    hiddenVolumeHelper = sharedHelpers.hiddenVolume;
    machineNodeFactory = "profile.buildMachineNode { ... }";
  };
}
