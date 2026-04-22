{ sharedHelpers, profileLib }:

profileLib.mkProfile {
  id = "graphical";
  displayName = "Graphical wrapper profile";
  description = ''
    Additive wrapper scaffold for future graphical forensics runs. It reuses the
    existing graphical VM fixture without changing the legacy E2E tree.
  '';
  vmModule = sharedHelpers.vmModules.graphical;
  acquisitionMode = "direct";
  inheritsFrom = [ "direct-headless" ];
  tags = [
    "future"
    "graphical"
  ];
  capabilities = {
    deterministicCanaries = true;
    baselineSubtraction = true;
    allowlist = true;
    graphicalSession = true;
    separateBootVolume = false;
  };
  runnerHints = {
    defaultScenarioId = "direct-baseline";
    sessionModel = "display-manager";
    machineNodeFactory = "profile.buildMachineNode { ... }";
  };
}
