{ sharedHelpers, profileLib }:

profileLib.mkProfile {
  id = "vfat-boot";
  displayName = "VFAT boot wrapper profile";
  description = ''
    Additive wrapper scaffold for future direct-acquisition runs that also need a
    VFAT-backed /boot device in the fixture.
  '';
  vmModule = sharedHelpers.vmModules.vfat-boot;
  acquisitionMode = "direct";
  inheritsFrom = [ "direct-headless" ];
  tags = [
    "future"
    "vfat"
  ];
  capabilities = {
    deterministicCanaries = true;
    baselineSubtraction = true;
    allowlist = true;
    graphicalSession = false;
    separateBootVolume = true;
  };
  runnerHints = {
    defaultScenarioId = "direct-baseline";
    bootDevice = "/dev/vdc";
    machineNodeFactory = "profile.buildMachineNode { ... }";
  };
}
