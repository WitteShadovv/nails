{
  pkgs,
  self ? null,
}:

let
  inherit (pkgs) lib;
  e2eLibRoot = ../../e2e-tests/lib;

  imports = {
    assertions = import (e2eLibRoot + "/assertions.nix");
    contractHelpers = import (e2eLibRoot + "/contract-helpers.nix");
    hiddenVolume = import (e2eLibRoot + "/hidden-volume.nix");
    preflightHelpers = import (e2eLibRoot + "/preflight-helpers.nix");
    sessionHelpers = import (e2eLibRoot + "/session-helpers.nix");
    stateHelpers = import (e2eLibRoot + "/state-helpers.nix");
    testHelpers = import (e2eLibRoot + "/test-helpers.nix");
  };
in
rec {
  inherit e2eLibRoot imports;

  vmModules = {
    direct-headless = e2eLibRoot + "/vm-config.nix";
    graphical = e2eLibRoot + "/graphical-vm-config.nix";
    vfat-boot = e2eLibRoot + "/vfat-boot-vm-config.nix";
  };

  inherit (imports) hiddenVolume;

  pythonFns = lib.foldl' lib.recursiveUpdate { } [
    imports.assertions
    imports.contractHelpers
    imports.preflightHelpers
    imports.sessionHelpers
    imports.stateHelpers
    imports.testHelpers
  ];

  buildMachineNode =
    {
      vmModule,
      extraImports ? [ ],
      extraConfig ? { },
      includeNailsPackage ? self != null,
      system ? pkgs.system,
    }:
    _:
    (
      {
        imports = [ vmModule ] ++ extraImports;
      }
      // lib.optionalAttrs includeNailsPackage {
        environment.systemPackages = [ self.packages.${system}.nails ];
      }
      // extraConfig
    );
}
