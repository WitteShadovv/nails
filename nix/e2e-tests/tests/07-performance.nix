# Placeholder for Story 13.8: Performance Validation Test
# This will be implemented in Story 13.8

{ self, pkgs, ... }: {
  name = "performance";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # Placeholder test - will be implemented in Story 13.8
    machine.succeed("true")
  '';
}
