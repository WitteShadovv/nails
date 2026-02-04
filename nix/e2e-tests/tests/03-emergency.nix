# Placeholder for Story 13.5: Emergency Deactivation Test
# This will be implemented in Story 13.5

{ self, pkgs, ... }: {
  name = "emergency";

  nodes = {
    machine = { ... }: {
      imports = [ ./../lib/vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # Placeholder test - will be implemented in Story 13.5
    machine.succeed("true")
  '';
}
