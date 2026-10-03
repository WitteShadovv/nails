{
  description = "NAILS real-rebuild E2E hidden configuration";

  # @nixpkgs@ is replaced at test time with a `path:` reference to the guest's
  # seeded nixpkgs (virtualisation.additionalPaths), so the hidden toplevel
  # builds fully offline with no substituters configured.
  inputs.nixpkgs.url = "@nixpkgs@";

  outputs =
    { nixpkgs, ... }:
    {
      nixosConfigurations.nails-e2e = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          # Import the decoy's own configuration so the hidden toplevel's closure
          # is already present in the guest store and nothing has to be fetched.
          /etc/nixos/configuration.nix
          ./module.nix
        ];
      };
    };
}
