# Minimal impermanence module for E2E tests
# Simplified version to support basic persistence needs

{ lib, ... }:

{
  options.environment.persistence = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule (_: {
      options = {
        hideMounts = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Whether to hide mount points";
        };

        directories = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Directories to persist";
        };

        files = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Files to persist";
        };
      };
    }));
    default = { };
    description = "Persistent directories and files";
  };

  # For E2E tests, we don't need full impermanence implementation
  # The tests themselves handle creating the necessary structure
  config = { };
}
