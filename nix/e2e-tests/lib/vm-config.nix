# Base VM Configuration for E2E Tests
# Simplified: let NixOS test framework handle boot/filesystems
# Secondary disk (/dev/vdb) is available for LUKS hidden volume testing

{ lib, pkgs, ... }:
let
  # CI computes a safe per-VM core count automatically and exports it through
  # NAILS_E2E_VM_CORES before each NixOS test build. Because this value is read
  # with builtins.getEnv, the corresponding flake build must opt into impure
  # evaluation at that call site. Keep the local fallback at 4 cores so ad-hoc
  # runs behave as they did previously.
  vmCoresEnv = builtins.getEnv "NAILS_E2E_VM_CORES";
  vmCores =
    if builtins.match "[1-9][0-9]*" vmCoresEnv != null then builtins.fromJSON vmCoresEnv else 4;
in
{
  # Virtual hardware configuration
  virtualisation = {
    memorySize = 4096; # 4GB RAM
    cores = vmCores;
    diskSize = 20480; # 20GB primary disk

    # Secondary disk for hidden volume simulation (2GB)
    # Available as /dev/vdb inside the VM
    emptyDiskImages = [ 2048 ];

    # Keeping restrictNetwork = false is harmless and avoids the QEMU "-net none"
    # flag that can interfere with the test framework's own virtual network.
    restrictNetwork = false;
  };

  # No swap for forensic safety
  swapDevices = lib.mkForce [ ];

  # Test user with sudo privileges
  users.users.testuser = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    initialPassword = "test";
  };

  # Allow sudo without password for testing
  security.sudo.wheelNeedsPassword = false;

  # Required tools for testing
  environment.systemPackages = with pkgs; [
    tree # For directory structure inspection
    findutils # For file searching
    diffutils # For comparing files
    cryptsetup # For LUKS operations
    sleuthkit # For forensic analysis (fls, etc.)
    coreutils # Basic utilities
    util-linux # For mount operations
  ];

  # Provide a baseline /etc/nixos tree matching a normal NixOS install.
  # Several activation/preflight tests exercise the product's current
  # contract around base configuration discovery and hidden hardware-config
  # bootstrapping, so the VM fixture must expose these files up front.
  environment.etc = {
    "nixos/configuration.nix".text = ''
      { ... }: {
        imports = [ /etc/nixos/hardware-configuration.nix ];
        boot.loader.grub.enable = false;
        documentation.nixos.enable = false;
        fileSystems."/" = {
          device = "/dev/disk/by-label/nixos";
          fsType = "ext4";
        };
        system.stateVersion = "25.11";
      }
    '';

    "nixos/hardware-configuration.nix".text = ''
      { ... }: {
        imports = [ ];
      }
    '';
  };

  # Mirror the normal legacy NixOS rebuild environment so tests exercising
  # `nixos-rebuild test -I nixos-config=...` do not fail for unrelated fixture
  # reasons when the VM lacks channel-based defaults.
  nix.nixPath = [
    "nixpkgs=${pkgs.path}"
    "nixos-config=/etc/nixos/configuration.nix"
  ];

  # Networking: disable firewall, basic config for test framework management connection
  networking = {
    firewall.enable = false;
    usePredictableInterfaceNames = false;
    useDHCP = true;
  };

  # Enable SSH for debugging (optional)
  services.openssh.enable = true;

  # System configuration
  system.stateVersion = "25.11";
}
