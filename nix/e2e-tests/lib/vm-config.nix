# Base VM Configuration for E2E Tests
# Fully configured for Story 13.2 requirements

{ lib, pkgs, ... }: {
  # Virtual hardware configuration
  virtualisation = {
    memorySize = 4096; # 4GB RAM
    cores = 4; # 4 CPU cores
    diskSize = 20480; # 20GB primary disk (default)

    # Boot configuration
    useBootLoader = true;
    useEFIBoot = true; # UEFI boot mode
  };

  # No swap for forensic safety
  swapDevices = lib.mkForce [ ];

  # Test user with sudo privileges
  users.users.testuser = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };

  # Allow sudo without password for testing
  security.sudo.wheelNeedsPassword = false;

  # Required tools for testing
  environment.systemPackages = with pkgs; [
    tree # For directory structure inspection
    findutils # For file searching
    cryptsetup # For LUKS operations
    sleuthkit # For forensic analysis (fls, etc.)
    coreutils # Basic utilities
    util-linux # For mount operations
  ];

  # Disable firewall for simpler testing
  networking.firewall.enable = false;

  # Enable SSH for debugging (optional)
  services.openssh.enable = true;

  # System configuration
  system.stateVersion = "24.11";
}
