# Base VM Configuration for E2E Tests
# Simplified: let NixOS test framework handle boot/filesystems
# Secondary disk (/dev/vdb) is available for LUKS hidden volume testing

{ lib, pkgs, ... }: {
  # Virtual hardware configuration
  virtualisation = {
    memorySize = 4096; # 4GB RAM
    cores = 4; # 4 CPU cores
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
