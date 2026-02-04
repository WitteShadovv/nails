# Base VM Configuration for E2E Tests
# Fully configured for Story 13.2 with impermanence

{ config, lib, pkgs, ... }: {
  # Virtual hardware configuration
  virtualisation = {
    memorySize = 4096; # 4GB RAM
    cores = 4; # 4 CPU cores
    diskSize = 20480; # 20GB primary disk (default)

    # Secondary disk for hidden volume simulation (2GB)
    emptyDiskImages = [ 2048 ];

    # Boot configuration
    useBootLoader = true;
    useEFIBoot = true; # UEFI boot mode
    mountHostNixStore = true; # Mount host's /nix/store for performance
  };

  # Impermanence module configuration
  imports = [ (import ./impermanence.nix) ];

  # Filesystem configuration
  fileSystems = {
    # Root filesystem is tmpfs (ephemeral)
    "/" = {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [ "defaults" "size=4G" "mode=755" ];
    };

    # /nix on persistent storage (needed for boot)
    "/nix" = {
      device = "/dev/disk/by-label/nix";
      fsType = "ext4";
      options = [ "defaults" ];
      neededForBoot = true;
    };

    # /persist on persistent storage (needed for boot)
    "/persist" = {
      device = "/dev/disk/by-label/persist";
      fsType = "ext4";
      options = [ "defaults" ];
      neededForBoot = true;
    };
  };

  # Ensure disks are labeled for the mount points above
  boot.initrd.services.udev.rules = ''
    ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="*disk1", SYMLINK+="disk/by-label/nix%n"
    ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_SERIAL}=="*disk2", SYMLINK+="disk/by-label/persist%n"
  '';

  # Impermanence: persistent directories and files
  environment.persistence."/persist" = {
    hideMounts = true;
    directories = [
      "/var/log"
      "/var/lib/nixos"
      "/var/lib/systemd"
    ];
    files = [
      "/etc/machine-id"
    ];
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

  # Disable firewall for simpler testing
  networking.firewall.enable = false;

  # Enable SSH for debugging (optional)
  services.openssh.enable = true;

  # System configuration
  system.stateVersion = "24.11";
}
