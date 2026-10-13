# Base VM Configuration for E2E Tests
# Simplified: let NixOS test framework handle boot/filesystems
# Secondary disk (serial "data", /dev/disk/by-id/virtio-data) is available for LUKS hidden volume testing

{ lib, pkgs, ... }:
{
  # NAILS enters and leaves the hidden session with `systemctl soft-reboot`.
  imports = [ ./soft-reboot-units.nix ];

  # Virtual hardware configuration
  virtualisation = {
    # Fixed rather than sized to the host, so that a test's derivation, and
    # the cached result of a passed test, is the same on every machine and
    # no build needs --impure. Two cores and 2 GB let two VMs share a
    # four-vCPU, 16 GB hosted runner; graphical nodes get 4 GB in
    # graphical-vm-config.nix.
    memorySize = 2048;
    cores = 2;
    diskSize = 20480; # 20GB primary disk

    # Secondary disk for hidden volume simulation (2GB). It carries the neutral
    # serial "data", so the guest addresses it as /dev/disk/by-id/virtio-data:
    # its /dev/vdX letter shifts when a profile adds a Nix store image disk.
    emptyDiskImages = [
      {
        size = 2048;
        driveConfig.deviceExtraOpts.serial = "data";
      }
    ];

    # Keeping restrictNetwork = false is harmless and avoids the QEMU "-net none"
    # flag that can interfere with the test framework's own virtual network.
    restrictNetwork = false;
  };

  # No swap for forensic safety
  swapDevices = lib.mkForce [ ];

  # Model an amnesic decoy: journald keeps no persistent journal on the decoy
  # disk, so the decoy-persistence pre-flight check passes and the E2E suite
  # exercises the supported posture. A test that wants to exercise the refusal
  # path overrides this back to "persistent".
  services.journald.settings.Journal.Storage = lib.mkDefault "volatile";

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
    psmisc # fuser, for listing processes that keep a mount or backend busy
  ];

  # Provide a baseline /etc/nixos tree matching a normal NixOS install.
  # Several activation/preflight tests exercise the product's current
  # contract around base configuration discovery and hidden hardware-config
  # bootstrapping, so the VM fixture must expose these files up front.
  #
  # An explicit mode makes NixOS copy these as regular files into /etc. Without
  # it, environment.etc stores the content under /etc/static and links /etc/nixos
  # entries to it, which a real install never does and which some tests (and the
  # forensic baseline) must not see: a stock /etc/nixos/*.nix is a plain file.
  environment.etc = {
    "nixos/configuration.nix" = {
      mode = "0644";
      text = ''
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
    };

    "nixos/hardware-configuration.nix" = {
      mode = "0644";
      text = ''
        { ... }: {
          imports = [ ];
        }
      '';
    };
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
    # dhcpcd's default (wait = "any") holds multi-user.target until the QEMU
    # user-mode network hands out a lease, which took about 6 s of every
    # boot's 17 s in the driver logs. No test needs that address before
    # multi-user: the test driver talks over its virtio-console backdoor and
    # multi-machine tests use the static VLAN addresses on eth1. dhcpcd still
    # runs and still configures eth0; it just no longer gates the boot.
    dhcpcd.wait = "background";
  };

  # No sshd: the driver reaches the guest over its backdoor shell (and
  # `machine.shell_interact()` covers debugging), so sshd only cost a
  # 4096-bit RSA host key generation on every first boot and a listening
  # socket no test uses.
  services.openssh.enable = false;

  # System configuration
  system.stateVersion = "25.11";
}
