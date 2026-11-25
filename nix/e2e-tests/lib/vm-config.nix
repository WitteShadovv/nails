# SPDX-FileCopyrightText: 2025-2026 WitteShadovv
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Base VM Configuration for E2E Tests
# Simplified: let NixOS test framework handle boot/filesystems
# Secondary disk (serial "data", /dev/disk/by-id/virtio-data) is available for LUKS hidden volume testing

{
  config,
  lib,
  pkgs,
  ...
}:
{
  # Reports what PID 1 waits on when a switch or a power-off never ends.
  imports = [ ./stall-report.nix ];

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

  # The QEMU VM module registers the VM's store paths (the closure that
  # regInfo= on the kernel command line names) from register-nix-paths.service,
  # which sysinit.target pulls in at every start of the service manager, the
  # one after a soft-reboot included. Run again on the decoy after it collected
  # garbage, it puts the collected paths back into the decoy's store database,
  # a change no session made. The registration belongs to the boot: a marker in
  # /run, which a soft-reboot carries over, keeps it to the first start.
  #
  # Opening the store makes Nix create /nix/var/nix/temproots again, which
  # NixOS deletes at every start of the service manager (the boot-only tmpfiles
  # rule `R! /nix/var/nix/temproots`), the start after the way back included.
  # Left unordered, the registration ran after that clean-up, so every boot
  # ended with the directory on the decoy disk and only the way back, where
  # the marker skips the registration, without it: the oracle read that as a
  # removal no reboot makes. Run before the clean-up, a boot ends without the
  # directory, as on a decoy that has no such unit, until a Nix client runs.
  systemd.services.register-nix-paths = lib.mkIf config.nix.enable {
    before = [ "systemd-tmpfiles-setup.service" ];
    unitConfig.ConditionPathExists = "!/run/register-nix-paths.done";
    serviceConfig.ExecStartPost = "${pkgs.coreutils}/bin/touch /run/register-nix-paths.done";
  };

  # The block-write oracle's cut (nix/e2e-tests/py/nails_e2e/blockwrites.py):
  # at every start of the service manager after 8 s of uptime (a soft-reboot
  # into the hidden root, or back to the decoy; a cold boot reaches it sooner),
  # print a hold line on the serial console the driver reads, each second,
  # and wait, at most 15 s, for the line the host types on that console once
  # it has cut the dirty bitmaps it keeps of the decoy disk. Ordered
  # before the units that write to the disk early in a start, so what the
  # decoy's own start writes after the way back lands after the cut. It writes
  # nothing but the two lines.
  systemd.services.blkstat-mark = {
    description = "Boot marker";
    unitConfig.DefaultDependencies = false;
    wantedBy = [ "sysinit.target" ];
    before = [
      "sysinit.target"
      # journald opens the decoy's persistent journal as it starts, a write
      # that would otherwise land before the cut of the way back.
      "systemd-journald.service"
      "local-fs-pre.target"
      "systemd-fsck-root.service"
      "systemd-remount-fs.service"
      "systemd-random-seed.service"
      "systemd-tmpfiles-setup.service"
      "systemd-journal-flush.service"
      "systemd-update-utmp.service"
    ];
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "null";
      StandardError = "null";
      # A backstop: no mark may hold a start for longer.
      TimeoutStartSec = "30s";
    };
    script = ''
      read -r up _ < /proc/uptime
      if [ "''${up%%.*}" -ge 8 ]; then
        # The console is opened in a child, which is no session leader: the
        # service itself is one, and the console would become its controlling
        # terminal, which the kernel hangs up for every process that has it
        # open (the test backdoor's stderr among them) when the service ends.
        # The kernel can cut a line in two with one of its own, so the hold
        # line is said again each second until the host answers.
        (
          exec 3<>/dev/ttyS0
          i=0
          while [ "$i" -lt 15 ]; do
            echo 'blkstat-mark hold' >&3
            if line=$(timeout --foreground 1 head -n 1 <&3); then
              # Before it cuts a plain soft-reboot, the host asks for a flush,
              # so what the decoy's stop jobs left in the page cache counts.
              case "$line" in
                *blkstat-sync*)
                  sync
                  echo 'blkstat-mark synced' >&3
                  i=0
                  continue
                  ;;
              esac
              break
            fi
            i=$((i + 1))
          done
          echo 'blkstat-mark release' >&3
        ) &
        wait "$!"
      fi
    '';
  };

  # The block-write oracle counts a discard only where the drive passes it on:
  # QEMU drops it at the drive otherwise. drive1 is the root disk.
  virtualisation.qemu.options = lib.mkIf (config.virtualisation.diskImage != null) [
    "-set drive.drive1.discard=unmap"
  ];

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
  #
  # configuration.nix keeps the comment nixos-generate-config writes above
  # system.stateVersion. It holds the word "data", the mapping name of the
  # hidden volume these tests open, and a stock decoy must still pass the
  # check that refuses an /etc/nixos naming the hidden volume.
  environment.etc = {
    # The stateVersion comment below is the configuration.nix template from
    # Nixpkgs, under its MIT licence.
    # SPDX-SnippetBegin
    # SPDX-SnippetCopyrightText: Eelco Dolstra and the Nixpkgs/NixOS contributors
    # SPDX-License-Identifier: MIT
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

          # This option defines the first version of NixOS you have installed on this particular machine,
          # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
          #
          # Most users should NEVER change this value after the initial install, for any reason,
          # even if you've upgraded your system to a new NixOS release.
          #
          # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
          # so changing it will NOT upgrade your system - see https://nixos.org/manual/nixos/stable/#sec-upgrading for how
          # to actually do that.
          #
          # This value being lower than the current NixOS release does NOT mean your system is
          # out of date, out of support, or vulnerable.
          #
          # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
          # and migrated your data accordingly.
          #
          # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
          system.stateVersion = "25.11"; # Did you read the comment?
        }
      '';
    };
    # SPDX-SnippetEnd

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
