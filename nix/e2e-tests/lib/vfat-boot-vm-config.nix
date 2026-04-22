{ lib, pkgs, ... }:
{
  imports = [ ./vm-config.nix ];

  swapDevices = lib.mkForce [ ];

  boot.supportedFilesystems = [ "vfat" ];

  virtualisation.emptyDiskImages = lib.mkForce [
    2048
    256
  ];

  environment.systemPackages = with pkgs; [ dosfstools ];

  systemd.services.nails-vfat-boot-setup = {
    description = "Prepare VFAT /boot for E2E pivot tests";
    wantedBy = [ "multi-user.target" ];
    before = [ "multi-user.target" ];
    after = [ "local-fs.target" ];
    path = with pkgs; [
      coreutils
      dosfstools
      util-linux
    ];
    serviceConfig.Type = "oneshot";
    script = ''
      if ! blkid /dev/vdc >/dev/null 2>&1; then
        mkfs.vfat -F 32 /dev/vdc
      fi

      mkdir -p /boot

      if ! mountpoint -q /boot; then
        mount -t vfat /dev/vdc /boot
      fi
    '';
  };
}
