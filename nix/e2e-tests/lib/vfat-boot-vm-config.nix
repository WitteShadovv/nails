{ lib, pkgs, ... }:
let
  blkidBin = lib.getExe' pkgs.util-linux "blkid";
  mkfsVfatBin = lib.getExe' pkgs.dosfstools "mkfs.vfat";
  mountBin = lib.getExe' pkgs.util-linux "mount";
  mountpointBin = lib.getExe' pkgs.util-linux "mountpoint";
in
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
      if ! ${blkidBin} /dev/vdc >/dev/null 2>&1; then
        ${mkfsVfatBin} -F 32 /dev/vdc
      fi

      mkdir -p /boot

      if ! ${mountpointBin} -q /boot; then
        ${mountBin} -t vfat /dev/vdc /boot
      fi
    '';
  };
}
