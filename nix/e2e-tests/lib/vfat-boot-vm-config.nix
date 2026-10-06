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
    {
      size = 2048;
      driveConfig.deviceExtraOpts.serial = "data";
    }
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
        # strictatime so a plain read updates the access time: this makes the
        # snapshot-pivot atime regression guard in overlay/70 meaningful (an
        # O_NOATIME read must leave it untouched).
        ${mountBin} -t vfat -o strictatime /dev/vdc /boot
      fi
    '';
  };
}
