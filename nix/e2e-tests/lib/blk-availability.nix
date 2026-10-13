# The blk-availability.service Debian and Ubuntu enable wherever dmsetup is
# installed (lvm2's unit, with store paths for /usr/bin/true and
# /usr/sbin/blkdeactivate). Its stop runs `blkdeactivate -u`, which unmounts
# every filesystem on a device-mapper device that is not mounted on one of a
# few system paths (/, /usr, /var, ...) and then deactivates the device. Every
# soft-reboot stops it, so on such a decoy it would unmount what the switch
# needs below /run/nextroot; NAILS clears its stop for the session.
#
# NixOS already links lvm2's own copy of the unit, disabled, whose ExecStop=
# names lvm2's `bin` output while nixpkgs ships the script in `scripts`. The
# definition below lands as a drop-in on it, `overrides.conf`; the stop
# command comes from a drop-in of its own all the same. systemd applies every
# drop-in in the order of its file name; NAILS's guard,
# `zz-overlay-runtime.conf`, sorts after both, and on Debian the command is in
# the unit file itself, before any drop-in, which `10-blkdeactivate.conf`
# mirrors. blkdeactivate runs umount, lsblk, findmnt, mountpoint, dmsetup and lvm
# by store path; grep is the one tool it takes from PATH, and with it the
# script unmounts with `umount --all-targets`, as on Debian.
{ pkgs, ... }:
{
  systemd.packages = [
    (pkgs.writeTextDir "lib/systemd/system/blk-availability.service.d/10-blkdeactivate.conf" ''
      [Service]
      ExecStop=
      ExecStop=${pkgs.lvm2.scripts}/bin/blkdeactivate -u -l wholevg -m disablequeueing -r wait
    '')
  ];

  systemd.services.blk-availability = {
    description = "Availability of block devices";
    before = [ "shutdown.target" ];
    after = [
      "iscsi-shutdown.service"
      "iscsi.service"
      "iscsid.service"
      "fcoe.service"
      "rbdmap.service"
    ];
    conflicts = [ "shutdown.target" ];
    wantedBy = [ "sysinit.target" ];
    unitConfig.DefaultDependencies = false;
    path = [ pkgs.gnugrep ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = [
        ""
        "${pkgs.coreutils}/bin/true"
      ];
    };
  };
}
