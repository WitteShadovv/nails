# The two units that implement `systemctl soft-reboot` (systemd 254+).
#
# The pinned nixpkgs ships systemd 259 but does not install soft-reboot.target
# and systemd-soft-reboot.service; nixpkgs PR #514100 (merged 2026-05-14) adds
# them to upstreamSystemUnits. NAILS enters and leaves the hidden session with a
# soft-reboot, so every decoy (and every hidden NixOS configuration) needs them;
# `nails check` refuses a host without them and prints this module's text.
#
# The text is the upstream v259 unit text. It is declared through
# systemd.units rather than additionalUpstreamSystemUnits: a duplicate entry
# there breaks the unit build once nixpkgs ships the units itself, whereas
# systemd.units then turns into a harmless drop-in.
_: {
  systemd.units = {
    "soft-reboot.target".text = ''
      [Unit]
      Description=Reboot System Userspace
      Documentation=man:systemd.special(7)
      DefaultDependencies=no
      Requires=systemd-soft-reboot.service
      After=systemd-soft-reboot.service
      AllowIsolate=yes
      JobTimeoutSec=30min
      JobTimeoutAction=soft-reboot-force
    '';
    "systemd-soft-reboot.service".text = ''
      [Unit]
      Description=Reboot System Userspace
      Documentation=man:systemd-soft-reboot.service(8)
      DefaultDependencies=no
      Requires=shutdown.target umount.target final.target
      After=shutdown.target umount.target final.target
      SuccessAction=soft-reboot-force
    '';
  };
}
