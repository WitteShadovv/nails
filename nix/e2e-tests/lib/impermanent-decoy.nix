# Impermanent decoy profile: a volatile tmpfs root over an on-disk Nix store,
# with a /persist volume holding only the state a NixOS host must keep.
#
# Rationale: a hidden session is meant to leave nothing on the decoy that a later
# forensic read of the disk could find. A persistent decoy root makes that hard
# to test honestly, because ordinary boot noise and NAILS residue look alike. An
# impermanence layout makes the test sharp: the decoy `/` is a tmpfs that is
# wiped on every power-off, and only /nix (the store image) and /var/lib/nixos
# are persisted. Anything NAILS fails to contain on the decoy root is therefore
# gone after a reboot unless it reached one of the persisted trees, where it
# stands out as drift against the pre-activation baseline.
#
# A real impermanent host would also keep /etc/nixos, but in these VMs /etc/nixos
# is store-backed (vm-config.nix supplies it through environment.etc) and NixOS
# regenerates it into the tmpfs /etc on every boot, so it needs no persistence —
# and binding an empty /persist over it would hide the fixture the hidden flake
# imports. Only /var/lib/nixos, the tree switch-to-configuration actually
# rewrites, is persisted here.
#
# This builds on forensic-vm-config.nix, which already gives the guest its own
# on-disk, non-tmpfs Nix store image (useNixStoreImage = true,
# writableStoreUseTmpfs = false) and an imageable root disk for the host-side
# disk-image checks. On top of that it makes `/` itself a tmpfs and persists the
# handful of state trees, and switches the journal to volatile so a forensic
# journal carve sees only what a hidden session forced onto a persisted tree.
#
# DEFERRED (evaluate on a Nix host): the tmpfs-root override, the /persist disk
# and its early-boot bind mounts, and offline closure completeness for anything
# built against this profile can only be confirmed by `nix build` of a test that
# imports it — none of it can be evaluated in the offline sandbox.
{ lib, ... }:
{
  imports = [ ./forensic-vm-config.nix ];

  virtualisation = {
    # A second empty disk (/dev/vdc) backs /persist; /dev/vdb stays the hidden
    # LUKS volume from vm-config.nix. mkForce because vm-config.nix already
    # assigns emptyDiskImages.
    emptyDiskImages = lib.mkForce [
      2048
      2048
    ];

    # The decoy root is a tmpfs: every write that is not explicitly persisted
    # below vanishes on power-off. mkForce overrides the qemu-vm root device.
    fileSystems."/" = lib.mkForce {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [ "mode=0755" ];
    };

    # The persistent volume for the trees that must outlive the tmpfs root. It is
    # needed before the bind mounts below, so it mounts early.
    fileSystems."/persist" = {
      device = "/dev/vdc";
      fsType = "ext4";
      autoFormat = true;
      neededForBoot = true;
    };
  };

  # Persist the one tree switch-to-configuration rewrites. This bind is the only
  # non-store write that survives a power-off, so a forensic diff of
  # /persist/var/lib/nixos after deactivation is the decoy's real drift.
  #
  # It is left out of the stage-1 (neededForBoot) set so it mounts in stage-2 —
  # by then postMountCommands below has created its source on the freshly
  # formatted /persist, avoiding the bind-before-source chicken-and-egg.
  fileSystems."/var/lib/nixos" = {
    device = "/persist/var/lib/nixos";
    options = [ "bind" ];
    depends = [ "/persist" ];
  };

  # /persist is mounted under /mnt-root in stage-1 (neededForBoot); create the
  # bind source there before stage-2 sets up the bind above. postMountCommands is
  # a scripted-stage-1 hook that systemd stage-1 (the test driver's default)
  # rejects, so pin this VM to the scripted initrd, which this hook needs.
  boot.initrd.systemd.enable = lib.mkForce false;
  boot.initrd.postMountCommands = ''
    mkdir -p /mnt-root/persist/var/lib/nixos
  '';

  # A volatile journal: the decoy journal lives only in RAM, so a journal carve
  # of the image sees only lines a hidden session forced onto a persisted tree.
  # mkForce overrides the persistent journal forensic-vm-config.nix sets.
  services.journald.extraConfig = lib.mkForce "Storage=volatile";
}
