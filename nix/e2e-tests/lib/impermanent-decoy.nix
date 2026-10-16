# Impermanent decoy profile: a volatile tmpfs root over an on-disk Nix store,
# with a /persist volume holding only the state a NixOS host must keep.
#
# The whole-root session needs the decoy root as the lower of its overlay, so
# NAILS refuses a tmpfs root (the decoy-root pre-flight check):
# tests/forensic/10-impermanent-decoy.nix uses this profile to prove that
# `nails check` and `nails activate` refuse such a host and leave nothing
# behind, neither in /run nor on the persisted trees.
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
{ lib, pkgs, ... }:
{
  imports = [ ./forensic-vm-config.nix ];

  virtualisation = {
    # A second empty disk backs /persist; the first stays the hidden LUKS volume
    # from vm-config.nix. Both are addressed by serial: the store image disk of
    # this profile shifts their /dev/vdX letters. mkForce because vm-config.nix
    # already assigns emptyDiskImages.
    emptyDiskImages = lib.mkForce [
      {
        size = 2048;
        driveConfig.deviceExtraOpts.serial = "data";
      }
      {
        size = 2048;
        driveConfig.deviceExtraOpts.serial = "persist";
      }
    ];

    # Declared as one attrset so the three mounts share the `fileSystems` key.
    # They must live under `virtualisation.fileSystems`, not a top-level
    # `fileSystems`: the qemu-vm module replaces `fileSystems` with
    # `mkVMOverride virtualisation.fileSystems`, so a top-level entry is dropped
    # and would never be created.
    fileSystems = {
      # The decoy root is a tmpfs: every write that is not explicitly persisted
      # below vanishes on power-off. mkForce overrides the qemu-vm root device.
      "/" = lib.mkForce {
        device = "tmpfs";
        fsType = "tmpfs";
        options = [ "mode=0755" ];
      };

      # The persistent volume for the trees that must outlive the tmpfs root. It
      # is needed before the bind mounts below, so it mounts early.
      "/persist" = {
        device = "/dev/disk/by-id/virtio-persist";
        fsType = "ext4";
        autoFormat = true;
        neededForBoot = true;
      };

      # Persist the one tree switch-to-configuration rewrites. This bind is the
      # only non-store write that survives a power-off, so a forensic diff of
      # /persist/var/lib/nixos after deactivation is the decoy's real drift.
      #
      # It is left out of the stage-1 (neededForBoot) set so it mounts in
      # stage-2 — by then the stage-1 unit below has created its source on the
      # freshly formatted /persist, avoiding the bind-before-source
      # chicken-and-egg.
      "/var/lib/nixos" = {
        device = "/persist/var/lib/nixos";
        # virtualisation.fileSystems entries have no fsType default (the qemu-vm
        # module reads it unconditionally), so a bind must name it explicitly.
        fsType = "none";
        options = [ "bind" ];
        depends = [ "/persist" ];
      };
    };
  };

  # /persist is mounted under /sysroot in stage-1 (neededForBoot); create the
  # bind source there before stage-2 sets up the bind above. The VM needs systemd
  # stage-1 (the writable store overlay depends on it), which rejects the old
  # boot.initrd.postMountCommands hook, so this is a stage-1 unit modelled on the
  # one nixpkgs uses to create overlay upper directories.
  boot.initrd.systemd.services.persist-var-lib-nixos-source = {
    wantedBy = [ "initrd-fs.target" ];
    before = [ "initrd-fs.target" ];
    unitConfig = {
      DefaultDependencies = false;
      RequiresMountsFor = "/sysroot/persist";
    };
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/mkdir -p -m 0755 /sysroot/persist/var/lib/nixos";
    };
  };

  # A volatile journal: the decoy journal lives only in RAM, so a journal carve
  # of the image sees only lines a hidden session forced onto a persisted tree.
  # mkForce overrides the persistent journal forensic-vm-config.nix sets.
  services.journald.settings.Journal.Storage = lib.mkForce "volatile";
}
