# Forensic VM configuration: one imageable root disk.
#
# The default E2E VM shares the host Nix store over 9p and writes through a
# tmpfs layer, so nothing a hidden session does to the store ever reaches a disk
# that can be imaged -- which is exactly why the old forensic checks could never
# fail. This profile gives the guest its own on-disk Nix store (a store image
# plus an on-disk, non-tmpfs writable layer) and a persistent journal, so hidden
# store writes and log lines land on the root disk and survive a power-off. The
# driver then converts that single root disk to a raw image across the whole
# baseline -> active -> post lineage and reads it from the outside.
{ ... }:
{
  imports = [ ./vm-config.nix ];

  virtualisation = {
    # The store is a real disk image whose writable layer is on disk, not in
    # tmpfs, so store residue persists and can be imaged.
    useNixStoreImage = true;
    writableStore = true;
    writableStoreUseTmpfs = false;
  };

  # A persistent journal, so a logged canary survives into the image for the
  # carve-and-scan journal check. It overrides the volatile default of
  # vm-config.nix.
  services.journald.settings.Journal.Storage = "persistent";
}
