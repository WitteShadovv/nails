# Shared setup snippets for the non-LUKS hidden-root backends (bind mount,
# VeraCrypt/tcrypt, and the NFS refusal case).
#
# lib/hidden-volume.nix covers the LUKS-on-the-data-disk happy path every positive
# test uses. These helpers give the other backends the same on-disk layout so a
# single headless config activates over any of them. Every on-disk name stays
# neutral ("data"); the Nix identifiers here are internal to the harness and
# never reach the guest's disk.
{
  # Create the overlay upper/work layout NAILS expects, rooted at an arbitrary
  # mount point. Mirrors what lib/hidden-volume.nix lays down on the LUKS volume,
  # so a bind, tcrypt or network-mounted root presents an identical tree. `root`
  # is a shell-safe absolute path with no trailing slash.
  nailsDirStructure = root: ''
    mkdir -p ${root}/home ${root}/etc ${root}/var ${root}/nix
    mkdir -p ${root}/.work/home ${root}/.work/etc ${root}/.work/var ${root}/.work/nix
    mkdir -p ${root}/config ${root}/config/nixos ${root}/nixos
  '';
}
