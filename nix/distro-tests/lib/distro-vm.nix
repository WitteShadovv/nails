# Wrap numtide/nix-vm-test so one image-table entry becomes one bootable VM
# test that runs on the NixOS test driver.
#
# nix-vm-test reuses the NixOS test driver (the same `machine` object, the same
# `testScript` Python API, `start`/`shutdown`/`wait_for_unit`/`succeed`/`fail`),
# which is why every host-side helper the NixOS suite already has -- the
# disk-image forensic scanners in nix/e2e-tests/lib/disk_forensics.py chief among
# them -- works unchanged against a Debian or Ubuntu guest.
#
# The single call into nix-vm-test is `buildVmTest` below: each distribution
# is an attribute set keyed by release, and each release is a function of the
# test script. Keeping the coupling to this one function means an upstream API
# change is a one-line fix here, not a rewrite of every test.
{ pkgs, nix-vm-test }:
let
  inherit (pkgs) lib;
  inherit (pkgs.stdenv.hostPlatform) system;

  # The per-system nix-vm-test library. The flake threads the input in; this is
  # the only place that reaches into its attribute set.
  vmLib = nix-vm-test.lib.${system};
in
{
  # Build one distribution VM test.
  #
  #   entry      one value from images.nix: { distro, image, release }.
  #   sharedDirs host paths exposed read-only in the guest, as
  #              { <name> = { source = <store path>; target = <guest path>; }; }.
  #              The static musl `nails` binary is shared this way.
  #   testScript the driver Python, same dialect as the NixOS suite.
  buildVmTest =
    {
      entry,
      sharedDirs ? { },
      testScript,
    }:
    assert lib.assertMsg (
      vmLib ? ${entry.distro} && vmLib.${entry.distro} ? ${entry.image}
    ) "nix-vm-test has no ${entry.distro} image ${entry.image} (see nix/distro-tests/images.nix)";
    vmLib.${entry.distro}.${entry.image} {
      inherit sharedDirs testScript;
    };
}
