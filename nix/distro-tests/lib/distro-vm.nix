# Wrap numtide/nix-vm-test so one image-table entry becomes one bootable VM
# test that runs on the NixOS test driver.
#
# nix-vm-test reuses the NixOS test driver (the same `machine` object, the same
# `testScript` Python API, `start`/`shutdown`/`wait_for_unit`/`succeed`/`fail`),
# which is why every host-side helper the NixOS suite already has -- the
# disk-image forensic scanners in nix/e2e-tests/lib/disk_forensics.py chief among
# them -- works unchanged against a Debian or Ubuntu guest.
#
#   API COUPLING (confirm at evaluation time): the single call into nix-vm-test
#   is `buildVmTest` below. The numtide attribute layout is versioned, so the
#   exact spelling of "run this testScript against this pinned image" must be
#   checked against the pinned revision when flake.lock is first generated on a
#   KVM host (the development sandbox has no Nix and cannot fetch the input).
#   Everything else in the distro tier is image-table data and plain testScript
#   text; keeping the coupling to this one function means a spelling fix is a
#   one-line change here, not a rewrite of every test.
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
  #   entry      one value from images.nix: { distro, release, format, image }.
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
    assert lib.assertMsg (entry.image.outputHash or null != lib.fakeHash)
      "distro image ${entry.distro}-${entry.release} still has a placeholder hash; pin it before building (see nix/distro-tests/images.nix)";
    # The per-distribution builder, selected by the image table's `distro`
    # field. numtide exposes one attribute per supported distribution; passing an
    # explicit `image` overrides its default pin with our content-addressed one.
    vmLib.${entry.distro} {
      inherit (entry) image;
      inherit sharedDirs testScript;
    };
}
