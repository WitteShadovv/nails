# Wrap numtide/nix-vm-test so one image-table entry becomes one bootable VM
# test that runs on the NixOS test driver.
#
# nix-vm-test reuses the NixOS test driver (the same `testScript` Python API,
# `start`/`shutdown`/`wait_for_unit`/`succeed`/`fail`), so the host-side helpers
# the NixOS suite already has -- the disk-image forensic scanners in
# nix/e2e-tests/lib/disk_forensics.py chief among them -- work against a Debian
# or Ubuntu guest. Three differences matter to a test script:
#
#   - the single machine is called `vm` (the `machine` alias is deprecated);
#   - QEMU boots the cloud image straight from the Nix store with `-snapshot`,
#     so guest writes live in a temporary layer that is discarded when QEMU
#     exits: a `shutdown()`/`start()` cycle boots the pristine image again, and
#     there is no root qcow2 in the state directory for the forensic helpers to
#     image (a test mirrors the live disk there first; see tests/smoke.nix);
#   - the driver starts QEMU with `-no-reboot` unless `start(allow_reboot=True)`,
#     so a guest reboot otherwise ends the QEMU process, and the disk with it.
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
  #              The static musl `nails` binary is shared this way. The
  #              shares are mounted once, before the test script runs, and are
  #              NOT remounted after a reboot: a test that reboots remounts them.
  #   memorySize guest RAM in MiB (null keeps the nix-vm-test default).
  #   testScript the driver Python, same dialect as the NixOS suite.
  buildVmTest =
    {
      entry,
      sharedDirs ? { },
      memorySize ? null,
      testScript,
    }:
    assert lib.assertMsg (
      vmLib ? ${entry.distro} && vmLib.${entry.distro} ? ${entry.image}
    ) "nix-vm-test has no ${entry.distro} image ${entry.image} (see nix/distro-tests/images.nix)";
    # nix-vm-test returns { driver, driverInteractive, sandboxed }; the
    # sandboxed run is the buildable test.
    (vmLib.${entry.distro}.${entry.image} (
      {
        inherit sharedDirs testScript;
      }
      // lib.optionalAttrs (memorySize != null) { inherit memorySize; }
    )).sandboxed;
}
