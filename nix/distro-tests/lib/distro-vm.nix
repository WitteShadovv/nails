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
# The single call into nix-vm-test is `buildVmTest` below. An image-table entry
# (nix/distro-tests/images.nix) reaches nix-vm-test one of two ways:
#
#   - a release nix-vm-test already pins (Debian, Ubuntu): its per-release
#     function is called straight from `lib.<system>`;
#   - a hash-pinned upstream cloud image (Fedora, Arch): the image is fetched by
#     hash, prepared with nix-vm-test's own per-family prepare function, then
#     booted with its generic test builder. That builder lives at nix-vm-test's
#     non-exported `generic/` path, so it is reached directly, with an eval-time
#     assert that turns an upstream move into a message pointing back here.
#
# Keeping the coupling in this one file means an upstream API change is a fix
# here, not a rewrite of every test.
{ pkgs, nix-vm-test }:
let
  inherit (pkgs) lib;
  inherit (pkgs.stdenv.hostPlatform) system;

  # The per-system nix-vm-test library. The flake threads the input in; this is
  # the only place that reaches into its attribute set.
  vmLib = nix-vm-test.lib.${system};

  mirrors = import ../mirrors.nix;

  # nix-vm-test keeps its own nixpkgs on purpose (its test driver is invoked
  # with a command line that newer NixOS drivers reject), so the Fedora and Arch
  # prepare functions and the generic VM-test builder must be evaluated against
  # THAT nixpkgs, the one this flake's lock resolved for nix-vm-test, not against
  # this flake's own nixpkgs. The primary path reads it as a resolved transitive
  # flake input; the fallback reads the same revision out of this flake's lock,
  # so neither depends on the other being available. Everything here is forced
  # only when a fetchurl-backed entry is actually built, so the pinned Debian and
  # Ubuntu path never evaluates it.
  vmNixpkgs =
    nix-vm-test.inputs.nixpkgs or (
      let
        lock = builtins.fromJSON (builtins.readFile ../../../flake.lock);
        node = lock.nodes.${lock.nodes.nix-vm-test.inputs.nixpkgs}.locked;
      in
      builtins.fetchTree {
        type = "github";
        inherit (node)
          owner
          repo
          rev
          narHash
          ;
      }
    );
  vmPkgs = import vmNixpkgs { inherit system; };

  genericDir = nix-vm-test + "/generic";
  generic =
    assert lib.assertMsg (builtins.pathExists (genericDir + "/default.nix"))
      "nix-vm-test no longer exposes generic/default.nix; the Fedora and Arch image seam (nix/distro-tests/images.nix) needs it";
    vmPkgs.callPackage genericDir { nixpkgs = vmNixpkgs; };

  # The per-family prepare functions, built against the one `generic` above so a
  # prepared image and the builder that boots it agree on the backdoor service.
  prepareFns = {
    fedora =
      (vmPkgs.callPackage (nix-vm-test + "/fedora") { inherit generic system; }).prepareFedoraImage;
    archlinux =
      (vmPkgs.callPackage (nix-vm-test + "/archlinux") { inherit generic system; }).prepareArchlinuxImage;
  };

  # Whether an entry's image can be had today: a release nix-vm-test pins, a
  # hash-pinned upstream image, or a mirrored asset once the mirror is set and
  # the entry names its asset. A pending entry has none. `fetchImage` fetches
  # exactly these, and the probe metadata lists only the probes they boot.
  imageAvailable =
    entry:
    let
      inherit (entry) source;
      kind = source.kind or "nix-vm-test";
    in
    if kind == "nix-vm-test" || kind == "upstream" then
      true
    else if kind == "mirror" then
      mirrors.urlFor { inherit (source) family asset; } != null && source.sha256 != null
    else
      false;

  # The upstream (or mirrored) cloud image, by hash, or null when the entry is
  # not pinned or hosted yet (so the caller can stage a buildable-later entry).
  fetchImage =
    entry:
    let
      inherit (entry) source;
    in
    if !(imageAvailable entry) then
      null
    else if source.kind == "upstream" then
      vmPkgs.fetchurl {
        inherit (source) url name;
        hash = source.sha256;
      }
    else if source.kind == "mirror" then
      vmPkgs.fetchurl {
        url = mirrors.urlFor { inherit (source) family asset; };
        hash = source.sha256;
        name = source.asset;
      }
    else
      null;

  # Hand the fetched image to nix-vm-test's per-family prepare function.
  prepareImage =
    entry: originalImage:
    if entry.prepare == "fedora" then
      prepareFns.fedora {
        hostPkgs = vmPkgs;
        inherit originalImage;
        diskSize = null;
        extraPathsToRegister = [ ];
        selinuxEnforcing = entry.enforcing;
      }
    else if entry.prepare == "archlinux" then
      prepareFns.archlinux {
        hostPkgs = vmPkgs;
        inherit originalImage;
        diskSize = null;
        extraPathsToRegister = [ ];
      }
    else
      throw "distro image ${entry.osId} ${entry.release}: no prepare function for '${entry.prepare}'";

  # Evaluates, but refuses to build, so `nix eval` of every entry still succeeds
  # while an unpinned or unhosted image cannot be booted by accident.
  unavailable =
    entry: reason:
    pkgs.runCommandLocal "distro-image-${entry.osId}-${entry.release}-unavailable" { } ''
      echo "the ${entry.osId} ${entry.release} test image is not available yet: ${reason}" >&2
      exit 1
    '';
in
{
  inherit imageAvailable;

  # Build one distribution VM test.
  #
  #   entry      one value from images.nix.
  #   sharedDirs host paths exposed read-only in the guest, as
  #              { <name> = { source = <store path>; target = <guest path>; }; }.
  #              The static musl `nails` binary is shared this way. The
  #              shares are mounted once, before the test script runs, and are
  #              NOT remounted after a reboot: a test that reboots remounts them.
  #   memorySize guest RAM in MiB (null keeps the nix-vm-test default).
  #   testScript the driver Python, same dialect as the NixOS suite.
  #   target     which of nix-vm-test's three outputs to take:
  #                "sandboxed"  (default) a derivation that runs the test in the
  #                             Nix build sandbox -- hermetic, but no network;
  #                "driver"     a `test-driver` script run on the host, outside
  #                             the sandbox, so the guest's user-mode networking
  #                             reaches the internet (needed to install the
  #                             distro's own record packages, e.g. wtmpdb);
  #                "driverInteractive" the same with a REPL and full qemu.
  #              The smoke suite leaves this at "sandboxed"; the login- and
  #              boot-record test uses "driver" because it installs a package in
  #              the guest (wtmpdb on Debian).
  buildVmTest =
    {
      entry,
      sharedDirs ? { },
      memorySize ? null,
      testScript,
      target ? "sandboxed",
    }:
    assert lib.assertMsg (builtins.elem target [
      "sandboxed"
      "driver"
      "driverInteractive"
    ]) "distro-vm target must be sandboxed, driver or driverInteractive, not ${target}";
    let
      kind = entry.source.kind or "nix-vm-test";
    in
    if kind == "nix-vm-test" then
      # A release nix-vm-test already pins. `entry.source` carries the distro
      # and image keys; an entry straight from records.nix carries them at the
      # top level, so both shapes resolve to the same call -- the one the
      # pinned Debian and Ubuntu tests have always made.
      let
        distro = entry.source.distro or entry.distro;
        image = entry.source.image or entry.image;
      in
      assert lib.assertMsg (
        vmLib ? ${distro} && vmLib.${distro} ? ${image}
      ) "nix-vm-test has no ${distro} image ${image} (see nix/distro-tests/images.nix)";
      # nix-vm-test returns { driver, driverInteractive, sandboxed }.
      (vmLib.${distro}.${image} (
        {
          inherit sharedDirs testScript;
        }
        // lib.optionalAttrs (memorySize != null) { inherit memorySize; }
      )).${target}
    else
      let
        originalImage = fetchImage entry;
      in
      if originalImage == null then
        unavailable entry "source kind '${kind}' is not pinned or hosted yet"
      else
        (generic.makeVmTest {
          name = "vm-test-${entry.osId}-${entry.release}";
          inherit
            system
            testScript
            sharedDirs
            memorySize
            ;
          image = prepareImage entry originalImage;
        }).${target};
}
