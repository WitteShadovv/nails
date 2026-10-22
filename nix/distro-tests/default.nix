# The portable distribution smoke suite.
#
# Maps the smoke scenario over the enabled entries of the image table
# (images.nix), so every enabled entry becomes one buildable VM test plus one
# metadata record. An entry with `enabled = false` is still a full entry the
# `distro-images` check evaluates and the next package can boot, but it stays
# out of the smoke set and the CI matrix, so staging a distribution changes
# nothing that runs today; enabling it is a single flip in images.json.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  enabledImages = lib.filterAttrs (_: entry: entry.enabled) images;

  distroVm = import ./lib/distro-vm.nix { inherit pkgs nix-vm-test; };
  makeSmoke = import ./tests/smoke.nix { inherit self pkgs nix-vm-test; };

  # Distribution boot plus repeated disk-image conversions make a distro VM
  # slower than a single-boot NixOS test; this leaves margin on a shared runner.
  smokeTimeout = 2400;

  # distro name -> its smoke test derivation, keyed "<distro>-smoke".
  scenarioName = name: "${name}-smoke";

  tests = lib.mapAttrs' (
    name: entry: lib.nameValuePair (scenarioName name) (makeSmoke entry)
  ) enabledImages;

  # The login- and boot-record regression scenarios, keyed "<distro>-records".
  # They run on the host (nix-vm-test `driver`), not in CI, so they stay out of
  # the metadata and the smoke planner never sees them.
  records = import ./records.nix { inherit self pkgs nix-vm-test; };

  # Fact-capture probes for the families not admitted yet, keyed "<name>-probe".
  # Like the records tests they are host drivers, run by hand on a KVM machine,
  # so they stay out of the metadata and the CI planner never sees them.
  probes = lib.mapAttrs' (name: drv: lib.nameValuePair "${name}-probe" drv) (
    import ./probe.nix { inherit pkgs nix-vm-test; }
  );

  distros = builtins.attrNames enabledImages;

  metadata = {
    inherit distros;
    scenarios = lib.listToAttrs (map (name: lib.nameValuePair name [ (scenarioName name) ]) distros);
    timeouts = lib.listToAttrs (map (name: lib.nameValuePair (scenarioName name) smokeTimeout) distros);
  };

  # Every entry reduced to the derivation path of a minimal VM test, so the
  # `distro-images` check can force the whole table -- fetch, prepare and build,
  # for the disabled entries too -- through evaluation without building a VM.
  # A pinned Debian or Ubuntu entry resolves straight to its nix-vm-test
  # derivation; a Fedora or Arch entry resolves through the fetchurl-and-prepare
  # seam; an unpinned entry resolves to the "unavailable" placeholder.
  probeScript = "vm.wait_for_unit('multi-user.target')\n";
  imageProbes = lib.mapAttrs (
    _: entry:
    # The drvPath forces the whole seam (fetch, prepare, build) through
    # evaluation, which is the proof; discarding its string context keeps the
    # VM test from becoming a build dependency, so the check stays eval-only and
    # never tries to build a VM (or fetch a not-yet-pinned image).
    builtins.unsafeDiscardStringContext
      (distroVm.buildVmTest {
        inherit entry;
        testScript = probeScript;
        memorySize = entry.memory;
      }).drvPath
  ) images;
in
tests
// records
// probes
// {
  _metadata = metadata;
  # Plain data the `distro-images` check serialises to force evaluation of the
  # whole table and of every entry's image seam. Not read by the CI planner.
  _images = {
    table = images;
    probes = imageProbes;
  };
}
