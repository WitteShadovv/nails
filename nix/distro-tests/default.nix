# The portable distribution smoke suite.
#
# Maps the smoke scenario over the image table (images.nix), so every entry
# there becomes one buildable VM test plus one metadata record. Bringing another
# distribution online -- once its backend and detection land -- is a single entry
# in images.nix; this file and the CI planner enumerate whatever it reports.
#
# The flake exposes `tests` as `legacyPackages.<system>.e2e-distro` and `metadata`
# as `legacyPackages.<system>.e2e-distro-metadata`. The metadata is plain data the
# ci.e2e distro planner reads (via `nix eval`) to build the CI matrix, so it
# evaluates without building a single VM.
{
  self,
  pkgs,
  nix-vm-test,
}:
let
  inherit (pkgs) lib;

  images = import ./images.nix { inherit pkgs; };
  makeSmoke = import ./tests/smoke.nix { inherit self pkgs nix-vm-test; };

  # Distribution boot plus repeated disk-image conversions make a distro VM
  # slower than a single-boot NixOS test; this leaves margin on a shared runner.
  smokeTimeout = 2400;

  # distro name -> its smoke test derivation, keyed "<distro>-smoke".
  scenarioName = name: "${name}-smoke";

  tests = lib.mapAttrs' (name: entry: lib.nameValuePair (scenarioName name) (makeSmoke entry)) images;

  # The login- and boot-record regression scenarios, keyed "<distro>-records".
  # They run on the host (nix-vm-test `driver`), not in CI, so they stay out of
  # the metadata and the smoke planner never sees them.
  records = import ./records.nix { inherit self pkgs nix-vm-test; };

  distros = builtins.attrNames images;

  metadata = {
    inherit distros;
    scenarios = lib.listToAttrs (map (name: lib.nameValuePair name [ (scenarioName name) ]) distros);
    timeouts = lib.listToAttrs (map (name: lib.nameValuePair (scenarioName name) smokeTimeout) distros);
  };
in
tests
// records
// {
  _metadata = metadata;
}
