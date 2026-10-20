# The distribution table: the single source of which distributions the test
# suites know about, and how each one's cloud image is obtained.
#
# The table itself is plain data in images.json, so a pin can be bumped by a
# script (scripts/distro_images.py) without touching Nix. Everything downstream
# -- the per-distribution smoke tests, the flake's `e2e-distro` attribute set,
# the distro metadata the CI planner reads -- is derived by mapping over this
# set, so bringing a distribution into the matrix is a single `enabled` flip.
#
# Each entry carries:
#   osId           the /etc/os-release ID ("debian", "ubuntu", "fedora", "arch");
#   release        the distribution's own version string, for diagnostics;
#   rootfs         the root filesystem the cloud image ships ("ext4", "btrfs");
#   enforcing      whether SELinux stays enforcing (Fedora; ignored elsewhere);
#   memory         guest RAM in MiB;
#   enabled        whether the smoke matrix runs it today (false stages an image
#                  that the next package can boot without putting it in CI);
#   upstreamUntil  the date the pinned upstream image is expected to lapse from
#                  its download mirror (null when the source does not expire, as
#                  for a nix-vm-test pin or a self-hosted mirror asset);
#   prepare        which image-preparation path builds the bootable qcow2
#                  ("nix-vm-test" for a pinned nix-vm-test release, "fedora" or
#                  "archlinux" for nix-vm-test's per-family prepare function);
#   source         where the image comes from (see below).
#
# A `source` is one of:
#   { kind = "nix-vm-test"; distro; image; }  a release nix-vm-test already pins,
#                                             fixed by the flake.lock pin of it;
#   { kind = "upstream"; url; name; sha256; } a hash-pinned upstream cloud image
#                                             fetched with `fetchurl`;
#   { kind = "mirror"; asset; sha256; }       an image with no upstream URL, from
#                                             the assets-repo mirror (mirrors.nix);
#   { kind = "pending"; }                     declared but not pinned yet (a
#                                             pre-release distro, or an image the
#                                             hosting does not produce yet).
{ pkgs }:
let
  inherit (pkgs) lib;

  table = lib.importJSON ./images.json;

  knownOsIds = [
    "debian"
    "ubuntu"
    "fedora"
    "arch"
  ];
  knownPrepare = [
    "nix-vm-test"
    "fedora"
    "archlinux"
  ];
  knownKinds = [
    "nix-vm-test"
    "upstream"
    "mirror"
    "pending"
  ];

  # Fail at evaluation with a message that names the offending entry, so a
  # malformed table is caught by any `nix eval` of it rather than deep inside a
  # VM-test build.
  checkEntry =
    name: entry:
    let
      kind = entry.source.kind;
      requires =
        field:
        lib.assertMsg (
          entry.source ? ${field} && entry.source.${field} != null
        ) "distro image ${name}: an ${kind} source needs a non-null ${field}";
    in
    assert lib.assertMsg (
      lib.isString entry.osId && builtins.elem entry.osId knownOsIds
    ) "distro image ${name}: osId must be one of ${lib.concatStringsSep ", " knownOsIds}";
    assert lib.assertMsg (lib.isBool entry.enabled) "distro image ${name}: enabled must be a boolean";
    assert lib.assertMsg (
      lib.isInt entry.memory && entry.memory > 0
    ) "distro image ${name}: memory must be a positive integer (MiB)";
    assert lib.assertMsg (builtins.elem entry.prepare knownPrepare)
      "distro image ${name}: prepare must be one of ${lib.concatStringsSep ", " knownPrepare}";
    assert lib.assertMsg (builtins.elem kind knownKinds)
      "distro image ${name}: source.kind must be one of ${lib.concatStringsSep ", " knownKinds}";
    assert lib.assertMsg (
      entry.upstreamUntil == null || builtins.isString entry.upstreamUntil
    ) "distro image ${name}: upstreamUntil must be null or a YYYY-MM-DD string";
    # A pin that is still the placeholder hash may not be in the matrix: it
    # would fail its own fetch. This is what keeps an unpinned image `enabled`
    # from slipping through.
    assert lib.assertMsg (
      !(entry.enabled && kind == "pending")
    ) "distro image ${name}: a pending source cannot be enabled";
    assert lib.assertMsg (!(entry.enabled && kind == "upstream" && entry.source.sha256 == lib.fakeHash))
      "distro image ${name}: still has the placeholder hash; run `scripts/distro_images.py repin ${name}` before enabling it";
    assert (kind == "upstream") -> (requires "url" && requires "name" && requires "sha256");
    assert (kind == "nix-vm-test") -> (requires "distro" && requires "image");
    entry;
in
lib.mapAttrs checkEntry table
