# Host-side build of the hidden NixOS system toplevel used by the real offline
# rebuild tests (27-activate-full-rebuild, 34-var-lib-nixos-drift and
# 28-activate-flake-override).
#
# These tests make `nails activate` build the hidden system toplevel in the guest
# with no network and no substituters. Seeding only the nixpkgs *source* is not
# enough: the guest still has to realise the whole toplevel closure (stdenv,
# glibc, python, …), which it cannot fetch offline. Instead we evaluate the hidden
# configuration here, on the host, where the test derivation is built with the
# cache available, and hand the resulting toplevel (and its closure) to the guest
# through `virtualisation.additionalPaths`. The guest's own `nix build
# …#…system.build.toplevel` then finds the output already present and switches to
# it without building or fetching anything.
#
# The toplevel must be the *same* derivation the in-guest flake builds, so this
# mirrors the guest hidden flake (fixtures/hidden-config/flake.nix) exactly:
#   * the same nixpkgs, taken as a flake from the guest's `pkgs.path`, so
#     `lib.nixosSystem` is the identical function the flake calls;
#   * the same module list — the decoy's own /etc/nixos (reproduced from
#     vm-config.nix) plus the shared marker module — evaluated for the same
#     system. A NixOS toplevel derivation is a function of the merged `config`
#     alone, so reproducing the decoy /etc/nixos as inline modules of equal
#     content yields the identical store path the guest computes from the files.
{ pkgs, nixpkgs }:
let
  # The in-guest hidden flake takes the seeded nixpkgs *source* as a `path:`
  # input (fixtures/hidden-config/flake.nix, substituted with `pkgs.path`). To
  # compute the identical `lib.nixosSystem` here we fetch that same source as a
  # flake. Two constraints shape the ref:
  #   * pure evaluation (flake check) forbids a bare string that carries a store
  #     path in its context, so the context is discarded with
  #     `unsafeDiscardStringContext`; and
  #   * pure evaluation also rejects an *unlocked* flakeref, so the ref is pinned
  #     with the input's own `narHash`.
  # `pkgs.path` is the source tree of this same `nixpkgs` input, so its store
  # path equals `nixpkgs.outPath`; the assertion below makes that explicit, and a
  # drift would surface here rather than as a mismatched guest store path.
  nixpkgsSource = builtins.unsafeDiscardStringContext nixpkgs.outPath;
  nixpkgsFlake =
    assert nixpkgs.outPath == pkgs.path;
    builtins.getFlake "path:${nixpkgsSource}?narHash=${nixpkgs.narHash}";

  # The decoy's /etc/nixos/configuration.nix (see lib/vm-config.nix). The guest
  # hidden flake imports this file; the import of the (empty) hardware
  # configuration adds nothing, so an inline empty module reproduces it.
  decoyConfiguration = _: {
    imports = [ (_: { imports = [ ]; }) ];
    boot.loader.grub.enable = false;
    documentation.nixos.enable = false;
    fileSystems."/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };
    system.stateVersion = "25.11";
  };

  hiddenSystem = nixpkgsFlake.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      decoyConfiguration
      ../fixtures/hidden-config/module.nix
    ];
  };
in
hiddenSystem.config.system.build.toplevel
