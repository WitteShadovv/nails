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
# `pkgs` is accepted (callers `inherit pkgs nixpkgs`) but no longer referenced:
# the toplevel is now evaluated purely from the locked `nixpkgs` flake input.
{ nixpkgs, ... }:
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
  # `pkgs.path` is the source tree of this same `nixpkgs` input, so realising
  # this flake yields the same `lib.nixosSystem` the guest flake calls. We cannot
  # assert `nixpkgs.outPath == pkgs.path`: `outPath` is a string carrying store
  # context while `pkgs.path` is a lazy source-tree path (a flake-ref value such
  # as «github:NixOS/nixpkgs/…»), so the two are never `==` even when they denote
  # the same tree. The `narHash` pin below is what actually ties the fetched
  # flake to the locked input, so any drift surfaces as a mismatched guest store
  # path rather than being caught here.
  nixpkgsSource = builtins.unsafeDiscardStringContext nixpkgs.outPath;
  nixpkgsFlake = builtins.getFlake "path:${nixpkgsSource}?narHash=${nixpkgs.narHash}";

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
