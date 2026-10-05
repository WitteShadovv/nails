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
{ pkgs }:
let
  nixpkgsFlake = builtins.getFlake "path:${pkgs.path}";

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
