# The builder of the archinstall test image (the `arch-install` entry of
# ../images.json), which no upstream publishes.
#
# `nix run .#arch-install-image-builder -- <out-dir> <asset-name>` boots the
# Arch ISO that inputs.json pins by hash under UEFI, runs archinstall in it
# from the package snapshot inputs.json names, and writes the compressed image,
# its SHA-256 and a manifest (build.sh). It needs KVM and the network, so it is
# a program, not a derivation: the test-images workflow runs it on a hosted
# runner every night and publishes the image to the mirror (../mirrors.nix).
{ pkgs }:
let
  inherit (pkgs) lib;

  inputs = lib.importJSON ./inputs.json;

  iso = pkgs.fetchurl {
    inherit (inputs.iso) url name;
    hash = inputs.iso.sha256;
  };

  # What the live system fetches from the build's HTTP server.
  guest = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./install.sh
      ./disk_layout.py
      ./user_configuration.json
      ./user_credentials.json
    ];
  };
in
pkgs.writeShellApplication {
  name = "build-arch-install-image";
  runtimeInputs = with pkgs; [
    coreutils
    dosfstools
    gnugrep
    jq
    libarchive
    mtools
    python3
    qemu_kvm
    util-linux
  ];
  runtimeEnv = {
    ISO = iso;
    GUEST = guest;
    INPUTS = ./inputs.json;
    OVMF_CODE = "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
    OVMF_VARS = "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";
    OVMF_FD = "${pkgs.OVMF.fd}/FV/OVMF.fd";
  };
  text = builtins.readFile ./build.sh;
  passthru = { inherit iso inputs; };
}
