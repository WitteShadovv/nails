{
  description = "NixOS Anti-forensics Isolation & Layering System (NAILS)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Rust toolchain pinned to 1.93.0 (with musl target)
        rustToolchain = pkgs.rust-bin.stable."1.93.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };

        # Build with musl stdenv but keep the pinned Rust toolchain (1.93.0)
        rustPlatformMusl = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        pkgsMusl = pkgs.pkgsCross.musl64;

        # NAILS binary with static musl linking
        nails = rustPlatformMusl.buildRustPackage rec {
          pname = "nails";
          version = "0.1.0";

          # Use builtins.path to include all files without filtering
          src = builtins.path {
            path = ./.;
            name = "nails-${version}";
          };

          cargoLock = { lockFile = ./Cargo.lock; };

          # Use musl stdenv for static linking
          inherit (pkgsMusl) stdenv;

          # Cross target to musl
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

          # Configure for static linking
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

          doCheck = false; # Tests run separately in checks
        };

        # Import E2E tests (impermanence is now local)
        e2e-tests = import ./nix/e2e-tests { inherit self pkgs; };

      in {
        # Packages
        packages = {
          inherit nails;
          default = nails;
        };

        # Apps (for interactive execution)
        apps = {
          e2e-test-interactive = {
            type = "app";
            program = "${e2e-tests.interactive-driver}/bin/interactive-test";
          };
        };

        # Dev shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-tarpaulin
            cargo-llvm-cov
            llvmPackages_latest.llvm
          ];
        };

        # E2E test checks
        checks = {
          e2e-basic-workflow = e2e-tests.basic-workflow;
          e2e-emergency = e2e-tests.emergency;
          e2e-forensic-clean = e2e-tests.forensic-clean;
          e2e-snapshot-diff = e2e-tests.snapshot-diff;
          e2e-performance = e2e-tests.performance;
          e2e-all = e2e-tests.all;
        };
      });
}
