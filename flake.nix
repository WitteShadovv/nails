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

        sourceFiles = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./LICENSE
            ./README.md
            (pkgs.lib.fileset.maybeMissing ./.cargo)
            ./nails-cli
            ./nails-core
            (pkgs.lib.fileset.maybeMissing ./rust-toolchain.toml)
          ];
        };

        reproducibleRustFlags = pkgs.lib.concatStringsSep " " [
          "-C target-feature=+crt-static"
          "-C link-arg=-Wl,--build-id=none"
          "--remap-path-prefix=/build/source=."
        ];

        # NAILS binary with static musl linking
        nails = rustPlatformMusl.buildRustPackage rec {
          pname = "nails";
          version = "0.1.0";

          src = sourceFiles;

          cargoLock = { lockFile = ./Cargo.lock; };
          cargoDepsName = pname;

          # Use musl stdenv for static linking
          inherit (pkgsMusl) stdenv;
          strictDeps = true;

          # Cross target to musl
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";

          # Configure for reproducible static linking
          CARGO_INCREMENTAL = "0";
          SOURCE_DATE_EPOCH = toString (self.lastModified or 1);
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS =
            reproducibleRustFlags;

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
