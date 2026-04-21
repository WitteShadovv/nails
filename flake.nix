{
  description = "NixOS Anti-forensics Isolation & Layering System (NAILS)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        inherit (pkgs) lib;
        targetTriple = "x86_64-unknown-linux-musl";
        sourceDateEpoch = toString (self.lastModified or 1);
        shortRev = self.shortRev or (self.dirtyShortRev or "dirty");

        # Native Rust toolchain pinned for local development.
        rustToolchain = pkgs.rust-bin.stable."1.93.0".default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "llvm-tools-preview"
          ];
          targets = [ targetTriple ];
        };

        # Dedicated musl cross toolchain for the canonical release build.
        pkgsMusl = pkgs.pkgsCross.musl64;
        rustToolchainMusl = pkgsMusl.buildPackages.rust-bin.stable."1.93.0".default.override {
          extensions = [ "rust-src" ];
          targets = [ targetTriple ];
        };
        rustPlatformMusl = pkgsMusl.makeRustPlatform {
          cargo = rustToolchainMusl;
          rustc = rustToolchainMusl;
        };

        sourceFiles = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./LICENSE
            ./README.md
            (lib.fileset.maybeMissing ./.cargo)
            ./nails-cli
            ./nails-core
            ./nix
            (lib.fileset.maybeMissing ./rust-toolchain.toml)
          ];
        };

        reproducibleRustFlags = lib.concatStringsSep " " [
          "-C target-feature=+crt-static"
          "-C link-arg=-Wl,--build-id=none"
          "--remap-path-prefix=/build/source=."
        ];

        workspaceManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        workspaceVersion = workspaceManifest.workspace.package.version;
        releaseVersion = "${workspaceVersion}-git.${shortRev}";
        releaseArchiveName = "nails-${releaseVersion}-${targetTriple}.tar.gz";

        # Canonical release binary: static x86_64-unknown-linux-musl.
        nails = rustPlatformMusl.buildRustPackage rec {
          pname = "nails";
          version = workspaceVersion;

          src = sourceFiles;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          cargoDepsName = pname;

          inherit (pkgsMusl) stdenv;
          strictDeps = true;
          allowSubstitutes = false;
          preferLocalBuild = true;

          cargoBuildFlags = [
            "--package"
            "nails-cli"
            "--bin"
            "nails"
          ];

          CARGO_BUILD_TARGET = targetTriple;
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgsMusl.stdenv.cc}/bin/${pkgsMusl.stdenv.cc.targetPrefix}cc";

          CARGO_INCREMENTAL = "0";
          SOURCE_DATE_EPOCH = sourceDateEpoch;
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = reproducibleRustFlags;

          doCheck = false;

          installPhase = ''
            runHook preInstall
            install -Dm755 target/${targetTriple}/release/nails $out/bin/nails
            runHook postInstall
          '';
        };

        nails-release =
          pkgs.runCommand "nails-release-${releaseVersion}"
            {
              nativeBuildInputs = [
                pkgs.coreutils
                pkgs.gnutar
                pkgs.gzip
              ];
              SOURCE_DATE_EPOCH = sourceDateEpoch;
              allowSubstitutes = false;
              preferLocalBuild = true;
            }
            ''
              set -euo pipefail

              export LC_ALL=C
              export TZ=UTC
              umask 022

              package_dir="nails-${releaseVersion}-${targetTriple}"
              stage_dir="$TMPDIR/stage/$package_dir"
              mkdir -p "$stage_dir" "$out"

              install -m 0755 ${nails}/bin/nails "$stage_dir/nails"
              install -m 0644 ${sourceFiles}/LICENSE "$stage_dir/LICENSE"
              install -m 0644 ${sourceFiles}/README.md "$stage_dir/README.md"

              tar \
                --sort=name \
                --format=gnu \
                --mtime="@${sourceDateEpoch}" \
                --owner=0 \
                --group=0 \
                --numeric-owner \
                -C "$TMPDIR/stage" \
                -cf - \
                "$package_dir" | gzip -n > "$out/${releaseArchiveName}"

              install -m 0755 ${nails}/bin/nails "$out/nails"

              archive_sha256=$(sha256sum "$out/${releaseArchiveName}" | cut -d' ' -f1)
              binary_sha256=$(sha256sum "$out/nails" | cut -d' ' -f1)

              printf '%s  %s\n' "$archive_sha256" "${releaseArchiveName}" > "$out/checksums.txt"
              printf '%s  %s\n' "$binary_sha256" "nails" >> "$out/checksums.txt"
            '';

        # Import E2E tests (impermanence is now local)
        rawE2eTests = import ./nix/e2e-tests { inherit self pkgs; };
        e2eTests = lib.filterAttrs (name: _: !(lib.hasPrefix "_" name)) rawE2eTests;
        e2eTestMetadata = {
          availableTargets = builtins.attrNames e2eTests;
          leafTests = rawE2eTests._testNames;
          groups = rawE2eTests._groups;
          nodeCounts = lib.mapAttrs (_: meta: meta.nodeCount) rawE2eTests._meta;
        };

      in
      {
        # Packages
        packages = {
          inherit nails nails-release;
          default = nails;
        };

        # Apps (for interactive execution)
        apps = {
          e2e-test-interactive = {
            type = "app";
            program = "${rawE2eTests._interactive-driver}/bin/interactive-test";
          };
        };

        e2e-tests = e2eTests;
        e2e-test-metadata = e2eTestMetadata;

        # Dev shell
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            pre-commit
            bash
            coreutils
            gnugrep
            ripgrep
            nixfmt
            deadnix
            statix
            shellcheck
            cargo-audit
            cargo-deny
            cargo-tarpaulin
            cargo-llvm-cov
            bc # Floating-point arithmetic for coverage threshold checks
          ];
        };

        # E2E test checks
        checks = lib.mapAttrs' (name: value: lib.nameValuePair "e2e-${name}" value) e2eTests;
      }
    );
}
