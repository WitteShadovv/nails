{
  description = "NAILS: run a hidden session on a decoy Linux system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Boots real Debian/Ubuntu cloud images on the NixOS test driver, so the
    # overlay-only backend is exercised on a non-NixOS host. See
    # nix/distro-tests/. flake.lock must be regenerated on a networked host to
    # pin this input; the development sandbox cannot fetch it.
    # nix-vm-test keeps its own nixpkgs: it drives the NixOS test driver with a
    # command line that newer drivers reject, so it must not follow ours.
    nix-vm-test.url = "github:numtide/nix-vm-test";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      nix-vm-test,
      ...
    }:
    let
      # The release binary targets x86_64-unknown-linux-musl and the VM tests
      # boot x86_64-linux guests, so no other system is exposed.
      system = "x86_64-linux";
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs { inherit system overlays; };
      inherit (pkgs) lib;
      targetTriple = "x86_64-unknown-linux-musl";
      # Only the release archive records the commit time, as its file mtimes.
      releaseSourceDateEpoch = toString (self.lastModified or 1);

      # rust-toolchain.toml is the single source of truth for the pinned
      # version; rustup reads it in CI and the flake reads it here.
      rustChannel = (lib.importTOML ./rust-toolchain.toml).toolchain.channel;

      # Native Rust toolchain pinned for local development.
      rustToolchain = pkgs.rust-bin.stable.${rustChannel}.default.override {
        extensions = [
          "rust-src"
          "rust-analyzer"
          "llvm-tools-preview"
        ];
        targets = [ targetTriple ];
      };

      # Dedicated musl cross toolchain for the canonical release build. It has
      # no rust-src: with the sources installed, rustc writes their store path
      # into std's panic locations, and the binary then keeps this whole
      # toolchain alive at run time. Without them the locations keep rustc's
      # own /rustc/<commit> prefix.
      pkgsMusl = pkgs.pkgsCross.musl64;
      rustToolchainMusl = pkgsMusl.buildPackages.rust-bin.stable.${rustChannel}.default.override {
        targets = [ targetTriple ];
      };
      rustPlatformMusl = pkgsMusl.makeRustPlatform {
        cargo = rustToolchainMusl;
        rustc = rustToolchainMusl;
      };

      # Only what cargo reads. Every VM test embeds the binary, so any other
      # file in here would rebuild the binary, and rerun every test, whenever
      # it changed. checks.nails-source keeps it that way.
      sourceFiles = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          (lib.fileset.maybeMissing ./.cargo)
          ./nails-base
          ./nails-cli
          ./nails-core
          ./nails-forensics
          ./nails-platform
          ./nails-session
          ./nails-teardown
          (lib.fileset.maybeMissing ./rust-toolchain.toml)
        ];
      };

      # rustc links a +crt-static musl binary against the musl that ships with
      # the Rust toolchain (1.2.5 in Rust 1.93), not the C toolchain's, unless
      # self-contained linking is off. With it off, libc.a and musl's crt files
      # (crt1/rcrt1/Scrt1.o, crti.o, crtn.o) come from pkgsMusl's musl: the one
      # nixpkgs patches and the one the release SBOM names (nails.libc). The
      # crtbegin/crtend files come from the GCC of pkgsMusl's C toolchain. The
      # link still needs the Rust toolchain's libunwind.a; this directory holds
      # it alone, so the bundled libc.a cannot come along.
      rustLibunwind = pkgs.linkFarm "rust-libunwind-${rustChannel}" [
        {
          name = "libunwind.a";
          path = "${rustToolchainMusl}/lib/rustlib/${targetTriple}/lib/self-contained/libunwind.a";
        }
      ];

      reproducibleRustFlags = lib.concatStringsSep " " [
        "-C target-feature=+crt-static"
        "-C link-self-contained=no"
        "-L native=${rustLibunwind}"
        "-C link-arg=-Wl,--build-id=none"
        "--remap-path-prefix=/build/source=."
      ];

      workspaceManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      workspaceVersion = workspaceManifest.workspace.package.version;
      # The tag already names the commit; the asset is named after the version.
      releaseName = "nails-${workspaceVersion}-${targetTriple}";
      releaseArchiveName = "${releaseName}.tar.gz";

      # Vendored crate dependencies, downloaded from crates.io's static CDN
      # (static.crates.io), which importCargoLock uses by default.
      cratesVendor = pkgs.rustPlatform.importCargoLock {
        lockFile = ./Cargo.lock;
      };

      # Canonical release binary: static x86_64-unknown-linux-musl.
      nails = rustPlatformMusl.buildRustPackage rec {
        pname = "nails";
        version = workspaceVersion;

        src = sourceFiles;

        cargoDeps = cratesVendor;
        cargoDepsName = pname;

        inherit (pkgsMusl) stdenv;
        strictDeps = true;

        # A Cargo.lock that does not match the manifests fails the build
        # instead of being rewritten silently, as it was for v0.2.0.
        cargoBuildFlags = [
          "--locked"
          "--package"
          "nails-cli"
          "--bin"
          "nails"
        ];

        CARGO_BUILD_TARGET = targetTriple;
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgsMusl.stdenv.cc}/bin/${pkgsMusl.stdenv.cc.targetPrefix}cc";

        CARGO_INCREMENTAL = "0";
        # Nothing in the build reads it. A constant (stdenv's own fallback,
        # 1980-01-01) keeps the derivation, and every VM test built on it,
        # the same from one commit to the next.
        SOURCE_DATE_EPOCH = "315532800";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = reproducibleRustFlags;

        # The C library linked into the binary; release.yml puts its version
        # into the SBOM.
        passthru.libc = pkgsMusl.stdenv.cc.libc;

        # The linker map lists every file the link loaded. The build fails
        # unless libc.a and musl's crt files (crt1/rcrt1/Scrt1.o, crti.o,
        # crtn.o) all came from passthru.libc. GCC's crtbegin/crtend files are
        # not musl's, so the check leaves them out.
        preBuild = ''
          export NIX_LDFLAGS_AFTER_${pkgsMusl.stdenv.cc.suffixSalt}+=" -Map=$NIX_BUILD_TOP/nails.map"
        '';
        postBuild = ''
          libc=${passthru.libc}/lib
          loaded=$(grep -oE '[^ ()]+/(libc\.a|[rS]?crt1\.o|crt[in]\.o)' "$NIX_BUILD_TOP/nails.map" | sort -u) || true
          if ! grep -qxF "$libc/libc.a" <<< "$loaded" || grep -vqF "$libc/" <<< "$loaded"; then
            printf 'nails must take libc.a and the musl crt files (crt1/rcrt1/Scrt1.o, crti.o, crtn.o) from %s only; the link loaded:\n%s\n' "$libc" "$loaded" >&2
            exit 1
          fi
        '';

        # The binary must not name the toolchain that built it.
        disallowedReferences = [ rustToolchainMusl ];

        doCheck = false;

        installPhase = ''
          runHook preInstall
          install -Dm755 target/${targetTriple}/release/nails $out/bin/nails
          runHook postInstall
        '';

        meta = {
          description = "CLI that layers a hidden environment over a decoy system with OverlayFS";
          inherit (workspaceManifest.workspace.package) homepage;
          license = lib.getLicenseFromSpdxId workspaceManifest.workspace.package.license;
          mainProgram = "nails";
          platforms = [ system ];
        };
      };

      # The same static binary with the test-only hooks compiled in, for the
      # E2E gate and override subtests only. The release `nails` above carries
      # none of them (checks.nails-release-hygiene asserts this), so the gate
      # tests that drive `NAILS_TEST_*_GATE_PATH` and the reboot/systemctl path
      # overrides must run against this build instead. Never released.
      nails-e2e = nails.overrideAttrs (old: {
        pname = "nails-e2e";
        cargoBuildFlags = old.cargoBuildFlags ++ [
          "--features"
          "test-hooks"
        ];
        meta = old.meta // {
          description = "nails built with the non-default test-hooks feature, for the E2E gate tests";
        };
      });

      nails-release =
        pkgs.runCommand "nails-release-${workspaceVersion}"
          {
            nativeBuildInputs = [
              pkgs.coreutils
              pkgs.gnutar
              pkgs.gzip
            ];
            SOURCE_DATE_EPOCH = releaseSourceDateEpoch;
            # Assembled from the binary in seconds; fetching it saves nothing.
            allowSubstitutes = false;
            preferLocalBuild = true;
            meta = {
              description = "Release archive and checksums for the static nails binary";
              inherit (nails.meta) homepage license platforms;
            };
          }
          ''
            set -euo pipefail

            export LC_ALL=C
            export TZ=UTC
            umask 022

            package_dir="${releaseName}"
            stage_dir="$TMPDIR/stage/$package_dir"
            mkdir -p "$stage_dir" "$out"

            install -m 0755 ${nails}/bin/nails "$stage_dir/nails"
            install -m 0644 ${./LICENSE} "$stage_dir/LICENSE"
            install -m 0644 ${./README.md} "$stage_dir/README.md"
            # Operator-facing documentation and the generated man page travel with
            # the tarball on the hidden root. The completion scripts and man page
            # are never installed into decoy paths; `nails completions` prints to
            # stdout and the man page is read from here, not from /usr/share/man.
            install -m 0644 ${./nails.1} "$stage_dir/nails.1"
            install -Dm 0644 ${./docs/cli.md} "$stage_dir/docs/cli.md"
            install -Dm 0644 ${./docs/operator-guide.md} "$stage_dir/docs/operator-guide.md"
            install -Dm 0644 ${./docs/threat-model.md} "$stage_dir/docs/threat-model.md"

            tar \
              --sort=name \
              --format=gnu \
              --mtime="@${releaseSourceDateEpoch}" \
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

      rawE2eTests = import ./nix/e2e-tests { inherit self pkgs nixpkgs; };
      e2eTests = lib.filterAttrs (name: _: !(lib.hasPrefix "_" name)) rawE2eTests;

      # The portable distribution smoke suite (Debian/Ubuntu on nix-vm-test).
      # Kept separate from the NixOS `e2e` set: it uses a different driver input
      # and its own CI tier. `_metadata` is the plain data the ci.e2e distro
      # planner reads.
      rawDistroTests = import ./nix/distro-tests { inherit self pkgs nix-vm-test; };
      distroTests = lib.filterAttrs (name: _: !(lib.hasPrefix "_" name)) rawDistroTests;
      distroMetadata = rawDistroTests._metadata;
      e2eTestMetadata = {
        # Research spikes build as `e2e.<name>` but are not runner targets.
        availableTargets = lib.subtractLists rawE2eTests._researchTargets (builtins.attrNames e2eTests);
        leafTests = rawE2eTests._testNames;
        groups = rawE2eTests._groups;
        # Former test names that now run as scenarios of a merged test.
        aliases = rawE2eTests._aliases;
        timeouts = lib.mapAttrs (_: meta: meta.timeout) rawE2eTests._meta;
      };
    in
    {
      packages.${system} = {
        inherit nails nails-e2e nails-release;
        default = nails;
      };

      # Building every VM test takes hours, so the tests stay out of `checks`.
      # `nix flake check` and `nix flake show` do not descend into
      # legacyPackages, which also holds the plain-data metadata.
      legacyPackages.${system} = {
        e2e = e2eTests;
        e2e-metadata = e2eTestMetadata;
        e2e-distro = distroTests;
        e2e-distro-metadata = distroMetadata;
      };

      checks.${system} = import ./nix/checks.nix {
        inherit pkgs nails;
        e2eMetadata = e2eTestMetadata;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          rustToolchain
          pre-commit
          git
          bash
          # Shells the prompt-syntax tests shell out to, so `nix develop`
          # exercises them instead of skipping (bash is above).
          zsh
          fish
          coreutils
          gnugrep
          ripgrep
          nixfmt
          deadnix
          statix
          shellcheck
          reuse # SPDX/REUSE licensing lint (`reuse lint`)
          actionlint
          zizmor
          lychee # scripts/docs-check.sh link-checks the Markdown docs
          just
          # The Python that pyproject.toml targets, for ci/, scripts/ and the
          # E2E helpers; nix/checks.nix runs the same one.
          python314
          ruff
          mypy
          cargo-deny
          cargo-nextest
          cargo-llvm-cov
          cargo-fuzz # `just fuzz-run`: the fuzz targets in fuzz/
        ];

        # A fresh clone has no git hooks. Install them on first shell entry so
        # the pre-commit, pre-push and commit-msg checks run without a manual
        # step. This is the only place that installs them.
        shellHook = ''
          if git rev-parse --git-dir >/dev/null 2>&1; then
            hooks_dir="$(git rev-parse --git-path hooks)"
            if [ ! -x "$hooks_dir/pre-commit" ] \
              || [ ! -x "$hooks_dir/pre-push" ] \
              || [ ! -x "$hooks_dir/commit-msg" ]; then
              pre-commit install --install-hooks \
                --hook-type pre-commit \
                --hook-type pre-push \
                --hook-type commit-msg
            fi
          fi
        '';
      };
    };
}
