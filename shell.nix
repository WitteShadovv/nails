let
  flakeLock = builtins.fromJSON (builtins.readFile ./flake.lock);
  rustOverlayLocked = flakeLock.nodes.rust-overlay.locked;
  rustOverlayTarball = builtins.fetchTarball {
    url = "https://github.com/${rustOverlayLocked.owner}/${rustOverlayLocked.repo}/archive/${rustOverlayLocked.rev}.tar.gz";
    sha256 = rustOverlayLocked.narHash;
  };
in
{
  pkgs ? import <nixpkgs> { overlays = [ (import rustOverlayTarball) ]; },
}:

let
  targetTriple = "x86_64-unknown-linux-musl";

  # Compatibility shell for users not using flakes.
  # Keep this broadly aligned with flake.nix devShells.default while
  # reusing the flake-locked rust-overlay revision instead of master.
  rustToolchain = pkgs.rust-bin.stable."1.93.0".default.override {
    extensions = [
      "rust-src"
      "rust-analyzer"
      "llvm-tools-preview"
    ];
    targets = [ targetTriple ];
  };
in
pkgs.mkShell {
  packages = with pkgs; [
    rustToolchain
    git
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

  shellHook = ''
    echo "🔧 NAILS development shell (nix-shell compatibility)"
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
    echo "Pre-commit: $(pre-commit --version)"
    echo ""

    if git rev-parse --git-dir >/dev/null 2>&1; then
      hooks_dir="$(git rev-parse --git-path hooks)"

      if [ ! -x "$hooks_dir/pre-commit" ] || [ ! -x "$hooks_dir/commit-msg" ]; then
        echo "🔗 Installing git hooks (pre-commit, commit-msg)..."
        pre-commit install --quiet --install-hooks --hook-type pre-commit --hook-type commit-msg
      fi
    fi

    echo "✅ Development environment ready"
    echo ""
    echo "Available commands:"
    echo "  cargo build                # Build the Rust workspace"
    echo "  cargo test                 # Run Rust tests"
    echo "  pre-commit run --all-files # Run all configured checks"
    echo ""
  '';
}
