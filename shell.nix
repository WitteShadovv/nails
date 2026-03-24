{ pkgs ? import <nixpkgs> {
  overlays = [
    (import (builtins.fetchTarball
      "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
  ];
} }:

let
  # Rust toolchain pinned to 1.93.0
  rustToolchain = pkgs.rust-bin.stable."1.93.0".default.override {
    extensions = [ "rust-src" "rust-analyzer" "llvm-tools-preview" ];
    targets = [ "x86_64-unknown-linux-musl" ];
  };

in pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain (pinned to 1.93.0)
    rustToolchain
    rustup

    # Development tools
    pre-commit
    git
    bc # Floating-point arithmetic for coverage threshold checks

    # Security and forensics tools (for testing)
    veracrypt

    # Rust security auditing
    cargo-audit

    # Dependency policy enforcement
    cargo-deny

    # Coverage enforcement (TDD workflow) - uses llvm-tools-preview from Rust toolchain
    cargo-llvm-cov

    # Rust linter
    clippy

    # Shell script linting
    shellcheck

    # musl toolchain for static linking
    pkgsStatic.stdenv.cc
  ];

  shellHook = ''
    echo "🔧 NAILS Development Environment"
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
    echo "Pre-commit: $(pre-commit --version)"
    echo ""

    # Install pre-commit hooks if not already installed
    if [ ! -f .git/hooks/pre-commit ]; then
        echo "🔗 Installing pre-commit hooks..."
        pre-commit install --quiet
    fi

    echo "✅ Development environment ready!"
    echo "🐍 Virtual environment: $(which python)"
    echo "🦀 Rust toolchain: $(which cargo)"
    echo ""
    echo "Available commands:"
    echo "  cargo build                  # Build the Rust workspace"
    echo "  cargo test                   # Run Rust tests"
    echo "  cargo build --release        # Build release binary"
    echo "  pre-commit run --all-files   # Run all checks"
    echo ""
  '';
}
