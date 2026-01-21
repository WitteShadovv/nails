{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust toolchain
    rustc
    cargo
    rust-analyzer

    # Python environment
    python312
    python312Packages.pip
    python312Packages.setuptools
    python312Packages.wheel

    # Development tools
    pre-commit
    git

    # Security and forensics tools (for testing)
    veracrypt

    # Rust security auditing
    cargo-audit
  ];

  shellHook = ''
    echo "🔧 NAILS Development Environment"
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
    echo "Python: $(python --version)"
    echo "Pre-commit: $(pre-commit --version)"
    echo ""

    # Create and activate virtual environment
    if [ ! -d ".venv" ]; then
        echo "🐍 Creating Python virtual environment..."
        python -m venv .venv
    fi

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
    echo "  ./nails.py init              # Initialize NAILS (Python)"
    echo "  sudo ./nails.py activate     # Activate hidden environment (Python)"
    echo ""
    echo "⚠️  Remember: NAILS requires root privileges for overlay operations"
    echo "💡 To deactivate venv later: deactivate"
  '';
}
