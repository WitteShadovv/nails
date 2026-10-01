# Task runner shared by local development and CI; `just` lists the recipes.
# The tools come from the flake dev shell (`nix develop`).

[private]
default:
    @{{ just_executable() }} --list --justfile {{ justfile() }}

# The crates that can end up in a release binary: the x86_64 Linux targets
# without dev-dependencies. Crates that only build for other platforms (wasm,
# Windows, macOS) or only for tests and benchmarks never ship.

shipped_graph := "--exclude-dev --target x86_64-unknown-linux-musl --target x86_64-unknown-linux-gnu"

# Check the shipped dependency graph against deny.toml (the CI merge gate)
deny *checks="advisories bans licenses sources":
    cargo deny --locked {{ shipped_graph }} check {{ checks }}

# Check every target and dev-dependency against deny.toml (weekly, never gates)
deny-full *checks="advisories bans licenses sources":
    cargo deny --locked check {{ checks }}
